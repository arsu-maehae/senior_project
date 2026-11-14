"""T7.4 task 2 tests for ``stitch.identity``: the identity facts per (hop, moving account, LSASS read on the source
host). Fast, synthetic rows only; nothing real is opened.

Written from spec 03_stitch (hop_identity.csv as amended by 049, ST-01, ST-02, ST-05, ST-10, ST-60..ST-64, STT-09,
STT-11, STT-15, section 5), CLAUDE.md (Identity, Identity input), decisions 013, 014, 039, 044 (c), 047 and 049 item
6, not from the implementation (the code was read only for names and signatures).

Readings tested as stated by the coordinator:
- offsets None: no host is bad, uncertainties are None, only the 2.5 s floor applies, the host part of the clock flag
  is 0;
- with offsets, a host missing from the file or with status none / stale sets order_within_uncertainty; ``wide``
  does not (it is corrected and reports its uncertainty);
- the read's clock flag is the scan's per-event flag; the offset_unc columns are filled whenever the host is in the
  offsets file, also on not_applicable rows;
- a member with a NULL account gives no rows.

World: source host ep-01, target host ep-02, endpoint IP 192.168.50.21. Times are seconds after 10:30:00
(``stitch_fixtures.at``); the window is 10:00-11:00 (-2000 s is before it, 2000 s after). The LSASS read is at
300 s unless a test says otherwise. A "move after the dump" is a member 4624 later than 300 s. Messages carry uids
and ids only; no command text anywhere.
"""
from __future__ import annotations

import dataclasses
import inspect
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from clock_offset.correct import Offsets, offsets_from_rows  # noqa: E402
from gate.timeutil import fmt_us, to_us  # noqa: E402
from stitch import identity as idn  # noqa: E402
from stitch.errors import StitchError  # noqa: E402
from stitch.hops import Hop, HopSet, RemoteLogon  # noqa: E402
from stitch.identity import (NA_MACHINE, NA_NO_LOGS, NA_SOURCE_UNKNOWN, IdentityRow, LsassRead,  # noqa: E402
                             build_identity, hop_identity, lsass_reads, order_fields, sessions_at)
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402
from stitch.sessions import build_sessions  # noqa: E402
from stitch.source import SubjectLinks  # noqa: E402

START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
P = StitchParams()
SRC, TGT, OTHER = "ep-01", "ep-02", "ep-03"
SRC_IP = "192.168.50.21"
PRE = -2000.0                  # before the window start (T0 - 1800 s)
POST = 2000.0                  # after the window end
DUMP_T = 300.0
MOVE_T = 400.0                 # a move after the dump
TRIAL = sf.TRIAL
R1 = idn.R1_RULE


def U(t: float) -> int:
    """Logged instant (us) of `t` seconds after T0."""
    return to_us(sf.at(t))


# ------------------------------------------------------------------------------------------------ event builders
def L(uid, t, lid, *, host=SRC, ltype=3, account="acct_a", **kw) -> dict:
    return sf.ev(uid, "Security", 4624, host=host, off=t, logon_type=ltype, target_logon_id=lid,
                 account_name=account, **kw)


def C(uid, t, lid, eid=4634, *, host=SRC) -> dict:
    return sf.ev(uid, "Security", eid, host=host, off=t, target_logon_id=lid)


def B(uid, t, eid, *, host=SRC) -> dict:
    return sf.ev(uid, "System", eid, host=host, off=t)


def X(uid, t, *, host=SRC) -> dict:
    return sf.ev(uid, "Security", 1102, host=host, off=t)


def S10(uid, t=DUMP_T, *, host=SRC, image=None, record_id="auto") -> dict:
    return sf.ev(uid, "Sysmon", 10, host=host, off=t, source_image=image if image is not None else f"IMG-{uid}",
                 record_id=record_id)


# ------------------------------------------------------------------------------------------------ offsets
def offs(**hosts: tuple) -> Offsets:
    """Offsets from `host=(status, offset_ms, unc_ms)`; use `ep_01` for `ep-01`."""
    rows = [{"trial_id": TRIAL, "host": h.replace("_", "-"), "offset_ms": ms, "offset_status": st,
             "offset_unc_ms": unc, "host_has_events": "true", "db_sha256": "0" * 64, "clock_changes_sha256": "",
             "clock_scan": ""} for h, (st, ms, unc) in hosts.items()]
    return offsets_from_rows(rows)


def good(unc_src: int = 1, unc_tgt: int = 1) -> Offsets:
    """Both hosts `ok`, zero offset, the given uncertainties."""
    return offs(ep_01=("ok", 0, unc_src), ep_02=("ok", 0, unc_tgt), dc01=("reference", 0, 0))


# ------------------------------------------------------------------------------------------------ the world
@dataclass
class W:
    scan: object
    idx: object
    reads: list


def scan_of(rows, offsets=None):
    return scan_rows(rows, START_US, END_US, offsets, ())


def sup(scan, uid: str, *, account="acct_x", rule=R1, host=None, shift_us: int = 0) -> dict:
    """A gate `supporting.csv` row for the in-window scan row that holds `uid`."""
    row = next(r for r in scan.in_window if uid in r["event_uids"])
    return {"event_uid": uid, "rule": rule, "host": host if host is not None else row["host"],
            "event_utc_corrected": fmt_us(row["us"] + shift_us), "account_name": account}


def world(events, offsets=None, accounts: dict | None = None) -> W:
    """Scan, sessions and the LSASS reads of every in-window Sysmon 10 row (one R1 supporting row each)."""
    scan = scan_of(events, offsets)
    idx = build_sessions(scan.in_window + scan.lookback)
    s10 = [r for r in scan.in_window if (r["channel"], r["event_id"]) == ("Sysmon", 10)]
    gate = [sup(scan, r["event_uid"], account=(accounts or {}).get(r["event_uid"], "acct_x")) for r in s10]
    return W(scan, idx, lsass_reads(gate, scan))


def rl(uid, us, account="acct_a", *, host=TGT, machine=0, flag=0, gate_flag=0, us_raw=None, lid=1000) -> RemoteLogon:
    """A remote 4624 member; `us` is the corrected time in microseconds."""
    return RemoteLogon(uid=uid, event_uids=[uid], gate_uids=[uid], host=host, us_raw=us if us_raw is None else us_raw,
                       us=us, source_ip=SRC_IP, ip_kind="lab", source_port=50000, account=account,
                       account_key=account.lower() if account else None, logon_id=lid, logon_id_hex=hex(lid),
                       authentication_package="NTLM", logon_guid=None, machine_account=machine, rules=["R4_smb"],
                       trigger_ids=["t"], gate_clock_unreliable=gate_flag, clock_unreliable=flag, session_key=None)


def mk_hop(members, hop_id="h1", target=TGT, followups=()) -> Hop:
    return Hop(hop_id=hop_id, target_host=target, source_ip=SRC_IP, ip_kind="lab", members=list(members),
               protocol="smb", rules=["R4_smb"], trigger_ids=["t"], authentication_packages=["NTLM"],
               mixed_account=int(len({(m.account or "").lower() for m in members}) > 1), followups=list(followups))


def mem(uid="m1", t=MOVE_T, account="acct_a", **kw) -> RemoteLogon:
    return rl(uid, U(t), account, **kw)


def rows_of(events, members, *, source=SRC, reason="", offsets=None, accounts=None, hop_id="h1"):
    """(hop, world, identity rows) for one hop."""
    w = world(events, offsets, accounts)
    h = mk_hop(members, hop_id)
    return h, w, hop_identity(h, source, reason, w.reads, w.idx, offsets)


def one(rows) -> IdentityRow:
    assert len(rows) == 1, [(r.account, r.dump_event_uid) for r in rows]
    return rows[0]


def links(source_host, reason="", **over) -> SubjectLinks:
    """A hand-built SubjectLinks with no candidate; `over` replaces fields."""
    base = dict(target_host=TGT, source_host=source_host, member_uids=[], rows=[], target_only_reason=reason,
                candidate_counts={}, candidate_count_all=0, session_methods={}, sessions={}, evidence_before_range=0,
                evidence_after_range=0, system_session_evidence={}, methods={}, host_clock_unreliable=0)
    base.update(over)
    return SubjectLinks(**base)


class Poison:
    """A stand-in for linked-session data: any access fails the test (decision 013)."""

    def __getattr__(self, name):
        raise AssertionError(f"identity touched the linked session data ({name})")

    def __iter__(self):
        raise AssertionError("identity iterated the linked session data")

    def __len__(self):
        raise AssertionError("identity measured the linked session data")

    def __getitem__(self, k):
        raise AssertionError("identity indexed the linked session data")

    def __contains__(self, k):
        raise AssertionError("identity searched the linked session data")

    def __bool__(self):
        raise AssertionError("identity tested the linked session data")


def uids(sessions) -> list[str]:
    return [min(s.open_uids) for s in sessions]


# ================================================================================================ 1. contract
SPEC_COLUMNS = ["hop_id", "account", "source_host", "move_utc_corrected", "dump_event_uid", "dump_utc_corrected",
                "dump_source_image", "dump_account", "gap_ms", "order_margin_ms", "order_ok", "order_within_tolerance",
                "order_within_uncertainty", "offset_unc_source_ms", "offset_unc_target_ms", "open_session_uids",
                "open_session_types", "session_open_before_window", "end_unknown_session_uids", "not_applicable",
                "clock_unreliable"]


def test_identity_row_carries_every_spec_column_and_no_value() -> None:
    names = {f.name for f in dataclasses.fields(IdentityRow)}
    times = {"move_utc_corrected": "move_us", "dump_utc_corrected": "dump_us"}
    for col in SPEC_COLUMNS:
        assert times.get(col, col) in names, col
    for n in names:                                     # ST-64: facts only, T9 computes the value
        assert not any(w in n for w in ("value", "coherence", "score", "identity", "verdict")), n


def test_constants_are_spelled_as_the_spec() -> None:
    assert (NA_SOURCE_UNKNOWN, NA_NO_LOGS, NA_MACHINE) == ("source_host_unknown", "source_host_no_logs",
                                                            "machine_account")
    assert idn.R1_RULE == "R1_lsass"
    assert tuple(idn.NOT_APPLICABLE) == (NA_SOURCE_UNKNOWN, NA_NO_LOGS, NA_MACHINE)     # 049 item 6 precedence


def test_spec_parameters() -> None:
    assert P.order_tol_s == 5.0 and P.order_unc_floor_s == 2.5 and P.boot_group_s == 120.0


def test_rows_are_one_per_account_and_read_none_lost_or_duplicated() -> None:
    members = [mem("a1", 400, "acct_a"), mem("b1", 410, "acct_b")]
    ev = [S10("R1", 300), S10("R2", 310), S10("R3", 320)]
    _, _, rows = rows_of(ev, members)
    assert len(rows) == 6
    assert {(r.account, r.dump_event_uid) for r in rows} == {(a, d) for a in ("acct_a", "acct_b")
                                                             for d in ("R1", "R2", "R3")}
    assert all(r.hop_id == "h1" and r.source_host == SRC for r in rows)


def test_row_order_is_deterministic_whatever_the_input_order() -> None:
    members = [mem("a1", 400, "acct_a"), mem("b1", 410, "acct_b")]
    ev = [S10("R1", 300), S10("R2", 310), S10("R3", 320)]
    w = world(ev)
    h1, h2 = mk_hop(members), mk_hop(list(reversed(members)))
    r1 = hop_identity(h1, SRC, "", w.reads, w.idx, None)
    r2 = hop_identity(h2, SRC, "", list(reversed(w.reads)), w.idx, None)
    assert r1 == r2


def test_hop_identity_returns_frozen_rows() -> None:
    _, _, rows = rows_of([S10("R1")], [mem()])
    with pytest.raises(dataclasses.FrozenInstanceError):
        rows[0].order_ok = 0                            # type: ignore[misc]


# ================================================================================================ 2. ST-60 / STT-09
def test_target_only_hop_still_gets_identity_rows() -> None:
    ev = [L("O", 100, 1000), S10("R1")]
    _, _, rows = rows_of(ev, [mem()], reason="no_evidence_in_range")
    r = one(rows)
    assert r.not_applicable == "" and r.dump_event_uid == "R1" and r.open_session_uids == ("O",)
    assert r.order_ok == 1


def test_one_row_set_per_member_account_in_a_mixed_hop() -> None:
    members = [mem("a1", 390, "acct_a"), mem("a2", 400, "acct_a"), mem("b1", 450, "acct_b")]
    _, _, rows = rows_of([S10("R1")], members)
    by = {r.account: r for r in rows}
    assert set(by) == {"acct_a", "acct_b"} and len(rows) == 2
    assert by["acct_a"].move_uid == "a1" and by["acct_a"].move_us == U(390)
    assert by["acct_b"].move_uid == "b1" and by["acct_b"].move_us == U(450)
    assert by["acct_a"].gap_ms == 90_000 and by["acct_b"].gap_ms == 150_000


def test_move_is_the_first_member_by_corrected_time_not_by_logged_time() -> None:
    """ST-60 / ST-02: the move time is the corrected one; the first member is chosen on it."""
    later_raw_first_corrected = rl("B", U(405), us_raw=U(410))
    earlier_raw_later_corrected = rl("A", U(420), us_raw=U(400))
    _, _, rows = rows_of([S10("R1")], [earlier_raw_later_corrected, later_raw_first_corrected])
    r = one(rows)
    assert r.move_uid == "B" and r.move_us == U(405)


def test_equal_corrected_times_take_the_smaller_uid() -> None:
    _, _, rows = rows_of([S10("R1")], [mem("z9", 400), mem("a1", 400)])
    assert one(rows).move_uid == "a1"


def test_accounts_are_grouped_case_insensitively() -> None:
    members = [mem("a2", 420, "ALICE"), mem("a1", 400, "alice")]
    _, _, rows = rows_of([S10("R1")], members)
    r = one(rows)
    assert r.account.lower() == "alice" and r.move_uid == "a1"


def test_null_account_members_give_no_rows() -> None:
    null = rl("n1", U(400), None)
    _, _, rows = rows_of([S10("R1")], [null])
    assert rows == [] and idn.null_account_members(mk_hop([null])) == ["n1"]
    _, _, rows2 = rows_of([S10("R1")], [null, mem("a1", 410, "acct_a")])
    assert [r.account for r in rows2] == ["acct_a"] and rows2[0].move_uid == "a1"


def test_followup_logons_give_no_rows() -> None:
    w = world([S10("R1")])
    h = mk_hop([mem("a1", 400, "acct_a")], followups=[mem("f1", 500, "acct_f")])
    rows = hop_identity(h, SRC, "", w.reads, w.idx, None)
    assert [r.account for r in rows] == ["acct_a"]


def test_a_hop_with_no_member_has_no_rows() -> None:
    w = world([S10("R1")])
    assert hop_identity(mk_hop([]), SRC, "", w.reads, w.idx, None) == []


def _assert_empty(r: IdentityRow) -> None:
    assert r.dump_event_uid == "" and r.dump_us is None and r.dump_source_image is None and r.dump_account is None
    assert (r.gap_ms, r.order_margin_ms, r.order_ok, r.order_within_tolerance, r.order_within_uncertainty) == (
        None, None, None, None, None)
    assert r.open_session_uids == () and r.open_session_types == () and r.open_session_ids_hex == ()
    assert r.end_unknown_session_uids == () and r.session_open_before_window == 0


def test_source_host_unknown_gives_one_empty_row_per_account() -> None:
    ev = [L("O", 100, 1000), S10("R1")]
    members = [mem("a1", 400, "acct_a"), mem("b1", 410, "acct_b")]
    _, _, rows = rows_of(ev, members, source=None, reason=NA_SOURCE_UNKNOWN)
    assert len(rows) == 2
    for r in rows:
        assert r.not_applicable == NA_SOURCE_UNKNOWN and r.source_host is None
        _assert_empty(r)
    assert {r.move_uid for r in rows} == {"a1", "b1"}


def test_source_host_no_logs_gives_one_empty_row() -> None:
    _, _, rows = rows_of([S10("R1")], [mem()], source=OTHER, reason=NA_NO_LOGS)
    r = one(rows)
    assert r.not_applicable == NA_NO_LOGS and r.source_host == OTHER
    _assert_empty(r)


def test_no_logs_stays_not_applicable_even_when_a_read_is_listed_for_the_host() -> None:
    _, _, rows = rows_of([S10("R1", host=OTHER)], [mem()], source=OTHER, reason=NA_NO_LOGS)
    r = one(rows)
    assert r.not_applicable == NA_NO_LOGS
    _assert_empty(r)


def test_machine_account_gives_one_empty_row() -> None:
    ev = [L("O", 100, 1000, account="ep-03$"), S10("R1")]
    _, _, rows = rows_of(ev, [mem("m1", 400, "ep-03$", machine=1), mem("m2", 405, "ep-03$", machine=1)])
    r = one(rows)
    assert r.not_applicable == NA_MACHINE and r.move_uid == "m1"
    _assert_empty(r)


def test_precedence_unknown_over_no_logs_over_machine() -> None:
    machine = [mem("m1", 400, "ep-03$", machine=1)]
    _, _, a = rows_of([S10("R1")], machine, source=None, reason=NA_NO_LOGS)
    assert one(a).not_applicable == NA_SOURCE_UNKNOWN
    _, _, b = rows_of([S10("R1")], machine, source=OTHER, reason=NA_NO_LOGS)
    assert one(b).not_applicable == NA_NO_LOGS
    _, _, c = rows_of([S10("R1")], machine, source=SRC, reason="")
    assert one(c).not_applicable == NA_MACHINE
    _, _, d = rows_of([S10("R1")], machine, source=None, reason=NA_SOURCE_UNKNOWN)
    assert one(d).not_applicable == NA_SOURCE_UNKNOWN


def test_not_applicable_is_set_per_account_in_a_mixed_hop() -> None:
    members = [mem("a1", 400, "acct_a"), mem("m1", 410, "ep-03$", machine=1)]
    _, _, rows = rows_of([S10("R1")], members)
    by = {r.account: r for r in rows}
    assert by["acct_a"].not_applicable == "" and by["acct_a"].dump_event_uid == "R1"
    assert by["ep-03$"].not_applicable == NA_MACHINE
    _assert_empty(by["ep-03$"])


def test_an_account_with_one_machine_member_and_one_user_member_is_not_machine() -> None:
    """049 item 6: machine_account only when every member of the account is a machine account."""
    members = [mem("m1", 400, "acct_a", machine=1), mem("m2", 405, "acct_a", machine=0)]
    _, _, rows = rows_of([S10("R1")], members)
    assert one(rows).not_applicable == ""


def test_no_read_on_the_source_host_gives_one_row_per_account_with_empty_dump_columns() -> None:
    members = [mem("a1", 400, "acct_a"), mem("b1", 410, "acct_b")]
    ev = [L("O", 100, 1000), S10("R1", host=OTHER), S10("R2", host=TGT)]
    _, _, rows = rows_of(ev, members)
    assert len(rows) == 2
    for r in rows:
        assert r.not_applicable == ""
        _assert_empty(r)
    assert {r.account for r in rows} == {"acct_a", "acct_b"}


def test_no_read_at_all_gives_the_same_empty_rows() -> None:
    w = world([L("O", 100, 1000)])
    rows = hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, None)
    r = one(rows)
    assert r.not_applicable == ""
    _assert_empty(r)
    assert r.move_uid == "m1"


def test_build_identity_covers_every_hop_and_sorts_by_hop_id() -> None:
    w = world([S10("R1")])
    h2, h1 = mk_hop([mem("x2", 400)], "h2"), mk_hop([mem("x1", 400)], "h1")
    hs = HopSet(trial_id=TRIAL, hops=[h2, h1], followups=[], counts={})
    rows = build_identity(hs, {"h1": links(SRC), "h2": links(None, NA_SOURCE_UNKNOWN)}, w.reads, w.idx, None)
    assert [(r.hop_id, r.not_applicable) for r in rows] == [("h1", ""), ("h2", NA_SOURCE_UNKNOWN)]


def test_build_identity_needs_a_links_entry_for_every_hop() -> None:
    w = world([S10("R1")])
    hs = HopSet(trial_id=TRIAL, hops=[mk_hop([mem()], "h1")], followups=[], counts={})
    with pytest.raises(StitchError):
        build_identity(hs, {}, w.reads, w.idx, None)


def test_build_identity_takes_source_host_and_reason_from_links() -> None:
    w = world([S10("R1")])
    hs = HopSet(trial_id=TRIAL, hops=[mk_hop([mem()], "h1")], followups=[], counts={})
    r = one(build_identity(hs, {"h1": links(OTHER, NA_NO_LOGS)}, w.reads, w.idx, None))
    assert r.source_host == OTHER and r.not_applicable == NA_NO_LOGS


# ================================================================================================ 3. ST-61 / Q9
def test_every_r1_read_on_the_source_host_gives_a_row_whatever_account_or_time() -> None:
    ev = [S10("SYS", 100, image="IMG-SYS"), S10("SVC", 250, image="IMG-SVC"), S10("DOM", 350, image="IMG-DOM"),
          S10("LATE", 900, image="IMG-LATE")]
    acc = {"SYS": "NT AUTHORITY\\SYSTEM", "SVC": "svc_backup", "DOM": "DOM\\admin_it", "LATE": "acct_a"}
    _, _, rows = rows_of(ev, [mem("m1", 400)], accounts=acc)
    assert [r.dump_event_uid for r in rows] == ["SYS", "SVC", "DOM", "LATE"]      # in dump-time order
    assert [r.dump_account for r in rows] == [acc[u] for u in ("SYS", "SVC", "DOM", "LATE")]
    assert [r.dump_source_image for r in rows] == ["IMG-SYS", "IMG-SVC", "IMG-DOM", "IMG-LATE"]
    assert [r.dump_us for r in rows] == [U(100), U(250), U(350), U(900)]
    assert [r.order_ok for r in rows] == [1, 1, 1, 0]        # the read after the move is listed, with order_ok 0


def test_a_read_before_the_move_and_after_both_appear() -> None:
    _, _, rows = rows_of([S10("BEFORE", 100), S10("AFTER", 500)], [mem("m1", 400)])
    assert [(r.dump_event_uid, r.gap_ms > 0) for r in rows] == [("BEFORE", True), ("AFTER", False)]


def test_reads_on_other_hosts_never_give_a_row() -> None:
    ev = [S10("ON_SRC", 250), S10("ON_TGT", 250, host=TGT), S10("ON_OTHER", 250, host=OTHER)]
    _, _, rows = rows_of(ev, [mem("m1", 400)])
    assert [r.dump_event_uid for r in rows] == ["ON_SRC"]


def test_a_read_with_no_account_or_image_is_kept() -> None:
    scan = scan_of([S10("R1")])
    reads = lsass_reads([sup(scan, "R1", account=None)], scan)
    assert len(reads) == 1 and reads[0].account is None
    reads2 = lsass_reads([sup(scan, "R1", account="")], scan)
    assert reads2[0].account is None


def test_lsass_reads_keeps_only_r1_rows_and_copies_the_scan_fields() -> None:
    ev = [S10("R1", 250, image="IMG-ONE"), S10("R2", 260)]
    scan = scan_of(ev)
    reads = lsass_reads([sup(scan, "R1", account="acct_x"), sup(scan, "R2", rule="R2_other")], scan)
    assert [r.event_uid for r in reads] == ["R1"]
    r = reads[0]
    assert isinstance(r, LsassRead) and r.host == SRC and r.us == U(250) and r.us_raw == U(250)
    assert r.source_image == "IMG-ONE" and r.account == "acct_x" and r.clock_unreliable == 0
    assert r.supporting_uids == ("R1",)


def test_a_non_r1_row_is_not_checked_against_the_scan() -> None:
    scan = scan_of([S10("R1")])
    other = {"event_uid": "NOT-IN-SCAN", "rule": "R4_smb", "host": SRC, "event_utc_corrected": "", "account_name": ""}
    assert [r.event_uid for r in lsass_reads([sup(scan, "R1"), other], scan)] == ["R1"]


def test_reads_are_sorted_by_host_time_uid() -> None:
    ev = [S10("B", 300), S10("A", 300), S10("C", 100), S10("D", 50, host=OTHER)]
    scan = scan_of(ev)
    reads = lsass_reads([sup(scan, u) for u in ("B", "A", "C", "D")], scan)
    assert [r.event_uid for r in reads] == ["C", "A", "B", "D"]


def test_no_supporting_rows_no_reads() -> None:
    assert lsass_reads([], scan_of([S10("R1")])) == []


def test_error_uid_missing_from_the_scan() -> None:
    scan = scan_of([S10("R1")])
    bad = {"event_uid": "GHOST", "rule": R1, "host": SRC, "event_utc_corrected": fmt_us(U(300)), "account_name": ""}
    with pytest.raises(StitchError):
        lsass_reads([bad], scan)


@pytest.mark.parametrize("t", [PRE, POST])
def test_error_read_outside_the_window_is_never_listed(t) -> None:
    """ST-01: an LSASS read outside the window is not in the scan, so naming it is an error."""
    scan = scan_of([S10("OUT", t)])
    gate = {"event_uid": "OUT", "rule": R1, "host": SRC, "event_utc_corrected": fmt_us(U(t)), "account_name": ""}
    with pytest.raises(StitchError):
        lsass_reads([gate], scan)


def test_error_uid_is_not_a_sysmon_10_row() -> None:
    scan = scan_of([L("O", 100, 1000), S10("R1")])
    gate = sup(scan, "O")
    with pytest.raises(StitchError):
        lsass_reads([gate], scan)


def test_error_corrected_time_differs() -> None:
    scan = scan_of([S10("R1")])
    with pytest.raises(StitchError):
        lsass_reads([sup(scan, "R1", shift_us=1000)], scan)


def test_error_corrected_time_differs_when_a_clock_offset_is_applied() -> None:
    """The gate must carry the corrected time; the logged time with an applied offset is a disagreement."""
    o = offs(ep_01=("ok", 10_000, 5), ep_02=("ok", 0, 5), dc01=("reference", 0, 0))
    scan = scan_of([S10("R1", 300)], o)
    row = scan.in_window[0]
    assert row["us"] == row["us_raw"] - 10_000_000
    g = sup(scan, "R1")
    assert lsass_reads([g], scan)[0].us == U(300) - 10_000_000
    g["event_utc_corrected"] = fmt_us(row["us_raw"])
    with pytest.raises(StitchError):
        lsass_reads([g], scan)


def test_error_host_differs() -> None:
    scan = scan_of([S10("R1")])
    with pytest.raises(StitchError):
        lsass_reads([sup(scan, "R1", host=OTHER)], scan)


def test_error_rows_collapsed_into_one_read_disagree_on_account() -> None:
    scan = scan_of([S10("R-A", record_id=77), S10("R-B", record_id=77)])
    with pytest.raises(StitchError):
        lsass_reads([sup(scan, "R-A", account="one"), sup(scan, "R-B", account="two")], scan)


def test_st05_near_duplicate_copies_give_one_read_named_by_the_kept_uid() -> None:
    scan = scan_of([S10("R-B", record_id=77), S10("R-A", record_id=77)])
    assert len(scan.in_window) == 1 and scan.in_window[0]["event_uid"] == "R-A"
    reads = lsass_reads([sup(scan, "R-B", account="x"), sup(scan, "R-A", account="x")], scan)
    assert len(reads) == 1
    assert reads[0].event_uid == "R-A" and reads[0].supporting_uids == ("R-A", "R-B")


def test_st05_a_supporting_row_naming_only_the_non_representative_copy() -> None:
    scan = scan_of([S10("R-B", record_id=77), S10("R-A", record_id=77)])
    reads = lsass_reads([sup(scan, "R-B", account="x")], scan)
    assert len(reads) == 1 and reads[0].event_uid == "R-A" and reads[0].supporting_uids == ("R-B",)


def test_st05_a_near_duplicate_pair_gives_one_identity_row_per_account() -> None:
    scan = scan_of([S10("R-B", record_id=77), S10("R-A", record_id=77)])
    idx = build_sessions(scan.in_window + scan.lookback)
    reads = lsass_reads([sup(scan, "R-A"), sup(scan, "R-B")], scan)
    rows = hop_identity(mk_hop([mem()]), SRC, "", reads, idx, None)
    assert [r.dump_event_uid for r in rows] == ["R-A"]


def test_distinct_events_with_distinct_record_ids_stay_two_reads() -> None:
    scan = scan_of([S10("R-A", record_id=77), S10("R-B", record_id=78)])
    assert len(lsass_reads([sup(scan, "R-A"), sup(scan, "R-B")], scan)) == 2


def test_the_read_clock_flag_is_the_scans_event_flag() -> None:
    o = offs(ep_01=("wide", 0, 800), ep_02=("ok", 0, 5), dc01=("reference", 0, 0))
    scan = scan_of([S10("R1")], o)
    assert lsass_reads([sup(scan, "R1")], scan)[0].clock_unreliable == 1
    scan2 = scan_of([S10("R1")], good())
    assert lsass_reads([sup(scan2, "R1")], scan2)[0].clock_unreliable == 0


# ================================================================================================ 4. ST-62 order
DUMP = 1_000_000_000_000        # an arbitrary dump instant in microseconds


def of(move_off_ms: float, unc_s=1, unc_t=1, bad=False, params=P):
    """order_fields for a move `move_off_ms` after the dump (negative = before)."""
    return order_fields(DUMP + int(round(move_off_ms * 1000)), DUMP, unc_s, unc_t, bad, params)


def test_gap_and_margin_signs() -> None:
    gap, margin, *_ = of(12_000)
    assert (gap, margin) == (12_000, 17_000)
    gap, margin, *_ = of(-12_000)
    assert (gap, margin) == (-12_000, -7_000)
    assert of(0)[:2] == (0, 5_000)


def test_order_ok_at_margin_zero_is_one_and_one_ms_earlier_is_zero() -> None:
    gap, margin, ok, *_ = of(-5_000)
    assert (gap, margin, ok) == (-5_000, 0, 1)
    gap, margin, ok, *_ = of(-5_001)
    assert (gap, margin, ok) == (-5_001, -1, 0)
    assert of(-4_999)[2] == 1


def test_order_ok_is_never_changed_by_the_flags() -> None:
    for off in (-60_000, -5_001, -5_000, -1_000, 0, 60_000):
        base = of(off, 1, 1, False)
        for unc in ((1, 1), (50_000, 50_000), (None, None)):
            for bad in (False, True):
                assert of(off, *unc, bad)[2] == base[2]
    assert of(60_000, bad=True)[2] == 1 and of(-60_000, bad=True)[2] == 0


@pytest.mark.parametrize("off, expected", [(5_000, 0), (4_999, 1), (-5_000, 0), (-4_999, 1), (0, 1),
                                           (5_001, 0), (-5_001, 0)])
def test_order_within_tolerance_is_strict_at_five_seconds(off, expected) -> None:
    assert of(off)[3] == expected


def test_stt15_the_spec_case_move_4s_inside_the_boundary() -> None:
    """Margin 4 s, uncertainties 1.76 s and 2.97 s (sum 4.73 s): flagged, order_ok unchanged."""
    gap, margin, ok, in_tol, in_unc = of(-1_000, 1_760, 2_970)
    assert margin == 4_000 and gap == -1_000
    assert in_unc == 1 and ok == 1 and in_tol == 1
    _, _, ok_small, _, in_unc_small = of(-1_000, 1, 1)
    assert ok_small == ok and in_unc_small == 0         # 4 s > 2.5 s floor: not flagged without the uncertainties


def test_the_spec_case_on_the_other_side_of_the_boundary() -> None:
    _, margin, ok, _, in_unc = of(-9_000, 1_760, 2_970)
    assert margin == -4_000 and ok == 0 and in_unc == 1


def test_stt15_uncertainties_of_1_ms_use_the_2_5_s_floor() -> None:
    assert of(-1_000, 1, 1)[4] == 0         # margin 4 s
    assert of(-3_000, 1, 1)[4] == 1         # margin 2 s
    assert of(-2_500, 1, 1)[4] == 0         # margin 2.5 s exactly: strict
    assert of(-2_501, 1, 1)[4] == 1         # margin 2.499 s
    assert of(-7_500, 1, 1)[4] == 0         # margin -2.5 s
    assert of(-7_499, 1, 1)[4] == 1         # margin -2.499 s


def test_the_band_is_the_sum_of_the_uncertainties_when_it_exceeds_the_floor() -> None:
    assert of(-1_001, 3_000, 1_000)[4] == 1          # margin 3.999 s < 4 s
    assert of(-1_000, 3_000, 1_000)[4] == 0          # margin 4 s
    assert of(-1_000, 4_001, 0)[4] == 1
    assert of(-1_000, 0, 4_001)[4] == 1


def test_none_uncertainties_leave_only_the_floor() -> None:
    assert of(-3_000, None, None)[4] == 1
    assert of(-1_000, None, None)[4] == 0
    assert of(-1_000, 4_001, None)[4] == 1


def test_a_bad_host_always_sets_within_uncertainty() -> None:
    assert of(60_000, 1, 1, True)[4] == 1
    assert of(-60_000, 1, 1, True)[4] == 1
    assert of(60_000, None, None, True)[4] == 1


def test_parameters_are_read_from_params() -> None:
    p = StitchParams(order_tol_s=10.0, order_unc_floor_s=1.0)
    gap, margin, ok, in_tol, in_unc = of(-10_000, 1, 1, False, p)
    assert (gap, margin, ok, in_tol) == (-10_000, 0, 1, 0)
    assert of(-9_999, 1, 1, False, p)[3] == 1
    assert of(-10_000 + 500, 1, 1, False, p)[4] == 1        # margin 0.5 s < 1 s floor
    assert of(-10_000 + 1_500, 1, 1, False, p)[4] == 0      # margin 1.5 s


def test_order_fields_returns_integers() -> None:
    out = of(1_234)
    assert all(isinstance(v, int) for v in out)


# -- the same flags on a row
def move_row(move_off_ms, offsets=None, **kw) -> IdentityRow:
    """One identity row for a read at 300 s and a member `move_off_ms` after it."""
    m = rl("m1", U(DUMP_T) + int(round(move_off_ms * 1000)))
    _, _, rows = rows_of([S10("R1")], [m], offsets=offsets, **kw)
    return one(rows)


def test_row_order_facts_on_corrected_times() -> None:
    r = move_row(-1_000, good(1_760, 2_970))
    assert (r.gap_ms, r.order_margin_ms, r.order_ok, r.order_within_tolerance, r.order_within_uncertainty) == (
        -1_000, 4_000, 1, 1, 1)
    assert (r.offset_unc_source_ms, r.offset_unc_target_ms) == (1_760, 2_970)


def test_row_without_offsets_uses_the_floor_and_has_no_uncertainties() -> None:
    r = move_row(-3_000, None)
    assert r.order_within_uncertainty == 1 and r.offset_unc_source_ms is None and r.offset_unc_target_ms is None
    assert move_row(-1_000, None).order_within_uncertainty == 0


@pytest.mark.parametrize("bad_host", ["ep_01", "ep_02"])
@pytest.mark.parametrize("status", ["none", "stale"])
def test_row_none_or_stale_host_sets_within_uncertainty(bad_host, status) -> None:
    spec = dict(ep_01=("ok", 0, 1), ep_02=("ok", 0, 1), dc01=("reference", 0, 0))
    spec[bad_host] = (status, 0, 1)
    r = move_row(60_000, offs(**spec))
    assert r.order_within_uncertainty == 1 and r.order_ok == 1 and r.clock_unreliable == 1


@pytest.mark.parametrize("missing", ["ep_01", "ep_02"])
def test_row_host_missing_from_the_offsets_sets_within_uncertainty(missing) -> None:
    spec = dict(ep_01=("ok", 0, 1), ep_02=("ok", 0, 1), dc01=("reference", 0, 0))
    del spec[missing]
    r = move_row(60_000, offs(**spec))
    assert r.order_within_uncertainty == 1


def test_row_wide_host_is_corrected_so_only_the_band_applies() -> None:
    o = offs(ep_01=("wide", 0, 1_500), ep_02=("ok", 0, 1_500), dc01=("reference", 0, 0))
    r = move_row(60_000, o)
    assert r.order_within_uncertainty == 0 and r.clock_unreliable == 1       # wide is unreliable (ST-02)
    r2 = move_row(-1_000, o)                                                 # margin 4 s vs band 3 s
    assert r2.order_within_uncertainty == 0
    r3 = move_row(-2_000, o)                                                 # margin 3 s: strict
    assert r3.order_within_uncertainty == 0
    r4 = move_row(-2_001, o)
    assert r4.order_within_uncertainty == 1


def test_offset_unc_columns_are_filled_when_the_host_is_in_the_file_also_on_not_applicable_rows() -> None:
    o = good(111, 222)
    _, _, rows = rows_of([S10("R1")], [mem("m1", 400, "ep-03$", machine=1)], offsets=o)
    r = one(rows)
    assert r.not_applicable == NA_MACHINE and (r.offset_unc_source_ms, r.offset_unc_target_ms) == (111, 222)
    _, _, rows = rows_of([S10("R1")], [mem()], source=None, reason=NA_SOURCE_UNKNOWN, offsets=o)
    r = one(rows)
    assert r.offset_unc_source_ms is None and r.offset_unc_target_ms == 222
    _, _, rows = rows_of([S10("R1")], [mem()], source=OTHER, reason=NA_NO_LOGS, offsets=o)
    r = one(rows)
    assert r.offset_unc_source_ms is None and r.offset_unc_target_ms == 222        # ep-03 not in this offsets file


def test_offset_unc_is_none_for_a_host_not_in_the_file() -> None:
    o = offs(ep_01=("ok", 0, 7), dc01=("reference", 0, 0))
    r = move_row(60_000, o)
    assert r.offset_unc_source_ms == 7 and r.offset_unc_target_ms is None


# ================================================================================================ 5. ST-63 sessions
def dump_row(events, **kw) -> IdentityRow:
    """The identity row of acct_a for a read at 300 s (one read in `events`)."""
    return one(rows_of(events + [S10("R1", DUMP_T)], [mem("m1", MOVE_T)], **kw)[2])


def test_an_open_session_is_listed_with_type_hex_and_no_pre_window_flag() -> None:
    r = dump_row([L("O", 100, 1000, ltype=10)])
    assert r.open_session_uids == ("O",) and r.open_session_types == (10,)
    assert r.open_session_ids_hex == ("0x3e8",) and r.session_open_before_window == 0
    assert r.end_unknown_session_uids == ()


def test_the_session_open_at_the_instant_of_the_dump_counts() -> None:
    assert dump_row([L("O", DUMP_T, 1000)]).open_session_uids == ("O",)
    assert dump_row([L("O", DUMP_T + 1, 1000)]).open_session_uids == ()


@pytest.mark.parametrize("eid", [4634, 4647])
def test_session_closed_before_the_dump_is_not_open(eid) -> None:
    r = dump_row([L("O", 100, 1000), C("K", 200, 1000, eid)])
    assert r.open_session_uids == () and r.end_unknown_session_uids == ()


def test_session_closed_after_the_dump_was_open_at_it() -> None:
    assert dump_row([L("O", 100, 1000), C("K", 350, 1000)]).open_session_uids == ("O",)


@pytest.mark.parametrize("eid", [41, 6005, 6008, 1074, 6006])
def test_a_boot_between_the_open_and_the_dump_closes_it(eid) -> None:
    r = dump_row([L("O", 100, 1000), B("S", 200, eid)])
    assert r.open_session_uids == ()


def test_a_session_opened_between_two_startup_events_of_one_restart_stays_open() -> None:
    """047 / STT-11: 41 and 6005 40 s apart are one restart; a logon between them is in the new epoch."""
    ev = [L("OLD", 100, 900), B("E41", 250, 41), L("MID", 270, 1000), B("E6005", 290, 6005)]
    r = dump_row(ev)
    assert r.open_session_uids == ("MID",)


def test_a_4624_between_the_shutdown_group_and_the_startup_belongs_to_the_new_boot() -> None:
    ev = [L("OLD", 100, 900), B("S1074", 150, 1074), B("S6006", 180, 6006), L("NEW", 237, 1000),
          B("U6005", 240, 6005)]
    r = dump_row(ev)
    assert r.open_session_uids == ("NEW",)


def test_logon_id_reused_after_a_boot_is_a_different_session() -> None:
    ev = [L("OLD", 100, 1000), B("S", 150, 1074), L("NEW", 200, 1000)]
    assert dump_row(ev).open_session_uids == ("NEW",)
    ev2 = [L("OLD", 100, 1000), B("S", 150, 1074)]
    assert dump_row(ev2).open_session_uids == ()


def test_session_opened_and_closed_before_the_window_is_not_open() -> None:
    r = dump_row([L("PRE", PRE, 1000), C("K", PRE + 50, 1000)])
    assert r.open_session_uids == () and r.session_open_before_window == 0


def test_session_opened_before_the_window_and_still_open_is_used_and_flagged() -> None:
    ev = [L("PRE", PRE, 1000)]
    h, w, rows = rows_of(ev + [S10("R1")], [mem()])
    r = one(rows)
    assert r.open_session_uids == ("PRE",) and r.session_open_before_window == 1
    assert "PRE" not in {u for row in w.scan.in_window for u in row["event_uids"]}      # ST-01: not an in-window row
    assert all("PRE" not in min(s.open_uids or [""]) for s in w.idx.window_view())      # absent from the window view


def test_a_pre_window_boot_closes_a_pre_window_session() -> None:
    ev = [L("PRE", PRE, 1000), B("S", PRE + 100, 1074)]
    r = dump_row(ev)
    assert r.open_session_uids == () and r.session_open_before_window == 0


def test_the_pre_window_flag_is_set_when_any_open_session_is_pre_window() -> None:
    r = dump_row([L("PRE", PRE, 1000), L("IN", 100, 1001, ltype=10)])
    assert r.open_session_uids == ("PRE", "IN") and r.session_open_before_window == 1
    r2 = dump_row([L("PRE", PRE, 1000), C("K", PRE + 10, 1000), L("IN", 100, 1001)])
    assert r2.open_session_uids == ("IN",) and r2.session_open_before_window == 0


def test_a_1102_between_the_open_and_the_dump_is_end_unknown_and_not_open() -> None:
    r = dump_row([L("O", 100, 1000), X("X", 200)])
    assert r.open_session_uids == () and r.end_unknown_session_uids == ("O",)


def test_a_1102_before_the_open_or_after_the_dump_changes_nothing() -> None:
    assert dump_row([X("X", 50), L("O", 100, 1000)]).open_session_uids == ("O",)
    r = dump_row([L("O", 100, 1000), X("X", 350)])
    assert r.open_session_uids == ("O",) and r.end_unknown_session_uids == ()


def test_a_close_before_the_dump_wins_over_a_1102_between() -> None:
    r = dump_row([L("O", 100, 1000), X("X", 150), C("K", 200, 1000)])
    assert r.open_session_uids == () and r.end_unknown_session_uids == ()


def test_another_accounts_session_never_counts() -> None:
    r = dump_row([L("O2", 100, 1001, account="someone_else")])
    assert r.open_session_uids == ()


@pytest.mark.parametrize("lid", [0x3e4, 0x3e5, 0x3e7])
def test_a_system_logon_id_session_never_counts(lid) -> None:
    r = dump_row([L("SYS", 100, lid)])
    assert r.open_session_uids == () and r.end_unknown_session_uids == ()


def test_a_machine_account_session_never_counts() -> None:
    r = dump_row([L("MA", 100, 1000, machine_account=1)])
    assert r.open_session_uids == ()


def test_a_machine_session_with_a_1102_is_not_end_unknown_either() -> None:
    r = dump_row([L("MA", 100, 1000, machine_account=1), X("X", 200)])
    assert r.end_unknown_session_uids == ()


def test_the_account_is_compared_case_insensitively() -> None:
    assert dump_row([L("O", 100, 1000, account="ACCT_A")]).open_session_uids == ("O",)
    r = one(rows_of([L("O", 100, 1000, account="acct_a"), S10("R1")], [mem("m1", MOVE_T, "ACCT_A")])[2])
    assert r.open_session_uids == ("O",)


def test_a_session_on_another_host_never_counts() -> None:
    ev = [L("T", 100, 1000, host=TGT), L("OT", 100, 1001, host=OTHER)]
    assert dump_row(ev).open_session_uids == ()


def test_several_open_sessions_are_listed_in_open_order_with_parallel_columns() -> None:
    ev = [L("S3", 200, 1002, ltype=2), L("S1", 50, 1000, ltype=3), L("S2", 100, 1001, ltype=10)]
    r = dump_row(ev)
    assert r.open_session_uids == ("S1", "S2", "S3")
    assert r.open_session_types == (3, 10, 2)
    assert r.open_session_ids_hex == ("0x3e8", "0x3e9", "0x3ea")


def test_open_and_end_unknown_sessions_are_listed_apart() -> None:
    ev = [L("A", 100, 1000), L("B", 250, 1001), X("X", 200)]
    r = dump_row(ev)
    assert r.end_unknown_session_uids == ("A",) and r.open_session_uids == ("B",)


def test_each_read_has_its_own_sessions() -> None:
    ev = [L("O", 100, 1000), C("K", 400, 1000), S10("EARLY", 250), S10("LATE", 500)]
    _, _, rows = rows_of(ev, [mem("m1", 600)])
    by = {r.dump_event_uid: r for r in rows}
    assert by["EARLY"].open_session_uids == ("O",) and by["LATE"].open_session_uids == ()


def test_the_session_is_judged_on_the_source_hosts_own_clock() -> None:
    """ST-63: the open and the dump are both source-host logged times. With a +10 s source clock the dump's
    corrected time is 10 s earlier than its logged time and lies BEFORE the open's corrected time, yet the session
    was open at the dump."""
    o = offs(ep_01=("ok", 10_000, 5), ep_02=("ok", 0, 5), dc01=("reference", 0, 0))
    ev = [L("O", 100, 1000), S10("R1", 100)]            # same logged instant: corrected both -10 s
    r = one(rows_of(ev, [mem("m1", MOVE_T)], offsets=o)[2])
    assert r.open_session_uids == ("O",)
    ev2 = [L("O", 105, 1000), S10("R1", 100)]           # open logged 5 s after the dump: not open
    r2 = one(rows_of(ev2, [mem("m1", MOVE_T)], offsets=o)[2])
    assert r2.open_session_uids == ()
    ev3 = [L("O", 100, 1000), S10("R1", 105)]           # dump corrected 95 s, open corrected 90 s: open
    r3 = one(rows_of(ev3, [mem("m1", MOVE_T)], offsets=o)[2])
    assert r3.open_session_uids == ("O",)


def test_a_logged_time_vs_corrected_time_mix_would_give_the_wrong_answer() -> None:
    """The open is logged at 100, the dump at 105 (corrected 95): the logged comparison says open."""
    o = offs(ep_01=("ok", 10_000, 5), ep_02=("ok", 0, 5), dc01=("reference", 0, 0))
    h, w, rows = rows_of([L("O", 100, 1000), S10("R1", 105)], [mem("m1", MOVE_T)], offsets=o)
    assert w.reads[0].us == w.reads[0].us_raw - 10_000_000
    assert one(rows).open_session_uids == ("O",)


def test_an_unrelated_session_added_on_the_source_host_changes_no_row_of_the_account() -> None:
    base = dump_row([L("O", 100, 1000)])
    more = dump_row([L("O", 100, 1000), L("X1", 120, 1500, account="other"), L("X2", 130, 0x3e7)])
    assert base == more


# -- sessions_at directly
def test_sessions_at_returns_open_and_end_unknown_session_objects() -> None:
    w = world([L("A", 100, 1000), L("B", 250, 1001), X("X", 200), L("C", 100, 1002, account="o")])
    op, unk = sessions_at(w.idx, SRC, "acct_a", U(300))
    assert uids(op) == ["B"] and uids(unk) == ["A"]
    op2, unk2 = sessions_at(w.idx, SRC, "ACCT_A", U(150))
    assert uids(op2) == ["A"] and unk2 == []
    assert sessions_at(w.idx, SRC, "acct_a", U(50)) == ([], [])
    assert sessions_at(w.idx, OTHER, "acct_a", U(300)) == ([], [])


def test_sessions_at_uses_the_look_back() -> None:
    w = world([L("PRE", PRE, 1000)])
    op, _ = sessions_at(w.idx, SRC, "acct_a", U(10))
    assert uids(op) == ["PRE"] and op[0].opened_before_window


def test_sessions_at_ignores_system_machine_and_other_accounts() -> None:
    w = world([L("SYS", 100, 0x3e5), L("MA", 100, 1000, machine_account=1), L("OT", 100, 1001, account="z")])
    assert sessions_at(w.idx, SRC, "acct_a", U(300)) == ([], [])


# ================================================================================================ 6. decision 013
def test_hop_identity_takes_only_the_source_host_and_the_reason_from_t73() -> None:
    names = list(inspect.signature(hop_identity).parameters)
    assert names[:3] == ["hop", "source_host", "target_only_reason"]
    assert not any(n in ("links", "link", "subject_links", "session", "candidates", "link_rows") for n in names)
    assert set(names) <= {"hop", "source_host", "target_only_reason", "reads", "sessions", "offsets", "params"}


def test_changing_the_linked_session_changes_no_identity_row() -> None:
    w = world([L("O", 100, 1000), C("K", 450, 1000), S10("R1"), S10("R2", 500)])
    h = mk_hop([mem("m1", 400), mem("m2", 405, "acct_b")])
    hs = HopSet(trial_id=TRIAL, hops=[h], followups=[], counts={})
    key = (SRC, 1000, 0, 0)
    plain = links(SRC)
    linked = links(SRC, rows=[Poison()], sessions={key: Poison()}, session_methods={key: ["sysmon3_port"]},
                   candidate_counts={"sysmon3_port": 1}, candidate_count_all=1, methods={"sysmon3_port": Poison()})
    other = links(SRC, rows=[Poison(), Poison()], sessions={(SRC, 77, 0, 0): Poison()},
                  session_methods={(SRC, 77, 0, 0): ["source_4648"]}, candidate_count_all=1,
                  methods={"source_4648": Poison()}, host_clock_unreliable=1)
    r0 = build_identity(hs, {"h1": plain}, w.reads, w.idx, None)
    r1 = build_identity(hs, {"h1": linked}, w.reads, w.idx, None)
    r2 = build_identity(hs, {"h1": other}, w.reads, w.idx, None)
    assert r0 == r1 == r2 and len(r0) == 4


def test_target_only_and_linked_hops_give_the_same_rows() -> None:
    w = world([L("O", 100, 1000), S10("R1")])
    h = mk_hop([mem()])
    a = hop_identity(h, SRC, "", w.reads, w.idx, None)
    b = hop_identity(h, SRC, "no_evidence_in_range", w.reads, w.idx, None)
    assert a == b and one(a).dump_event_uid == "R1" and one(a).not_applicable == ""


def test_the_linked_sessions_account_never_reaches_a_row() -> None:
    """The moving account is the member's; a session of another account on the source host (the one a link might
    name) is not listed."""
    r = dump_row([L("LINKED", 100, 1000, account="svc_backup")])
    assert r.account == "acct_a" and r.open_session_uids == ()


# ================================================================================================ 7. ST-02 clock flag
def test_flag_from_a_flagged_member_only_for_that_accounts_rows() -> None:
    members = [mem("a1", 400, "acct_a", flag=1), mem("b1", 410, "acct_b", flag=0)]
    _, _, rows = rows_of([S10("R1")], members)
    by = {r.account: r for r in rows}
    assert by["acct_a"].clock_unreliable == 1 and by["acct_b"].clock_unreliable == 0


def test_flag_from_any_member_of_the_account_not_only_the_first() -> None:
    members = [mem("a1", 400, "acct_a", flag=0), mem("a2", 420, "acct_a", flag=1)]
    _, _, rows = rows_of([S10("R1")], members)
    assert one(rows).clock_unreliable == 1


def test_flag_from_a_flagged_read() -> None:
    w = world([S10("R1")])
    flagged = [dataclasses.replace(w.reads[0], clock_unreliable=1)]
    rows = hop_identity(mk_hop([mem()]), SRC, "", flagged, w.idx, None)
    assert one(rows).clock_unreliable == 1
    assert one(hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, None)).clock_unreliable == 0


def test_flag_from_a_wide_source_host_through_the_scan() -> None:
    o = offs(ep_01=("wide", 0, 800), ep_02=("ok", 0, 5), dc01=("reference", 0, 0))
    _, w, rows = rows_of([S10("R1")], [mem()], offsets=o)
    assert w.reads[0].clock_unreliable == 1 and one(rows).clock_unreliable == 1


@pytest.mark.parametrize("status", ["none", "wide", "stale"])
@pytest.mark.parametrize("host", ["ep_01", "ep_02"])
def test_flag_from_an_unreliable_host(host, status) -> None:
    spec = dict(ep_01=("ok", 0, 1), ep_02=("ok", 0, 1), dc01=("reference", 0, 0))
    spec[host] = (status, 0, 1)
    w = world([S10("R1")])
    rows = hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, offs(**spec))
    assert one(rows).clock_unreliable == 1


def test_flag_is_zero_for_reliable_hosts_and_for_no_offsets() -> None:
    w = world([S10("R1")])
    assert one(hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, good())).clock_unreliable == 0
    assert one(hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, None)).clock_unreliable == 0


def test_flag_for_a_host_missing_from_the_offsets_is_one() -> None:
    w = world([S10("R1")])
    o = offs(ep_02=("ok", 0, 1), dc01=("reference", 0, 0))
    assert one(hop_identity(mk_hop([mem()]), SRC, "", w.reads, w.idx, o)).clock_unreliable == 1


def test_the_gates_own_clock_flag_is_kept_apart() -> None:
    """ST-02: gate_clock_unreliable is a different column; it does not set this flag."""
    _, _, rows = rows_of([S10("R1")], [mem(gate_flag=1)], offsets=good())
    assert one(rows).clock_unreliable == 0


def test_flag_on_not_applicable_rows_follows_the_hosts_and_members() -> None:
    o = offs(ep_01=("ok", 0, 1), ep_02=("none", 0, 1), dc01=("reference", 0, 0))
    _, _, rows = rows_of([S10("R1")], [mem("m1", 400, "ep-03$", machine=1)], offsets=o)
    r = one(rows)
    assert r.not_applicable == NA_MACHINE and r.clock_unreliable == 1
    _, _, rows = rows_of([S10("R1")], [mem("m1", 400, flag=1)], source=None, reason=NA_SOURCE_UNKNOWN,
                         offsets=good())
    assert one(rows).clock_unreliable == 1


def test_an_unknown_source_host_adds_nothing_to_the_host_flag() -> None:
    _, _, rows = rows_of([S10("R1")], [mem()], source=None, reason=NA_SOURCE_UNKNOWN,
                         offsets=offs(ep_02=("ok", 0, 1), dc01=("reference", 0, 0)))
    assert one(rows).clock_unreliable == 0


def test_flag_on_the_empty_row_of_a_hop_with_no_read_on_the_source() -> None:
    o = offs(ep_01=("stale", 0, 1), ep_02=("ok", 0, 1), dc01=("reference", 0, 0))
    _, _, rows = rows_of([S10("R1", host=OTHER)], [mem()], offsets=o)
    assert one(rows).clock_unreliable == 1
