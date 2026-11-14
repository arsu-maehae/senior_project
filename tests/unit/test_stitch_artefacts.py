"""Tests for T7.3 task 3: target-side artefacts of each hop (`stitch.artefacts`): share bursts (ST-30, ST-31), service
installs and the copy <-> install tie (ST-32, STT-03), other artefacts (ST-33), spans (ST-34), follow-up rows (ST-26 with
decision 048 item 9), the install count (spec 3 / section 6) and ST-01. Fast: synthetic event rows and synthetic gate
rows, nothing real.

Written from docs/specs/03_stitch.md (ST-30..ST-34, ST-26, ST-47 data side, STT-03, section 6), decision 048 items 9 and 10
and the T7.3 plan task 3, not from the implementation (the code was read only for names and signatures).

Readings tested as stated by the coordinator:
- the install time is the earliest of its 4697 and 7045;
- `wsmprovhost` needs the member's session (at or after its 4624, same session key);
- one `winrm_91` / `rdp_connection` row per gate trigger row and kind, tier = that row's `gate_tier`;
- a burst's `candidate_count` is 1 for `logon_id`, and the install's number of tied bursts when it moves;
- a burst ties on its LAST same-name write (last write after the install -> untied and listed);
- follow-up rows: kind `followup_logon`, method `port_reuse`, tier C, `time_delta_ms` measured from the hop's FIRST member,
  and they count in the hop span.

Event times are seconds after 10:30:00 (`stitch_fixtures.at`); the window is 10:00-11:00, so -2000 s and +2000 s are outside.
"""
from __future__ import annotations

import dataclasses
import random
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from clock_offset.correct import load_clock_changes, load_offsets  # noqa: E402
from gate.classify import ip_kind  # noqa: E402
from gate.params import GateParams  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch.artefacts import (SERVICE_PAIR_S, ArtefactRow, ArtefactSet, Install, ShareBurst, Tie,  # noqa: E402
                              base_name, binary_file_name, build_artefacts)
from stitch.hops import build_hops  # noqa: E402
from stitch.index import build_index  # noqa: E402
from stitch.inputs import GateRows  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402

TRIAL = sf.TRIAL
START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
P = StitchParams()
TARGET = "ep-02"
IP_X, IP_Y, IP_Z = "192.168.50.21", "192.168.50.23", "192.168.50.22"
R4, R8 = "R4_smb", "R8_winrm"
OUT_BEFORE, OUT_AFTER = -2000.0, 2000.0          # outside the 10:00-11:00 window


def U(off: float) -> int:
    """Logged microseconds of `off` seconds after 10:30:00 (the same rounding as the event rows)."""
    return to_us(sf.at(off))


# ------------------------------------------------------------------------------------------------ the synthetic world
@dataclass
class World:
    events: list[dict] = field(default_factory=list)
    triggers: list[dict] = field(default_factory=list)
    unmatched: list[dict] = field(default_factory=list)

    def logon(self, uid: str, off: float, lid: int, *, ip: str = IP_X, port: int | None = None,
              account: str = "acct_a", host: str = TARGET, rule: str | None = R4, tier: str = "A",
              support: tuple[str, ...] | list[str] = (), gate: bool = True, machine: int = 0) -> str:
        """A 4624 (type 3) and, when `gate`, its gate row: a trigger row when `rule` is given, else an unmatched row."""
        port = 40000 + lid if port is None else port
        self.events.append(sf.ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid,
                                 account_name=account, source_ip=ip, source_port=port,
                                 authentication_package="NTLM"))
        if gate:
            row = {"trigger_id": f"{'t' if rule else 'u'}-{uid}", "host": host, "anchor_logon_uid": uid,
                   "trigger_event_uid": uid, "target_logon_id": str(lid), "source_ip": ip, "ip_kind": ip_kind(ip),
                   "machine_account": str(machine), "clock_unreliable": "0", "gate_tier": tier,
                   "supporting_event_uids": ";".join(support)}
            if rule:
                row["rule"] = rule
                self.triggers.append(row)
            else:
                self.unmatched.append(row)
        return uid

    def share(self, uid: str, off: float, lid: int | None, name: str | None = None, *, eid: int = 5145,
              host: str = TARGET) -> str:
        """A 5145 (with a file name) or a 5140 (`name` is then written into `relative_target_name` too, to prove that
        only a 5145 is read for names)."""
        self.events.append(sf.ev(uid, "Security", eid, host=host, off=off, subject_logon_id=lid,
                                 share_name=r"\\*\ADMIN$", relative_target_name=name))
        return uid

    def install(self, uid4697: str | None, uid7045: str | None, off: float, lid: int | None, *,
                name: str = "SyncService", image: str = r"C:\Windows\Ypay.exe", off7045: float | None = None,
                host: str = TARGET) -> None:
        """A 4697 (by `lid`) and/or a 7045 of one service; the 7045 may be at another time."""
        if uid4697 is not None:
            self.events.append(sf.ev(uid4697, "Security", 4697, host=host, off=off, subject_logon_id=lid,
                                     service_name=name, service_image_path=image))
        if uid7045 is not None:
            self.events.append(sf.ev(uid7045, "System", 7045, host=host, off=off if off7045 is None else off7045,
                                     service_name=name, service_image_path=image))

    def wsmprovhost(self, uid: str, off: float, session: int, *, image: str = r"C:\Windows\System32\wsmprovhost.exe",
                    host: str = TARGET) -> str:
        self.events.append(sf.ev(uid, "Sysmon", 1, host=host, off=off, process_guid=f"{{G-{uid}}}",
                                 process_id=abs(hash(uid)) % 60000 + 1, session_id=session, image=image,
                                 parent_image=r"C:\Windows\System32\svchost.exe"))
        return uid

    def winrm91(self, uid: str, off: float, host: str = TARGET) -> str:
        self.events.append(sf.ev(uid, "WinRM", 91, host=host, off=off))
        return uid

    def sysmon3(self, uid: str, off: float, *, port: int = 3389, initiated: int = 0, host: str = TARGET) -> str:
        self.events.append(sf.ev(uid, "Sysmon", 3, host=host, off=off, process_guid=f"{{N-{uid}}}", initiated=initiated,
                                 destination_port=port, source_ip=IP_X, source_port=51000, destination_ip="192.168.50.22"))
        return uid

    def boot(self, uid: str, off: float, event_id: int = 6005, host: str = TARGET) -> str:
        self.events.append(sf.ev(uid, "System", event_id, host=host, off=off))
        return uid


def gate_of(w: World) -> GateRows:
    return GateRows(triggers=[dict(r) for r in w.triggers], unmatched=[dict(r) for r in w.unmatched], supporting=[])


def run(w: World, params: StitchParams = P, offsets=None, changes=(), seed: int | None = None):
    """(hop set, artefact set, scan) built from the world. `seed` shuffles the order of the input lists."""
    events = [dict(e) for e in w.events]
    trig = [dict(r) for r in w.triggers]
    unm = [dict(r) for r in w.unmatched]
    if seed is not None:
        rnd = random.Random(seed)
        for lst in (events, trig, unm):
            rnd.shuffle(lst)
    scan = scan_rows(events, START_US, END_US, offsets, changes)
    sessions = build_index(TRIAL, scan).sessions
    gate = GateRows(triggers=trig, unmatched=unm, supporting=[])
    hs = build_hops(TRIAL, gate, scan, sessions, params)
    return hs, build_artefacts(hs, scan, sessions, gate, params), scan


def hop_of(hs, uid: str):
    found = [h for h in hs.hops if any(uid in m.event_uids for m in h.members)]
    assert len(found) == 1, f"{uid} is a member of {len(found)} hops"
    return found[0]


def rows_of(art: ArtefactSet, kind: str | None = None, hop=None) -> list[ArtefactRow]:
    return [r for r in art.rows if (kind is None or r.kind == kind) and (hop is None or r.hop_id == hop.hop_id)]


def one(rows: list[ArtefactRow]) -> ArtefactRow:
    assert len(rows) == 1, f"{len(rows)} rows: {[(r.hop_id[-5:], r.kind, r.event_uids) for r in rows]}"
    return rows[0]


def lower(names) -> list[str]:
    return [n.lower() for n in names]


# ================================================================================================ names
@pytest.mark.parametrize("image,want", [
    (r'"C:\Program Files\x y\a.exe" -k svc', "a.exe"),                  # quoted path with spaces and arguments
    (r'"C:\Program Files\x y\a.exe"', "a.exe"),
    (r'  "C:\a b\c.exe"  -arg  ', "c.exe"),
    (r"C:\Windows\a.exe -k netsvcs", "a.exe"),                            # unquoted path with arguments
    (r"C:\Windows\a.exe", "a.exe"),
    ("C:/Windows/System32/a.exe -x", "a.exe"),                           # forward slashes
    ("C:/Windows\\mixed/a.exe", "a.exe"),
    ("a.exe", "a.exe"),                                                  # bare name
    ("a.exe /c something", "a.exe"),
    (r"C:\X\Ypay.EXE", "Ypay.EXE"),                                      # original spelling kept
    (r"%SystemRoot%\system32\svchost.exe -k x", "svchost.exe"),
    ("", ""), (None, ""), ("   ", ""),
])
def test_binary_file_name_cases(image, want):
    assert binary_file_name(image) == want


@pytest.mark.parametrize("path,want", [
    (r"Windows\Temp\Ypay.exe", "Ypay.exe"), ("a/b/c.exe", "c.exe"), ("c.exe", "c.exe"), (r" dir\c.exe ", "c.exe"),
    ("", ""), (None, ""), ("\\", ""),
])
def test_base_name_cases(path, want):
    assert base_name(path) == want


def test_service_pair_tolerance_is_the_gates_own_value():
    assert SERVICE_PAIR_S == GateParams().service_pair_s == 5.0


# ================================================================================================ contract
def _rich_world() -> World:
    """Two hops with bursts, installs, a moved copy, a winrm hop with wsmprovhost / 91 / 3389 and a follow-up."""
    w = World()
    w.logon("LX", 0.0, 2000, ip=IP_X)
    w.logon("LY", 100.0, 2100, ip=IP_Y)
    w.share("XS1", 1.0, 2000, r"Windows\Xpay.exe")
    w.install("XI4", "XI7", 1.1, 2000, name="XferService", image=r"C:\Windows\Xpay.exe")
    w.share("XS2", 100.55, 2000, r"Windows\Ypay.exe")                     # under X's logon, 100 s later
    w.install("YI4", "YI7", 100.6, 2100)
    w.logon("W0", 200.0, 3000, ip=IP_Z, rule=R8, support=["V91", "R3389", "XS1"])
    w.logon("W1", 200.4, 3001, ip=IP_Z, rule=None, port=40000 + 3000)
    w.logon("F0", 211.8, 3002, ip=IP_Z, rule=None, port=40000 + 3000)    # follow-up (same port, untriggered)
    w.wsmprovhost("WP", 201.0, 3000)
    w.winrm91("V91", 200.7)
    w.sysmon3("R3389", 200.6)
    return w


def test_contract_types_and_fields():
    hs, art, _ = run(_rich_world())
    assert isinstance(art, ArtefactSet)
    assert all(isinstance(r, ArtefactRow) for r in art.rows)
    assert all(isinstance(b, ShareBurst) for b in art.bursts)
    assert all(isinstance(i, Install) for i in art.installs)
    assert all(isinstance(t, Tie) for t in art.ties)
    hop_ids = {h.hop_id for h in hs.hops}
    assert {r.hop_id for r in art.rows} <= hop_ids
    assert set(art.service_install_count) == hop_ids and set(art.supporting_span_ms) == hop_ids
    assert set(art.gate_support_moved) == hop_ids and set(art.gate_support_not_attached) == hop_ids
    for r in art.rows:
        assert r.kind in {"share_burst", "service_install", "winrm_host", "winrm_91", "rdp_connection", "followup_logon"}
        assert r.method in {"logon_id", "file_name_time", "ip_time", "port_reuse"}
        assert r.confidence_tier in {"A", "B", "C"}
        assert isinstance(r.candidate_count, int) and r.candidate_count >= 1
        assert isinstance(r.time_delta_ms, int) and isinstance(r.supporting_span_ms, int) and r.supporting_span_ms >= 0
        assert r.event_uids and r.event_uids == sorted(r.event_uids)
        assert isinstance(r.names, list) and isinstance(r.untied_same_name_bursts, list)
        assert r.first_us_raw <= r.last_us_raw


def test_the_rich_world_gives_every_kind_once_and_no_row_is_lost_or_duplicated():
    hs, art, _ = run(_rich_world())
    kinds = sorted(r.kind for r in art.rows)
    assert kinds == sorted(["share_burst", "share_burst", "service_install", "service_install",
                            "winrm_host", "winrm_91", "rdp_connection", "followup_logon"])
    keys = [(r.hop_id, r.kind, tuple(r.event_uids), r.ref_id) for r in art.rows]
    assert len(keys) == len(set(keys)), "a row is duplicated"
    # every burst appears in exactly one row (nothing moved twice) and every install in exactly one row
    for b in art.bursts:
        assert sum(1 for r in art.rows if r.kind == "share_burst" and r.ref_id == b.burst_id) == 1
    for i in art.installs:
        assert sum(1 for r in art.rows if r.kind == "service_install" and r.ref_id == i.install_id) == 1
    # every event of the target that is in a row is accounted for exactly once per row
    for r in art.rows:
        assert len(r.event_uids) == len(set(r.event_uids))


# ================================================================================================ ST-30 bursts
def _x() -> World:
    w = World()
    w.logon("LX", 0.0, 2000)
    return w


@pytest.mark.parametrize("second,n_bursts", [(6.0, 1), (5.999999, 1), (6.000001, 2), (7.0, 2), (3.0, 1)])
def test_a_gap_of_exactly_burst_gap_joins_and_one_microsecond_more_splits(second, n_bursts):
    w = _x()
    w.share("S1", 1.0, 2000, "a.txt")
    w.share("S2", second, 2000, "b.txt")                                  # first gap 5.0 s when second = 6.0
    hs, art, _ = run(w)
    assert len(art.bursts) == n_bursts, f"gap {second - 1.0}: {len(art.bursts)} bursts"
    assert len(rows_of(art, "share_burst")) == n_bursts


def test_the_gap_is_between_consecutive_events_not_from_the_first_and_burst_gap_is_a_parameter():
    w = _x()
    for i, off in enumerate([1.0, 5.0, 9.0, 13.0]):                      # 4 s steps, 12 s long: one burst
        w.share(f"S{i}", off, 2000, f"f{i}.txt")
    w.share("S4", 18.5, 2000, "g.txt")                                    # 5.5 s after the last: a second burst
    hs, art, _ = run(w)
    assert [b.event_uids for b in art.bursts] == [["S0", "S1", "S2", "S3"], ["S4"]]
    assert len(run(w, replace(P, burst_gap_s=6.0))[1].bursts) == 1
    assert len(run(w, replace(P, burst_gap_s=3.0))[1].bursts) == 5


def test_5140_and_5145_events_of_one_logon_share_a_burst():
    w = _x()
    w.share("S0", 1.0, 2000, eid=5140)
    w.share("S1", 1.2, 2000, "a.txt")
    w.share("S2", 1.4, 2000, eid=5140)
    hs, art, _ = run(w)
    (b,) = art.bursts
    assert b.event_uids == ["S0", "S1", "S2"] and b.logon_id == 2000 and b.logon_id_hex == "0x7d0"


def test_bursts_of_two_member_logons_are_never_mixed():
    w = World()
    w.logon("LA", 0.0, 2000)
    w.logon("LB", 0.5, 2001)
    w.share("A1", 1.0, 2000, "a.txt")
    w.share("B1", 1.1, 2001, "b.txt")                                     # interleaved in time
    w.share("A2", 1.2, 2000, "c.txt")
    hs, art, _ = run(w)
    assert sorted(b.event_uids for b in art.bursts) == [["A1", "A2"], ["B1"]]
    assert {b.member_uid for b in art.bursts} == {"LA", "LB"}


def test_a_share_event_before_the_members_4624_is_not_attached_and_one_at_the_same_instant_is():
    w = _x()
    w.share("EARLY", -1.0, 2000, "a.txt")                                 # logged before the 4624
    w.share("SAME", 0.0, 2000, "b.txt")                                   # at the 4624 instant
    w.share("LATE", 1.0, 2000, "c.txt")
    hs, art, _ = run(w)
    uids = {u for b in art.bursts for u in b.event_uids}
    assert "EARLY" not in uids and {"SAME", "LATE"} <= uids
    assert art.counts["share_events_unattached"] == 1


def test_a_share_event_in_another_session_of_the_same_logon_id_after_a_boot_is_not_attached():
    w = _x()
    w.share("S1", 5.0, 2000, "a.txt")
    w.boot("B", 100.0)                                                    # a restart: the session ends
    w.share("AFTER", 200.0, 2000, "b.txt")                                # the same ID, another boot epoch
    hs, art, _ = run(w)
    uids = {u for b in art.bursts for u in b.event_uids}
    assert uids == {"S1"}
    assert art.counts["share_events_unattached"] == 1


def test_share_events_outside_the_window_are_in_no_burst_and_not_counted():
    w = _x()
    w.share("S1", 1.0, 2000, "a.txt")
    w.share("OLD", OUT_BEFORE, 2000, "b.txt")
    w.share("NEW", OUT_AFTER, 2000, "c.txt")
    hs, art, _ = run(w)
    assert {u for b in art.bursts for u in b.event_uids} == {"S1"}
    assert not any(u in r.event_uids for r in art.rows for u in ("OLD", "NEW"))
    assert art.counts["share_events_unattached"] == 0


def test_share_events_of_a_non_member_logon_are_counted_unattached():
    w = _x()
    w.logon("LN", 5.0, 7777, ip=IP_Y, gate=False)                          # a 4624 the gate never named: not a member
    w.share("N1", 6.0, 7777, "a.txt")
    w.share("N2", 6.5, 7777, eid=5140)
    w.share("N3", 7.0, 9999, "b.txt")                                     # no 4624 at all
    w.share("N4", 7.5, None, "c.txt")                                     # NULL logon ID
    w.share("S1", 1.0, 2000, "d.txt")
    hs, art, _ = run(w)
    assert {u for b in art.bursts for u in b.event_uids} == {"S1"}
    assert art.counts["share_events_unattached"] == 4
    assert not any(u in r.event_uids for r in art.rows for u in ("N1", "N2", "N3", "N4"))


def test_exe_names_come_from_5145_only_unique_case_insensitively_and_a_5140_carries_none():
    w = _x()
    w.share("S0", 1.0, 2000, r"Windows\Temp\Ypay.exe")
    w.share("S1", 1.1, 2000, "ypay.EXE")                                  # same name, other case
    w.share("S2", 1.2, 2000, "readme.txt")                                # a file, not an .exe
    w.share("S3", 1.3, 2000, "evil.exe", eid=5140)                        # a 5140 has no file name: never read
    w.share("S4", 1.4, 2000, r"x\Xpay.exe")
    hs, art, _ = run(w)
    (b,) = art.bursts
    assert lower(b.exe_names) == ["xpay.exe", "ypay.exe"]
    assert lower(one(rows_of(art, "share_burst")).names) == ["xpay.exe", "ypay.exe"]
    w2 = _x()
    w2.share("S0", 1.0, 2000, eid=5140)
    w2.share("S1", 1.1, 2000, "evil.exe", eid=5140)
    hs, art2, _ = run(w2)
    assert one(rows_of(art2, "share_burst")).names == []


# ================================================================================================ ST-31 attachment
def test_a_burst_belongs_to_its_logons_hop_with_logon_id_tier_a_and_correct_deltas():
    w = World()
    w.logon("LA", 0.0, 2000)
    w.logon("LB", 0.5, 2001)                                              # one hop of two members
    w.logon("LY", 50.0, 2100, ip=IP_Y)
    w.share("S1", 3.0, 2001, "a.txt")
    w.share("S2", 4.5, 2001, "b.exe")
    hs, art, _ = run(w)
    assert hop_of(hs, "LA") is hop_of(hs, "LB")
    hop = hop_of(hs, "LA")
    r = one(rows_of(art, "share_burst"))
    assert r.hop_id == hop.hop_id and r.logged_under_hop_id == hop.hop_id
    assert r.member_logon_uid == "LB"                                      # the member whose logon ID the events carry
    assert (r.method, r.confidence_tier, r.candidate_count) == ("logon_id", "A", 1)
    assert r.time_delta_ms == 3000                                         # first event minus the HOP's first 4624
    assert r.supporting_span_ms == 1500
    assert r.event_uids == ["S1", "S2"] and r.names == ["b.exe"] and r.untied_same_name_bursts == []
    assert art.supporting_span_ms[hop.hop_id] == 1500
    assert art.supporting_span_ms[hop_of(hs, "LY").hop_id] is None


def test_a_burst_far_from_its_logon_is_visible_in_time_delta_ms():
    w = _x()
    w.share("S1", 95.3, 2000, "a.txt")
    hs, art, _ = run(w)
    assert one(rows_of(art, "share_burst")).time_delta_ms == 95300


# ================================================================================================ ST-32 / STT-03
def _xy(*, x_install: bool = True, copy_off: float = 100.55, install_off: float = 100.6, copy_name=r"Windows\Ypay.exe",
        image=r"C:\Windows\Ypay.exe") -> World:
    """Hop X (logon 2000, t = 0) and hop Y (logon 2100, t = 100). X copied Xpay.exe at 1.0 and installed it at 1.1.
    Y's install of Ypay.exe is at `install_off`; the Ypay.exe copy is logged under X's logon at `copy_off`."""
    w = World()
    w.logon("LX", 0.0, 2000, ip=IP_X)
    w.logon("LY", 100.0, 2100, ip=IP_Y)
    if x_install:
        w.share("XS1", 1.0, 2000, r"Windows\Xpay.exe")
        w.install("XI4", "XI7", 1.1, 2000, name="XferService", image=r"C:\Windows\Xpay.exe")
    w.share("XS2", copy_off, 2000, copy_name)
    w.install("YI4", "YI7", install_off, 2100, name="SyncService", image=image)
    return w


def test_a_copy_under_another_hops_logon_moves_to_the_installs_hop_and_leaves_its_own():
    hs, art, _ = run(_xy())
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    moved = one([r for r in rows_of(art, "share_burst", hy)])
    assert moved.event_uids == ["XS2"] and lower(moved.names) == ["ypay.exe"]
    assert (moved.method, moved.confidence_tier, moved.candidate_count) == ("file_name_time", "B", 1)
    assert moved.logged_under_hop_id == hx.hop_id and moved.member_logon_uid == "LX"
    assert moved.time_delta_ms == 550                                       # 100.55 - Y's 4624 at 100.0
    # not on its own hop any more
    own = rows_of(art, "share_burst", hx)
    assert [r.event_uids for r in own] == [["XS1"]] and lower(one(own).names) == ["xpay.exe"]
    assert not any("XS2" in r.event_uids for r in rows_of(art, hop=hx))


def test_a_burst_tied_to_its_own_hops_install_stays_logon_id_tier_a_and_the_tie_is_recorded():
    hs, art, _ = run(_xy())
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    own = one(rows_of(art, "share_burst", hx))
    assert (own.method, own.confidence_tier, own.candidate_count) == ("logon_id", "A", 1)
    assert own.logged_under_hop_id == hx.hop_id
    own_ties = [t for t in art.ties if t.hop_id == hx.hop_id]
    assert len(own_ties) == 1 and own_ties[0].logged_under_hop_id == hx.hop_id
    assert own_ties[0].delta_ms == 100 and own_ties[0].candidate_count == 1
    y_ties = [t for t in art.ties if t.hop_id == hy.hop_id]
    assert len(y_ties) == 1 and y_ties[0].logged_under_hop_id == hx.hop_id
    assert y_ties[0].delta_ms == 50 and y_ties[0].method == "file_name_time"
    assert len(art.ties) == 2


def test_each_hop_has_its_own_install_row_by_logon_id_with_names_and_the_install_count():
    hs, art, _ = run(_xy())
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    ix, iy = one(rows_of(art, "service_install", hx)), one(rows_of(art, "service_install", hy))
    assert ix.ref_id != iy.ref_id
    assert (ix.method, ix.confidence_tier, ix.candidate_count, ix.member_logon_uid) == ("logon_id", "A", 1, "LX")
    assert (iy.method, iy.confidence_tier, iy.candidate_count, iy.member_logon_uid) == ("logon_id", "A", 1, "LY")
    assert ix.event_uids == ["XI4", "XI7"] and iy.event_uids == ["YI4", "YI7"]
    assert ix.names == ["XferService", "Xpay.exe"] and iy.names == ["SyncService", "Ypay.exe"]
    assert art.service_install_count == {hx.hop_id: 1, hy.hop_id: 1}
    assert ix.time_delta_ms == 1100 and iy.time_delta_ms == 600


def test_a_hop_has_a_tie_when_a_ties_install_belongs_to_it():
    """ST-47 data side: the hop of the INSTALL has the tie; the hop whose logon the copy was logged under has none."""
    hs, art, _ = run(_xy(x_install=False))
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    assert {t.hop_id for t in art.ties} == {hy.hop_id}
    assert art.ties[0].logged_under_hop_id == hx.hop_id
    assert rows_of(art, hop=hx) == [] and art.supporting_span_ms[hx.hop_id] is None
    hs2, art2, _ = run(_xy())
    assert {t.hop_id for t in art2.ties} == {hop_of(hs2, "LX").hop_id, hop_of(hs2, "LY").hop_id}


def test_two_same_name_bursts_before_one_install_are_both_attached_with_candidate_count_2():
    w = _xy(x_install=False, copy_off=95.0, install_off=100.6)               # copy 1 under X at 95.0
    w.logon("LZ", 50.0, 2200, ip=IP_Z)
    w.share("ZS1", 99.0, 2200, r"Windows\Ypay.exe")                          # copy 2 under Z, 6 s after... another logon
    hs, art, _ = run(w)
    hx, hy, hz = hop_of(hs, "LX"), hop_of(hs, "LY"), hop_of(hs, "LZ")
    on_y = sorted(rows_of(art, "share_burst", hy), key=lambda r: r.event_uids)
    assert [r.event_uids for r in on_y] == [["XS2"], ["ZS1"]]
    assert all((r.method, r.confidence_tier, r.candidate_count) == ("file_name_time", "B", 2) for r in on_y)
    assert [r.logged_under_hop_id for r in on_y] == [hx.hop_id, hz.hop_id]
    assert len(art.ties) == 2 and all(t.candidate_count == 2 and t.hop_id == hy.hop_id for t in art.ties)
    assert rows_of(art, "share_burst", hx) == [] and rows_of(art, "share_burst", hz) == []
    assert one(rows_of(art, "service_install", hy)).candidate_count == 1       # a 4697 install is by logon ID


def test_two_same_name_bursts_under_one_logon_in_one_burst_are_one_burst_and_candidate_count_1():
    w = _xy(x_install=False, copy_off=95.0)
    w.share("XS3", 97.0, 2000, r"Windows\Ypay.exe")                          # 2 s later: the same burst
    hs, art, _ = run(w)
    assert len(rows_of(art, "share_burst", hop_of(hs, "LY"))) == 1
    assert all(t.candidate_count == 1 for t in art.ties) and len(art.ties) == 1


@pytest.mark.parametrize("after", [0.000001, 1.0, 12.0])
def test_a_copy_after_the_install_never_ties_and_is_listed(after):
    hs, art, _ = run(_xy(x_install=False, copy_off=100.6 + after))
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    assert art.ties == []
    burst = one(rows_of(art, "share_burst", hx))
    assert (burst.method, burst.confidence_tier, burst.candidate_count) == ("logon_id", "A", 1)
    inst = one(rows_of(art, "service_install", hy))
    assert inst.untied_same_name_bursts == [burst.ref_id]
    assert art.installs[0].untied_same_name_bursts == [burst.ref_id]


@pytest.mark.parametrize("before,tied", [(0.0, True), (0.05, True), (9.999999, True), (10.0, True),
                                         (10.000001, False), (12.0, False), (60.0, False)])
def test_a_copy_exactly_copy_install_s_before_ties_and_one_microsecond_more_does_not(before, tied):
    hs, art, _ = run(_xy(x_install=False, copy_off=100.6 - before))
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    inst = one(rows_of(art, "service_install", hy))
    if tied:
        assert len(art.ties) == 1 and art.ties[0].delta_ms == round(before * 1000)
        assert one(rows_of(art, "share_burst", hy)).method == "file_name_time"
        assert inst.untied_same_name_bursts == []
    else:
        assert art.ties == []
        assert one(rows_of(art, "share_burst", hx)).method == "logon_id"
        assert len(inst.untied_same_name_bursts) == 1
        assert inst.untied_same_name_bursts == [one(rows_of(art, "share_burst", hx)).ref_id]


def test_copy_install_s_is_a_parameter():
    w = _xy(x_install=False, copy_off=100.6 - 12.0)
    assert len(run(w)[1].ties) == 0
    assert len(run(w, replace(P, copy_install_s=30.0))[1].ties) == 1
    assert len(run(_xy(x_install=False, copy_off=100.6 - 5.0), replace(P, copy_install_s=2.0))[1].ties) == 0


def test_the_file_name_compare_is_case_insensitive_and_uses_the_base_name_of_the_path():
    w = _xy(x_install=False, copy_name=r"Windows\Temp\sub\yPAY.ExE", image=r"C:\Windows\YPAY.EXE -k netsvcs")
    hs, art, _ = run(w)
    assert len(art.ties) == 1 and art.ties[0].hop_id == hop_of(hs, "LY").hop_id


@pytest.mark.parametrize("image", [r'"C:\Program Files\app dir\Ypay.exe" -k grp', r"C:\Windows\Ypay.exe -k grp",
                                   "C:/Windows/Ypay.exe", "Ypay.exe"])
def test_the_install_file_name_is_read_from_every_image_path_shape(image):
    hs, art, _ = run(_xy(x_install=False, image=image))
    assert len(art.ties) == 1


def test_a_file_name_inside_a_longer_name_does_not_tie():
    hs, art, _ = run(_xy(x_install=False, copy_name=r"Windows\Ypay.exe.bak"))
    assert art.ties == []
    hs, art, _ = run(_xy(x_install=False, copy_name=r"Windows\xYpay.exe"))
    assert art.ties == []


@pytest.mark.parametrize("variant", ["7045_first", "4697_first"])
def test_the_install_time_is_the_earliest_of_its_4697_and_7045(variant):
    """A copy between the two events is after the install, so it never ties; a copy before both ties, measured to the
    earliest."""
    for copy_off, tied in ((100.5, False), (99.9, True)):
        w = World()
        w.logon("LX", 0.0, 2000)
        w.logon("LY", 90.0, 2100, ip=IP_Y)
        w.share("XS2", copy_off, 2000, "Ypay.exe")
        t4697, t7045 = (101.0, 100.0) if variant == "7045_first" else (100.0, 101.0)
        w.install("YI4", "YI7", t4697, 2100, off7045=t7045)
        hs, art, _ = run(w)
        assert len(art.ties) == (1 if tied else 0), f"{variant} copy at {copy_off}"
        if tied:
            assert art.ties[0].delta_ms == 100
        inst = one(rows_of(art, "service_install", hop_of(hs, "LY")))
        assert inst.event_uids == ["YI4", "YI7"]                                # both events, paired


def test_a_burst_ties_on_its_last_same_name_write():
    """Writes at 86 and 98 in one burst (a chain of other files keeps the gaps under 5 s); install at 100.6."""
    w = World()
    w.logon("LX", 0.0, 2000)
    w.logon("LY", 90.0, 2100, ip=IP_Y)
    for uid, off, name in [("W1", 86.0, "Ypay.exe"), ("O1", 89.0, "a.txt"), ("O2", 93.0, "b.txt"),
                           ("O3", 97.0, "c.txt"), ("W2", 98.0, "Ypay.exe")]:
        w.share(uid, off, 2000, name)
    w.install("YI4", "YI7", 100.6, 2100)
    hs, art, _ = run(w)
    assert len(art.bursts) == 1
    assert len(art.ties) == 1 and art.ties[0].delta_ms == 2600                  # 100.6 - 98.0, not 100.6 - 86.0


def test_a_burst_whose_last_same_name_write_is_after_the_install_is_untied_and_listed():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.logon("LY", 90.0, 2100, ip=IP_Y)
    for uid, off, name in [("W1", 98.0, "Ypay.exe"), ("O1", 100.0, "a.txt"), ("W2", 103.0, "Ypay.exe")]:
        w.share(uid, off, 2000, name)
    w.install("YI4", "YI7", 100.6, 2100)
    hs, art, _ = run(w)
    assert art.ties == []
    burst = one(rows_of(art, "share_burst", hop_of(hs, "LX")))
    assert one(rows_of(art, "service_install", hop_of(hs, "LY"))).untied_same_name_bursts == [burst.ref_id]


@pytest.mark.parametrize("lid", [999, 996, 997, 5555])
def test_an_install_by_a_system_logon_id_or_no_member_is_not_a_hop_artefact_and_never_ties(lid):
    w = World()
    w.logon("LX", 0.0, 2000)
    w.share("XS2", 95.0, 2000, "Ypay.exe")
    w.install("SI4", "SI7", 100.6, lid)                                         # 0x3e7, 0x3e4, 0x3e5, an unknown ID
    hs, art, _ = run(w)
    assert rows_of(art, "service_install") == []
    assert art.ties == []
    burst = one(rows_of(art, "share_burst"))
    assert (burst.method, burst.confidence_tier) == ("logon_id", "A")
    assert burst.untied_same_name_bursts == []
    (inst,) = art.installs
    assert inst.hop_id is None and inst.tie_hop_ids == []
    assert sum(art.service_install_count.values()) == 0


def test_a_system_install_does_not_hide_a_member_install_of_the_same_name():
    w = World()
    w.logon("LY", 90.0, 2100, ip=IP_Y)
    w.install("SI4", None, 50.0, 999, name="SyncService")
    w.install("YI4", "YI7", 100.0, 2100, name="SyncService")
    hs, art, _ = run(w)
    r = one(rows_of(art, "service_install"))
    assert "YI4" in r.event_uids and "SI4" not in r.event_uids


def test_a_7045_with_no_4697_attaches_only_through_a_tie_to_the_tied_bursts_hop():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.logon("LY", 90.0, 2100, ip=IP_Y)
    w.share("XS2", 95.0, 2000, "Ypay.exe")
    w.install(None, "YI7", 100.6, None)
    hs, art, _ = run(w)
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    inst = one(rows_of(art, "service_install"))
    assert inst.hop_id == hx.hop_id, "the install goes to the hop of the tied burst's logon, not to LY"
    assert (inst.method, inst.confidence_tier, inst.candidate_count) == ("file_name_time", "B", 1)
    assert inst.member_logon_uid == "" and inst.event_uids == ["YI7"]
    assert rows_of(art, "service_install", hy) == []
    assert art.service_install_count[hx.hop_id] == 1 and art.service_install_count[hy.hop_id] == 0
    assert len(art.ties) == 1 and art.ties[0].hop_id == hx.hop_id


def test_a_7045_alone_with_bursts_of_two_hops_attaches_to_both_with_candidate_count_2():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.logon("LY", 50.0, 2100, ip=IP_Y)
    w.share("XS2", 93.0, 2000, "Ypay.exe")
    w.share("YS2", 96.0, 2100, "Ypay.exe")
    w.install(None, "YI7", 100.6, None)
    hs, art, _ = run(w)
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    rows = rows_of(art, "service_install")
    assert sorted(r.hop_id for r in rows) == sorted([hx.hop_id, hy.hop_id])
    assert all(r.method == "file_name_time" and r.confidence_tier == "B" and r.candidate_count == 2 for r in rows)


@pytest.mark.parametrize("copy_off", [None, 100.6 - 12.0, 100.6 + 1.0])
def test_a_7045_with_no_4697_and_no_tie_is_unattached(copy_off):
    w = World()
    w.logon("LX", 0.0, 2000)
    if copy_off is not None:
        w.share("XS2", copy_off, 2000, "Ypay.exe")                              # untied (12 s before or after)
    w.install(None, "YI7", 100.6, None)
    hs, art, _ = run(w)
    assert rows_of(art, "service_install") == []
    assert not any("YI7" in r.event_uids for r in art.rows)
    (inst,) = art.installs
    assert inst.hop_id is None and inst.tie_hop_ids == [] and inst.uids_4697 == []
    assert art.counts["installs_unattached"] == 1
    assert all(n == 0 for n in art.service_install_count.values())


def test_an_install_with_no_binary_name_ties_nothing():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.share("XS2", 95.0, 2000, "Ypay.exe")
    w.install("XI4", "XI7", 100.6, 2000, image="")
    hs, art, _ = run(w)
    assert art.ties == []
    assert one(rows_of(art, "service_install")).method == "logon_id"


# ================================================================================================ section 6
def test_two_installs_in_one_hop_give_service_install_count_2():
    w = World()
    w.logon("LA", 0.0, 2000)
    w.logon("LB", 0.5, 2001)
    w.logon("LY", 50.0, 2100, ip=IP_Y)
    w.install("A4", "A7", 10.0, 2000, name="SvcOne", image=r"C:\Windows\one.exe")
    w.install("B4", "B7", 20.0, 2001, name="SvcTwo", image=r"C:\Windows\two.exe")
    hs, art, _ = run(w)
    hop, other = hop_of(hs, "LA"), hop_of(hs, "LY")
    assert art.service_install_count == {hop.hop_id: 2, other.hop_id: 0}
    assert len(rows_of(art, "service_install", hop)) == 2
    assert art.counts["hops_with_more_than_one_install"] == 1


def test_an_install_before_the_members_4624_is_not_a_hop_artefact():
    w = World()
    w.logon("LA", 10.0, 2000)
    w.install("A4", "A7", 5.0, 2000)                                            # 4697 logged before the 4624
    hs, art, _ = run(w)
    assert rows_of(art, "service_install") == []


# ================================================================================================ ST-33
def test_wsmprovhost_of_the_members_session_is_a_winrm_host_row_by_logon_id_tier_a():
    w = World()
    w.logon("W0", 0.0, 3000, ip=IP_Z, rule=R8)
    w.logon("W1", 0.3, 3001, ip=IP_Z, rule=None)
    w.wsmprovhost("WP1", 1.5, 3001)
    hs, art, _ = run(w)
    hop = hop_of(hs, "W0")
    r = one(rows_of(art, "winrm_host"))
    assert r.hop_id == hop.hop_id and r.member_logon_uid == "W1" and r.event_uids == ["WP1"]
    assert (r.method, r.confidence_tier, r.candidate_count) == ("logon_id", "A", 1)
    assert r.time_delta_ms == 1500 and r.supporting_span_ms == 0 and r.logged_under_hop_id == hop.hop_id


def test_a_wsmprovhost_of_another_session_before_the_4624_or_in_another_epoch_is_not_attached():
    w = World()
    w.logon("W0", 10.0, 3000, ip=IP_Z, rule=R8)
    w.wsmprovhost("WP_OTHER", 11.0, 3999)                                       # a session no member owns
    w.wsmprovhost("WP_EARLY", 9.0, 3000)                                        # before the member's 4624
    w.boot("B", 100.0)
    w.wsmprovhost("WP_REBOOT", 200.0, 3000)                                     # the same ID after a boot
    w.wsmprovhost("WP_OK", 12.0, 3000)
    hs, art, _ = run(w)
    assert [r.event_uids for r in rows_of(art, "winrm_host")] == [["WP_OK"]]


def test_only_a_wsmprovhost_image_makes_a_winrm_host_row():
    w = World()
    w.logon("W0", 0.0, 3000, ip=IP_Z, rule=R8)
    w.wsmprovhost("NOT_WSM", 1.0, 3000, image=r"C:\Windows\System32\cmd.exe")
    w.wsmprovhost("WSM_UP", 2.0, 3000, image=r"C:\WINDOWS\SYSTEM32\WSMPROVHOST.EXE")
    hs, art, _ = run(w)
    assert [r.event_uids for r in rows_of(art, "winrm_host")] == [["WSM_UP"]]


def test_winrm_91_and_inbound_3389_in_a_member_trigger_row_become_ip_time_rows_with_the_gate_tier():
    w = World()
    w.logon("W0", 0.0, 3000, ip=IP_Z, rule=R8, tier="B", support=["V91", "R3389", "OUT3389", "S1", "NOSUCH"])
    w.winrm91("V91", 0.7)
    w.sysmon3("R3389", 0.9)
    w.sysmon3("OUT3389", 0.95, initiated=1)                                      # outbound 3389: not an RDP connection
    w.share("S1", 1.0, 3000, "a.txt")
    hs, art, _ = run(w)
    hop = hop_of(hs, "W0")
    v = one(rows_of(art, "winrm_91"))
    r = one(rows_of(art, "rdp_connection"))
    for row, uid, delta in ((v, "V91", 700), (r, "R3389", 900)):
        assert row.hop_id == hop.hop_id and row.event_uids == [uid] and row.member_logon_uid == "W0"
        assert (row.method, row.confidence_tier) == ("ip_time", "B")
        assert row.time_delta_ms == delta and row.supporting_span_ms == 0
    assert sorted(x.kind for x in art.rows) == ["rdp_connection", "share_burst", "winrm_91"]
    assert not any("OUT3389" in x.event_uids for x in art.rows)                 # other supporting uids are ignored here
    assert not any(u in x.event_uids for x in art.rows if x.kind in ("winrm_91", "rdp_connection")
                   for u in ("S1", "NOSUCH"))


def test_one_row_per_trigger_row_and_kind_each_with_its_own_gate_tier():
    w = World()
    w.logon("W0", 0.0, 3000, ip=IP_Z, rule=R8, tier="A", support=["V91"])
    w.logon("W1", 0.3, 3001, ip=IP_Z, rule=R8, tier="C", support=["V91"])
    w.winrm91("V91", 0.7)
    hs, art, _ = run(w)
    rows = rows_of(art, "winrm_91")
    assert sorted((r.member_logon_uid, r.confidence_tier) for r in rows) == [("W0", "A"), ("W1", "C")]
    assert all(r.method == "ip_time" and r.event_uids == ["V91"] for r in rows)


def test_a_trigger_row_with_no_member_anchor_gives_no_ip_time_row():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.triggers.append({"trigger_id": "t-orphan", "host": TARGET, "anchor_logon_uid": "", "trigger_event_uid": "V91",
                       "rule": R8, "gate_tier": "D", "supporting_event_uids": "V91", "source_ip": "", "ip_kind": "",
                       "machine_account": "0", "clock_unreliable": "0", "target_logon_id": ""})
    w.winrm91("V91", 0.7)
    hs, art, _ = run(w)
    assert rows_of(art, "winrm_91") == []


def test_a_91_that_is_not_in_any_trigger_row_is_not_an_artefact():
    w = World()
    w.logon("W0", 0.0, 3000, ip=IP_Z, rule=R8)
    w.winrm91("V91", 0.7)
    hs, art, _ = run(w)
    assert rows_of(art, "winrm_91") == []


# ================================================================================================ ST-34 spans
def test_row_spans_and_the_hop_span_cover_every_artefact_row_of_the_hop():
    w = World()
    w.logon("LX", 0.0, 2000)
    w.logon("LY", 400.0, 2100, ip=IP_Y)
    w.share("S1", 2.0, 2000, "a.txt")
    w.share("S2", 3.5, 2000, "b.txt")                                            # burst 2.0 .. 3.5: span 1500
    w.install("XI4", "XI7", 10.0, 2000, off7045=10.25, image=r"C:\Windows\x.exe")
    hs, art, _ = run(w)
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    assert one(rows_of(art, "share_burst", hx)).supporting_span_ms == 1500
    inst = one(rows_of(art, "service_install", hx))
    assert inst.supporting_span_ms == 250 and inst.time_delta_ms == 10000
    assert art.supporting_span_ms[hx.hop_id] == 8250                             # 2.0 .. 10.25
    assert art.supporting_span_ms[hy.hop_id] is None                             # no artefact at all


def test_a_hop_with_one_instant_artefact_has_span_zero_not_none():
    w = _x()
    w.share("S1", 2.0, 2000, "a.txt")
    hs, art, _ = run(w)
    assert art.supporting_span_ms[hs.hops[0].hop_id] == 0


def test_a_moved_burst_counts_in_the_receiving_hops_span_and_not_in_its_own():
    hs, art, _ = run(_xy())
    hx, hy = hop_of(hs, "LX"), hop_of(hs, "LY")
    assert art.supporting_span_ms[hx.hop_id] == 100                              # Xpay copy 1.0 .. install 1.1
    assert art.supporting_span_ms[hy.hop_id] == 50                               # moved copy 100.55 .. install 100.6


# ================================================================================================ ST-26 rows
def _seed_with_followup(*, follow_off: float = 11.8) -> World:
    w = World()
    w.logon("S0", 0.0, 2000, ip=IP_X, rule=R8, port=50001)
    w.logon("S1", 0.4, 2001, ip=IP_X, rule=None, port=50002)
    w.logon("S2", 0.8, 2002, ip=IP_X, rule=None, port=50003)
    w.logon("F0", follow_off, 2003, ip=IP_X, rule=None, port=50001)
    w.logon("F1", follow_off + 0.5, 2004, ip=IP_X, rule=None, port=50003)
    return w


def test_a_follow_up_group_is_one_followup_logon_row_port_reuse_tier_c_measured_from_the_hops_first_member():
    hs, art, _ = run(_seed_with_followup())
    assert len(hs.hops) == 1 and len(hs.followups) == 1
    hop = hs.hops[0]
    r = one(rows_of(art, "followup_logon"))
    assert r.hop_id == hop.hop_id and r.logged_under_hop_id == hop.hop_id
    assert (r.method, r.confidence_tier, r.candidate_count) == ("port_reuse", "C", 1)
    assert r.event_uids == ["F0", "F1"] and r.member_logon_uid == ""
    assert r.time_delta_ms == 11800                                              # from the FIRST member (0.0), not the last
    assert r.supporting_span_ms == 500
    assert art.service_install_count[hop.hop_id] == 0


def test_the_follow_up_row_counts_in_the_hop_span_and_is_a_hops_only_artefact_when_alone():
    w = _seed_with_followup()
    hs, art, _ = run(w)
    assert art.supporting_span_ms[hs.hops[0].hop_id] == 500                      # only artefact: the follow-up (11.8 .. 12.3)
    w.share("B1", 2.0, 2000, "a.txt")
    hs, art, _ = run(w)
    assert art.supporting_span_ms[hs.hops[0].hop_id] == 10300                    # burst at 2.0 .. follow-up end at 12.3


def test_no_follow_up_row_when_the_group_is_a_hop():
    hs, art, _ = run(_seed_with_followup(follow_off=40.0))
    assert len(hs.hops) == 2 and rows_of(art, "followup_logon") == []


# ================================================================================================ ST-01 / determinism
def _world_with_outsiders() -> World:
    w = _rich_world()
    w.share("OLD_SHARE", OUT_BEFORE, 2000, "a.txt")
    w.share("NEW_SHARE", OUT_AFTER, 2000, "Ypay.exe")
    w.install("OLD4", "OLD7", OUT_BEFORE, 2000, name="OldSvc", image=r"C:\x\old.exe")
    w.install("NEW4", "NEW7", OUT_AFTER, 2100, name="NewSvc", image=r"C:\x\Ypay.exe")
    w.wsmprovhost("OLD_WP", OUT_BEFORE, 3000)
    w.winrm91("OLD_91", OUT_BEFORE)
    w.triggers[-1]["supporting_event_uids"] += ";OLD_91"
    return w


def test_no_row_holds_an_out_of_window_uid():
    w = _world_with_outsiders()
    hs, art, scan = run(w)
    in_window = {u for r in scan.in_window + scan.link_rows for u in r["event_uids"]}
    uids = [u for r in art.rows for u in r.event_uids] + [u for b in art.bursts for u in b.event_uids] \
        + [u for i in art.installs for u in i.event_uids]
    assert set(uids) <= in_window
    out = {"OLD_SHARE", "NEW_SHARE", "OLD4", "OLD7", "NEW4", "NEW7", "OLD_WP", "OLD_91"}
    assert out.isdisjoint(uids)
    lo, hi = START_US, END_US
    assert all(lo <= r.first_us_raw <= hi and lo <= r.last_us_raw <= hi for r in art.rows)
    # the in-window result is the same as without the outsiders
    base_hs, base_art, _ = run(_rich_world())
    assert [(r.hop_id, r.kind, r.event_uids) for r in art.rows] == [(r.hop_id, r.kind, r.event_uids) for r in base_art.rows]


def test_building_twice_gives_equal_rows_in_the_documented_order():
    w = _rich_world()
    hs1, a1, _ = run(w)
    hs2, a2, _ = run(w)
    assert [dataclasses.asdict(r) for r in a1.rows] == [dataclasses.asdict(r) for r in a2.rows]
    assert [dataclasses.asdict(t) for t in a1.ties] == [dataclasses.asdict(t) for t in a2.ties]
    assert a1.service_install_count == a2.service_install_count and a1.supporting_span_ms == a2.supporting_span_ms
    assert a1.counts == a2.counts
    order = [(r.hop_id, r.first_us_raw, r.kind, r.event_uids[0]) for r in a1.rows]
    assert order == sorted(order), "rows are not sorted by hop id, first event, kind, first uid"
    assert len({r.hop_id for r in a1.rows}) >= 3


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_the_result_does_not_depend_on_the_order_of_the_input_rows(seed):
    w = _rich_world()
    _, base, _ = run(w)
    _, shuffled, _ = run(w, seed=seed)
    assert [dataclasses.asdict(r) for r in shuffled.rows] == [dataclasses.asdict(r) for r in base.rows]
    assert [dataclasses.asdict(t) for t in shuffled.ties] == [dataclasses.asdict(t) for t in base.ties]


def test_a_host_clock_offset_changes_no_artefact_time_or_tie(tmp_path):
    """Every artefact comparison is on the target host's own clock, so a correction cannot change a tie or a delta."""
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, TRIAL, "0" * 64, cf.offsets_spec(ep_02=(7000, "ok", True)), None)
    offs, chg = load_offsets(cf.offsets_path(repo, TRIAL)), load_clock_changes(cf.changes_path(repo, TRIAL))
    w = _xy()
    _, base, _ = run(w)
    _, shifted, _ = run(w, offsets=offs, changes=chg)
    view = lambda a: [(r.hop_id, r.kind, r.method, r.confidence_tier, r.time_delta_ms, r.supporting_span_ms,  # noqa: E731
                       r.event_uids) for r in a.rows]
    assert view(shifted) == view(base)
    assert [(t.delta_ms, t.candidate_count) for t in shifted.ties] == [(t.delta_ms, t.candidate_count) for t in base.ties]


def test_gate_support_diagnostics_list_a_shared_uid_that_no_row_holds_and_one_that_moved():
    """`gate_support_not_attached` lists a trigger row's supporting uid held by no artefact row of the hop;
    `gate_support_moved` lists those that ST-32 moved to another hop."""
    w = World()
    w.logon("LX", 0.0, 2000, support=["XS2", "LOST"])
    w.logon("LY", 100.0, 2100, ip=IP_Y)
    w.share("XS2", 100.55, 2000, "Ypay.exe")
    w.install("YI4", "YI7", 100.6, 2100)
    w.share("LOST", 1.0, 7777, "a.txt")                                          # a share of no member logon
    hs, art, _ = run(w)
    hx = hop_of(hs, "LX")
    assert art.gate_support_moved[hx.hop_id] == ["XS2"]
    assert art.gate_support_not_attached[hx.hop_id] == ["LOST"]
