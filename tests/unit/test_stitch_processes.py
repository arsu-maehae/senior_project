"""Tests for T7.2 task 4: process trees (spec 03_stitch ST-11), the session of a process (ST-10 as amended by
decision 047 items 1, 2, 7), `resolve_session` (ST-41 last sentence), `events_of_session` (ST-71 data side) and the
counts-only index summary. Fast, synthetic rows only.

Written from the spec, decision 047 and plan section 3 / 5, not from the implementation. The code was read only for
callable names and signatures. Rows are built raw and passed through `stitch.scan.scan_rows` with a window; sessions
come from `stitch.sessions.build_sessions` on the same kept rows. T = 0 is 10:30:00; a time below -1800 s is before
the 10:00 window start. Image paths and command text are neutral placeholders.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from clock_offset.correct import load_clock_changes, load_offsets  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch.index import build_index, index_counts  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from stitch.processes import build_processes, collapse, collapse_with_stats, session_logon_id_of  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402
from stitch.sessions import build_sessions, window_open  # noqa: E402

START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
PARAMS = StitchParams()
H = "ep-02"
PRE = -2000.0            # seconds from T0: before the window


def U(t: float) -> int:
    return to_us(sf.at(t))


# ------------------------------------------------------------------------------------------------ row builders
def L(uid, t, lid, *, host=H, account="acct_a", **kw) -> dict:
    return sf.ev(uid, "Security", 4624, host=host, off=t, logon_type=3, target_logon_id=lid, account_name=account, **kw)


def S1(uid, t, guid, pid, lid, *, parent=None, host=H, **kw) -> dict:
    return sf.ev(uid, "Sysmon", 1, host=host, off=t, process_guid=guid, parent_process_guid=parent, process_id=pid,
                 session_id=lid, image="PLACEHOLDER-IMAGE-PATH-AAAA", parent_image="PLACEHOLDER-PARENT-IMAGE-BBBB",
                 **kw)


def E88(uid, t, pid, *, target=None, subject=None, host=H, **kw) -> dict:
    return sf.ev(uid, "Security", 4688, host=host, off=t, process_id=pid, target_logon_id=target,
                 subject_logon_id=subject, **kw)


def A(uid, t, eid, guid, *, host=H, **kw) -> dict:
    return sf.ev(uid, "Sysmon", eid, host=host, off=t, process_guid=guid, **kw)


def B(uid, t, eid, *, host=H) -> dict:
    return sf.ev(uid, "System", eid, host=host, off=t)


def scan(tmp_path: Path, rows: list[dict], spec: dict | None = None):
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, sf.TRIAL, "0" * 64, spec, None)
    offsets = load_offsets(cf.offsets_path(repo, sf.TRIAL))
    changes = load_clock_changes(cf.changes_path(repo, sf.TRIAL))
    return scan_rows(rows, START_US, END_US, offsets, changes)


def build(tmp_path: Path, rows: list[dict]):
    """(sessions, processes) built the way `build_index` does."""
    res = scan(tmp_path, rows)
    sessions = build_sessions(res.in_window + res.lookback, PARAMS)
    return sessions, build_processes(res.in_window, sessions, PARAMS)


def key(lid: int, epoch: int = 0, seq: int = 0, host: str = H) -> tuple:
    return (host, lid, epoch, seq)


def pkey(guid: str, host: str = H) -> tuple:
    return (host, guid.lower())


# bare rows for the pure collapse function
def raw(uid, t_us, pid, host=H) -> dict:
    return {"event_uid": uid, "host": host, "process_id": pid, "us_raw": t_us}


def uid_pairs(pairs) -> list[tuple]:
    return [(a["event_uid"] if a else None, b["event_uid"] if b else None) for a, b in pairs]


# ================================================================================================ 1. collapse
BASE = 10_000_000_000


def test_collapse_delta_exactly_2s_collapses_and_2s_plus_1us_does_not():
    on = collapse([raw("S", BASE, 10)], [raw("E", BASE + 2_000_000, 10)], 2.0)
    assert uid_pairs(on) == [("S", "E")]
    off = collapse([raw("S", BASE, 10)], [raw("E", BASE + 2_000_001, 10)], 2.0)
    assert sorted(uid_pairs(off), key=str) == [("S", None), (None, "E")]


def test_collapse_is_symmetric_when_the_4688_is_before_the_sysmon_1():
    assert uid_pairs(collapse([raw("S", BASE, 10)], [raw("E", BASE - 2_000_000, 10)], 2.0)) == [("S", "E")]
    assert len(collapse([raw("S", BASE, 10)], [raw("E", BASE - 2_000_001, 10)], 2.0)) == 2


def test_collapse_different_pid_or_host_does_not_collapse():
    assert len(collapse([raw("S", BASE, 10)], [raw("E", BASE, 11)], 2.0)) == 2
    assert len(collapse([raw("S", BASE, 10, "ep-01")], [raw("E", BASE, 10, "ep-02")], 2.0)) == 2


def test_collapse_null_process_id_never_pairs():
    assert len(collapse([raw("S", BASE, None)], [raw("E", BASE, None)], 2.0)) == 2
    assert len(collapse([raw("S", BASE, None)], [raw("E", BASE, 10)], 2.0)) == 2
    assert len(collapse([raw("S", BASE, 10)], [raw("E", BASE, None)], 2.0)) == 2


def test_collapse_two_4688_candidates_pairs_the_nearest():
    pairs = collapse([raw("S", BASE, 10)], [raw("E-FAR", BASE + 1_500_000, 10), raw("E-NEAR", BASE + 500_000, 10)], 2.0)
    assert ("S", "E-NEAR") in uid_pairs(pairs) and (None, "E-FAR") in uid_pairs(pairs) and len(pairs) == 2


def test_collapse_equal_delta_picks_the_smaller_uid():
    e = [raw("E-B", BASE + 1_000_000, 10), raw("E-A", BASE - 1_000_000, 10)]
    for order in (e, list(reversed(e))):
        pairs = collapse([raw("S", BASE, 10)], order, 2.0)
        assert ("S", "E-A") in uid_pairs(pairs) and (None, "E-B") in uid_pairs(pairs)


def test_collapse_is_one_to_one_two_sysmon_1_and_one_4688():
    pairs, stats = collapse_with_stats([raw("S-NEAR", BASE + 100_000, 10), raw("S-FAR", BASE + 900_000, 10)],
                                       [raw("E", BASE, 10)], 2.0)
    assert sorted(uid_pairs(pairs), key=str) == [("S-FAR", None), ("S-NEAR", "E")]
    assert stats["ambiguous_pairs"] >= 1


def test_collapse_with_no_ambiguity_reports_zero_ambiguous():
    _, stats = collapse_with_stats([raw("S", BASE, 10)], [raw("E", BASE, 10)], 2.0)
    assert stats["ambiguous_pairs"] == 0


def test_collapse_two_candidates_for_one_sysmon_1_is_ambiguous():
    _, stats = collapse_with_stats([raw("S", BASE, 10)], [raw("E1", BASE, 10), raw("E2", BASE + 1, 10)], 2.0)
    assert stats["ambiguous_pairs"] >= 1 and stats["ambiguous_sysmon1"] >= 1


def test_collapse_keeps_every_row_exactly_once():
    s = [raw(f"S{i}", BASE + i * 10_000_000, 10 + i % 2) for i in range(6)]
    e = [raw(f"E{i}", BASE + i * 10_000_000 + 500_000, 10 + i % 2) for i in range(4)]
    pairs = collapse(s, e, 2.0)
    flat = [u for p in uid_pairs(pairs) for u in p if u]
    assert sorted(flat) == sorted([r["event_uid"] for r in s + e])


def test_collapsed_process_has_both_uids_and_counts_once(tmp_path):
    rows = [L("L", -5, 1000), S1("S", 10, "GUID-A", 4242, 1000), E88("E", 10.5, 4242, target=1000, subject=999)]
    _, procs = build(tmp_path, rows)
    assert len(procs.processes) == 1
    p = procs.processes[pkey("GUID-A")]
    assert p.sysmon1_uids == ["S"] and p.sec4688_uids == ["E"]
    c = procs.counts
    assert (c["sysmon1"], c["sec4688"], c["collapsed_pairs"], c["sysmon1_only"], c["sec4688_only"]) == (1, 1, 1, 0, 0)


def test_counts_for_alone_processes(tmp_path):
    rows = [S1("S1", 10, "GUID-A", 1, 1000), S1("S2", 20, "GUID-B", 2, 1000), E88("E1", 30, 3, subject=1000),
            E88("E2", 40, 4, subject=1000), E88("E3", 41, 5, subject=1000)]
    _, procs = build(tmp_path, rows)
    c = procs.counts
    assert (c["sysmon1"], c["sec4688"], c["collapsed_pairs"], c["sysmon1_only"], c["sec4688_only"]) == (2, 3, 0, 2, 3)
    assert len(procs.processes) == 5


def test_a_4688_alone_has_a_process_key_with_its_uid_and_a_sysmon_1_a_lower_case_guid_key(tmp_path):
    rows = [S1("S", 10, "GUID-A", 1, 1000), E88("E1", 30, 3, subject=1000)]
    _, procs = build(tmp_path, rows)
    assert set(procs.processes) == {(H, "guid-a"), (H, "4688:E1")}


# ================================================================================================ 2. session of a process
def test_sysmon_1_session_is_its_session_id(tmp_path):
    rows = [L("L", -5, 1000), S1("S", 10, "GUID-A", 1, 1000)]
    sessions, procs = build(tmp_path, rows)
    p = procs.processes[pkey("GUID-A")]
    assert p.session_logon_id == 1000 and p.session_key == key(1000)
    assert session_logon_id_of({"session_id": 1000}, None) == 1000


@pytest.mark.parametrize("target,subject,want", [(2000, 999, 2000), (None, 1500, 1500), (0, 1500, 1500),
                                                 (2000, None, 2000), (None, None, None), (0, None, None)])
def test_4688_alone_session_is_target_when_non_zero_else_subject(target, subject, want):
    row = {"target_logon_id": target, "subject_logon_id": subject}
    assert session_logon_id_of(None, row) == want


def test_4688_alone_session_through_the_build(tmp_path):
    rows = [L("L-USER", -5, 2000), L("L-SYS", -5, 999, ), E88("E-T", 10, 1, target=2000, subject=999),
            E88("E-N", 20, 2, target=None, subject=999), E88("E-Z", 30, 3, target=0, subject=999)]
    sessions, procs = build(tmp_path, rows)
    assert procs.processes[(H, "4688:E-T")].session_key == key(2000)
    assert procs.processes[(H, "4688:E-N")].session_key == key(999)
    assert procs.processes[(H, "4688:E-Z")].session_key == key(999)


def test_pair_where_the_4688_rule_gives_another_id_uses_the_sysmon_1_value_and_counts_the_disagreement(tmp_path):
    rows = [L("L1", -5, 3000), L("L2", -5, 2000),
            S1("S", 10, "GUID-A", 4242, 3000), E88("E", 10.5, 4242, target=2000, subject=999)]
    _, procs = build(tmp_path, rows)
    p = procs.processes[pkey("GUID-A")]
    assert p.session_logon_id == 3000 and p.session_key == key(3000)
    assert procs.counts["session_rule_disagreements"] == 1


def test_pair_where_both_rules_agree_is_no_disagreement(tmp_path):
    rows = [L("L", -5, 2000), S1("S", 10, "GUID-A", 4242, 2000), E88("E", 10.5, 4242, target=2000, subject=999)]
    _, procs = build(tmp_path, rows)
    assert procs.counts["session_rule_disagreements"] == 0


def test_process_session_is_the_session_at_marked_referenced_and_in_window_view(tmp_path):
    rows = [L("L", -5, 1000), S1("S", 10, "GUID-A", 1, 1000)]
    sessions, procs = build(tmp_path, rows)
    s = sessions.sessions[key(1000)]
    assert procs.processes[pkey("GUID-A")].session_key == s.key
    assert s.key in sessions.referenced and s in sessions.window_view()


def test_process_with_no_4624_gets_an_unknown_open_session(tmp_path):
    rows = [S1("S", 10, "GUID-A", 1, 4242)]
    sessions, procs = build(tmp_path, rows)
    p = procs.processes[pkey("GUID-A")]
    s = sessions.sessions[p.session_key]
    assert s.open_known is False and s.logon_id == 4242
    assert s in sessions.window_view()
    assert sessions.counts["open_unknown"] == 1


def test_process_in_a_pre_window_opened_session_keeps_its_key_and_window_open_is_empty(tmp_path):
    rows = [L("PRE-L", PRE, 1000), S1("S", 10, "GUID-A", 1, 1000)]
    sessions, procs = build(tmp_path, rows)
    p = procs.processes[pkey("GUID-A")]
    assert p.session_key == key(1000)
    s = sessions.sessions[p.session_key]
    assert s.opened_before_window is True and s in sessions.window_view()
    assert window_open(s) == ([], None, None)


def test_process_after_a_boot_is_in_the_new_epoch_session(tmp_path):
    rows = [L("L1", 10, 1000), B("BOOT", 100, 1074), L("L2", 200, 1000), S1("S", 210, "GUID-A", 1, 1000)]
    _, procs = build(tmp_path, rows)
    assert procs.processes[pkey("GUID-A")].session_key == key(1000, 1)


def test_sysmon_1_with_null_session_id_forms_no_session(tmp_path):
    rows = [S1("S", 10, "GUID-A", 1, None)]
    sessions, procs = build(tmp_path, rows)
    p = procs.processes[pkey("GUID-A")]
    assert p.session_logon_id is None and p.session_key is None
    assert sessions.sessions == {}
    assert procs.resolve_session(H, "GUID-A")[0] is None


# ================================================================================================ 3. tree
def test_children_and_ancestors_by_guid(tmp_path):
    rows = [L("L", -5, 1000),
            S1("S-P", 10, "GUID-P", 1, 1000, parent="GUID-X"),
            S1("S-C", 11, "GUID-C", 2, 1000, parent="guid-p"),          # parent given in another case
            S1("S-G", 12, "GUID-G", 3, 1000, parent="GUID-C")]
    _, procs = build(tmp_path, rows)
    p, c, g = pkey("GUID-P"), pkey("GUID-C"), pkey("GUID-G")
    assert procs.children(p) == [c] and procs.children(c) == [g] and procs.children(g) == []
    assert procs.ancestors(g) == [c, p] and procs.ancestors(c) == [p] and procs.ancestors(p) == []
    assert procs.processes[p].parent_resolved is False
    assert procs.processes[c].parent_resolved is True and procs.processes[g].parent_resolved is True
    assert procs.counts["parent_resolved"] == 2 and procs.counts["parent_unresolved"] == 1


def test_a_parent_in_another_host_is_not_resolved(tmp_path):
    rows = [S1("S-P", 10, "GUID-P", 1, 1000, host="ep-01"), S1("S-C", 11, "GUID-C", 2, 1000, parent="GUID-P")]
    _, procs = build(tmp_path, rows)
    assert procs.processes[pkey("GUID-C")].parent_resolved is False
    assert procs.children(pkey("GUID-P", "ep-01")) == []


def test_a_guid_cycle_terminates(tmp_path):
    rows = [S1("S-A", 10, "GUID-A", 1, 1000, parent="GUID-B"), S1("S-B", 11, "GUID-B", 2, 1000, parent="GUID-A"),
            S1("S-S", 12, "GUID-S", 3, 1000, parent="GUID-S")]
    _, procs = build(tmp_path, rows)
    a, b, s = pkey("GUID-A"), pkey("GUID-B"), pkey("GUID-S")
    assert a not in procs.ancestors(a) and set(procs.ancestors(a)) <= {b}
    assert b not in procs.ancestors(b) and len(procs.ancestors(b)) <= 1
    assert s not in procs.ancestors(s)


def test_a_pre_window_sysmon_1_is_not_a_process_so_its_child_is_parent_unresolved(tmp_path):
    rows = [S1("S-PRE", PRE, "GUID-OLD", 1, 1000), S1("S-C", 10, "GUID-C", 2, 1000, parent="GUID-OLD")]
    _, procs = build(tmp_path, rows)
    assert pkey("GUID-OLD") not in procs.processes
    assert procs.processes[pkey("GUID-C")].parent_resolved is False
    assert procs.counts["sysmon1"] == 1


def test_a_pre_window_4688_is_not_a_process(tmp_path):
    rows = [E88("E-PRE", PRE, 1, subject=1000), E88("E", 10, 2, subject=1000)]
    _, procs = build(tmp_path, rows)
    assert set(procs.processes) == {(H, "4688:E")}


# ================================================================================================ 4. attachment
def test_sysmon_3_10_11_attach_by_host_and_guid(tmp_path):
    rows = [L("L", -5, 1000), S1("S", 10, "GUID-A", 1, 1000), A("N3", 11, 3, "GUID-A"), A("N10", 12, 10, "guid-a"),
            A("N11", 13, 11, "GUID-A")]
    _, procs = build(tmp_path, rows)
    assert procs.processes[pkey("GUID-A")].event_uids_by_kind == {"sysmon3": ["N3"], "sysmon10": ["N10"],
                                                                   "sysmon11": ["N11"]}
    att = procs.counts["attached"]
    for kind in ("sysmon3", "sysmon10", "sysmon11"):
        assert att[kind]["resolved"] == 1 and att[kind]["no_sysmon1_in_window"] == 0
        assert att[kind]["system_process"] == 0


def test_a_guid_with_no_in_window_sysmon_1_is_unattached_and_counted(tmp_path):
    rows = [A("N3", 11, 3, "GUID-NONE"), A("N10", 12, 10, "GUID-NONE"), A("N11", 13, 11, "GUID-NONE")]
    _, procs = build(tmp_path, rows)
    assert procs.processes == {}
    att = procs.counts["attached"]
    for kind in ("sysmon3", "sysmon10", "sysmon11"):
        assert att[kind]["no_sysmon1_in_window"] == 1 and att[kind]["resolved"] == 0
    assert procs.resolve_session(H, "GUID-NONE") == (None, "no_sysmon1_in_window")


def test_a_sysmon_3_of_a_pre_window_sysmon_1_is_unattached(tmp_path):
    """Owner Q13b: a pre-window Sysmon 1 is not a process."""
    rows = [S1("S-PRE", PRE, "GUID-OLD", 1, 1000), A("N3", 11, 3, "GUID-OLD")]
    _, procs = build(tmp_path, rows)
    assert procs.counts["attached"]["sysmon3"]["no_sysmon1_in_window"] == 1
    assert procs.resolve_session(H, "GUID-OLD") == (None, "no_sysmon1_in_window")


def test_a_pre_window_attached_event_is_not_attached_or_counted(tmp_path):
    rows = [S1("S", 10, "GUID-A", 1, 1000), A("N3-PRE", PRE, 3, "GUID-A")]
    _, procs = build(tmp_path, rows)
    assert procs.processes[pkey("GUID-A")].event_uids_by_kind["sysmon3"] == []
    att = procs.counts["attached"]["sysmon3"]
    assert (att["resolved"], att["no_sysmon1_in_window"], att["system_process"]) == (0, 0, 0)


def test_resolve_session_of_a_user_process_is_its_key_and_empty_reason(tmp_path):
    rows = [L("L", -5, 1000), S1("S", 10, "GUID-A", 1, 1000)]
    _, procs = build(tmp_path, rows)
    assert procs.resolve_session(H, "GUID-A") == (key(1000), "")
    assert procs.resolve_session(H, "guid-a") == (key(1000), "")


def test_a_process_in_session_0x3e7_is_a_system_process(tmp_path):
    rows = [L("L", -5, 999, ), S1("S", 10, "GUID-SYS", 1, 0x3E7), A("N3", 11, 3, "GUID-SYS")]
    _, procs = build(tmp_path, rows)
    k, reason = procs.resolve_session(H, "GUID-SYS")
    assert reason == "system_process" and k == procs.processes[pkey("GUID-SYS")].session_key == key(999)
    att = procs.counts["attached"]["sysmon3"]
    assert att["system_process"] == 1 and att["resolved"] == 0


@pytest.mark.parametrize("lid", [0x3E4, 0x3E5, 0x3E7])
def test_every_system_logon_id_is_a_system_process(tmp_path, lid):
    _, procs = build(tmp_path, [S1("S", 10, "GUID-SYS", 1, lid)])
    assert procs.resolve_session(H, "GUID-SYS")[1] == "system_process"


def test_a_guid_match_on_another_host_does_not_attach(tmp_path):
    rows = [S1("S", 10, "GUID-A", 1, 1000, host="ep-02"), A("N3", 11, 3, "GUID-A", host="ep-01")]
    _, procs = build(tmp_path, rows)
    assert procs.processes[pkey("GUID-A", "ep-02")].event_uids_by_kind["sysmon3"] == []
    assert procs.counts["attached"]["sysmon3"]["no_sysmon1_in_window"] == 1
    assert procs.resolve_session("ep-01", "GUID-A") == (None, "no_sysmon1_in_window")


def test_resolve_session_of_a_4688_alone_has_no_guid_so_it_is_unresolved(tmp_path):
    """A 4688 has no guid: only a Sysmon 1 gives a process by guid (ST-11 / ST-41)."""
    _, procs = build(tmp_path, [E88("E", 10, 1, subject=1000)])
    assert procs.resolve_session(H, "anything") == (None, "no_sysmon1_in_window")


# ================================================================================================ 5. events_of_session
def _session_rows():
    return [L("L-1000", -5, 1000), L("L-2000", -5, 2000), L("PRE-L", PRE, 1000, record_id=999001),
            S1("S-P", 10, "GUID-P", 1, 1000), A("N3", 11, 3, "GUID-P"),
            E88("E-ALONE", 20, 2, target=1000, subject=999),
            S1("S-PAIR", 30, "GUID-Q", 3, 1000), E88("E-PAIR", 30.2, 3, target=1000, subject=999),
            A("N11", 40, 11, "GUID-P"), A("N10", 50, 10, "GUID-P"),
            S1("S-OTHER", 15, "GUID-O", 4, 2000), A("N3-OTHER", 16, 3, "GUID-O"),
            # pre-window events of the same session: never in the result (ST-01)
            S1("S-PRE", PRE, "GUID-OLD", 5, 1000), A("N3-PRE", PRE, 3, "GUID-OLD"), E88("E-PRE", PRE, 6, target=1000)]


def test_events_of_session_lists_processes_and_attached_events_sorted_unique(tmp_path):
    sessions, procs = build(tmp_path, _session_rows())
    out = procs.events_of_session(key(1000))
    assert out == sorted({"S-P", "N3", "E-ALONE", "S-PAIR", "E-PAIR", "N11", "N10"})
    assert out == sorted(set(out))
    assert procs.events_of_session(key(2000)) == ["N3-OTHER", "S-OTHER"]


def test_events_of_session_never_lists_a_pre_window_event_or_the_logons(tmp_path):
    _, procs = build(tmp_path, _session_rows())
    out = procs.events_of_session(key(1000))
    for u in ("S-PRE", "N3-PRE", "E-PRE", "PRE-L", "L-1000", "L-2000"):
        assert u not in out


def test_events_of_session_until_excludes_later_events(tmp_path):
    _, procs = build(tmp_path, _session_rows())
    assert procs.events_of_session(key(1000), U(25)) == sorted(["S-P", "N3", "E-ALONE"])
    assert procs.events_of_session(key(1000), U(10)) == ["S-P"]
    assert procs.events_of_session(key(1000), U(9)) == []
    assert procs.events_of_session(key(1000), U(45)) == sorted(["S-P", "N3", "E-ALONE", "S-PAIR", "E-PAIR", "N11"])


def test_events_of_unknown_session_is_empty(tmp_path):
    _, procs = build(tmp_path, _session_rows())
    assert procs.events_of_session(key(7777)) == []
    assert procs.events_of_session(key(1000, 5, 0)) == []


# ================================================================================================ 6. index
def _index_scan(tmp_path):
    rows = [L("L-1", -5, 1000, account="PLACEHOLDER-ACCOUNT-NAME"), L("PRE-L", PRE, 3000),
            S1("S-P", 10, "PLACEHOLDER-GUID-0001", 1, 1000, command_line="PLACEHOLDER-COMMAND-TEXT-CCCC-0123456789"),
            S1("S-C", 11, "PLACEHOLDER-GUID-0002", 2, 1000, parent="PLACEHOLDER-GUID-0001",
               command_line="PLACEHOLDER-COMMAND-TEXT-CCCC-0123456789"),
            E88("E", 11.5, 2, target=1000, subject=999, command_line="PLACEHOLDER-COMMAND-TEXT-CCCC-0123456789"),
            A("N3", 12, 3, "PLACEHOLDER-GUID-0001"), S1("S-U", 13, "PLACEHOLDER-GUID-0003", 3, 5555),
            A("N-LOST", 14, 3, "PLACEHOLDER-GUID-9999"), S1("S-PRE", PRE, "PLACEHOLDER-GUID-OLD", 4, 1000)]
    return scan(tmp_path, rows)


def test_index_counts_is_json_serialisable_sorted_and_identical_across_builds(tmp_path):
    res = _index_scan(tmp_path)
    a = index_counts(build_index(sf.TRIAL, res, PARAMS))
    b = index_counts(build_index(sf.TRIAL, res, PARAMS))
    text = json.dumps(a)
    assert text == json.dumps(a, sort_keys=True)
    assert json.dumps(a) == json.dumps(b)
    assert json.loads(text) == a


def test_index_counts_has_the_plan_blocks_and_hand_counts(tmp_path):
    res = _index_scan(tmp_path)
    out = index_counts(build_index(sf.TRIAL, res, PARAMS), extra={"gate_stats_sha256": "abc"})
    assert out["trial_id"] == sf.TRIAL and out["gate_stats_sha256"] == "abc"
    for k in ("tool_version", "events", "sessions", "processes", "attached", "clock_unreliable_events"):
        assert k in out
    p = out["processes"]
    assert (p["sysmon1"], p["sec4688"], p["collapsed_pairs"], p["sysmon1_only"], p["sec4688_only"]) == (3, 1, 1, 2, 0)
    assert p["parent_resolved"] == 1 and p["parent_unresolved"] == 2
    att = out["attached"]["sysmon3"]
    assert (att["resolved"], att["no_sysmon1_in_window"], att["system_process"]) == (1, 1, 0)
    assert out["sessions"]["open_unknown"] == 1
    assert out["events"]["loaded"] == 9


def test_index_counts_contain_no_image_account_guid_or_command_text(tmp_path):
    res = _index_scan(tmp_path)
    text = json.dumps(index_counts(build_index(sf.TRIAL, res, PARAMS), extra={"parameters": {"x": 1}}))
    for secret in ("PLACEHOLDER-IMAGE-PATH-AAAA", "PLACEHOLDER-PARENT-IMAGE-BBBB", "PLACEHOLDER-ACCOUNT-NAME",
                   "PLACEHOLDER-GUID", "PLACEHOLDER-COMMAND-TEXT-CCCC-0123456789", "PLACEHOLDER"):
        assert secret not in text
    cmd = "PLACEHOLDER-COMMAND-TEXT-CCCC-0123456789"
    for i in range(len(cmd) - 11):
        assert cmd[i:i + 12] not in text


def test_trial_index_holds_sessions_processes_and_scan_counts(tmp_path):
    res = _index_scan(tmp_path)
    idx = build_index(sf.TRIAL, res, PARAMS)
    assert idx.trial_id == sf.TRIAL
    assert idx.sessions is not None and idx.processes is not None
    assert idx.scan_counts["loaded"] == 9
    assert pkey("PLACEHOLDER-GUID-OLD") not in idx.processes.processes          # pre-window Sysmon 1: not a process
    assert key(3000) in idx.sessions.sessions                                    # the look-back open is a session
    assert key(3000) not in {s.key for s in idx.sessions.window_view()}
