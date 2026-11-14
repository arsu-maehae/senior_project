"""Tests for T7.3 task 1: the link kinds of the scan (`stitch.scan.is_link_kind`, `ScanResult.link_rows` and their
ST-05 counters) and `stitch.inputs.load_link_inputs`. Fast, synthetic rows and fake repos in `tmp_path`.

Written from docs/specs/03_stitch.md (ST-01, ST-02, ST-05), decision 048 item 2 and the T7.3 plan section 2, not from
the implementation. The code was read only for names and signatures. Real data is never opened.
"""
from __future__ import annotations

import copy
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from clock_offset.correct import load_clock_changes, load_offsets  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch import params as sp  # noqa: E402
from stitch.cmdtext import read_command_results, target_name_forms  # noqa: E402
from stitch.inputs import StitchError, check_allowed, load_link_inputs, load_scan  # noqa: E402
from stitch.scan import is_link_kind, scan_rows  # noqa: E402

START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

LINK_KINDS = [("Security", 5140), ("Security", 5145), ("Security", 4697), ("Security", 4648), ("Security", 4769),
              ("System", 7045), ("WinRM", 91)]
T72_KINDS = [("Security", 4624), ("Security", 4634), ("Security", 4647), ("Security", 4688), ("Security", 1102),
             ("Sysmon", 1), ("Sysmon", 3), ("Sysmon", 10), ("Sysmon", 11), ("System", 41), ("System", 6005)]
OTHER_KINDS = [("Security", 4672), ("Sysmon", 5), ("Sysmon", 7), ("Sysmon", 91), ("Security", 91), ("WinRM", 5140),
               ("System", 4697), ("Application", 4648), ("Sysmon", 4769), ("System", 5145), ("WinRM", 4648)]


# ------------------------------------------------------------------------------------------------ helpers
def utc_of(us: int) -> str:
    return sf.iso6(EPOCH + timedelta(microseconds=us))


def at_us(us: int, uid: str, channel: str, event_id: int, *, host: str = "ep-02", **kw) -> dict:
    return sf.ev(uid, channel, event_id, host=host, utc=utc_of(us), **kw)


def clock(tmp_path: Path, spec: dict | None = None):
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, sf.TRIAL, "0" * 64, spec, None)
    return load_offsets(cf.offsets_path(repo, sf.TRIAL)), load_clock_changes(cf.changes_path(repo, sf.TRIAL))


def scan(tmp_path: Path, rows: list[dict], spec: dict | None = None):
    offsets, chg = clock(tmp_path, spec)
    return scan_rows([dict(r) for r in rows], START_US, END_US, offsets, chg)


def uids(rows: list[dict]) -> set[str]:
    return {r["event_uid"] for r in rows}


IN = START_US + 10_000_000
PRE = START_US - 5_000_000
POST = END_US + 5_000_000


# ================================================================================================ predicate
@pytest.mark.parametrize("channel,event_id", LINK_KINDS)
def test_is_link_kind_true_for_the_seven_kinds(channel, event_id):
    assert is_link_kind({"channel": channel, "event_id": event_id}) is True


@pytest.mark.parametrize("channel,event_id", T72_KINDS + OTHER_KINDS)
def test_is_link_kind_false_for_every_other_kind_and_needs_the_channel(channel, event_id):
    assert is_link_kind({"channel": channel, "event_id": event_id}) is False


def test_is_link_kind_on_a_row_without_the_keys_is_false():
    assert is_link_kind({}) is False


# ================================================================================================ window
@pytest.mark.parametrize("channel,event_id", LINK_KINDS)
def test_in_window_link_kind_goes_to_link_rows_only(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(IN, "L", channel, event_id)])
    assert uids(res.link_rows) == {"L"}
    assert res.in_window == [] and res.lookback == []
    assert res.link_rows[0]["in_window"] in (True, 1)
    assert res.loaded_total == 1


@pytest.mark.parametrize("channel,event_id", LINK_KINDS)
def test_same_row_before_the_window_is_never_kept(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(PRE, "L", channel, event_id)])
    assert res.link_rows == [] and res.in_window == [] and res.lookback == []
    assert res.kept_lookback_by_type == {}
    assert res.loaded_total == 1


@pytest.mark.parametrize("channel,event_id", LINK_KINDS)
def test_same_row_after_the_window_is_never_kept(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(POST, "L", channel, event_id)])
    assert res.link_rows == [] and res.in_window == [] and res.lookback == []
    assert res.loaded_total == 1


@pytest.mark.parametrize("channel,event_id", LINK_KINDS)
def test_out_of_window_link_rows_are_counted_in_removed_by_window(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(PRE, "A", channel, event_id), at_us(POST, "B", channel, event_id)])
    assert res.removed_by_window == {"ep-02": {f"{channel}/{event_id}": 2}}


def test_window_edges_for_link_rows_follow_the_gate_predicate(tmp_path):
    rows = [at_us(START_US - 1, "BEFORE", "Security", 5145), at_us(START_US, "START", "Security", 5145),
            at_us(END_US + 999, "LASTIN", "Security", 5145), at_us(END_US + 1000, "AFTER", "Security", 5145)]
    res = scan(tmp_path, rows)
    assert uids(res.link_rows) == {"START", "LASTIN"}


def test_link_row_window_test_uses_the_corrected_time(tmp_path):
    spec = cf.offsets_spec(ep_02=(7000, "ok", True))
    off = 7_000_000
    rows = [at_us(START_US + off - 1, "OUT", "Security", 4648), at_us(START_US + off, "IN", "Security", 4648)]
    res = scan(tmp_path, rows, spec)
    assert uids(res.link_rows) == {"IN"}
    (kept,) = res.link_rows
    assert kept["us_raw"] == START_US + off and kept["us"] == START_US


def test_link_rows_carry_clock_unreliable_like_other_rows(tmp_path):
    spec = cf.offsets_spec(ep_02=(2000, "wide", True))
    res = scan(tmp_path, [at_us(IN, "U", "Security", 5145, host="ep-02"), at_us(IN, "R", "Security", 5145, host="ep-01")],
               spec)
    by = {r["event_uid"]: r for r in res.link_rows}
    assert by["U"]["clock_unreliable"] == 1 and by["R"]["clock_unreliable"] == 0


def test_link_rows_are_sorted_by_corrected_time_then_uid(tmp_path):
    rows = [at_us(IN + 3, "C", "Security", 5145), at_us(IN, "B", "Security", 4697), at_us(IN, "A", "System", 7045),
            at_us(IN + 1, "D", "WinRM", 91)]
    res = scan(tmp_path, rows)
    assert [r["event_uid"] for r in res.link_rows] == ["A", "B", "D", "C"]


# ================================================================================================ disjoint lists
def test_link_rows_are_not_in_in_window_or_lookback_and_no_row_is_in_two_lists(tmp_path):
    rows = [at_us(IN, "IN-LOGON", "Security", 4624, target_logon_id=1), at_us(IN, "IN-SHARE", "Security", 5145),
            at_us(IN, "IN-SYSMON", "Sysmon", 1), at_us(PRE, "PRE-LOGON", "Security", 4624, target_logon_id=2),
            at_us(PRE, "PRE-SHARE", "Security", 5145), at_us(IN, "IN-4648", "Security", 4648),
            at_us(POST, "POST-4769", "Security", 4769), at_us(IN, "IN-4769", "Security", 4769, host="dc01"),
            at_us(IN, "IN-4672", "Security", 4672)]
    res = scan(tmp_path, rows)
    assert uids(res.in_window) == {"IN-LOGON", "IN-SYSMON"}
    assert uids(res.lookback) == {"PRE-LOGON"}
    assert uids(res.link_rows) == {"IN-SHARE", "IN-4648", "IN-4769"}
    all_lists = [uids(res.in_window), uids(res.lookback), uids(res.link_rows)]
    assert sum(len(x) for x in all_lists) == len(set().union(*all_lists))
    assert res.loaded_total == len(rows)


def test_link_rows_keep_their_non_command_columns_and_never_a_command_key(tmp_path):
    row = at_us(IN, "L", "Security", 5145, share_name="\\\\*\\C$", relative_target_name="Xpay.exe",
                subject_logon_id=77, logon_guid="{abc}", service_name="svc", service_image_path="C:\\x.exe",
                destination_host="ep-02", subject_account="acct_a", command_line=sf.PLACEHOLDER_COMMAND,
                field_values_json='{"k": "v"}')
    (kept,) = scan(tmp_path, [row]).link_rows
    assert kept["share_name"] == "\\\\*\\C$" and kept["relative_target_name"] == "Xpay.exe"
    assert kept["subject_logon_id"] == 77 and kept["logon_guid"] == "{abc}" and kept["service_name"] == "svc"
    assert kept["service_image_path"] == "C:\\x.exe" and kept["destination_host"] == "ep-02"
    assert kept["subject_account"] == "acct_a"
    for c in sp.SCAN_COLUMNS:
        assert c in kept, c
    for c in ("us_raw", "us", "in_window", "clock_unreliable", "event_uids"):
        assert c in kept, c
    assert "command_line" not in kept and "field_values_json" not in kept
    assert sf.PLACEHOLDER_COMMAND not in repr(kept)


def test_new_scan_columns_exist_on_t72_rows_too(tmp_path):
    (kept,) = scan(tmp_path, [at_us(IN, "L", "Security", 4624, target_logon_id=5, logon_guid="g1")]).in_window
    assert kept["logon_guid"] == "g1"
    for c in ("share_name", "relative_target_name", "service_name", "service_image_path", "destination_host",
              "subject_account"):
        assert c in kept


# ================================================================================================ ST-05 for link rows
def test_two_link_rows_with_one_host_channel_record_id_collapse_with_both_uids(tmp_path):
    rows = [at_us(IN, "UID-B", "Security", 5145, record_id=777), at_us(IN, "UID-A", "Security", 5145, record_id=777)]
    res = scan(tmp_path, rows)
    assert len(res.link_rows) == 1
    assert res.link_rows[0]["event_uids"] == ["UID-A", "UID-B"]
    assert res.link_rows[0]["event_uid"] in ("UID-A", "UID-B")
    assert res.link_near_duplicate_groups == 1
    assert res.near_duplicate_groups == 0
    assert res.loaded_total == 2


def test_three_link_copies_are_sorted_and_count_as_one_group(tmp_path):
    rows = [at_us(IN + i, uid, "System", 7045, record_id=9) for i, uid in enumerate(("C", "A", "B"))]
    res = scan(tmp_path, rows)
    assert len(res.link_rows) == 1 and res.link_rows[0]["event_uids"] == ["A", "B", "C"]
    assert res.link_near_duplicate_groups == 1


def test_the_representative_of_a_link_group_is_the_earliest_logged_copy(tmp_path):
    rows = [at_us(IN + 500, "LATE", "Security", 5140, record_id=3), at_us(IN, "EARLY", "Security", 5140, record_id=3)]
    (kept,) = scan(tmp_path, rows).link_rows
    assert kept["event_uid"] == "EARLY" and kept["us_raw"] == IN


def test_link_group_counter_and_t72_counter_are_independent(tmp_path):
    rows = [at_us(IN, "L1", "Security", 4697, record_id=1), at_us(IN, "L2", "Security", 4697, record_id=1),
            at_us(IN, "P1", "Security", 4624, record_id=2, target_logon_id=1),
            at_us(IN, "P2", "Security", 4624, record_id=2, target_logon_id=1),
            at_us(IN, "P3", "Sysmon", 1, record_id=3), at_us(IN, "P4", "Sysmon", 1, record_id=3)]
    res = scan(tmp_path, rows)
    assert res.link_near_duplicate_groups == 1 and res.near_duplicate_groups == 2
    assert len(res.link_rows) == 1 and len(res.in_window) == 2


def test_same_record_id_on_another_host_or_channel_is_not_a_link_duplicate(tmp_path):
    rows = [at_us(IN, "A", "Security", 5145, record_id=5, host="ep-02"),
            at_us(IN, "B", "Security", 5145, record_id=5, host="ep-01"),
            at_us(IN, "C", "System", 7045, record_id=5, host="ep-02"),
            at_us(IN, "D", "WinRM", 91, record_id=5, host="ep-02")]
    res = scan(tmp_path, rows)
    assert uids(res.link_rows) == {"A", "B", "C", "D"}
    assert res.link_near_duplicate_groups == 0
    assert all(len(r["event_uids"]) == 1 for r in res.link_rows)


def test_link_rows_without_record_id_are_never_grouped(tmp_path):
    rows = [at_us(IN, "A", "Security", 5145, record_id=None), at_us(IN, "B", "Security", 5145, record_id=None)]
    res = scan(tmp_path, rows)
    assert uids(res.link_rows) == {"A", "B"} and res.link_near_duplicate_groups == 0


def test_link_group_with_a_copy_before_the_window_is_placed_by_its_earliest_copy(tmp_path):
    """Same rule as T7.2 ST-05: the group is placed by its earliest copy, so it is not an in-window event, and the
    split is counted. (By analogy with the T7.2 counters; no link row is ever kept before the window.)"""
    rows = [at_us(PRE, "EARLY", "Security", 5145, record_id=8), at_us(IN, "LATE", "Security", 5145, record_id=8)]
    res = scan(tmp_path, rows)
    assert res.link_rows == []
    assert res.link_near_duplicate_groups == 1 and res.link_near_duplicate_split_by_window == 1
    assert res.near_duplicate_split_by_window == 0


def test_link_group_wholly_in_window_is_not_a_split(tmp_path):
    rows = [at_us(IN, "A", "Security", 5145, record_id=8), at_us(IN + 5, "B", "Security", 5145, record_id=8)]
    res = scan(tmp_path, rows)
    assert res.link_near_duplicate_groups == 1 and res.link_near_duplicate_split_by_window == 0


# ================================================================================================ T7.2 results unchanged
def t72_rows() -> list[dict]:
    rows = [
        at_us(IN, "L1", "Security", 4624, target_logon_id=1000, record_id=101),
        at_us(IN + 10, "L1-DUP", "Security", 4624, target_logon_id=1000, record_id=101),
        at_us(IN + 1_000_000, "L2", "Security", 4624, target_logon_id=1001, host="ep-01"),
        at_us(PRE, "PRE-LOGON", "Security", 4624, target_logon_id=999),
        at_us(PRE + 10, "PRE-OFF", "Security", 4634, target_logon_id=999),
        at_us(PRE, "PRE-BOOT", "System", 6005, host="ep-03"),
        at_us(PRE, "PRE-1102", "Security", 1102, host="ep-03"),
        at_us(START_US - 1_000, "PRE-SYSMON1", "Sysmon", 1),
        at_us(IN + 2_000_000, "P1", "Sysmon", 1, process_guid="{g1}", process_id=10, session_id=1000, record_id=102),
        at_us(IN + 2_000_000, "P1-DUP", "Sysmon", 1, process_guid="{g1}", process_id=10, session_id=1000,
              record_id=102),
        at_us(IN + 2_100_000, "B1", "Security", 4688, process_id=10, target_logon_id=1000),
        at_us(IN + 3_000_000, "S3", "Sysmon", 3, process_guid="{g1}"),
        at_us(IN + 3_000_000, "X1", "Security", 4672),
        at_us(POST, "POST-LOGON", "Security", 4624, target_logon_id=1002),
        at_us(START_US - 1, "BOUND", "Security", 4624, target_logon_id=1003, record_id=103),
        at_us(START_US + 1, "BOUND-DUP", "Security", 4624, target_logon_id=1003, record_id=103),
    ]
    return rows


def link_rows_in_window() -> list[dict]:
    return [at_us(IN + 100, f"K{i}", ch, eid, record_id=5000 + i) for i, (ch, eid) in enumerate(LINK_KINDS)] + \
           [at_us(IN + 100, "K-DUP-A", "Security", 5145, record_id=6000),
            at_us(IN + 100, "K-DUP-B", "Security", 5145, record_id=6000)]


T72_FIELDS = ("in_window", "lookback", "kept_lookback_by_type", "removed_by_window", "near_duplicate_groups",
              "near_duplicate_split_by_window")


def test_adding_in_window_link_rows_changes_no_t72_field(tmp_path):
    base_rows = t72_rows()
    extra = link_rows_in_window()
    before = scan(tmp_path, copy.deepcopy(base_rows))
    after = scan(tmp_path, copy.deepcopy(base_rows) + extra)
    for name in T72_FIELDS:
        assert getattr(after, name) == getattr(before, name), name
    assert after.loaded_total == before.loaded_total + len(extra)
    assert before.link_rows == [] and len(after.link_rows) == len(LINK_KINDS) + 1
    assert before.near_duplicate_groups >= 2          # the base data has real T7.2 groups, so the test is meaningful


def test_adding_out_of_window_link_rows_changes_only_removed_by_window_link_keys(tmp_path):
    base_rows = t72_rows()
    extra = [at_us(PRE, "OLD-A", "Security", 5145), at_us(POST, "NEW-A", "Security", 4648),
             at_us(PRE, "OLD-B", "Security", 4697, host="ep-03")]
    before = scan(tmp_path, copy.deepcopy(base_rows))
    after = scan(tmp_path, copy.deepcopy(base_rows) + extra)
    for name in ("in_window", "lookback", "kept_lookback_by_type", "near_duplicate_groups",
                 "near_duplicate_split_by_window"):
        assert getattr(after, name) == getattr(before, name), name
    assert after.link_rows == []
    assert after.loaded_total == before.loaded_total + 3

    def strip(table):
        return {h: {k: v for k, v in c.items() if k.split("/")[1] not in {"5145", "4648", "4697"}}
                for h, c in table.items()}
    assert {h: c for h, c in strip(after.removed_by_window).items() if c} == \
        {h: c for h, c in strip(before.removed_by_window).items() if c}


def test_link_row_order_in_the_input_does_not_change_the_result(tmp_path):
    rows = t72_rows() + link_rows_in_window()
    a = scan(tmp_path, copy.deepcopy(rows))
    b = scan(tmp_path, list(reversed(copy.deepcopy(rows))))
    assert [r["event_uids"] for r in a.link_rows] == [r["event_uids"] for r in b.link_rows]
    assert a.link_near_duplicate_groups == b.link_near_duplicate_groups
    assert [r["event_uid"] for r in a.in_window] == [r["event_uid"] for r in b.in_window]


def test_t72_kinds_never_land_in_link_rows(tmp_path):
    rows = [at_us(IN, f"T{i}", ch, eid) for i, (ch, eid) in enumerate(T72_KINDS)]
    res = scan(tmp_path, rows)
    assert res.link_rows == []


def test_other_kinds_are_in_no_list(tmp_path):
    rows = [at_us(IN, f"O{i}", ch, eid) for i, (ch, eid) in enumerate(OTHER_KINDS)]
    res = scan(tmp_path, rows)
    assert res.link_rows == [] and res.in_window == [] and res.lookback == []
    assert res.loaded_total == len(rows)


# ================================================================================================ load_scan / load_link_inputs
def logon_rows() -> list[dict]:
    return [sf.logon("E0", 1.0, 1000), sf.ev("SH1", "Security", 5145, off=2.0, subject_logon_id=1000,
                                              relative_target_name="Xpay.exe", share_name="\\\\*\\C$"),
            sf.ev("W91", "WinRM", 91, off=3.0)]


def test_load_scan_still_returns_three_values(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    out = load_scan(check_allowed(fr.paths), fr.paths)
    assert len(out) == 3
    res, before, after = out
    assert before == after == fr.stats["db"]["sha256_after"]
    assert uids(res.in_window) == {"E0"} and uids(res.link_rows) == {"SH1", "W91"}


def test_load_scan_and_load_link_inputs_give_the_same_scan(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    checked = check_allowed(fr.paths)
    plain, b1, a1 = load_scan(checked, fr.paths)
    scan2, extra_value, b2, a2 = load_link_inputs(checked, fr.paths, lambda con, s: "marker")
    assert extra_value == "marker"
    assert (b1, a1) == (b2, a2)
    assert plain.in_window == scan2.in_window and plain.link_rows == scan2.link_rows
    assert plain.removed_by_window == scan2.removed_by_window and plain.loaded_total == scan2.loaded_total


def test_load_link_inputs_returns_four_values_and_hashes_match_the_gate(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    out = load_link_inputs(check_allowed(fr.paths), fr.paths, lambda con, s: len(s.link_rows))
    assert len(out) == 4
    _, value, before, after = out
    assert value == 2
    assert before == after == sf.sha256_of(fr.paths.db) == fr.stats["db"]["sha256_after"]


def test_extra_runs_once_on_an_open_connection_with_the_scan(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    calls: list = []

    def extra(con, s):
        calls.append(1)
        n = con.execute("SELECT COUNT(*) FROM events_dedup").fetchone()[0]
        return n, uids(s.link_rows), con

    _, (n, link_uids, con), _, _ = load_link_inputs(check_allowed(fr.paths), fr.paths, extra)
    assert calls == [1]
    assert n == 3 and link_uids == {"SH1", "W91"}
    with pytest.raises(sqlite3.ProgrammingError):          # the connection is closed after the bracket
        con.execute("SELECT 1")


def test_a_write_through_the_extra_connection_raises_and_the_db_is_unchanged(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    snap = sf.snapshot(fr.repo)

    def extra(con, s):
        for stmt in ("CREATE TABLE written_by_test (a)", "DELETE FROM events_dedup",
                     "INSERT INTO events_dedup (event_uid) VALUES ('X')", "UPDATE events_dedup SET host = 'x'"):
            with pytest.raises(sqlite3.OperationalError):
                con.execute(stmt)
        return "done"

    _, value, before, after = load_link_inputs(check_allowed(fr.paths), fr.paths, extra)
    assert value == "done" and before == after == fr.stats["db"]["sha256_after"]
    assert sf.snapshot(fr.repo) == snap


def test_extra_can_read_command_results_for_in_window_uids_inside_the_bracket(tmp_path):
    rows = [sf.logon("E0", 1.0, 1000),
            sf.ev("P1", "Sysmon", 1, host="ep-01", off=2.0, process_guid="{g}", process_id=4, session_id=1000,
                  command_line="psexec \\\\ep-02 -s cmd"),
            sf.ev("P2", "Sysmon", 1, host="ep-01", off=3.0, process_guid="{h}", process_id=5, session_id=1000,
                  command_line="notepad"),
            sf.ev("PRE1", "Sysmon", 1, host="ep-01", off=-4000.0, process_guid="{i}", process_id=6, session_id=1000,
                  command_line="psexec \\\\ep-02 -s cmd")]
    fr = sf.make_repo(tmp_path, rows)
    forms = target_name_forms("ep-02", "192.168.50.2")

    def extra(con, s):
        want = {"ep-01": [u for r in s.in_window if r["channel"] == "Sysmon" and r["event_id"] == 1
                          for u in r["event_uids"]]}
        return read_command_results(con, want, {"ep-01": [("ep-02", forms)]})

    scan_res, results, before, after = load_link_inputs(check_allowed(fr.paths), fr.paths, extra)
    assert before == after
    assert sorted(results) == ["P1", "P2"]                     # the pre-window process is not an in-window uid
    assert results["P1"].targets == (("ep-02", "host_name", "plain"),) and results["P2"].targets == ()
    assert "PRE1" not in uids(scan_res.in_window)


def test_an_sqlite_error_inside_extra_is_a_stitch_error(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())

    def extra(con, s):
        con.execute("SELECT no_such_column FROM events_dedup")

    with pytest.raises(StitchError):
        load_link_inputs(check_allowed(fr.paths), fr.paths, extra)


def test_load_link_inputs_refuses_like_load_scan_and_never_calls_extra(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows(), stats_db_sha_after="0" * 64)
    checked = check_allowed(fr.paths)
    called: list = []
    with pytest.raises(StitchError):
        load_link_inputs(checked, fr.paths, lambda con, s: called.append(1))
    assert called == []


def test_load_link_inputs_refuses_a_view_missing_a_spec_column(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows(), drop_columns=["share_name"])
    checked = check_allowed(fr.paths)
    called: list = []
    with pytest.raises(StitchError) as exc:
        load_link_inputs(checked, fr.paths, lambda con, s: called.append(1))
    assert "share_name" in str(exc.value) and called == []


def test_load_link_inputs_refuses_a_missing_db(tmp_path):
    fr = sf.make_repo(tmp_path, logon_rows())
    checked = check_allowed(fr.paths)
    fr.paths.db.unlink()
    with pytest.raises(StitchError):
        load_link_inputs(checked, fr.paths, lambda con, s: None)


def test_scan_result_never_carries_command_text_even_with_link_rows(tmp_path):
    rows = logon_rows() + [sf.ev("S4648", "Security", 4648, off=4.0, command_line=sf.PLACEHOLDER_COMMAND,
                                 field_values_json='{"TargetServerName": "' + sf.PLACEHOLDER_COMMAND + '"}')]
    fr = sf.make_repo(tmp_path, rows)
    res, _, _ = load_scan(check_allowed(fr.paths), fr.paths)
    assert "S4648" in uids(res.link_rows)
    assert sf.PLACEHOLDER_COMMAND not in repr(res) and "PLACEHOLDER-COMMAND" not in repr(res)
