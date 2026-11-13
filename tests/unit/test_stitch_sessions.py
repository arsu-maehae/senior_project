"""Tests for T7.2 task 3: sessions per host, boot epochs and the session-state query (spec 03_stitch ST-10 as amended
by decision 047, ST-63 session-state part, ST-01 / decision 039 views, STT-11). Fast, synthetic rows only.

Written from the spec, decision 047 (with the 2026-11-14 amendment under item 3) and plan section 3, not from the
implementation. The code was read only for callable names and signatures. Rows are built raw and passed through
`stitch.scan.scan_rows` with a window, so in-window and look-back rows are what the real run keeps. T = 0 is
10:30:00 on 2026-09-24; the window is 10:00-11:00, so a time below -1800 s is before the window.
"""
from __future__ import annotations

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
from stitch.params import StitchParams  # noqa: E402
from stitch.scan import scan_rows  # noqa: E402
from stitch.sessions import (boot_boundaries, boot_groups, build_sessions, epoch_of, group_boundaries,  # noqa: E402
                             hex_id, logon_id_int, state_at, window_open)

START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
BOOT_S = StitchParams().boot_group_s
H = "ep-02"
PRE = -2000.0          # seconds from T0: before the window start (T0 - 1800 s)


def U(t: float) -> int:
    """Logged instant (us) of `t` seconds after T0, the value `us_raw` takes."""
    return to_us(sf.at(t))


# ------------------------------------------------------------------------------------------------ row builders
def L(uid, t, lid, *, host=H, ltype=3, account="acct_a", **kw) -> dict:
    return sf.ev(uid, "Security", 4624, host=host, off=t, logon_type=ltype, target_logon_id=lid,
                 account_name=account, **kw)


def C(uid, t, lid, eid=4634, *, host=H, **kw) -> dict:
    return sf.ev(uid, "Security", eid, host=host, off=t, target_logon_id=lid, **kw)


def B(uid, t, eid, *, host=H) -> dict:
    return sf.ev(uid, "System", eid, host=host, off=t)


def X(uid, t, *, host=H) -> dict:
    return sf.ev(uid, "Security", 1102, host=host, off=t)


def kept(tmp_path: Path, rows: list[dict], spec: dict | None = None) -> list[dict]:
    """The rows `scan_rows` keeps (in-window + look-back) for a synthetic trial window."""
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, sf.TRIAL, "0" * 64, spec, None)
    offsets = load_offsets(cf.offsets_path(repo, sf.TRIAL))
    changes = load_clock_changes(cf.changes_path(repo, sf.TRIAL))
    res = scan_rows(rows, START_US, END_US, offsets, changes)
    return res.in_window + res.lookback


def build(tmp_path: Path, rows: list[dict], spec: dict | None = None):
    return build_sessions(kept(tmp_path, rows, spec))


def key(lid: int, epoch: int = 0, seq: int = 0, host: str = H) -> tuple:
    return (host, lid, epoch, seq)


# ================================================================================================ 1. open / close
def test_open_then_4634_is_closed(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000), C("K", 20, 1000, 4634)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4634" and s.close_uids == ["K"] and s.close_us_raw == U(20)
    assert s.open_uids == ["O"] and s.open_us_raw == U(10) and s.open_known
    assert state_at(s, U(30)) == "closed" and state_at(s, U(15)) == "open"


def test_4647_alone_closes_the_session_by_target_logon_id(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000), C("K", 20, 1000, 4647)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4647" and s.close_uids == ["K"]
    assert state_at(s, U(21)) == "closed"


def test_4647_then_4634_first_is_the_kind_and_both_uids_are_kept(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000), C("K47", 20, 1000, 4647), C("K34", 21, 1000, 4634)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4647" and s.close_us_raw == U(20)
    assert sorted(s.close_uids) == ["K34", "K47"]


def test_4634_then_4647_first_is_the_kind(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000), C("K34", 20, 1000, 4634), C("K47", 21, 1000, 4647)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4634" and sorted(s.close_uids) == ["K34", "K47"]


def test_no_logoff_and_no_boot_is_close_kind_none_and_open(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "none" and s.close_uids == [] and s.close_us_raw is None
    assert state_at(s, U(100000)) == "open"


def test_close_at_the_same_instant_as_the_open_closes_it(tmp_path):
    """ST-10: closed by a 4634/4647 at or after the open."""
    idx = build(tmp_path, [L("O", 10, 1000), C("K", 10, 1000, 4634)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4634" and idx.counts["closes_without_open"] == 0


def test_close_before_its_open_is_ignored_and_counted(tmp_path):
    idx = build(tmp_path, [C("K", 5, 1000, 4634), L("O", 10, 1000)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "none" and s.close_uids == []
    assert idx.counts["closes_without_open"] == 1
    assert len(idx.sessions) == 1                 # the close alone makes no session


def test_close_with_no_open_makes_no_session(tmp_path):
    idx = build(tmp_path, [C("K", 5, 7777, 4647)])
    assert idx.sessions == {} and idx.counts["closes_without_open"] == 1


def test_close_in_another_epoch_does_not_close_the_session(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000), B("S", 100, 1074), C("K", 200, 1000, 4634)])
    s = idx.sessions[key(1000, 0)]
    assert s.close_kind == "boot" and s.close_us_raw == U(100) and s.close_uids == ["S"]
    assert idx.counts["closes_without_open"] == 1          # the 4634 in epoch 1 has no open in epoch 1


# ================================================================================================ 2. boot groups
@pytest.mark.parametrize("eid", [41, 6005, 6008, 1074, 6006])
def test_each_boot_id_alone_is_one_boundary_and_closes_an_open_session(tmp_path, eid):
    rows = kept(tmp_path, [L("O", 10, 1000), B("B", 100, eid)])
    assert boot_boundaries([r for r in rows if r["channel"] == "System"], BOOT_S) == {H: [U(100)]}
    s = build_sessions(rows).sessions[key(1000)]
    assert s.close_kind == "boot" and s.close_us_raw == U(100) and s.close_uids == ["B"]
    assert state_at(s, U(99)) == "open" and state_at(s, U(100)) == "closed"


def test_boot_boundaries_are_per_host(tmp_path):
    rows = kept(tmp_path, [B("A", 100, 6005, host="ep-01"), B("B", 300, 1074, host="ep-02")])
    assert boot_boundaries(rows, BOOT_S) == {"ep-01": [U(100)], "ep-02": [U(300)]}


def test_41_then_6005_40s_later_is_one_boundary_at_the_41_and_a_session_between_stays_open(tmp_path):
    rows = kept(tmp_path, [L("PRE", -10, 900), B("E41", 0, 41), L("MID", 20, 1000), B("E6005", 40, 6005)])
    assert boot_boundaries(rows, BOOT_S) == {H: [U(0)]}
    idx = build_sessions(rows)
    mid = idx.sessions[key(1000, 1)]
    assert mid.epoch == 1 and mid.close_kind == "none"
    assert state_at(mid, U(60)) == "open" and state_at(mid, U(100000)) == "open"      # STT-11
    pre = idx.sessions[key(900, 0)]
    assert pre.close_kind == "boot" and pre.close_us_raw == U(0) and pre.close_uids == ["E41"]


def test_startup_events_exactly_120s_apart_are_one_group_and_121s_apart_are_two(tmp_path):
    one = kept(tmp_path / "a", [B("A", 0, 6005), B("B", 120, 6008)])
    assert boot_boundaries(one, BOOT_S) == {H: [U(0)]}
    two = kept(tmp_path / "b", [B("A", 0, 6005), B("B", 121, 6008)])
    assert boot_boundaries(two, BOOT_S) == {H: [U(0), U(121)]}


def test_three_startup_events_chain_into_one_group_when_each_gap_is_within_120s(tmp_path):
    rows = kept(tmp_path, [B("A", 0, 41), B("B", 100, 6005), B("C", 200, 6008)])
    groups = boot_groups(rows, BOOT_S)
    assert [len(g[1]) for g in groups] == [3]
    assert boot_boundaries(rows, BOOT_S) == {H: [U(0)]}


def test_clean_restart_has_one_boundary_at_the_last_shutdown_event(tmp_path):
    """1074, 6006 30 s later, 6005 60 s after that: ONE boundary, at the 6006 (047 amendment)."""
    rows = kept(tmp_path, [L("OLD", -100, 900), B("S1074", 0, 1074), B("S6006", 30, 6006), L("NEW", 87, 1000),
                           B("U6005", 90, 6005)])
    assert boot_boundaries(rows, BOOT_S) == {H: [U(30)]}
    idx = build_sessions(rows)
    old = idx.sessions[key(900, 0)]
    assert old.close_kind == "boot" and old.close_us_raw == U(30) and old.close_uids == ["S6006"]
    new = idx.sessions[key(1000, 1)]               # 3 s before the 6005: the new boot's epoch
    assert new.epoch == 1 and new.close_kind == "none"
    assert state_at(new, U(200)) == "open"
    assert epoch_of(H, U(30), idx.boundaries) == 1 and epoch_of(H, U(29), idx.boundaries) == 0


def test_a_session_opened_between_1074_and_6006_is_still_old_epoch_and_closes_at_the_6006(tmp_path):
    rows = kept(tmp_path, [B("S1074", 0, 1074), L("MID", 10, 1000), B("S6006", 30, 6006), B("U6005", 90, 6005)])
    s = build_sessions(rows).sessions[key(1000, 0)]
    assert s.close_kind == "boot" and s.close_us_raw == U(30)


def test_a_change_of_kind_always_starts_a_new_group(tmp_path):
    rows = kept(tmp_path, [B("A", 0, 6005), B("B", 20, 1074)])           # 20 s apart, different kinds
    groups = boot_groups(rows, BOOT_S)
    assert [len(g[1]) for g in groups] == [1, 1]
    assert [u for _, u in group_boundaries(groups)] == [["A"], ["B"]]


def test_startup_after_startup_is_a_dirty_boot_with_its_own_boundary_at_its_first_event(tmp_path):
    rows = kept(tmp_path, [B("A", 0, 6005), B("B", 500, 41), B("C", 520, 6005)])
    assert boot_boundaries(rows, BOOT_S) == {H: [U(0), U(500)]}


def test_final_shutdown_group_has_a_boundary_at_its_last_event(tmp_path):
    rows = kept(tmp_path, [L("O", 10, 1000), B("A", 100, 1074), B("B", 130, 6006)])
    assert boot_boundaries(rows, BOOT_S) == {H: [U(130)]}
    s = build_sessions(rows).sessions[key(1000)]
    assert s.close_kind == "boot" and s.close_us_raw == U(130) and s.close_uids == ["B"]


def test_startup_group_not_preceded_by_shutdown_group_is_at_its_first_event(tmp_path):
    rows = kept(tmp_path, [B("A", 0, 41), B("B", 30, 6005)])
    assert [u for _, u in group_boundaries(boot_groups(rows, BOOT_S))] == [["A"]]


def test_epoch_of_counts_boundaries_at_or_before_the_instant():
    b = {H: [100, 200]}
    assert epoch_of(H, 99, b) == 0 and epoch_of(H, 100, b) == 1
    assert epoch_of(H, 199, b) == 1 and epoch_of(H, 200, b) == 2 and epoch_of(H, 10**12, b) == 2
    assert epoch_of("ep-01", 150, b) == 0                   # a host with no boundary


def test_same_logon_id_after_a_boundary_is_a_different_session(tmp_path):
    idx = build(tmp_path, [L("O1", 10, 1000), B("S", 100, 1074), L("O2", 200, 1000)])
    a, b = idx.sessions[key(1000, 0)], idx.sessions[key(1000, 1)]
    assert a is not b and a.epoch == 0 and b.epoch == 1
    assert a.close_kind == "boot" and b.close_kind == "none"
    assert a.open_uids == ["O1"] and b.open_uids == ["O2"]


def test_a_look_back_boot_counts_for_the_epoch_of_an_in_window_logon(tmp_path):
    idx = build(tmp_path, [B("S", PRE, 1074), L("O", 10, 1000)])
    assert idx.sessions[key(1000, 1)].epoch == 1


# ================================================================================================ 3. repeated opens
def test_second_4624_while_open_joins_the_same_session(tmp_path):
    idx = build(tmp_path, [L("O1", 10, 999, ltype=5), L("O2", 20, 999, ltype=5)])
    assert list(idx.sessions) == [key(999)]
    assert sorted(idx.sessions[key(999)].open_uids) == ["O1", "O2"]
    assert idx.sessions[key(999)].open_us_raw == U(10)
    assert idx.counts["duplicate_open"] == 1


def test_4624_after_a_close_in_the_same_epoch_is_seq_1(tmp_path):
    idx = build(tmp_path, [L("O1", 10, 1000), C("K", 20, 1000), L("O2", 30, 1000)])
    assert sorted(idx.sessions) == [key(1000, 0, 0), key(1000, 0, 1)]
    first, second = idx.sessions[key(1000, 0, 0)], idx.sessions[key(1000, 0, 1)]
    assert first.close_kind == "4634" and second.close_kind == "none"
    assert second.open_uids == ["O2"]
    assert idx.counts["reopen_after_close"] == 1 and idx.counts["duplicate_open"] == 0


def test_near_duplicate_4624_gives_one_session_with_both_uids(tmp_path):
    rows = [L("UID-B", 10, 1000, record_id=555), L("UID-A", 10, 1000, record_id=555)]
    idx = build(tmp_path, rows)
    assert list(idx.sessions) == [key(1000)]
    assert sorted(idx.sessions[key(1000)].open_uids) == ["UID-A", "UID-B"]
    assert idx.counts["duplicate_open"] == 0


# ================================================================================================ 4. ids
@pytest.mark.parametrize("lid,system", [(0x3e4, True), (0x3e5, True), (0x3e7, True), (1000, False), (0x3e6, False)])
def test_system_logon_ids_are_flagged(tmp_path, lid, system):
    s = build(tmp_path, [L("O", 10, lid)]).sessions[key(lid)]
    assert s.is_system is system


def test_hex_text_and_integer_are_the_same_key(tmp_path):
    assert logon_id_int("0x3e7") == logon_id_int(999) == logon_id_int("0X3E7") == logon_id_int(" 999 ") == 999
    idx = build(tmp_path, [L("O1", 10, "0x3e7"), C("K", 20, 999)])
    assert list(idx.sessions) == [key(999)]
    assert idx.sessions[key(999)].close_kind == "4634"
    assert idx.session_at(H, "0x3e7", U(15)) is idx.session_at(H, 999, U(15)) is idx.sessions[key(999)]


def test_logon_id_hex_is_lower_case_with_0x(tmp_path):
    assert hex_id(999) == "0x3e7" and hex_id(0xABC) == "0xabc" and hex_id(0) == "0x0"
    s = build(tmp_path, [L("O", 10, 0xABC)]).sessions[key(0xABC)]
    assert s.logon_id == 0xABC and s.logon_id_hex == "0xabc"


@pytest.mark.parametrize("value", [None, "", "  ", "zz", True])
def test_logon_id_int_returns_none_for_null_like_values(value):
    assert logon_id_int(value) is None


def test_null_logon_id_forms_no_session_and_matches_nothing(tmp_path):
    idx = build(tmp_path, [L("O", 10, None), C("K", 20, None), L("O2", 11, 1000)])
    assert list(idx.sessions) == [key(1000)]
    assert idx.sessions[key(1000)].close_kind == "none"          # the NULL close did not match it
    assert idx.session_at(H, None, U(15)) is None


def test_target_linked_logon_id_is_never_a_key(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000, target_linked_logon_id=2000)])
    assert list(idx.sessions) == [key(1000)]
    assert idx.session_at(H, 2000, U(15)) is None


def test_a_close_naming_only_the_linked_id_does_not_close(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000, target_linked_logon_id=2000), C("K", 20, 2000)])
    assert idx.sessions[key(1000)].close_kind == "none"


def test_session_fields_from_the_opening_4624(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000, ltype=10, account="acct_z", machine_account=1)]).sessions[key(1000)]
    assert (s.host, s.logon_type, s.account, s.machine_account) == (H, 10, "acct_z", 1)
    assert s.key == key(1000) and s.seq == 0 and s.epoch == 0 and s.clock_unreliable == 0
    assert s.open_us_raw == U(10) and s.open_us == U(10)


def test_session_at_returns_the_session_open_at_the_instant(tmp_path):
    idx = build(tmp_path, [L("O1", 10, 1000), C("K", 20, 1000), L("O2", 30, 1000), B("S", 100, 1074)])
    assert idx.session_at(H, 1000, U(5)) is None
    assert idx.session_at(H, 1000, U(15)) is idx.sessions[key(1000, 0, 0)]
    assert idx.session_at(H, 1000, U(35)) is idx.sessions[key(1000, 0, 1)]
    assert idx.session_at(H, 1000, U(150)) is None            # epoch 1: no open
    assert idx.session_at("ep-01", 1000, U(15)) is None        # other host


# ================================================================================================ 5. state_at
def test_state_before_the_open_is_not_open(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000)]).sessions[key(1000)]
    assert state_at(s, U(9)) == "not_open" and state_at(s, U(10)) == "open"


def test_1102_between_open_and_t_is_end_unknown(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000), X("X", 20)]).sessions[key(1000)]
    assert state_at(s, U(15)) == "open"
    assert state_at(s, U(20)) == "end_unknown" and state_at(s, U(30)) == "end_unknown"


def test_1102_before_the_open_does_not_make_end_unknown(tmp_path):
    s = build(tmp_path, [X("X", 5), L("O", 10, 1000)]).sessions[key(1000)]
    assert state_at(s, U(30)) == "open"


def test_close_before_t_is_closed_even_with_a_1102_in_between(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000), X("X", 15), C("K", 20, 1000)]).sessions[key(1000)]
    assert state_at(s, U(30)) == "closed"
    assert state_at(s, U(17)) == "end_unknown"                # before the close, after the clear


def test_1102_after_the_close_is_closed(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000), C("K", 20, 1000), X("X", 25)]).sessions[key(1000)]
    assert state_at(s, U(30)) == "closed"


def test_instant_in_an_earlier_epoch_is_not_open(tmp_path):
    idx = build(tmp_path, [B("S", 100, 1074), L("O", 150, 1000)])
    s = idx.sessions[key(1000, 1)]
    assert state_at(s, U(50)) == "not_open" and state_at(s, U(99)) == "not_open"
    assert state_at(s, U(150)) == "open"


def test_instant_after_a_boundary_is_closed(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000), B("S", 100, 1074)]).sessions[key(1000)]
    assert state_at(s, U(99)) == "open" and state_at(s, U(100)) == "closed" and state_at(s, U(500)) == "closed"


def test_boundary_closes_even_with_a_1102_before_it(tmp_path):
    s = build(tmp_path, [L("O", 10, 1000), X("X", 20), B("S", 100, 1074)]).sessions[key(1000)]
    assert state_at(s, U(50)) == "end_unknown" and state_at(s, U(150)) == "closed"


# ================================================================================================ 6. views (ST-01, 039)
def test_look_back_open_is_in_lookback_view_only(tmp_path):
    idx = build(tmp_path, [L("PRE", PRE, 1000)])
    s = idx.sessions[key(1000)]
    assert s.opened_before_window is True
    assert s in idx.lookback_view() and s not in idx.window_view()
    assert state_at(s, U(10)) == "open"                      # still usable for identity


def test_marking_a_look_back_session_referenced_puts_it_in_window_view_with_no_open_fields(tmp_path):
    idx = build(tmp_path, [L("PRE", PRE, 1000, account="acct_pre")])
    s = idx.sessions[key(1000)]
    idx.mark_referenced(s.key)
    assert s in idx.window_view() and s in idx.lookback_view()
    assert window_open(s) == ([], None, None)               # its pre-window 4624 never reaches a link row
    assert s.key == key(1000)


def test_mark_referenced_unknown_key_raises_keyerror(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000)])
    with pytest.raises(KeyError):
        idx.mark_referenced(key(4242))


def test_in_window_open_gives_window_open_fields_and_is_in_window_view(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000, ltype=10, account="acct_a")])
    s = idx.sessions[key(1000)]
    assert s.opened_before_window is False and s in idx.window_view()
    assert window_open(s) == (["O"], "acct_a", 10)


def test_ensure_unknown_makes_an_open_known_false_session_in_window_view(tmp_path):
    idx = build(tmp_path, [L("O", 10, 1000)])
    s = idx.ensure_unknown(H, 4242, U(50))
    assert s.open_known is False and s.logon_id == 4242 and s.logon_id_hex == "0x1092"
    assert s.open_uids == [] and s.open_us_raw is None
    assert idx.sessions[s.key] is s and s in idx.window_view() and s in idx.lookback_view()
    assert window_open(s) == ([], None, None)
    assert idx.ensure_unknown(H, "0x1092", U(60)) is s        # the same ID in the same epoch: the same session


def test_unknown_open_session_closes_like_a_known_one(tmp_path):
    idx = build(tmp_path, [C("K", 100, 4242, 4634)])
    s = idx.ensure_unknown(H, 4242, U(50))
    assert s.close_kind == "4634" and s.close_us_raw == U(100)
    s2 = idx.ensure_unknown(H, 5555, U(50))
    assert s2.close_kind == "none"


def test_unknown_open_state_before_its_epoch_start_is_not_open(tmp_path):
    idx = build(tmp_path, [B("S", 100, 1074)])
    s = idx.ensure_unknown(H, 4242, U(150))
    assert s.epoch == 1 and state_at(s, U(50)) == "not_open" and state_at(s, U(200)) == "open"


def test_a_pre_window_session_closed_before_the_window_is_closed_in_the_look_back_view(tmp_path):
    idx = build(tmp_path, [L("PRE", PRE, 1000), C("K", PRE + 50, 1000)])
    s = idx.sessions[key(1000)]
    assert s.close_kind == "4634" and state_at(s, U(10)) == "closed"
    assert s not in idx.window_view()


def test_look_back_logon_id_reused_after_a_pre_window_boot_is_a_separate_session(tmp_path):
    idx = build(tmp_path, [L("OLD", PRE, 1000), B("S", PRE + 100, 1074), L("NEW", 10, 1000)])
    old, new = idx.sessions[key(1000, 0)], idx.sessions[key(1000, 1)]
    assert old.close_kind == "boot" and state_at(old, U(10)) == "closed"
    assert state_at(new, U(10)) == "open" and new in idx.window_view() and old not in idx.window_view()


# ================================================================================================ 7. counts
def test_counts_agree_with_a_hand_count(tmp_path):
    rows = [
        L("A", 10, 1000), C("A-K", 20, 1000, 4634),                       # closed 4634
        L("B", 11, 1001), C("B-K", 21, 1001, 4647),                       # closed 4647
        L("C", 12, 1002),                                                 # closed by the boot at 300
        L("E1", 13, 999, ltype=5), L("E2", 14, 999, ltype=5),             # system, duplicate open
        L("F", 30, 1000),                                                 # re-open after A closed
        L("G", PRE, 1005),                                                # opened before the window
        C("Z-K", 5, 7777),                                                # close with no open
        B("S", 300, 1074),                                                # boundary of ep-02
        L("D", 400, 1003),                                                # epoch 1, no close
        L("H", 15, 2000, host="ep-01"),                                   # other host, no boundary
    ]
    idx = build(tmp_path, rows)
    idx.ensure_unknown(H, 5555, U(40))                                    # an unknown open
    c = idx.counts
    assert c["per_host"] == {"ep-01": 1, "ep-02": 8}
    assert c["open_in_window"] == 7
    assert c["opened_before_window"] == 1
    assert c["open_unknown"] == 1
    assert c["system"] == 1
    assert c["close_kind"] == {"4634": 1, "4647": 1, "boot": 5, "none": 2}
    assert c["duplicate_open"] == 1
    assert c["reopen_after_close"] == 1
    assert c["closes_without_open"] == 1
    assert sum(c["close_kind"].values()) == len(idx.sessions) == 9


# ================================================================================================ 8. same-host order
def _summary(idx):
    out = {}
    for k, s in sorted(idx.sessions.items()):
        probes = (U(-50), U(15), U(25), U(45), U(95), U(110), U(500))
        out[k] = (s.close_kind, s.close_us_raw, sorted(s.open_uids), sorted(s.close_uids), s.open_us_raw,
                  s.opened_before_window, s.epoch, [state_at(s, t) for t in probes])
    return out


def test_a_large_host_offset_gives_the_same_sessions_and_states_as_offset_zero(tmp_path):
    rows = [L("A", 10, 1000), C("A-K", 20, 1000), L("A2", 30, 1000), L("B", 12, 1001), X("X", 40),
            L("E1", 13, 999, ltype=5), L("E2", 14, 999, ltype=5), B("S", 100, 1074), L("N", 150, 1000),
            L("PRE", PRE, 1005), C("PRE-K", PRE + 10, 1005)]
    base = build(tmp_path / "zero", [dict(r) for r in rows], cf.offsets_spec(ep_02=(0, "ok", True)))
    shifted = build(tmp_path / "plus60", [dict(r) for r in rows], cf.offsets_spec(ep_02=(60000, "ok", True)))
    assert _summary(base) == _summary(shifted)
    assert base.boundaries == shifted.boundaries
    for k, s in shifted.sessions.items():
        if s.open_us_raw is not None:
            assert s.open_us == s.open_us_raw - 60_000_000      # open_us is the corrected time; order uses raw
            assert base.sessions[k].open_us == base.sessions[k].open_us_raw
