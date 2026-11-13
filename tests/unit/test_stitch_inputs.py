"""Tests for T7.2 task 2: stitcher input refusals (ST-00), the development allowlist (decision 046) and the
read-only event scan (ST-01, ST-02, ST-05). Fast, synthetic data in `tmp_path` only.

Written from docs/specs/03_stitch.md (sections 2, 4 ST-00/01/02/05, 5), the T7.2 plan (sections 2, 3, 5) and
decisions 046 and 047, not from the implementation. The code was read only for callable names and signatures.
The real data/processed, out/gate and ground_truth are never opened.
"""
from __future__ import annotations

import builtins
import contextlib
import dataclasses
import os
import pathlib
import re
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
from answer_key.db import open_ro  # noqa: E402
from clock_offset import params as co_params  # noqa: E402
from clock_offset.correct import load_clock_changes, load_offsets  # noqa: E402
from gate.inputs import scan_events as gate_scan_events  # noqa: E402
from gate.params import GateParams  # noqa: E402
from gate.timeutil import to_us  # noqa: E402
from stitch import params as sp  # noqa: E402
from stitch.inputs import StitchError, check_allowed, load_scan, trial_paths  # noqa: E402
from stitch.scan import in_window, scan_rows  # noqa: E402

SRC_STITCH = REPO / "src" / "stitch"
START_US = to_us(sf.WIN_START)
END_US = to_us(sf.WIN_END)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Spec 03 section 2, literal copy of "Columns used from events_dedup".
SPEC_COLUMNS_LITERAL = (
    "event_uid, host, channel, event_id, record_id, event_utc, logon_type, source_ip, source_port, destination_ip, "
    "destination_port, destination_host, initiated, account_name, subject_account, target_logon_id, "
    "target_linked_logon_id, subject_logon_id, session_id, logon_guid, authentication_package, image, parent_image, "
    "command_line, process_guid, parent_process_guid, process_id, share_name, relative_target_name, service_name, "
    "service_image_path, source_image, target_image, granted_access, machine_account, field_values_json"
).split(", ")


# ------------------------------------------------------------------------------------------------ helpers
def utc_of(us: int) -> str:
    """DB-style time text for an integer microsecond instant (no float arithmetic)."""
    return sf.iso6(EPOCH + timedelta(microseconds=us))


def at_us(us: int, uid: str, channel: str = "Security", event_id: int = 4624, *, host: str = "ep-02", **kw) -> dict:
    return sf.ev(uid, channel, event_id, host=host, utc=utc_of(us), **kw)


def clock(tmp_path: Path, spec: dict | None = None, changes: list | None = None):
    """(offsets, changes) loaded from synthetic clock files written under tmp_path/clk."""
    repo = tmp_path / "clk"
    cf.write_clock_files(repo, sf.TRIAL, "0" * 64, spec, changes)
    return load_offsets(cf.offsets_path(repo, sf.TRIAL)), load_clock_changes(cf.changes_path(repo, sf.TRIAL))


def scan(tmp_path: Path, rows: list[dict], spec: dict | None = None, changes: list | None = None):
    offsets, chg = clock(tmp_path, spec, changes)
    return scan_rows(rows, START_US, END_US, offsets, chg)


def uids(rows: list[dict]) -> set[str]:
    return {r["event_uid"] for r in rows}


@contextlib.contextmanager
def watch_fs(root: Path, monkeypatch):
    """Record every filesystem call whose path is under `root`, then delegate (the paths do not exist)."""
    seen: list[str] = []
    needle = str(root)

    def wrap(obj, name):
        orig = getattr(obj, name)

        def inner(*args, **kw):
            try:
                text = str(args[0]) if args else ""
            except Exception:  # noqa: BLE001
                text = ""
            if needle in text:
                seen.append(f"{name}({text})")
            return orig(*args, **kw)
        monkeypatch.setattr(obj, name, inner)

    with monkeypatch.context():
        wrap(builtins, "open")
        for n in ("stat", "lstat", "scandir", "listdir"):
            wrap(os, n)
        for n in ("exists", "isfile", "isdir"):
            wrap(os.path, n)
        for n in ("stat", "exists", "is_file", "is_dir", "open", "read_bytes", "read_text", "mkdir", "iterdir"):
            wrap(pathlib.Path, n)
        wrap(sqlite3, "connect")
        yield seen


# ================================================================================================ 1. allowlist
ALL_TEST_IDS = [f"s{n:02d}_t{m:02d}" for n in range(1, 8) for m in range(2, 11)]


@pytest.mark.parametrize("trial", ALL_TEST_IDS)
def test_decision046_every_t02_to_t10_trial_is_refused_before_any_file_is_opened(tmp_path, monkeypatch, trial):
    """046: the paths point to NOTHING, so any later check would give another message; the refusal must be the
    allowlist. Nothing is created and no path under the tmp dir is touched."""
    before = sf.snapshot(tmp_path)
    paths = trial_paths(tmp_path, trial)
    with watch_fs(tmp_path, monkeypatch) as seen:
        with pytest.raises(StitchError) as exc:
            check_allowed(paths)
    assert "decision 046" in str(exc.value)
    assert seen == []
    assert sf.snapshot(tmp_path) == before == {}


@pytest.mark.parametrize("trial", ["s01_t00", "s04_t01", "s07_t01", "s05q_t00"])
def test_decision046_s01_clock_only_and_quarantined_ids_are_refused_by_the_allowlist(tmp_path, monkeypatch, trial):
    before = sf.snapshot(tmp_path)
    paths = trial_paths(tmp_path, trial)
    with watch_fs(tmp_path, monkeypatch) as seen:
        with pytest.raises(StitchError) as exc:
            check_allowed(paths)
    assert "046" in str(exc.value)
    assert seen == []
    assert sf.snapshot(tmp_path) == before == {}


@pytest.mark.parametrize("trial", ["../x", "s02_t00/..", "..", "s02_t00/../s02_t01", "s02_t00\\..", "", "a b"])
def test_decision046_id_with_path_characters_is_refused(tmp_path, trial):
    before = sf.snapshot(tmp_path)
    with pytest.raises(StitchError):
        check_allowed(trial_paths(tmp_path, trial))
    assert sf.snapshot(tmp_path) == before == {}


def test_decision046_allowlist_is_the_clock_offset_development_list():
    assert tuple(sp.ALLOWED_TRIALS) == tuple(co_params.DEVELOPMENT_TRIALS)
    assert set(sp.ALLOWED_TRIALS) == {"s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00",
                                      "s02_t01", "s03_t01", "s06_t01"}


def test_decision046_no_t02_to_t10_id_is_allowed():
    assert not [t for t in sp.ALLOWED_TRIALS if re.search(r"_t(0[2-9]|10)$", t)]


@pytest.mark.parametrize("trial", sorted(co_params.DEVELOPMENT_TRIALS))
def test_decision046_every_development_trial_passes_the_allowlist_step(tmp_path, trial):
    """The allowlist does not refuse a development id: the synthetic repo for it passes ST-00 completely."""
    fr = sf.make_repo(tmp_path, trial=trial)
    assert check_allowed(fr.paths).trial_id == trial


def test_trial_paths_is_pure_and_names_the_documented_inputs(tmp_path):
    p = trial_paths(tmp_path, "s04_t00")
    assert p.trial_id == "s04_t00" and Path(p.repo) == tmp_path
    assert Path(p.db).name == "s04_t00.sqlite3" and Path(p.db).parent.name == "processed"
    assert Path(p.gate_dir).name == "s04_t00" and Path(p.gate_dir).parent.name == "gate"
    assert Path(p.windows_csv).name == "trial_windows.csv"
    assert Path(p.offsets_csv).name == "s04_t00.clock_offsets.csv"
    assert Path(p.changes_csv).name == "s04_t00.clock_changes.csv"
    assert sf.snapshot(tmp_path) == {}


# ================================================================================================ 2. ST-00
def test_st00_happy_path_passes_and_loads(tmp_path):
    fr = sf.make_repo(tmp_path)
    checked = check_allowed(fr.paths)
    assert checked.trial_id == sf.TRIAL
    assert checked.start_us == START_US and checked.end_us == END_US
    assert checked.gate_stats["time_basis"] == "corrected"
    assert checked.gate_stats_sha256 == sf.sha256_of(fr.stats_path)
    assert {k: str(v).strip() for k, v in checked.window_row.items()} == fr.window_row
    assert checked.clock is not None
    result, before, after = load_scan(checked, fr.paths)
    assert before == after == sf.sha256_of(fr.paths.db) == fr.stats["db"]["sha256_after"]
    assert result.loaded_total == 1


@pytest.mark.parametrize("gate_file", list(sp.GATE_FILES))
def test_st00_each_gate_file_missing_refuses_and_writes_nothing(tmp_path, gate_file):
    fr = sf.make_repo(tmp_path, skip_gate_file=gate_file)
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_gate_files_are_the_five_of_the_spec():
    assert tuple(sp.GATE_FILES) == ("triggers.csv", "unmatched_remote.csv", "supporting.csv", "dispositions.csv",
                                    "stats.json")


def test_st00_time_basis_raw_is_refused(tmp_path):
    fr = sf.make_repo(tmp_path, time_basis="raw")
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


@pytest.mark.parametrize("column,value", [("start_utc", "2026-09-24T09:59:00.000Z"),
                                          ("end_utc", "2026-09-24T11:01:00.000Z"),
                                          ("margin_end_s", "301"), ("rule", "another rule"),
                                          ("window_source", "operator_times"),
                                          ("clock_flag", "ep-02")])
def test_st00_window_row_that_differs_in_one_column_is_refused(tmp_path, column, value):
    fr = sf.make_repo(tmp_path, stats_window_changes={column: value})
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_window_csv_edited_after_the_gate_ran_is_refused(tmp_path):
    """The other direction: stats.json is untouched, the trial_windows.csv row changed afterwards."""
    fr = sf.make_repo(tmp_path)
    sf.write_windows_csv(fr.paths.windows_csv, dict(fr.window_row, end_utc="2026-09-24T11:30:00.000Z"))
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_offsets_sha_mismatch_is_refused(tmp_path):
    fr = sf.make_repo(tmp_path, stats_offsets_sha="0" * 64)
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_clock_changes_sha_mismatch_is_refused(tmp_path):
    fr = sf.make_repo(tmp_path, stats_changes_sha="f" * 64)
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_offsets_file_edited_after_the_gate_ran_is_refused(tmp_path):
    fr = sf.make_repo(tmp_path)
    with open(fr.paths.offsets_csv, "a", encoding="utf-8") as fh:
        fh.write("\n")
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_clock_file_missing_is_refused(tmp_path):
    fr = sf.make_repo(tmp_path)
    fr.paths.changes_csv.unlink()
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        check_allowed(fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_db_sha_different_from_gate_sha256_after_is_refused_by_load_scan(tmp_path):
    fr = sf.make_repo(tmp_path, stats_db_sha_after="0" * 64)
    checked = check_allowed(fr.paths)             # the DB is not hashed by ST-00 itself
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        load_scan(checked, fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_db_changed_after_the_gate_ran_is_refused_by_load_scan(tmp_path):
    fr = sf.make_repo(tmp_path)
    checked = check_allowed(fr.paths)
    sf.write_events_db(fr.paths.db, [sf.logon("E0", 1.0, 1000), sf.logon("E1", 2.0, 1001)])
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError):
        load_scan(checked, fr.paths)
    assert sf.snapshot(fr.repo) == before


def test_st00_missing_db_file_is_refused_by_load_scan(tmp_path):
    fr = sf.make_repo(tmp_path)
    checked = check_allowed(fr.paths)
    fr.paths.db.unlink()
    with pytest.raises(StitchError):
        load_scan(checked, fr.paths)


@pytest.mark.parametrize("as_view", [False, True])
def test_st00_view_lacking_two_spec_columns_is_refused_naming_both(tmp_path, as_view):
    missing = ["share_name", "granted_access"]
    fr = sf.make_repo(tmp_path, drop_columns=missing, as_view=as_view)
    checked = check_allowed(fr.paths)
    before = sf.snapshot(fr.repo)
    with pytest.raises(StitchError) as exc:
        load_scan(checked, fr.paths)
    assert all(c in str(exc.value) for c in missing)
    assert sf.snapshot(fr.repo) == before


def test_st00_every_missing_column_is_named_even_when_unused_by_the_scan(tmp_path):
    """The check is for presence of every section 2 column (the scan selects fewer)."""
    unused = [c for c in sp.SPEC_DB_COLUMNS if c not in sp.SCAN_COLUMNS]
    assert unused, "test needs a spec column the scan does not select"
    fr = sf.make_repo(tmp_path, drop_columns=unused[:2])
    checked = check_allowed(fr.paths)
    with pytest.raises(StitchError) as exc:
        load_scan(checked, fr.paths)
    assert all(c in str(exc.value) for c in unused[:2])


def test_st00_events_dedup_as_a_view_loads(tmp_path):
    fr = sf.make_repo(tmp_path, as_view=True)
    result, before, after = load_scan(check_allowed(fr.paths), fr.paths)
    assert before == after and result.loaded_total == 1


def test_st00_load_scan_leaves_db_bytes_and_repo_unchanged(tmp_path):
    rows = [sf.logon(f"E{i}", float(i), 1000 + i, command_line=sf.PLACEHOLDER_COMMAND) for i in range(5)]
    fr = sf.make_repo(tmp_path, rows)
    checked = check_allowed(fr.paths)
    snap = sf.snapshot(fr.repo)
    result, before, after = load_scan(checked, fr.paths)
    assert before == after == sf.sha256_of(fr.paths.db)
    assert sf.snapshot(fr.repo) == snap
    assert result.loaded_total == 5


def test_st00_db_connection_is_read_only(tmp_path):
    fr = sf.make_repo(tmp_path)
    con = open_ro(fr.paths.db)
    try:
        with pytest.raises(sqlite3.OperationalError):
            con.execute("CREATE TABLE written_by_test (a)")
        with pytest.raises(sqlite3.OperationalError):
            con.execute("DELETE FROM events_dedup")
    finally:
        con.close()
    assert sf.sha256_of(fr.paths.db) == fr.stats["db"]["sha256_after"]


def test_st00_command_text_never_reaches_the_scan_result(tmp_path):
    """Event level only: a DB `command_line` is never selected, so no part of it is in any kept row."""
    rows = [sf.logon("E0", 1.0, 1000, command_line=sf.PLACEHOLDER_COMMAND),
            sf.ev("P1", "Sysmon", 1, off=2.0, process_guid="{g1}", process_id=10, session_id=1000,
                  command_line=sf.PLACEHOLDER_COMMAND, field_values_json='{"k": "' + sf.PLACEHOLDER_COMMAND + '"}')]
    fr = sf.make_repo(tmp_path, rows)
    result, _, _ = load_scan(check_allowed(fr.paths), fr.paths)
    assert uids(result.in_window) == {"E0", "P1"}
    text = repr(result)
    assert sf.PLACEHOLDER_COMMAND not in text and "PLACEHOLDER-COMMAND" not in text
    for r in result.in_window + result.lookback:
        assert "command_line" not in r and "field_values_json" not in r


# ================================================================================================ 3. ST-01
def test_st01_predicate_edges():
    assert not in_window(START_US - 1, START_US, END_US)
    assert in_window(START_US, START_US, END_US)
    assert in_window(END_US, START_US, END_US)
    assert in_window(END_US + 999, START_US, END_US)         # end + 1 ms - 1 us is in
    assert not in_window(END_US + 1000, START_US, END_US)    # end + 1 ms is out


def test_st01_event_one_us_before_start_is_out_and_last_us_of_the_end_ms_is_in(tmp_path):
    rows = [at_us(START_US - 1, "BEFORE"), at_us(START_US, "START"), at_us(END_US + 999, "LASTIN"),
            at_us(END_US + 1000, "AFTER")]
    res = scan(tmp_path, rows)
    assert uids(res.in_window) == {"START", "LASTIN"}
    assert "BEFORE" not in uids(res.in_window) and "AFTER" not in uids(res.in_window)
    assert all(r["in_window"] is True or r["in_window"] == 1 for r in res.in_window)


def test_st01_predicate_equals_the_gate_scan_on_the_same_rows(tmp_path):
    """Same in/out answer as gate GT-01 for rows at both edges, with and without an offset (corrected time)."""
    spec = cf.offsets_spec(ep_02=(7000, "ok", True))
    offsets, chg = clock(tmp_path, spec)
    off_us = 7_000_000
    rows = []
    for i, d in enumerate((-1000, -1, 0, 1, 999, 1000, 1001)):
        rows.append(at_us(START_US + d, f"S{i}", host="ep-01"))
        rows.append(at_us(END_US + d, f"E{i}", host="ep-01"))
        rows.append(at_us(START_US + d + off_us, f"OS{i}", host="ep-02"))   # corrected = START + d
        rows.append(at_us(END_US + d + off_us, f"OE{i}", host="ep-02"))
    mine = scan_rows([dict(r) for r in rows], START_US, END_US, offsets, chg)
    gate = gate_scan_events([dict(r) for r in rows], START_US, END_US, GateParams(), offsets)
    assert len(mine.in_window) == gate.in_window_total
    assert uids(mine.in_window) == {r["event_uid"] for r in rows if _gate_in(r, START_US, END_US, offsets)}
    assert {h: dict(c) for h, c in mine.removed_by_window.items()} == \
        {h: dict(c) for h, c in gate.removed_by_window.items()}
    assert mine.loaded_total == gate.loaded_total == len(rows)


def _gate_in(row: dict, start: int, end: int, offsets) -> bool:
    """Independent restatement of GT-01: start <= corrected < end + 1 ms."""
    o = offsets.hosts.get(row["host"])
    shift = 0 if o is None or o.offset_ms is None else o.offset_ms * 1000
    t = to_us(row["event_utc"]) - shift
    return start <= t < end + 1000


def test_st01_pre_window_4624_is_in_lookback_only(tmp_path):
    res = scan(tmp_path, [at_us(START_US - 5_000_000, "PRE4624", target_logon_id=7)])
    assert uids(res.lookback) == {"PRE4624"}
    assert "PRE4624" not in uids(res.in_window)
    assert res.lookback[0]["in_window"] in (False, 0)
    assert res.kept_lookback_by_type == {"Security/4624": 1}


@pytest.mark.parametrize("channel,event_id", [("Security", 4624), ("Security", 4634), ("Security", 4647),
                                              ("Security", 1102), ("System", 41), ("System", 1074),
                                              ("System", 6005), ("System", 6006), ("System", 6008)])
def test_st01_lookback_kinds_before_the_window_are_kept_in_lookback(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(START_US - 1_000_000, "PRE", channel, event_id)])
    assert uids(res.lookback) == {"PRE"} and res.in_window == []
    assert res.kept_lookback_by_type == {f"{channel}/{event_id}": 1}


@pytest.mark.parametrize("channel,event_id", [("Security", 4688), ("Sysmon", 1), ("Sysmon", 3), ("Sysmon", 10),
                                              ("Sysmon", 11)])
def test_st01_pre_window_process_and_sysmon_events_are_in_neither_list_but_counted(tmp_path, channel, event_id):
    """Owner Q13b: never a pre-window Sysmon 1; the others are not look-back kinds either. Only counted."""
    res = scan(tmp_path, [at_us(START_US - 1_000_000, "PRE", channel, event_id)])
    assert res.in_window == [] and res.lookback == []
    assert res.removed_by_window == {"ep-02": {f"{channel}/{event_id}": 1}}
    assert res.loaded_total == 1


def test_st01_pre_window_non_lookback_rows_are_counted_per_host_and_kind(tmp_path):
    rows = [at_us(START_US - 1_000_000, "A", "Security", 4688, host="ep-02"),
            at_us(START_US - 2_000_000, "B", "Sysmon", 1, host="ep-02"),
            at_us(START_US - 3_000_000, "C", "Sysmon", 3, host="ep-02"),
            at_us(START_US - 4_000_000, "D", "Sysmon", 1, host="ep-01"),
            at_us(START_US - 5_000_000, "E", "Sysmon", 1, host="ep-01")]
    res = scan(tmp_path, rows)
    assert res.removed_by_window == {"ep-02": {"Security/4688": 1, "Sysmon/1": 1, "Sysmon/3": 1},
                                     "ep-01": {"Sysmon/1": 2}}


@pytest.mark.parametrize("channel,event_id", [("Security", 4624), ("Security", 4634), ("System", 6005),
                                              ("Security", 1102), ("Sysmon", 1), ("Security", 4688)])
def test_st01_post_window_events_are_in_neither_list(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(END_US + 5_000_000, "POST", channel, event_id)])
    assert res.in_window == [] and res.lookback == []
    assert res.loaded_total == 1


@pytest.mark.parametrize("channel,event_id", [("Security", 4624), ("Security", 4634), ("Security", 4647),
                                              ("Security", 4688), ("Security", 1102), ("Sysmon", 1),
                                              ("Sysmon", 3), ("Sysmon", 10), ("Sysmon", 11), ("System", 41),
                                              ("System", 1074), ("System", 6005), ("System", 6006),
                                              ("System", 6008)])
def test_st01_in_window_kinds_are_kept(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(START_US + 10_000_000, "IN", channel, event_id)])
    assert uids(res.in_window) == {"IN"} and res.lookback == []


@pytest.mark.parametrize("channel,event_id", [("Security", 4672), ("Sysmon", 5), ("Sysmon", 7)])
def test_st01_other_kinds_are_not_kept_by_t72(tmp_path, channel, event_id):
    res = scan(tmp_path, [at_us(START_US + 10_000_000, "IN", channel, event_id)])
    assert res.in_window == [] and res.lookback == []
    assert res.loaded_total == 1


def test_st01_same_event_id_in_another_channel_is_not_a_boot_or_logon(tmp_path):
    """Event ids collide across channels (Sysmon 1 vs System 1; Security 41-like ids): kinds need the channel."""
    rows = [at_us(START_US - 1_000_000, "SYS1", "System", 1), at_us(START_US - 1_000_000, "APP41", "Application", 41),
            at_us(START_US - 1_000_000, "SYSMON4624", "Sysmon", 4624)]
    res = scan(tmp_path, rows)
    assert res.lookback == [] and res.in_window == []


def test_st01_no_row_is_lost_or_duplicated_between_the_lists(tmp_path):
    rows = [at_us(START_US - 1_000_000, "PRE-L", "Security", 4624),
            at_us(START_US - 1_000_000, "PRE-P", "Sysmon", 1),
            at_us(START_US + 1_000_000, "IN-L", "Security", 4624),
            at_us(START_US + 2_000_000, "IN-P", "Sysmon", 1),
            at_us(END_US + 2_000_000, "POST-L", "Security", 4624),
            at_us(START_US + 3_000_000, "IN-X", "Security", 4672)]
    res = scan(tmp_path, rows)
    assert res.loaded_total == len(rows)
    assert uids(res.in_window) == {"IN-L", "IN-P"} and uids(res.lookback) == {"PRE-L"}
    assert len(res.in_window) + len(res.lookback) == 3
    assert uids(res.in_window).isdisjoint(uids(res.lookback))


def test_st01_scan_rows_contract_kept_row_fields(tmp_path):
    row = at_us(START_US + 1_000_000, "IN", "Security", 4624, target_logon_id=7, command_line=sf.PLACEHOLDER_COMMAND,
                field_values_json="{}", logon_type=3)
    res = scan(tmp_path, [row])
    (kept,) = res.in_window
    for c in sp.SCAN_COLUMNS:
        assert c in kept, c
    for c in ("us_raw", "us", "in_window", "clock_unreliable", "event_uids"):
        assert c in kept, c
    assert kept["event_uid"] == "IN" and kept["target_logon_id"] == 7 and kept["logon_type"] == 3
    assert kept["us_raw"] == START_US + 1_000_000
    assert type(kept["clock_unreliable"]) is int
    assert kept["event_uids"] == ["IN"]


# ================================================================================================ 4. ST-02
def test_st02_corrected_time_is_raw_minus_offset(tmp_path):
    spec = cf.offsets_spec(ep_02=(7000, "ok", True))
    raw = START_US + 100_000_000
    res = scan(tmp_path, [at_us(raw, "A", host="ep-02"), at_us(raw, "B", host="ep-01")], spec)
    by = {r["event_uid"]: r for r in res.in_window}
    assert by["A"]["us_raw"] == raw and by["A"]["us"] == raw - 7000 * 1000
    assert by["B"]["us_raw"] == raw and by["B"]["us"] == raw
    assert by["A"]["clock_unreliable"] == 0 and by["B"]["clock_unreliable"] == 0


def test_st02_window_uses_the_corrected_time(tmp_path):
    spec = cf.offsets_spec(ep_02=(7000, "ok", True))
    rows = [at_us(START_US + 7_000_000 - 1, "OUT", host="ep-02"), at_us(START_US + 7_000_000, "IN", host="ep-02")]
    res = scan(tmp_path, rows, spec)
    assert uids(res.in_window) == {"IN"}


def test_st02_reference_host_with_zero_offset_is_reliable(tmp_path):
    res = scan(tmp_path, [at_us(START_US + 1_000_000, "D", host="dc01")])
    assert res.in_window[0]["clock_unreliable"] == 0 and res.in_window[0]["us"] == res.in_window[0]["us_raw"]


@pytest.mark.parametrize("status,offset_ms,corrected", [("wide", 2000, True), ("none", None, False),
                                                        ("stale", 5000, False)])
def test_st02_wide_none_stale_hosts_are_clock_unreliable(tmp_path, status, offset_ms, corrected):
    spec = cf.offsets_spec(ep_02=(offset_ms, status, True))
    raw = START_US + 100_000_000
    res = scan(tmp_path, [at_us(raw, "U", host="ep-02"), at_us(raw, "R", host="ep-01")], spec)
    by = {r["event_uid"]: r for r in res.in_window}
    assert by["U"]["clock_unreliable"] == 1 and by["R"]["clock_unreliable"] == 0
    assert by["U"]["us"] == (raw - offset_ms * 1000 if corrected else raw)


def test_st02_event_before_a_counted_clock_change_is_unreliable_and_after_is_not(tmp_path):
    chg = cf.change(sf.TRIAL, "ep-02", sf.at(20.48), previous_time=sf.at(12), new_time=sf.at(20.48),
                    shift_ms=8480, counted=True)
    rows = [sf.logon("PRE", 5, 1, host="ep-02"), sf.logon("POST", 25, 2, host="ep-02"),
            sf.logon("OTHER", 5, 3, host="ep-01")]
    res = scan(tmp_path, rows, changes=[chg])
    by = {r["event_uid"]: r for r in res.in_window}
    assert by["PRE"]["clock_unreliable"] == 1
    assert by["POST"]["clock_unreliable"] == 0
    assert by["OTHER"]["clock_unreliable"] == 0
    assert by["PRE"]["us"] == by["PRE"]["us_raw"]            # host status ok, offset 0: the change flags, it does not move


def test_st02_a_not_counted_clock_change_does_not_flag(tmp_path):
    chg = cf.change(sf.TRIAL, "ep-02", sf.at(20.48), previous_time=sf.at(12), new_time=sf.at(20.48),
                    shift_ms=1, counted=False, classification="routine")
    res = scan(tmp_path, [sf.logon("PRE", 5, 1, host="ep-02")], changes=[chg])
    assert res.in_window[0]["clock_unreliable"] == 0


def test_st02_host_absent_from_the_offsets_file_is_not_corrected_and_is_flagged(tmp_path):
    spec = {"dc01": (0, "reference", True), "ep-01": (3000, "ok", True)}       # no ep-03
    raw = START_US + 100_000_000
    res = scan(tmp_path, [at_us(raw, "X", host="ep-03"), at_us(raw, "K", host="ep-01")], spec)
    by = {r["event_uid"]: r for r in res.in_window}
    assert by["X"]["us"] == raw and by["X"]["clock_unreliable"] == 1
    assert by["K"]["us"] == raw - 3_000_000 and by["K"]["clock_unreliable"] == 0


# ================================================================================================ 5. ST-05
def test_st05_near_duplicate_4624_rows_collapse_to_one_with_both_uids(tmp_path):
    rows = [at_us(START_US + 5_000_000, "UID-B", "Security", 4624, record_id=777, target_logon_id=9),
            at_us(START_US + 5_000_000, "UID-A", "Security", 4624, record_id=777, target_logon_id=9)]
    res = scan(tmp_path, rows)
    assert len(res.in_window) == 1
    assert res.in_window[0]["event_uids"] == ["UID-A", "UID-B"]
    assert res.in_window[0]["event_uid"] in ("UID-A", "UID-B")
    assert res.near_duplicate_groups == 1
    assert res.loaded_total == 2


def test_st05_same_record_id_on_another_host_or_channel_is_not_a_duplicate(tmp_path):
    rows = [at_us(START_US + 1_000_000, "A", "Security", 4624, record_id=5, host="ep-02"),
            at_us(START_US + 1_000_000, "B", "Security", 4624, record_id=5, host="ep-01"),
            at_us(START_US + 1_000_000, "C", "Sysmon", 1, record_id=5, host="ep-02")]
    res = scan(tmp_path, rows)
    assert uids(res.in_window) == {"A", "B", "C"}
    assert res.near_duplicate_groups == 0
    assert all(len(r["event_uids"]) == 1 for r in res.in_window)


def test_st05_different_record_ids_are_two_events(tmp_path):
    rows = [at_us(START_US + 1_000_000, "A", record_id=1), at_us(START_US + 1_000_000, "B", record_id=2)]
    res = scan(tmp_path, rows)
    assert uids(res.in_window) == {"A", "B"} and res.near_duplicate_groups == 0


def test_st05_event_uids_are_sorted_for_three_copies(tmp_path):
    rows = [at_us(START_US + 1_000_000, uid, record_id=42) for uid in ("C", "A", "B")]
    res = scan(tmp_path, rows)
    assert len(res.in_window) == 1 and res.in_window[0]["event_uids"] == ["A", "B", "C"]
    assert res.near_duplicate_groups == 1


# ================================================================================================ 6. hygiene
def test_hygiene_scan_columns_have_no_command_text_columns():
    assert "command_line" not in sp.SCAN_COLUMNS
    assert "field_values_json" not in sp.SCAN_COLUMNS


def test_hygiene_scan_columns_are_a_subset_of_the_spec_columns():
    assert set(sp.SCAN_COLUMNS) <= set(sp.SPEC_DB_COLUMNS)
    assert len(set(sp.SCAN_COLUMNS)) == len(sp.SCAN_COLUMNS)


def test_hygiene_spec_db_columns_equal_the_spec_section_2_list():
    assert list(sp.SPEC_DB_COLUMNS) == SPEC_COLUMNS_LITERAL


def test_hygiene_kept_rows_never_carry_a_command_line_key(tmp_path):
    rows = [at_us(START_US + 1_000_000, "P", "Sysmon", 1, command_line=sf.PLACEHOLDER_COMMAND,
                  field_values_json='{"x": 1}'),
            at_us(START_US - 1_000_000, "L", "Security", 4624, command_line=sf.PLACEHOLDER_COMMAND)]
    res = scan(tmp_path, rows)
    assert uids(res.in_window) == {"P"} and uids(res.lookback) == {"L"}
    for r in res.in_window + res.lookback:
        assert "command_line" not in r and "field_values_json" not in r
        assert sf.PLACEHOLDER_COMMAND not in repr(r)


def test_hygiene_stitch_sources_never_mention_ground_truth():
    files = sorted(SRC_STITCH.rglob("*.py"))
    assert files, "src/stitch has no source files"
    offenders = [f.name for f in files if "ground_truth" in f.read_text(encoding="utf-8")]
    assert offenders == []


# ================================================================================================ params (spec 5)
def test_params_values_equal_spec_section_5():
    p = sp.StitchParams()
    assert p.process_collapse_s == 2.0 and p.boot_group_s == 120.0
    assert (p.group_gap_s, p.burst_gap_s, p.copy_install_s, p.port_join_s) == (2.0, 5.0, 10.0, 5.0)
    assert (p.link_lookback_s, p.link_after_s, p.order_tol_s) == (30.0, 15.0, 5.0)
    assert (p.order_unc_floor_s, p.followup_max_s) == (2.5, 30.0)


def test_params_are_frozen():
    with pytest.raises(dataclasses.FrozenInstanceError):
        sp.StitchParams().group_gap_s = 3.0           # type: ignore[misc]


def test_params_boot_and_log_clear_constants():
    assert set(sp.BOOT_STARTUP_IDS) == {41, 6005, 6008}
    assert set(sp.BOOT_SHUTDOWN_IDS) == {1074, 6006}
    assert set(sp.LOG_CLEAR_EVENTS) == {("Security", 1102)}
