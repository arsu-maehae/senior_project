"""Tests for the T6 stage A step `src/trial_window/` (spec docs/specs/02_gate.md sections 2.1, 2.2, 5, 6, 7;
decisions 039 and 040).

Written from the spec and the two decisions. The code was read only for callable names and the SQLite schema.
Part A: rule tests on synthetic rows (TW-xx, fast). Part B: GTT-14 (the step never opens ground_truth/).
Part C: GTA-06 on the six t00 trials (slow, real data; reads the approved keys in the TEST only).
"""
from __future__ import annotations

import ast
import builtins
import csv
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
from answer_key import build as ak_build  # noqa: E402
from answer_key import db as ak_db  # noqa: E402
from trial_window import __main__ as tw_main  # noqa: E402
from trial_window import params, window  # noqa: E402
from trial_window.window import TrialWindowError  # noqa: E402

PROCESSED = REPO / "data" / "processed"
SRC_TW = REPO / "src" / "trial_window"
TRIALS = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]
SPLUNKD = r"C:\Users\Public\splunkd.exe"
EDGE_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
EXPECTED_COLUMNS = ["trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s",
                    "rule", "db_sha256", "time_basis", "offsets_sha256", "clock_changes_sha256", "clock_flag",
                    "clock_change_in_window", "start_host", "end_host"]       # spec 2.1 (T6b.2, decision 043)
CLOCK_ONLY = ("s04_t01", "s07_t01")


# ------------------------------------------------------------------------------------------ time helpers

def parse(text: str) -> datetime:
    """Independent ISO parser for `...Z` strings with any number of fractional digits."""
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z", text)
    assert m, f"unexpected time format {text!r}"
    y, mo, d, h, mi, s, frac = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=timezone.utc)


BASE = parse("2026-09-24T05:00:00Z")


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def at(offset_s: float) -> str:
    """ISO time `offset_s` seconds after BASE (the string form the DB holds)."""
    return iso(BASE + timedelta(seconds=offset_s))


def edge(offset_s: float) -> str:
    """The expected window-edge string (ms precision) for BASE + offset_s."""
    dt = BASE + timedelta(seconds=offset_s)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# ------------------------------------------------------------------------------------------ synthetic rows

_counter = [0]


def mk(event_id: int = 1, channel: str = "Sysmon", offset: float = 0.0, host: str = "ep-01", guid: str | None = None,
       pguid: str | None = None, pimage: str | None = None, image: str = r"C:\Windows\System32\cmd.exe",
       pid: int | None = None, cmd: str | None = "cmd /c x", uid: str | None = None, account: str = "svc") -> dict:
    _counter[0] += 1
    t = at(offset)
    return {"event_uid": uid or f"uid{_counter[0]:04d}", "host": host, "channel": channel, "event_id": event_id,
            "t_utc": t, "ts": parse(t).timestamp(), "process_guid": guid, "parent_process_guid": pguid,
            "parent_image": pimage, "image": image, "process_id": pid, "command_line": cmd, "account_name": account,
            "destination_port": None, "destination_ip": None}


def root(offset: float, guid: str, uid: str | None = None, host: str = "ep-01", pguid: str = "{r-parent}") -> dict:
    return mk(1, "Sysmon", offset, host, guid, pguid, SPLUNKD, r"C:\Windows\System32\cmd.exe", uid=uid)


def child(offset: float, guid: str, pguid: str, uid: str | None = None, image: str = "x.exe", host: str = "ep-01") -> dict:
    return mk(1, "Sysmon", offset, host, guid, pguid, r"C:\Windows\System32\cmd.exe", image, uid=uid)


def unrelated(offset: float, guid: str = "{unrel}", uid: str | None = None) -> dict:
    return mk(1, "Sysmon", offset, "ep-01", guid, "{explorer}", r"C:\Windows\explorer.exe", "notepad.exe", uid=uid)


def tree_rows(root_off: float = 0.0, last_off: float = 100.0) -> list[dict]:
    """Root -> powershell -> cmd -> sc.exe (depth 3, as in the lab), last at `last_off`."""
    return [root(root_off, "{R1}", uid="root1"),
            child(root_off + 10, "{P1}", "{R1}", uid="ps1", image="powershell.exe"),
            child(root_off + 20, "{C1}", "{P1}", uid="cmd1", image="cmd.exe"),
            child(last_off, "{S1}", "{C1}", uid="sc1", image="sc.exe")]


def span(start_off: float = -3600.0, end_off: float = 3600.0) -> dict:
    return {"start_utc": at(start_off), "end_utc": at(end_off)}


# ====================================================================================== A. rule tests

def test_tw01_start_is_earliest_root_minus_60s():
    """TW-01 (spec 2.1): start = earliest root of the run - 60 s."""
    rows = [root(5, "{R2}", uid="r2"), root(0, "{R1}", uid="r1"), root(12, "{R3}", uid="r3")]
    w = window.computed_window(rows, None)
    assert w is not None
    assert w.start_utc == edge(-60)
    assert w.start_event_uid == "r1"


def test_tw02_root_over_30min_before_run_excluded_from_start_and_end():
    """TW-02 (spec 2.1, decision 026): a root > 30 min before the run, and its descendants, are excluded."""
    rows = tree_rows(0, 100) + [root(-7200, "{OLD}", uid="oldroot"),
                                child(500, "{OLDC}", "{OLD}", uid="oldchild")]   # old-run child AFTER the new run's last step
    w = window.computed_window(rows, None)
    assert w.start_utc == edge(-60)
    assert w.end_utc == edge(100 + 300)
    assert w.end_event_uid == "sc1"


def test_tw03_root_within_30min_is_included():
    """TW-03 (spec 2.1): a root 20 min before the run's last root belongs to the same run."""
    rows = tree_rows(0, 100) + [root(-1200, "{EARLY}", uid="early")]
    w = window.computed_window(rows, None)
    assert w.start_utc == edge(-1200 - 60)
    assert w.start_event_uid == "early"


def test_tw04_end_is_last_sysmon1_in_tree_plus_300s_depth3():
    """TW-04 (spec 2.1): end = last Sysmon 1 descended from a root, any depth (depth 3 here) + 300 s."""
    rows = tree_rows(0, 100)
    w = window.computed_window(rows, None)
    assert w.end_utc == edge(400)
    assert w.end_event_uid == "sc1"


def test_tw05_later_sysmon1_outside_tree_does_not_set_end():
    """TW-05 (spec 2.1): a later Sysmon 1 with an unrelated parent guid is not in the tree."""
    rows = tree_rows(0, 100) + [unrelated(900, uid="late-unrelated")]
    w = window.computed_window(rows, None)
    assert w.end_utc == edge(400)
    assert w.end_event_uid == "sc1"


@pytest.mark.parametrize("eid,chan", [(3, "Sysmon"), (10, "Sysmon"), (11, "Sysmon"), (4688, "Security")])
def test_tw06_later_non_sysmon1_event_of_tree_process_does_not_set_end(eid, chan):
    """TW-06 (spec 2.1: 'last Sysmon 1'): a later Sysmon 3/10/11 or 4688 for a tree process does not move the end."""
    later = mk(eid, chan, 900, "ep-01", "{S1}", "{C1}", None, "sc.exe", uid="later-nonsysmon1")
    w = window.computed_window(tree_rows(0, 100) + [later], None)
    assert w.end_utc == edge(400)
    assert w.end_event_uid == "sc1"


def test_tw07_guid_case_differences_still_link():
    """TW-07 (decision 040: walks by ProcessGuid): upper/lower case guids still link child to root."""
    rows = [root(0, "{ABCDEF01-AAAA}", uid="r"),
            child(50, "{11112222-BBBB}", "{abcdef01-aaaa}", uid="c1"),
            child(120, "{33334444-CCCC}", "{11112222-bbbb}", uid="c2")]
    w = window.computed_window(rows, None)
    assert w.end_event_uid == "c2"
    assert w.end_utc == edge(420)
    tree = window.agent_tree(rows, parse(rows[0]["t_utc"]).timestamp())
    assert set(tree) == {"{abcdef01-aaaa}", "{11112222-bbbb}", "{33334444-cccc}"}


def _root_via_4688(offset: float = 0.0, delta: float = 1.0) -> list[dict]:
    s1 = mk(1, "Sysmon", offset, "ep-01", "{PS-ROOT}", "{00000000-0000-0000-0000-000000000000}", "-",
            "powershell.exe", pid=4242, cmd="powershell -c go", uid="ps-root")
    sec = mk(4688, "Security", offset + delta, "ep-01", None, None, SPLUNKD, "powershell.exe", pid=4242,
             cmd="powershell -c go", uid="sec4688")
    return [s1, sec]


def test_tw08_root_tied_only_by_4688_is_a_root_and_its_descendants_count():
    """TW-08 (spec 2.1 via answer_key roots rule): parent '-' + 4688 with splunkd parent, same pid/cmd within 3 s."""
    rows = _root_via_4688(0.0, 1.0) + [child(200, "{K1}", "{PS-ROOT}", uid="kid", image="whoami.exe")]
    w = window.computed_window(rows, None)
    assert w is not None
    assert w.start_event_uid == "ps-root"
    assert w.start_utc == edge(-60)
    assert w.end_event_uid == "kid"
    assert w.end_utc == edge(500)


def test_tw09_unresolved_parent_without_4688_is_not_a_root():
    """TW-09: a Sysmon 1 with parent '-' and no matching 4688 is no root, so there is no window."""
    rows = [_root_via_4688()[0]]
    assert window.computed_window(rows, None) is None


def test_tw09b_4688_with_different_command_is_not_a_tie():
    """TW-09b: the 4688 must have the same process id and command line."""
    s1, sec = _root_via_4688()
    sec["command_line"] = "powershell -c something-else"
    assert window.computed_window([s1, sec], None) is None


def test_tw10_agent_tree_contains_roots_and_descendants_only():
    """TW-10 (decision 040): agent_tree(rows, run_start) -> {guid_lower: row} of roots and descendants of the run."""
    rows = tree_rows(0, 100) + [unrelated(50, uid="nope"), root(-7200, "{OLD}", uid="oldroot")]
    tree = window.agent_tree(rows, parse(rows[0]["t_utc"]).timestamp())
    assert set(tree) == {"{r1}", "{p1}", "{c1}", "{s1}"}
    assert tree["{s1}"]["event_uid"] == "sc1"
    assert all(k == k.lower() for k in tree)


def test_tw11_manifest_clip_end_beyond_manifest_is_clipped():
    """TW-11 (spec 2.1): the end is clipped to the manifest export end; the flag is set."""
    w = window.computed_window(tree_rows(0, 100), span(-3600, 200.123))
    assert w.end_utc == edge(200.123)
    assert w.clipped_by_manifest_end is True
    assert w.raw_end_utc == edge(400)
    assert w.clipped_by_manifest_start is False


def test_tw11b_manifest_end_with_microseconds_gives_ms_edge():
    """TW-11b (spec 6, GTT-01b): manifest end ...07.787007Z gives the edge ...07.787Z."""
    manifest = {"start_utc": at(-3600), "end_utc": "2026-09-24T05:00:07.787007Z"}
    w = window.computed_window(tree_rows(0, 5), manifest)
    assert w.end_utc == "2026-09-24T05:00:07.787Z"
    assert w.clipped_by_manifest_end is True


def test_tw11c_manifest_not_binding_means_no_clip():
    """TW-11c: an end inside the manifest span is not clipped."""
    w = window.computed_window(tree_rows(0, 100), span(-3600, 3600))
    assert w.end_utc == edge(400)
    assert w.clipped_by_manifest_end is False
    assert w.clipped_by_manifest_start is False


def test_tw11d_no_manifest_gives_no_clip():
    """TW-11d: manifest_span None -> raw edges, both flags False."""
    w = window.computed_window(tree_rows(0, 100), None)
    assert (w.start_utc, w.end_utc) == (edge(-60), edge(400))
    assert (w.raw_start_utc, w.raw_end_utc) == (edge(-60), edge(400))
    assert w.clipped_by_manifest_start is False and w.clipped_by_manifest_end is False


def test_tw11e_manifest_start_clips_the_start():
    """TW-11e (spec 2.1: both edges clipped): a manifest start later than first root - 60 s clips the start."""
    w = window.computed_window(tree_rows(0, 100), {"start_utc": at(-30), "end_utc": at(3600)})
    assert w.start_utc == edge(-30)
    assert w.clipped_by_manifest_start is True
    assert w.raw_start_utc == edge(-60)


def test_tw12_no_agent_root_gives_none():
    """TW-12: no splunkd root anywhere -> None (no window, never an invented one)."""
    assert window.computed_window([unrelated(0), unrelated(10, "{u2}")], None) is None
    assert window.computed_window([], None) is None


def test_tw13_edge_format_ms_z():
    """TW-13 (spec 2.1): edges are ISO UTC with milliseconds, `YYYY-MM-DDTHH:MM:SS.mmmZ`."""
    w = window.computed_window(tree_rows(0.4567, 100.9999), span(-3600, 3600))
    assert EDGE_RE.match(w.start_utc) and EDGE_RE.match(w.end_utc)
    wo = window.operator_window("2026-09-24T05:10:00Z", "2026-09-24T05:20:00Z", None)
    assert EDGE_RE.match(wo.start_utc) and EDGE_RE.match(wo.end_utc)


def test_tw14_operator_window_margins_and_clip():
    """TW-14 (spec 2.1, S01): start - 60 s, end + 300 s, end clipped to the manifest end."""
    wo = window.operator_window("2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z", None)
    assert wo.start_utc == "2026-09-24T05:09:00.000Z"
    assert wo.end_utc == "2026-09-24T05:25:00.000Z"
    assert wo.clipped_by_manifest_end is False
    wc = window.operator_window("2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z",
                                {"start_utc": "2026-09-24T04:00:00.000Z", "end_utc": "2026-09-24T05:22:00.500Z"})
    assert wc.end_utc == "2026-09-24T05:22:00.500Z"
    assert wc.clipped_by_manifest_end is True
    assert wc.start_utc == "2026-09-24T05:09:00.000Z"


# ------------------------------------------------------------------------------------------ refusal (T6b.2, decision 043)

def _clock_files(tmp_path: Path, trial: str, spec: dict | None = None, db_sha: str = "ab" * 32,
                 changes: list | None = None, name: str = "clk") -> window.ClockFiles:
    """ClockFiles of a synthetic trial: offsets (default: zero offsets, every host ok) and an empty changes file."""
    repo = tmp_path / name
    cf.write_clock_files(repo, trial, db_sha, spec, changes)
    return window.load_clock_files(cf.offsets_path(repo, trial), cf.changes_path(repo, trial))


def test_tw20_refusal_t00_before_cutoff_is_allowed():
    """TW-20 (spec 2.2): a t00 trial starting before 2026-10-26 is not refused by the id checks."""
    assert window.refusal("s04_t00", "2026-09-24T10:52:55.893Z") is None


def test_tw21_refusal_non_t00_is_no_longer_refused():
    """TW-21 (spec 2.2, GTT-07 as amended in T6b.2): the t00-only refusal is removed; a non-t00 trial is allowed."""
    for trial in ("s02_t01", "s04_t05", "s03_t10", "s06_t01"):
        assert window.refusal(trial, "2026-09-24T05:00:00.000Z") is None, trial


def test_tw22_refusal_co17_boundary_with_a_none_host_that_has_events(tmp_path):
    """TW-22 (spec 2, CO-17): a window starting on 2026-10-26T00:00:00.000Z is refused when a host with events is `none`;
    2026-10-25T23:59:59.999Z is not. The reason names CO-17 and the host."""
    clock = _clock_files(tmp_path, "s06_t00", cf.offsets_spec(ep_01=(None, "none", True)))
    reason = window.refusal("s06_t00", "2026-10-26T00:00:00.000Z", clock=clock)
    assert reason and "CO-17" in reason and "ep-01" in reason
    assert window.refusal("s06_t00", "2026-10-25T23:59:59.999Z", clock=clock) is None
    assert window.refusal("s06_t00", "2026-10-27T08:00:00.000Z", clock=clock)


@pytest.mark.parametrize("status,offset,has_events,refused", [
    ("none", None, True, True), ("stale", 5000, True, True),       # uncorrected host with events
    ("wide", 2000, True, False),                                    # wide is corrected: it runs
    ("none", None, False, False), ("stale", 5000, False, False),    # no events in the window: no CO-17
    ("ok", 100, True, False), ("reference", 0, True, False),
])
def test_tw22b_co17_by_status(tmp_path, status, offset, has_events, refused):
    """TW-22b (CO-17): on or after 2026-10-26 only a `none` or `stale` host WITH events refuses; `wide` runs."""
    clock = _clock_files(tmp_path, "s06_t00", cf.offsets_spec(ep_03=(offset, status, has_events)))
    assert bool(window.refusal("s06_t00", "2026-11-02T08:00:00.000Z", clock=clock)) is refused
    # before the date every status runs
    assert window.refusal("s06_t00", "2026-09-24T08:00:00.000Z", clock=clock) is None


def test_tw23_refusal_start_none_runs_only_window_free_checks():
    """TW-23: start None -> only the id checks apply: t00 and non-t00 pass, a clock-only trial does not."""
    assert window.refusal("s02_t00", None) is None
    assert window.refusal("s02_t05", None) is None
    assert window.refusal("s04_t01", None)


def test_tw24_refusal_quarantine_by_trial_id():
    """TW-24 (spec 2, decision 030): s05q_* is refused."""
    assert window.refusal("s05q_t01", "2026-10-12T07:00:00.000Z")
    assert window.refusal("s05q_t00", "2026-10-12T07:00:00.000Z")


def test_tw25_refusal_clock_only_trials():
    """TW-25 (spec 2, decision 034, spec 08 COA-04): s04_t01 and s07_t01 are refused, with or without a start; the list
    is a parameter; the reason says it is a clock-only trial."""
    for trial in ("s04_t01", "s07_t01"):
        for start in (None, "2026-09-24T05:00:00.000Z"):
            reason = window.refusal(trial, start)
            assert reason and "clock-only" in reason.lower(), (trial, start, reason)
    assert window.refusal("s04_t01", None, clock_only_trials=()) is None
    assert window.refusal("s02_t01", None, clock_only_trials=("s02_t01",))


def test_tw26_refusal_co17_date_is_a_parameter(tmp_path):
    """TW-26: the CO-17 date argument is honoured."""
    clock = _clock_files(tmp_path, "s02_t00", cf.offsets_spec(ep_01=(None, "none", True)))
    assert window.refusal("s02_t00", "2026-09-24T05:00:00.000Z", clock=clock, co17_date=date(2026, 9, 24))
    assert window.refusal("s02_t00", "2026-09-23T23:59:59.999Z", clock=clock, co17_date=date(2026, 9, 24)) is None


def test_tw27_refusal_missing_clock_files_name_the_file(tmp_path):
    """TW-27 (spec 2): a missing offsets file and a missing clock-changes file are each refused and named."""
    repo = tmp_path / "r"
    cf.write_clock_files(repo, "s02_t00", "ab" * 32)
    o, c = cf.offsets_path(repo, "s02_t00"), cf.changes_path(repo, "s02_t00")
    o.unlink()
    reason = window.refusal("s02_t00", None, clock=window.load_clock_files(o, c))
    assert reason and o.name in reason
    cf.write_clock_files(repo, "s02_t00", "ab" * 32)
    c.unlink()
    reason = window.refusal("s02_t00", None, clock=window.load_clock_files(o, c))
    assert reason and c.name in reason


def test_tw28_refusal_offsets_from_another_db_version(tmp_path):
    """TW-28 (spec 2, spec 08 4.1 item 3): offsets whose db_sha256 differs from the DB hash are refused (hash given)."""
    clock = _clock_files(tmp_path, "s02_t00", db_sha="ab" * 32)
    assert window.refusal("s02_t00", None, clock=clock, db_sha256="ab" * 32) is None
    reason = window.refusal("s02_t00", None, clock=clock, db_sha256="cd" * 32)
    assert reason and "db_sha256" in reason


# ------------------------------------------------------------------------------------------ CSV and params

def _result(trial_off: float = 0.0) -> window.WindowResult:
    return window.computed_window(tree_rows(trial_off, trial_off + 100), None)


def test_tw30_window_result_is_frozen_dataclass():
    """TW-30: WindowResult is a frozen dataclass with the documented fields."""
    r = _result()
    with pytest.raises(Exception):
        r.start_utc = "x"  # type: ignore[misc]
    names = {f for f in window.WindowResult.__dataclass_fields__}
    assert names == {"start_utc", "end_utc", "start_event_uid", "end_event_uid", "raw_start_utc", "raw_end_utc",
                     "clipped_by_manifest_start", "clipped_by_manifest_end"}


def test_tw31_columns_exact_spec_order():
    """TW-31 (spec 2.1, T6b.2): the header is exactly the fifteen documented columns in order."""
    assert list(params.COLUMNS) == EXPECTED_COLUMNS


def test_tw32_window_row_keys_margins_basis():
    """TW-32 (spec 2.1, 5): window_row has exactly COLUMNS; margins 60/300; time_basis corrected by default; with no
    clock files given the clock columns are empty strings."""
    row = window.window_row("s02_t00", _result(), "computed_agent_run", "rule text", "ab" * 32)
    assert list(row) == EXPECTED_COLUMNS
    assert row["trial_id"] == "s02_t00"
    assert (int(row["margin_start_s"]), int(row["margin_end_s"])) == (60, 300)
    assert row["time_basis"] == "corrected"
    assert [row[c] for c in ("offsets_sha256", "clock_changes_sha256", "clock_flag", "clock_change_in_window",
                             "start_host", "end_host")] == [""] * 6
    assert row["window_source"] == "computed_agent_run"
    assert row["db_sha256"] == "ab" * 32
    assert row["start_utc"] == edge(-60) and row["end_utc"] == edge(400)


def test_tw33_write_csv_header_sorted_deterministic_lf_no_bom(tmp_path):
    """TW-33: header = COLUMNS; rows sorted by trial_id; two writes are byte-identical; LF; no BOM."""
    rows = [window.window_row(t, _result(i), "computed_agent_run", "r", "00" * 32)
            for i, t in enumerate(["s07_t00", "s02_t00", "s05_t00"])]
    p1, p2 = tmp_path / "a" / "w.csv", tmp_path / "b" / "w.csv"
    window.write_csv(rows, p1)
    window.write_csv(list(reversed(rows)), p2)
    b1, b2 = p1.read_bytes(), p2.read_bytes()
    assert b1 == b2
    assert not b1.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in b1
    window.write_csv(rows, p1)
    assert p1.read_bytes() == b1
    with open(p1, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        body = list(reader)
    assert header == EXPECTED_COLUMNS
    assert [r[0] for r in body] == ["s02_t00", "s05_t00", "s07_t00"]
    assert all(r[4] == "60" and r[5] == "300" and r[8] == "corrected" for r in body)


def test_tw34_read_operator_times_missing_file_is_empty(tmp_path):
    """TW-34: a missing operator file gives an empty mapping; an existing one is read by trial id."""
    assert window.read_operator_times(tmp_path / "nope.csv") == {}
    p = tmp_path / "ops.csv"
    p.write_text("trial_id,start_utc,end_utc\ns01_t00,2026-09-24T05:10:00.000Z,2026-09-24T05:20:00.000Z\n",
                 encoding="utf-8")
    got = window.read_operator_times(p)
    assert set(got) == {"s01_t00"}
    assert tuple(got["s01_t00"]) == ("2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z")


def test_tw35_params_values():
    """TW-35 (spec 5, decision 040): margins, basis, clock constants, agent identity, default trials."""
    assert params.MARGIN_START_S == 60 and params.MARGIN_END_S == 300
    assert params.MARGIN_START_S == ak_build.RUN_INTERVAL_BEFORE_S
    assert params.MARGIN_END_S == ak_build.RUN_INTERVAL_AFTER_S
    assert params.TIME_BASIS == "corrected"
    assert params.CLOCK_CORRECTION_AVAILABLE is True
    assert params.RAW_TIME_CUTOFF_DATE == date(2026, 10, 26)       # now only the CO-17 date
    assert tuple(params.CLOCK_ONLY_TRIALS) == CLOCK_ONLY
    assert params.AGENT_IMAGE == r"C:\Users\Public\splunkd.exe"
    assert params.AGENT_SERVER == "192.168.50.50:8888"
    assert list(params.DEFAULT_TRIALS) == TRIALS


def test_tw35a_clock_only_trials_equal_the_clock_offset_step_list_and_suffixes_agree():
    """TW-35a (spec 5): trial_window.params.CLOCK_ONLY_TRIALS equals clock_offset.params.CLOCK_ONLY_TRIALS (the copy
    cannot drift); the file suffixes name the spec 08 section 3 files; TIME_BASES holds corrected and raw."""
    from clock_offset import changes as co_changes
    from clock_offset import params as co_params
    assert tuple(params.CLOCK_ONLY_TRIALS) == tuple(co_params.CLOCK_ONLY_TRIALS) == CLOCK_ONLY
    assert params.OFFSETS_SUFFIX == co_params.OFFSETS_SUFFIX == ".clock_offsets.csv"
    assert params.CLOCK_CHANGES_SUFFIX == co_changes.CHANGES_SUFFIX == ".clock_changes.csv"
    assert set(params.TIME_BASES) == {"corrected", "raw"}


def test_tw35b_margins_come_from_lab_common_and_are_shared_with_answer_key():
    """Decision 041 / spec 02_gate GTT-14: the 60 s / 300 s margins live in `lab_common.margins`; trial_window and the
    answer-key code use those very values (re-exported, not copied)."""
    from answer_key import finish as ak_finish
    from lab_common import margins

    assert margins.RUN_INTERVAL_BEFORE_S == 60.0 and margins.RUN_INTERVAL_AFTER_S == 300.0
    assert margins.KEY_MARGIN_BEFORE_S == 60.0 and margins.KEY_MARGIN_AFTER_S == 300.0
    assert params.MARGIN_START_S == margins.RUN_INTERVAL_BEFORE_S == 60.0
    assert params.MARGIN_END_S == margins.RUN_INTERVAL_AFTER_S == 300.0
    assert ak_build.RUN_INTERVAL_BEFORE_S == margins.RUN_INTERVAL_BEFORE_S == 60.0
    assert ak_build.RUN_INTERVAL_AFTER_S == margins.RUN_INTERVAL_AFTER_S == 300.0
    assert ak_finish.KEY_MARGIN_BEFORE_S == margins.KEY_MARGIN_BEFORE_S == 60.0
    assert ak_finish.KEY_MARGIN_AFTER_S == margins.KEY_MARGIN_AFTER_S == 300.0


# ------------------------------------------------------------------------------------------ run() on a temp repo

EVENT_COLS = ["scenario_id", "event_uid", "timestamp_utc", "event_utc", "host", "channel", "event_id", "record_id",
              "account_name", "process_guid", "parent_process_guid", "process_id", "image", "parent_image",
              "command_line", "destination_ip", "destination_port"]
MANIFEST_COLS = ["path", "sha256", "size", "scenario", "trial", "host", "channel", "source_path", "date", "records",
                 "first_event_utc", "last_event_utc"]


def make_db(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    cols = ", ".join(f'"{c}"' for c in EVENT_COLS)
    con.execute(f"CREATE TABLE events ({cols})")
    for i, r in enumerate(rows):
        vals = {"scenario_id": "s", "event_uid": r["event_uid"], "timestamp_utc": r["t_utc"], "event_utc": r["t_utc"],
                "host": r["host"], "channel": r["channel"], "event_id": r["event_id"], "record_id": i + 1,
                "account_name": r["account_name"], "process_guid": r["process_guid"],
                "parent_process_guid": r["parent_process_guid"], "process_id": r["process_id"], "image": r["image"],
                "parent_image": r["parent_image"], "command_line": r["command_line"], "destination_ip": None,
                "destination_port": None}
        con.execute(f"INSERT INTO events VALUES ({', '.join('?' * len(EVENT_COLS))})", [vals[c] for c in EVENT_COLS])
    con.execute("CREATE VIEW events_dedup AS SELECT * FROM events")
    con.commit()
    con.close()


def make_manifest(repo: Path, entries: list[tuple]) -> None:
    """entries: (scenario, trial, first_event_utc, last_event_utc[, host]); host defaults to ep-01."""
    (repo / "data").mkdir(parents=True, exist_ok=True)
    with open(repo / "data" / "manifest.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_COLS, lineterminator="\n")
        w.writeheader()
        for e in entries:
            sc, tr, a, b = e[:4]
            host = e[4] if len(e) > 4 else "ep-01"
            w.writerow({"path": f"{sc}/{tr}/{host}/sysmon.evtx", "sha256": "0" * 64, "size": 1, "scenario": sc,
                        "trial": tr, "host": host, "channel": "sysmon", "source_path": "x", "date": "2026-09-24",
                        "records": 1, "first_event_utc": a, "last_event_utc": b})


def add_clock(repo: Path, trial: str, spec: dict | None = None, changes: list | None = None) -> tuple[str, str]:
    """Valid clock files for the trial DB now on disk (offsets db_sha256 = the DB hash); default zero offsets."""
    db_file = repo / "data" / "processed" / f"{trial}.sqlite3"
    return cf.write_clock_files(repo, trial, hashlib.sha256(db_file.read_bytes()).hexdigest(), spec, changes)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def temp_repo(tmp_path):
    repo = tmp_path / "repo"
    proc = repo / "data" / "processed"
    # good t00 trial in September
    make_db(proc / "s02_t00.sqlite3", tree_rows(0, 100))
    # t01 (allowed since T6b.2), quarantine id, t00 starting after the CO-17 date, t00 with no agent root, S01,
    # and a clock-only trial
    make_db(proc / "s02_t01.sqlite3", tree_rows(0, 100))
    make_db(proc / "s05q_t01.sqlite3", tree_rows(0, 100))
    late = tree_rows(0, 100)
    shift = (parse("2026-10-26T08:00:00Z") - BASE).total_seconds()
    for r in late:
        t = BASE + timedelta(seconds=shift + (parse(r["t_utc"]) - BASE).total_seconds())
        r["t_utc"] = iso(t)
    make_db(proc / "s04_t00.sqlite3", late)
    make_db(proc / "s03_t00.sqlite3", [unrelated(0), unrelated(5, "{u2}")])
    make_db(proc / "s01_t00.sqlite3", [unrelated(0)])
    make_manifest(repo, [("s02", "t00", at(-3600), at(3600)), ("s02", "t01", at(-3600), at(3600)),
                         ("s04", "t00", "2026-10-26T07:00:00.000000Z", "2026-10-26T10:00:00.000000Z"),
                         ("s03", "t00", at(-3600), at(3600)), ("s01", "t00", at(-3600), at(3600)),
                         ("s04", "t01", at(-3600), at(3600))])
    make_db(proc / "s04_t01.sqlite3", tree_rows(0, 100))
    for t in ("s02_t00", "s02_t01", "s04_t00", "s03_t00", "s01_t00", "s04_t01"):
        add_clock(repo, t)
    return repo


def test_tw40_run_refusals_skip_with_reason_and_write_no_row(temp_repo, tmp_path):
    """TW-40 (spec 2.1 / GTT-07 as amended in T6b.2): refused trials write no row and appear in `skipped` with a reason;
    s02_t01 (non-t00) and s04_t00 (starts after 2026-10-26, hosts ok) are NO LONGER refused."""
    out = tmp_path / "out" / "trial_windows.csv"
    trials = ["s02_t00", "s02_t01", "s05q_t01", "s04_t00", "s03_t00", "s01_t00", "s04_t01"]
    res = tw_main.run(temp_repo, trials, tmp_path / "no_operator_file.csv", out)
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00", "s02_t01", "s04_t00"]
    assert set(res["skipped"]) == {"s05q_t01", "s03_t00", "s01_t00", "s04_t01"}
    assert all(isinstance(v, str) and v for v in res["skipped"].values())
    assert "decision 019" in res["skipped"]["s01_t00"]            # s01_t00 is excluded from the split
    assert "quarantine" in res["skipped"]["s05q_t01"].lower()
    assert "clock-only" in res["skipped"]["s04_t01"].lower()
    assert "agent" in res["skipped"]["s03_t00"].lower()
    assert set(res["edges"]) == {"s02_t00", "s02_t01", "s04_t00"}
    with open(out, newline="", encoding="utf-8") as fh:
        written = list(csv.DictReader(fh))
    assert [r["trial_id"] for r in written] == ["s02_t00", "s02_t01", "s04_t00"]
    assert list(written[0]) == EXPECTED_COLUMNS
    row = written[0]
    assert row["window_source"] == "computed_agent_run"
    assert row["start_utc"] == edge(-60) and row["end_utc"] == edge(400)
    assert row["db_sha256"] == sha(temp_repo / "data" / "processed" / "s02_t00.sqlite3")
    assert row["time_basis"] == "corrected" and row["margin_start_s"] == "60" and row["margin_end_s"] == "300"
    assert row["offsets_sha256"] == sha(cf.offsets_path(temp_repo, "s02_t00"))
    assert row["clock_changes_sha256"] == sha(cf.changes_path(temp_repo, "s02_t00"))
    assert row["clock_flag"] == "" and row["clock_change_in_window"] == "false"
    assert row["start_host"] == "ep-01" and row["end_host"] == "ep-01"
    assert row["rule"]


def test_tw41_run_db_hash_unchanged_and_two_runs_identical(temp_repo, tmp_path):
    """TW-41 (spec 2, GTT-08): the DB is never written; two runs give byte-identical files."""
    db = temp_repo / "data" / "processed" / "s02_t00.sqlite3"
    before = sha(db)
    o1, o2 = tmp_path / "o1.csv", tmp_path / "o2.csv"
    tw_main.run(temp_repo, ["s02_t00"], tmp_path / "none.csv", o1)
    tw_main.run(temp_repo, ["s02_t00"], tmp_path / "none.csv", o2)
    assert sha(db) == before
    assert o1.read_bytes() == o2.read_bytes()


def test_tw42_run_clips_to_the_trials_manifest_span(temp_repo, tmp_path):
    """TW-42 (spec 2.1): run() reads data/manifest.csv and clips the end to the trial's export end."""
    make_manifest(temp_repo, [("s02", "t00", at(-3600), "2026-09-24T05:00:07.787007Z")])
    res = tw_main.run(temp_repo, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["rows"][0]["end_utc"] == "2026-09-24T05:00:07.787Z"
    assert res["edges"]["s02_t00"].clipped_by_manifest_end is True
    assert res["rows"][0]["end_host"] == "ep-01"               # the export file that set the clipped edge


def test_tw43_run_s01_without_operator_file_is_skipped(temp_repo, tmp_path):
    """TW-43 (spec 2.1, decision 019): s01_t00 is excluded, so it is skipped with the decision 019 reason; with
    the exclusion lifted and no operator-recorded start/end it is still skipped, with an operator reason."""
    res = tw_main.run(temp_repo, ["s01_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["rows"] == []
    assert "decision 019" in res["skipped"]["s01_t00"]
    res2 = tw_main.run(temp_repo, ["s01_t00"], tmp_path / "none.csv", tmp_path / "o2.csv", excluded_trials=())
    assert res2["rows"] == []
    assert "operator" in res2["skipped"]["s01_t00"].lower()


def test_tw44_run_s01_with_operator_file_uses_operator_source(temp_repo, tmp_path):
    """TW-44 (spec 2.1): S01 row has window_source == operator, start - 60 s, end + 300 s."""
    ops = tmp_path / "operator_times.csv"
    ops.write_text("trial_id,start_utc,end_utc\ns01_t00,2026-09-24T05:10:00.000Z,2026-09-24T05:20:00.000Z\n",
                   encoding="utf-8")
    out = tmp_path / "o.csv"
    res = tw_main.run(temp_repo, ["s01_t00"], ops, out, excluded_trials=())
    assert [r["trial_id"] for r in res["rows"]] == ["s01_t00"]
    row = res["rows"][0]
    assert row["window_source"] == "operator"
    assert row["start_utc"] == "2026-09-24T05:09:00.000Z"
    assert row["end_utc"] == "2026-09-24T05:25:00.000Z"
    assert res["skipped"] == {}


def test_tw45_run_rows_sorted_by_trial_id(temp_repo, tmp_path):
    """TW-45: output rows are sorted by trial id whatever the order asked for."""
    make_db(temp_repo / "data" / "processed" / "s06_t00.sqlite3", tree_rows(0, 100))
    add_clock(temp_repo, "s06_t00")
    make_manifest(temp_repo, [("s02", "t00", at(-3600), at(3600)), ("s06", "t00", at(-3600), at(3600))])
    res = tw_main.run(temp_repo, ["s06_t00", "s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00", "s06_t00"]


def test_tw46_main_cli_flags_write_the_out_file(temp_repo, tmp_path, capsys):
    """TW-46: main(argv) with --trials --repo --operator-times --out writes the CSV and exits 0."""
    out = tmp_path / "cli" / "w.csv"
    rc = tw_main.main(["--trials", "s02_t00", "s04_t01", "--repo", str(temp_repo),
                       "--operator-times", str(tmp_path / "none.csv"), "--out", str(out)])
    assert rc in (0, None)
    with open(out, newline="", encoding="utf-8") as fh:
        assert [r["trial_id"] for r in csv.DictReader(fh)] == ["s02_t00"]
    assert "s04_t01" in capsys.readouterr().out      # a skipped (clock-only) trial is reported, not silently dropped


# ------------------------------------------------------------------------------------------ follow-ups (owner 2026-11-12)

def _simple_repo(root: Path, trials: list[str], manifest: list[tuple],
                 rows: list[dict] | None = None, spec: dict | None = None, changes: list | None = None) -> Path:
    """Temp repo with one DB per trial, valid clock files (zero offsets unless `spec`), and a manifest."""
    repo = root / "repo"
    for t in trials:
        make_db(repo / "data" / "processed" / f"{t}.sqlite3", rows if rows is not None else tree_rows(0, 100))
        add_clock(repo, t, spec, changes)
    make_manifest(repo, manifest)
    return repo


def test_tw50_is_quarantined_by_path_below_repo(tmp_path):
    """TW-50 (spec 2.1, decision 030): a DB under data/processed/quarantine/ is quarantined whatever its id."""
    repo = tmp_path / "repo"
    p = repo / "data" / "processed" / "quarantine" / "s05_t01.sqlite3"
    assert window.is_quarantined("s05_t01", p, repo) is True
    assert window.is_quarantined("s05_t01", repo / "data" / "processed" / "s05_t01.sqlite3", repo) is False
    assert window.is_quarantined("s05q_t01") is True


def test_tw50b_repo_living_under_a_quarantine_folder_is_not_quarantined(tmp_path):
    """TW-50b: only path parts BELOW the repo count; tmp/quarantine/repo with a normal DB still gets its row."""
    root = tmp_path / "quarantine"
    repo = _simple_repo(root, ["s02_t00"], [("s02", "t00", at(-3600), at(3600))])
    db = repo / "data" / "processed" / "s02_t00.sqlite3"
    assert window.is_quarantined("s02_t00", db, repo) is False
    res = tw_main.run(repo, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00"]
    assert res["skipped"] == {}


def test_tw50c_run_quarantined_trial_gives_reason_not_error(tmp_path):
    """TW-50c (decision 030): s05q_t01 with its DB in data/processed/quarantine/ -> no row, a quarantine reason, no raise."""
    repo = _simple_repo(tmp_path, [], [("s05q", "t01", at(-3600), at(3600))])
    make_db(repo / "data" / "processed" / "quarantine" / "s05q_t01.sqlite3", tree_rows(0, 100))
    out = tmp_path / "o.csv"
    res = tw_main.run(repo, ["s05q_t01"], tmp_path / "none.csv", out)
    assert res["rows"] == []
    assert "quarantine" in res["skipped"]["s05q_t01"].lower()


def _s01_repo(tmp_path: Path, op_start: str, op_end: str, span: tuple[str, str],
              spec: dict | None = None) -> tuple[Path, Path]:
    repo = _simple_repo(tmp_path, ["s01_t00"], [("s01", "t00", span[0], span[1])], rows=[unrelated(0)], spec=spec)
    ops = tmp_path / "operator_times.csv"
    ops.write_text(f"trial_id,start_utc,end_utc\ns01_t00,{op_start},{op_end}\n", encoding="utf-8")
    return repo, ops


NONE_EP01 = cf.offsets_spec(ep_01=(None, "none", True))      # an uncorrected host WITH events (CO-17)


def test_tw51_operator_co17_boundary_uses_window_start_date(tmp_path):
    """TW-51 (spec 2 CO-17: the date is taken from the window start): with the exclusion lifted and an uncorrected
    host that has events, an operator start of 2026-10-26T00:00:30Z gives a window start of 2026-10-25T23:59:30.000Z, so a
    row IS written (flagged); an operator start of 2026-10-26T00:01:00Z gives a start of 2026-10-26T00:00:00.000Z, so
    there is NO row and the reason names CO-17 and 2026-10-26."""
    manifest = ("2026-10-25T00:00:00.000000Z", "2026-10-27T00:00:00.000000Z")
    repo, ops = _s01_repo(tmp_path / "a", "2026-10-26T00:00:30Z", "2026-10-26T00:20:00Z", manifest, NONE_EP01)
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "a.csv", excluded_trials=())
    assert [r["trial_id"] for r in res["rows"]] == ["s01_t00"]
    assert res["rows"][0]["start_utc"] == "2026-10-25T23:59:30.000Z"
    assert res["rows"][0]["clock_flag"] == "ep-01"
    assert res["skipped"] == {}
    repo, ops = _s01_repo(tmp_path / "b", "2026-10-26T00:01:00Z", "2026-10-26T00:20:00Z", manifest, NONE_EP01)
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "b.csv", excluded_trials=())
    assert res["rows"] == []
    assert "2026-10-26" in res["skipped"]["s01_t00"] and "CO-17" in res["skipped"]["s01_t00"]


def test_tw51b_operator_trial_clearly_after_cutoff_is_refused_only_with_an_uncorrected_host(tmp_path):
    """TW-51b (CO-17): a start clearly after the date is refused with a `none` host that has events and runs when every
    host is corrected (`ok`) or the none host has no events."""
    span = ("2026-10-25T00:00:00.000000Z", "2026-10-27T00:00:00.000000Z")
    repo, ops = _s01_repo(tmp_path / "n", "2026-10-26T08:00:00Z", "2026-10-26T08:20:00Z", span, NONE_EP01)
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "n.csv", excluded_trials=())
    assert res["rows"] == []
    assert "2026-10-26" in res["skipped"]["s01_t00"] and "CO-17" in res["skipped"]["s01_t00"]
    for name, spec in (("ok", None), ("noevents", cf.offsets_spec(ep_03=(None, "none", False))),
                       ("wide", cf.offsets_spec(ep_03=(2000, "wide", True)))):
        repo, ops = _s01_repo(tmp_path / name, "2026-10-26T08:00:00Z", "2026-10-26T08:20:00Z", span, spec)
        res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / f"{name}.csv", excluded_trials=())
        assert [r["trial_id"] for r in res["rows"]] == ["s01_t00"], name


def test_tw51c_operator_trial_before_cutoff_gets_operator_row(tmp_path):
    """TW-51c (spec 2.1, CO-17): an operator start of 2026-10-25T10:00:00Z gives a row with window_source operator, even
    with an uncorrected host that has events (before the date it runs on raw time with the flag)."""
    repo, ops = _s01_repo(tmp_path, "2026-10-25T10:00:00Z", "2026-10-25T10:20:00Z",
                          ("2026-10-25T00:00:00.000000Z", "2026-10-27T00:00:00.000000Z"), NONE_EP01)
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "o.csv", excluded_trials=())
    assert [r["trial_id"] for r in res["rows"]] == ["s01_t00"]
    assert res["rows"][0]["window_source"] == "operator"
    assert res["rows"][0]["start_utc"] == "2026-10-25T09:59:00.000Z"
    assert res["rows"][0]["clock_flag"] == "ep-01"
    assert res["rows"][0]["start_host"] == "" and res["rows"][0]["end_host"] == ""   # operator window: no edge host


def test_tw52_operator_window_start_clipped_by_manifest():
    """TW-52 (spec 2.1, decision 026 amendment): a manifest span starting after start - 60 s clips the start."""
    span_ = {"start_utc": "2026-09-24T05:09:30.250000Z", "end_utc": "2026-09-24T06:00:00.000000Z"}
    w = window.operator_window("2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z", span_)
    assert w.start_utc == "2026-09-24T05:09:30.250Z"
    assert w.clipped_by_manifest_start is True
    assert w.raw_start_utc == "2026-09-24T05:09:00.000Z"
    assert w.end_utc == "2026-09-24T05:25:00.000Z" and w.clipped_by_manifest_end is False


def test_tw52b_operator_start_clip_through_run(tmp_path):
    """TW-52b: the same start clip when the operator trial goes through run()."""
    repo, ops = _s01_repo(tmp_path, "2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z",
                          ("2026-09-24T05:09:30.250000Z", "2026-09-24T06:00:00.000000Z"))
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "o.csv", excluded_trials=())
    assert res["rows"][0]["start_utc"] == "2026-09-24T05:09:30.250Z"
    e = res["edges"]["s01_t00"]
    assert e.clipped_by_manifest_start is True and e.raw_start_utc == "2026-09-24T05:09:00.000Z"


def test_tw53_missing_db_for_allowed_trial_raises_and_writes_nothing(tmp_path):
    """TW-53 (spec 2.1 'missing DB is an error'): an allowed t00 trial without a DB raises TrialWindowError naming
    the path; no output file is written, even if another trial in the same call has a DB."""
    repo = _simple_repo(tmp_path, ["s02_t00"], [("s02", "t00", at(-3600), at(3600))])
    out = tmp_path / "out" / "w.csv"
    for trials in (["s08_t00"], ["s02_t00", "s08_t00"], ["s08_t00", "s02_t00"]):
        with pytest.raises(TrialWindowError) as ei:
            tw_main.run(repo, trials, tmp_path / "none.csv", out)
        assert str(repo / "data" / "processed" / "s08_t00.sqlite3") in str(ei.value)
        assert "trial DB not found" in str(ei.value)
        assert not out.exists()
    # s02_t00 in a repo without its DB file
    repo2 = _simple_repo(tmp_path / "two", [], [("s02", "t00", at(-3600), at(3600))])
    with pytest.raises(TrialWindowError) as ei:
        tw_main.run(repo2, ["s02_t00"], tmp_path / "none.csv", out)
    assert str(repo2 / "data" / "processed" / "s02_t00.sqlite3") in str(ei.value)
    assert not out.exists()


def test_tw53b_main_missing_db_exit_code_and_stderr(tmp_path, capsys):
    """TW-53b: main() prints `error: trial DB not found ...` to stderr, returns non-zero, writes no file."""
    repo = _simple_repo(tmp_path, [], [("s02", "t00", at(-3600), at(3600))])
    out = tmp_path / "w.csv"
    rc = tw_main.main(["--trials", "s02_t00", "--repo", str(repo), "--operator-times", str(tmp_path / "none.csv"),
                       "--out", str(out)])
    err = capsys.readouterr().err
    assert rc not in (0, None)
    assert "error: trial DB not found" in err
    assert not out.exists()


def test_tw53c_refused_trial_without_db_is_skipped_not_raised(tmp_path):
    """TW-53c (refused before the DB existence check): a quarantined, a clock-only and an excluded trial with no DB are
    skipped with a reason; a non-t00 trial is NOT refused any more, so its missing DB is the hard error."""
    repo = _simple_repo(tmp_path, ["s02_t00"], [("s02", "t00", at(-3600), at(3600))])
    res = tw_main.run(repo, ["s04_t01", "s07_t01", "s05q_t03", "s01_t00", "s02_t00"], tmp_path / "none.csv",
                      tmp_path / "o.csv")
    assert set(res["skipped"]) == {"s04_t01", "s07_t01", "s05q_t03", "s01_t00"}
    assert all(res["skipped"].values())
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00"]
    out = tmp_path / "o2.csv"
    with pytest.raises(TrialWindowError) as ei:
        tw_main.run(repo, ["s02_t07", "s02_t00"], tmp_path / "none.csv", out)
    assert "trial DB not found" in str(ei.value) and "s02_t07" in str(ei.value)
    assert not out.exists()


def test_tw54_s01_t00_refused_decision_019():
    """TW-54 (decision 019, spec 2.1): refusal('s01_t00') names decision 019, with or without clock correction."""
    assert "decision 019" in (window.refusal("s01_t00", None) or "")
    assert "decision 019" in (window.refusal("s01_t00", "2026-09-24T05:00:00.000Z") or "")
    assert tuple(params.EXCLUDED_TRIALS) == ("s01_t00",)
    # exclusion is a parameter, and the quarantine check comes first
    assert window.refusal("s01_t00", "2026-09-24T05:00:00.000Z", excluded_trials=()) is None
    assert "quarantine" in (window.refusal("s05q_t01", None, excluded_trials=("s05q_t01",)) or "").lower()


def test_tw54b_run_skips_s01_t00_even_with_operator_row(tmp_path):
    """TW-54b: run() skips s01_t00 with the decision 019 reason although an operator row exists."""
    repo, ops = _s01_repo(tmp_path, "2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z",
                          (at(-3600), at(3600)))
    res = tw_main.run(repo, ["s01_t00"], ops, tmp_path / "o.csv")
    assert res["rows"] == []
    assert "decision 019" in res["skipped"]["s01_t00"]


def test_tw54c_main_prints_skipped_line_with_decision_019(tmp_path, capsys):
    """TW-54c: main() prints `s01_t00  SKIPPED: ... decision 019 ...`."""
    repo, ops = _s01_repo(tmp_path, "2026-09-24T05:10:00.000Z", "2026-09-24T05:20:00.000Z",
                          (at(-3600), at(3600)))
    rc = tw_main.main(["--trials", "s01_t00", "--repo", str(repo), "--operator-times", str(ops),
                       "--out", str(tmp_path / "o.csv")])
    assert rc in (0, None)
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "SKIPPED" in ln]
    assert any(ln.startswith("s01_t00") and "decision 019" in ln for ln in lines), lines


def test_tw55_manifest_without_row_for_trial_gives_no_row(tmp_path):
    """TW-55 (spec 2.1): no export span for the trial -> no row, reason 'no export span'."""
    repo = _simple_repo(tmp_path, ["s02_t00"], [("s03", "t00", at(-3600), at(3600))])
    res = tw_main.run(repo, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["rows"] == []
    assert "no export span" in res["skipped"]["s02_t00"]
    repo2 = tmp_path / "nomanifest" / "repo"
    make_db(repo2 / "data" / "processed" / "s02_t00.sqlite3", tree_rows(0, 100))      # no data/manifest.csv at all
    add_clock(repo2, "s02_t00")
    res2 = tw_main.run(repo2, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o2.csv")
    assert res2["rows"] == [] and "no export span" in res2["skipped"]["s02_t00"]


@pytest.mark.parametrize("name,first,last", [("before", -7200, -3600), ("after", 3600, 7200)])
def test_tw56_manifest_span_not_overlapping_window_gives_no_row(tmp_path, name, first, last):
    """TW-56 (spec 2.1): a span entirely before or after the unclipped window -> no row, 'does not overlap'."""
    repo = _simple_repo(tmp_path, ["s02_t00"], [("s02", "t00", at(first), at(last))])
    res = tw_main.run(repo, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["rows"] == []
    assert "does not overlap" in res["skipped"]["s02_t00"]


def test_tw56b_partial_overlap_still_writes_clipped_row(tmp_path):
    """TW-56b (spec 2.1): a partial overlap is clipped, not refused."""
    repo = _simple_repo(tmp_path, ["s02_t00"], [("s02", "t00", at(-3600), at(200.5))])
    res = tw_main.run(repo, ["s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["skipped"] == {}
    assert res["rows"][0]["end_utc"] == edge(200.5)
    assert res["rows"][0]["start_utc"] == edge(-60)
    assert res["edges"]["s02_t00"].clipped_by_manifest_end is True


def test_tw57_manifest_coverage_reason_four_cases():
    """TW-57 (spec 2.1): manifest_coverage_reason: None for full/partial overlap; a reason for no span, before, after."""
    raw = window.computed_window(tree_rows(0, 100), None)             # raw edges -60 .. +400
    assert window.manifest_coverage_reason(raw, span(-3600, 3600), "s02_t00") is None            # full
    partial = span(-3600, 200)
    assert window.manifest_coverage_reason(window.computed_window(tree_rows(0, 100), partial), partial) is None
    no_span = window.manifest_coverage_reason(raw, None, "s02_t00")
    assert no_span and "no export span" in no_span
    before = window.manifest_coverage_reason(raw, span(-7200, -3600), "s02_t00")
    after = window.manifest_coverage_reason(raw, span(3600, 7200), "s02_t00")
    assert before and "does not overlap" in before
    assert after and "does not overlap" in after
    assert "s02_t00" in no_span or "s02_t00" in before          # trial id is used in the text


def test_tw57b_coverage_uses_raw_edges_not_clipped():
    """TW-57b: a result for a non-overlapping span is still judged on its raw (unclipped) edges."""
    far = span(-7200, -3600)
    res = window.computed_window(tree_rows(0, 100), far)
    if res is not None:
        assert "does not overlap" in (window.manifest_coverage_reason(res, far) or "")


# ====================================================================================== A2. corrected basis (T6b.2)
# spec 02_gate 2.1: on the corrected basis every Sysmon 1 is corrected (event_utc - offset_ms(host), CO-09) BEFORE the
# agent tree is walked and the edges taken; the manifest span is corrected per host; none/stale hosts keep raw time.

def _mixed_host_tree() -> list[dict]:
    """Root ep-01 @0 -> P1 -> C1 (ep-01); two leaves: S1 on ep-02 @100 raw, K1 on ep-01 @102 raw.
    Raw: K1 is the last Sysmon 1. With ep-01 +2 s and ep-02 -3 s: S1 is at 103 and K1 at 100 -> S1 is last."""
    return [root(0, "{R1}", uid="root1", host="ep-01"),
            child(10, "{P1}", "{R1}", uid="ps1", image="powershell.exe", host="ep-01"),
            child(20, "{C1}", "{P1}", uid="cmd1", image="cmd.exe", host="ep-01"),
            child(100, "{S1}", "{C1}", uid="sc1", image="sc.exe", host="ep-02"),
            child(102, "{K1}", "{C1}", uid="kid1", image="k.exe", host="ep-01")]


WIDE_MANIFEST = [("s02", "t00", at(-3600), at(3600))]
NO_OPERATOR = "no_operator_file.csv"


def _run_one(repo: Path, tmp_path: Path, trial: str = "s02_t00", **kw) -> dict:
    return tw_main.run(repo, [trial], tmp_path / NO_OPERATOR, tmp_path / "w.csv", **kw)


def test_tw60_edges_use_corrected_sysmon1_times_and_the_last_event_is_chosen_on_corrected_time(tmp_path):
    """TW-60 (spec 2.1): ep-01 +2 s, ep-02 -3 s. Corrected: root at -2 s, last Sysmon 1 = S1 (ep-02) at 103 s -> window
    -62 s .. 403 s. start_host = host of the root (ep-01), end_host = host of the last event (ep-02). On the raw basis the
    last event is K1 (102 s) and the window is -60 s .. 402 s."""
    spec = cf.offsets_spec(ep_01=(2000, "ok", True), ep_02=(-3000, "ok", True))
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=_mixed_host_tree(), spec=spec)
    res = _run_one(repo, tmp_path)
    row, e = res["rows"][0], res["edges"]["s02_t00"]
    assert row["start_utc"] == edge(-62) and row["end_utc"] == edge(403)
    assert e.start_event_uid == "root1" and e.end_event_uid == "sc1"
    assert row["start_host"] == "ep-01" and row["end_host"] == "ep-02"
    assert row["time_basis"] == "corrected"
    raw = _run_one(repo, tmp_path, time_basis="raw")
    rrow, re_ = raw["rows"][0], raw["edges"]["s02_t00"]
    assert rrow["start_utc"] == edge(-60) and rrow["end_utc"] == edge(402)
    assert re_.end_event_uid == "kid1"


def test_tw60b_every_row_is_corrected_before_the_agent_tree_is_walked(tmp_path):
    """TW-60b (spec 2.1): the 30-minute walk-back works on corrected times. A second root 29 min before on a host that is
    +2 min ahead is 31 min before once corrected, so it is NOT part of the run; a host with offset 0 keeps it."""
    rows = tree_rows(0, 100) + [root(-1740, "{EARLY}", uid="early", host="ep-02")]      # 29 min before the run, raw
    repo0 = _simple_repo(tmp_path / "zero", ["s02_t00"], WIDE_MANIFEST, rows=rows)
    r0 = _run_one(repo0, tmp_path / "zero")
    assert r0["edges"]["s02_t00"].start_event_uid == "early" and r0["rows"][0]["start_utc"] == edge(-1740 - 60)
    spec = cf.offsets_spec(ep_02=(120000, "ok", True))                                  # ep-02 120 s ahead: corrected -1860
    repo1 = _simple_repo(tmp_path / "plus", ["s02_t00"], WIDE_MANIFEST, rows=rows, spec=spec)
    r1 = _run_one(repo1, tmp_path / "plus")
    assert r1["edges"]["s02_t00"].start_event_uid == "root1" and r1["rows"][0]["start_utc"] == edge(-60)


def test_tw61_none_and_stale_hosts_keep_raw_time_in_the_window(tmp_path):
    """TW-61 (spec 2.1, CO-09): a `none` and a `stale` host are not corrected: the same tree with the same (ignored)
    offset gives the raw window; the clock_flag lists them."""
    for status, offset in (("none", None), ("stale", 9000)):
        spec = cf.offsets_spec(ep_01=(offset, status, True))
        repo = _simple_repo(tmp_path / status, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100), spec=spec)
        row = _run_one(repo, tmp_path / status)["rows"][0]
        assert row["start_utc"] == edge(-60) and row["end_utc"] == edge(400), status
        assert row["clock_flag"] == "ep-01", status
    wide = cf.offsets_spec(ep_01=(4000, "wide", True))                                 # wide IS corrected
    repo = _simple_repo(tmp_path / "wide", ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100), spec=wide)
    row = _run_one(repo, tmp_path / "wide")["rows"][0]
    assert row["start_utc"] == edge(-64) and row["end_utc"] == edge(396) and row["clock_flag"] == "ep-01"


def test_tw62_manifest_clip_edge_hosts_come_from_the_export_file_whose_corrected_time_set_the_edge(tmp_path):
    """TW-62 (spec 2.1): two export files (ep-01 offset 0, ep-02 offset +20 s). Corrected firsts: ep-01 -40, ep-02 -30-20 = -50;
    lasts: ep-01 250, ep-02 280-20 = 260. The corrected span is -50 .. 260, both set by ep-02, so the clipped window is
    -50 s .. 260 s with start_host = end_host = ep-02. On the raw basis the span is -40 .. 280 (the raw span)."""
    manifest = [("s02", "t00", at(-40), at(250), "ep-01"), ("s02", "t00", at(-30), at(280), "ep-02")]
    spec = cf.offsets_spec(ep_02=(20000, "ok", True))
    repo = _simple_repo(tmp_path, ["s02_t00"], manifest, rows=tree_rows(0, 100), spec=spec)
    res = _run_one(repo, tmp_path)
    row, e = res["rows"][0], res["edges"]["s02_t00"]
    assert row["start_utc"] == edge(-50) and row["end_utc"] == edge(260)
    assert e.clipped_by_manifest_start is True and e.clipped_by_manifest_end is True
    assert row["start_host"] == "ep-02" and row["end_host"] == "ep-02"
    raw = _run_one(repo, tmp_path, time_basis="raw")["rows"][0]
    assert raw["start_utc"] == edge(-40) and raw["end_utc"] == edge(280)


def test_tw62b_edge_hosts_when_only_one_edge_is_clipped_by_the_manifest(tmp_path):
    """TW-62b (spec 2.1): the end is clipped by an ep-03 export file (corrected last = 150 - (-5) = 155 s), the start is set by
    the agent root (ep-01): start_host = ep-01 (event host), end_host = ep-03 (export file host)."""
    manifest = [("s02", "t00", at(-3600), at(120), "ep-01"), ("s02", "t00", at(-3600), at(150), "ep-03")]
    spec = cf.offsets_spec(ep_03=(-5000, "ok", True))
    repo = _simple_repo(tmp_path, ["s02_t00"], manifest, rows=tree_rows(0, 100), spec=spec)
    res = _run_one(repo, tmp_path)
    row, e = res["rows"][0], res["edges"]["s02_t00"]
    assert row["end_utc"] == edge(155) and e.clipped_by_manifest_end is True and e.clipped_by_manifest_start is False
    assert row["start_utc"] == edge(-60)
    assert row["start_host"] == "ep-01" and row["end_host"] == "ep-03"


def test_tw63_manifest_span_is_corrected_per_host_and_none_stale_hosts_stay_raw(tmp_path):
    """TW-63 (spec 2.1): the export span ends are corrected by THEIR host offset before min/max. ep-02 file ends at 280 raw;
    ep-02 `ok` +20 s -> 260; ep-02 `none` -> stays 280; ep-02 `stale` (offset 20 s ignored) -> 280."""
    manifest = [("s02", "t00", at(-40), at(250), "ep-01"), ("s02", "t00", at(-30), at(280), "ep-02")]
    ends = {}
    for name, spec in (("ok", cf.offsets_spec(ep_02=(20000, "ok", True))),
                       ("none", cf.offsets_spec(ep_02=(None, "none", True))),
                       ("stale", cf.offsets_spec(ep_02=(20000, "stale", True)))):
        repo = _simple_repo(tmp_path / name, ["s02_t00"], manifest, rows=tree_rows(0, 100), spec=spec)
        ends[name] = _run_one(repo, tmp_path / name)["rows"][0]["end_utc"]
    assert ends == {"ok": edge(260), "none": edge(280), "stale": edge(280)}


def test_tw64_raw_basis_reproduces_the_old_edges_and_leaves_the_clock_columns_empty(tmp_path):
    """TW-64 (spec 2.1, GTA-06): time_basis='raw' ignores the offsets (and needs no clock files): edges = the raw rule
    (first root - 60 s, last Sysmon 1 + 300 s, raw manifest clip); offsets_sha256, clock_changes_sha256, clock_flag and
    clock_change_in_window are empty; time_basis says raw. The default basis on the same repo gives the shifted window."""
    spec = cf.offsets_spec(ep_01=(7000, "ok", True), ep_03=(None, "none", True))
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100), spec=spec)
    raw = _run_one(repo, tmp_path, time_basis="raw")["rows"][0]
    assert raw["start_utc"] == edge(-60) and raw["end_utc"] == edge(400)
    assert raw["time_basis"] == "raw"
    assert [raw[c] for c in ("offsets_sha256", "clock_changes_sha256", "clock_flag", "clock_change_in_window")] == [""] * 4
    cor = _run_one(repo, tmp_path)["rows"][0]
    assert cor["start_utc"] == edge(-67) and cor["end_utc"] == edge(393) and cor["time_basis"] == "corrected"
    # no clock files at all: the raw basis still gives a window, the corrected basis skips with a reason
    bare = tmp_path / "bare"
    make_db(bare / "data" / "processed" / "s02_t00.sqlite3", tree_rows(0, 100))
    make_manifest(bare, WIDE_MANIFEST)
    assert [r["trial_id"] for r in _run_one(bare, tmp_path / "bare", time_basis="raw")["rows"]] == ["s02_t00"]
    miss = _run_one(bare, tmp_path / "bare")
    assert miss["rows"] == [] and "clock_offsets" in miss["skipped"]["s02_t00"]


def test_tw64b_raw_basis_still_refuses_quarantine_and_clock_only_trials(tmp_path):
    """TW-64b: the raw basis (GTA-06) skips the clock-file checks only; the id refusals stay."""
    repo = _simple_repo(tmp_path, ["s04_t01"], [("s04", "t01", at(-3600), at(3600))])
    res = tw_main.run(repo, ["s04_t01", "s05q_t01"], tmp_path / NO_OPERATOR, tmp_path / "w.csv", time_basis="raw")
    assert res["rows"] == [] and set(res["skipped"]) == {"s04_t01", "s05q_t01"}


def test_tw65_clock_columns_hashes_flag_and_change_flag(tmp_path):
    """TW-65 (spec 2.1): offsets_sha256 / clock_changes_sha256 are the SHA-256 of the files used; clock_flag = hosts with
    status none/wide/stale that have events, `;`-joined, sorted; a host without events is left out."""
    spec = cf.offsets_spec(ep_02=(2000, "wide", True), ep_03=(None, "none", True), ep_01=(5000, "stale", False))
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100), spec=spec)
    row = _run_one(repo, tmp_path)["rows"][0]
    assert row["offsets_sha256"] == sha(cf.offsets_path(repo, "s02_t00"))
    assert row["clock_changes_sha256"] == sha(cf.changes_path(repo, "s02_t00"))
    assert row["clock_flag"] == "ep-02;ep-03"


@pytest.mark.parametrize("classification,counted,expect", [
    ("between_pairs", True, "true"), ("after_last_pair", True, "true"), ("no_pairs", True, "true"),
    ("expected_before_first_pair", True, "false"), ("routine", False, "false"),
])
def test_tw66_clock_change_in_window_follows_the_classification(tmp_path, classification, counted, expect):
    """TW-66 (spec 2.1, spec 08 CO-19 as amended): true only for a counted change after a host's first pair or on a host
    with no pairs (between_pairs, after_last_pair, no_pairs); expected / routine changes never flag."""
    chg = cf.change("s02_t00", "ep-02", at(30), previous_time=at(20), new_time=at(30), shift_ms=10000, counted=counted,
                    classification=classification)
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100), changes=[chg])
    assert _run_one(repo, tmp_path)["rows"][0]["clock_change_in_window"] == expect


def test_tw66b_no_changes_file_rows_means_false(tmp_path):
    """TW-66b: an empty clock-changes file gives clock_change_in_window = false (not empty)."""
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100))
    assert _run_one(repo, tmp_path)["rows"][0]["clock_change_in_window"] == "false"


def _expect_skipped(res: dict, trial: str, *words: str) -> None:
    assert res["rows"] == [], res["rows"]
    assert trial in res["skipped"], res
    for w in words:
        assert w in res["skipped"][trial], f"{w!r} not in {res['skipped'][trial]!r}"
    assert trial not in res["edges"]


def test_tw67_refusals_write_no_row_and_say_why(tmp_path):
    """TW-67 (GTT-07 for trial_window): quarantine, clock-only, missing offsets file, missing clock-changes file, offsets
    computed from another DB, and CO-17 each give no row and a SKIPPED reason; a missing DB is still a hard error."""
    manifest = [("s02", "t00", at(-3600), at(3600)), ("s06", "t00", "2026-10-25T00:00:00.000000Z",
                                                      "2026-10-28T00:00:00.000000Z")]
    # missing offsets file
    repo = _simple_repo(tmp_path / "a", ["s02_t00"], manifest)
    cf.offsets_path(repo, "s02_t00").unlink()
    _expect_skipped(_run_one(repo, tmp_path / "a"), "s02_t00", "clock_offsets")
    # missing clock-changes file
    repo = _simple_repo(tmp_path / "b", ["s02_t00"], manifest)
    cf.changes_path(repo, "s02_t00").unlink()
    _expect_skipped(_run_one(repo, tmp_path / "b"), "s02_t00", "clock_changes")
    # offsets computed from another DB version
    repo = _simple_repo(tmp_path / "c", ["s02_t00"], manifest)
    cf.write_offsets(cf.offsets_path(repo, "s02_t00"), "s02_t00", "9" * 64)
    _expect_skipped(_run_one(repo, tmp_path / "c"), "s02_t00", "db_sha256")
    # clock-only and quarantine
    repo = _simple_repo(tmp_path / "d", ["s04_t01", "s05q_t01"], [("s04", "t01", at(-3600), at(3600)),
                                                                  ("s05q", "t01", at(-3600), at(3600))])
    res = tw_main.run(repo, ["s04_t01", "s05q_t01"], tmp_path / NO_OPERATOR, tmp_path / "w.csv")
    assert res["rows"] == [] and "clock-only" in res["skipped"]["s04_t01"].lower()
    assert "quarantine" in res["skipped"]["s05q_t01"].lower()
    # CO-17: a window starting on/after 2026-10-26 with a none host that has events
    late = _shifted_tree("2026-10-26T08:00:00Z")
    repo = _simple_repo(tmp_path / "e", ["s06_t00"], manifest, rows=late,
                        spec=cf.offsets_spec(ep_01=(None, "none", True)))
    _expect_skipped(_run_one(repo, tmp_path / "e", "s06_t00"), "s06_t00", "CO-17", "ep-01")
    # missing DB: hard error, even without clock files
    bare = tmp_path / "f" / "repo"
    make_manifest(bare, manifest)
    with pytest.raises(TrialWindowError, match="trial DB not found"):
        _run_one(bare, tmp_path / "f")


def _shifted_tree(first_root_utc: str, last_off: float = 100.0) -> list[dict]:
    """tree_rows moved so that the first root is at `first_root_utc` (all ep-01)."""
    delta = parse(first_root_utc) - BASE
    out = tree_rows(0, last_off)
    for r in out:
        r["t_utc"] = iso(parse(r["t_utc"]) + delta)
        r["ts"] = parse(r["t_utc"]).timestamp()
    return out


def test_tw68_co17_wide_runs_none_before_the_date_runs_flagged_after_it_refuses(tmp_path):
    """TW-68 (CO-17 / spec 2): on or after 2026-10-26 a `wide` host runs flagged; a `none` host WITH events refuses; before
    that date a `none` host runs with the flag. A `none` host without events never refuses."""
    manifest = [("s06", "t00", "2026-10-25T00:00:00.000000Z", "2026-10-28T00:00:00.000000Z")]
    after, before = _shifted_tree("2026-10-26T08:00:00Z"), _shifted_tree("2026-10-25T08:00:00Z")
    cases = {
        "wide_after": (after, cf.offsets_spec(ep_03=(3000, "wide", True)), True, "ep-03"),
        "none_after": (after, cf.offsets_spec(ep_03=(None, "none", True)), False, None),
        "stale_after": (after, cf.offsets_spec(ep_03=(3000, "stale", True)), False, None),
        "none_noevents_after": (after, cf.offsets_spec(ep_03=(None, "none", False)), True, ""),
        "none_before": (before, cf.offsets_spec(ep_03=(None, "none", True)), True, "ep-03"),
    }
    for name, (rows, spec, written, flag) in cases.items():
        repo = _simple_repo(tmp_path / name, ["s06_t00"], manifest, rows=rows, spec=spec)
        res = _run_one(repo, tmp_path / name, "s06_t00")
        assert bool(res["rows"]) is written, name
        if written:
            assert res["rows"][0]["clock_flag"] == flag, name
        else:
            assert "CO-17" in res["skipped"]["s06_t00"], name


def test_tw68b_co17_uses_the_corrected_window_start(tmp_path):
    """TW-68b (CO-17): the date is that of the window start. A root at 2026-10-26T00:01:30Z gives a start of 00:00:30 on
    10-26 -> refused with a `none` host; the same root on a host 40 s ahead is at 00:00:50 corrected, so the start is
    2026-10-25T23:59:50 -> runs, flagged."""
    manifest = [("s06", "t00", "2026-10-25T00:00:00.000000Z", "2026-10-28T00:00:00.000000Z")]
    rows = _shifted_tree("2026-10-26T00:01:30Z")
    spec0 = cf.offsets_spec(ep_03=(None, "none", True))
    repo = _simple_repo(tmp_path / "zero", ["s06_t00"], manifest, rows=rows, spec=spec0)
    _expect_skipped(_run_one(repo, tmp_path / "zero", "s06_t00"), "s06_t00", "CO-17")
    spec40 = cf.offsets_spec(ep_01=(40000, "ok", True), ep_03=(None, "none", True))
    repo = _simple_repo(tmp_path / "plus", ["s06_t00"], manifest, rows=rows, spec=spec40)
    row = _run_one(repo, tmp_path / "plus", "s06_t00")["rows"][0]
    assert row["start_utc"] == "2026-10-25T23:59:50.000Z" and row["clock_flag"] == "ep-03"


def test_tw69_run_never_writes_the_db_or_the_clock_files(tmp_path):
    """TW-69 (GTT-08 for trial_window): the DB, the offsets file and the clock-changes file are byte-identical after a run."""
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100),
                        spec=cf.offsets_spec(ep_01=(7000, "ok", True)))
    paths = [repo / "data" / "processed" / "s02_t00.sqlite3", cf.offsets_path(repo, "s02_t00"),
             cf.changes_path(repo, "s02_t00"), repo / "data" / "manifest.csv"]
    before = [sha(p) for p in paths]
    _run_one(repo, tmp_path)
    assert [sha(p) for p in paths] == before


# ====================================================================================== B. GTT-14

class _Recorder:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def add(self, target) -> None:
        if isinstance(target, int):
            return
        try:
            s = os.fsdecode(os.fspath(target))
        except TypeError:
            return
        if s.startswith("file:"):                     # sqlite URI: file:D:/x/y.sqlite3?mode=ro
            s = s[len("file:"):].split("?", 1)[0]
            if re.match(r"^/+[A-Za-z]:", s):
                s = s.lstrip("/")
        self.paths.append(s)


def _install_recorders(monkeypatch, rec: _Recorder) -> None:
    orig_open, orig_io_open, orig_os_open = builtins.open, io.open, os.open
    orig_connect = sqlite3.connect
    orig_popen, orig_rt, orig_rb = Path.open, Path.read_text, Path.read_bytes

    def w_open(file, *a, **k):
        rec.add(file)
        return orig_open(file, *a, **k)

    def w_io_open(file, *a, **k):
        rec.add(file)
        return orig_io_open(file, *a, **k)

    def w_os_open(path, *a, **k):
        rec.add(path)
        return orig_os_open(path, *a, **k)

    def w_connect(database, *a, **k):
        rec.add(database)
        return orig_connect(database, *a, **k)

    def w_p_open(self, *a, **k):
        rec.add(self)
        return orig_popen(self, *a, **k)

    def w_p_rt(self, *a, **k):
        rec.add(self)
        return orig_rt(self, *a, **k)

    def w_p_rb(self, *a, **k):
        rec.add(self)
        return orig_rb(self, *a, **k)

    monkeypatch.setattr(builtins, "open", w_open)
    monkeypatch.setattr(io, "open", w_io_open)
    monkeypatch.setattr(os, "open", w_os_open)
    monkeypatch.setattr(sqlite3, "connect", w_connect)
    monkeypatch.setattr(Path, "open", w_p_open)
    monkeypatch.setattr(Path, "read_text", w_p_rt)
    monkeypatch.setattr(Path, "read_bytes", w_p_rb)


def _under(path: str, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _synthetic_recorder_selfcheck(tmp_path, monkeypatch):
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    p = tmp_path / "x.txt"
    p.write_text("a", encoding="utf-8")
    with open(p, encoding="utf-8") as fh:
        fh.read()
    return rec, p


def test_gtt14_recorder_sees_opens(tmp_path, monkeypatch):
    """GTT-14 (self-check): the recording wrappers really record opens, so 'no ground_truth path' is meaningful."""
    rec, p = _synthetic_recorder_selfcheck(tmp_path, monkeypatch)
    assert any(Path(x) == p for x in rec.paths)


def test_gtt14_run_on_a_synthetic_repo_never_opens_ground_truth_and_reads_the_clock_files(tmp_path, monkeypatch):
    """GTT-14 (T6b.2): run() and main() on a temp repo with a decoy ground_truth/approved/s02_t00.yaml open no path under
    ground_truth/; the recorder DOES see the DB, the offsets file and the clock-changes file (so the check is meaningful)."""
    repo = _simple_repo(tmp_path, ["s02_t00"], WIDE_MANIFEST, rows=tree_rows(0, 100))
    gt = repo / "ground_truth" / "approved"
    gt.mkdir(parents=True)
    (gt / "s02_t00.yaml").write_text("decoy: true\n", encoding="utf-8")
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    res = tw_main.run(repo, ["s02_t00"], tmp_path / NO_OPERATOR, tmp_path / "a.csv")
    rc = tw_main.main(["--trials", "s02_t00", "--repo", str(repo), "--out", str(tmp_path / "b.csv")])
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00"] and rc in (0, None)
    names = {Path(x).name for x in rec.paths}
    assert {"s02_t00.sqlite3", "s02_t00.clock_offsets.csv", "s02_t00.clock_changes.csv", "manifest.csv"} <= names
    bad = [p for p in rec.paths if _under(p, repo / "ground_truth")]
    assert bad == [], f"trial_window opened ground_truth paths: {bad}"


@pytest.mark.slow
def test_gtt14a_run_never_opens_ground_truth_on_real_inputs(tmp_path, monkeypatch):
    """GTT-14a (spec 7): run() and main() on one real t00 trial open no path under ground_truth/."""
    db = PROCESSED / "s02_t00.sqlite3"
    if not db.exists():
        pytest.skip(f"{db} missing")
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    out1, out2 = tmp_path / "a.csv", tmp_path / "b.csv"
    res = tw_main.run(REPO, ["s02_t00"], REPO / "data" / "operator_times.csv", out1)
    rc = tw_main.main(["--trials", "s02_t00", "--repo", str(REPO), "--out", str(out2)])
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00"]
    assert rc in (0, None)
    assert any(Path(x).name == "s02_t00.sqlite3" for x in rec.paths), "recorder did not see the DB open"
    bad = [p for p in rec.paths if _under(p, REPO / "ground_truth")]
    assert bad == [], f"trial_window opened ground_truth paths: {bad}"
    assert out1.read_bytes() == out2.read_bytes()


def test_gtt14b_source_text_has_no_forbidden_strings():
    """GTT-14b: no src/trial_window/*.py mentions ground_truth, build_draft, intended_steps, owner_reviews, provisional_windows."""
    forbidden = ["ground_truth", "build_draft", "intended_steps", "owner_reviews", "provisional_windows"]
    files = sorted(SRC_TW.glob("*.py"))
    assert files, "src/trial_window has no python files"
    assert {"window.py", "params.py", "__main__.py"} <= {f.name for f in files}
    hits = [(f.name, s) for f in files for s in forbidden if s in f.read_text(encoding="utf-8")]
    assert hits == [], f"forbidden strings in trial_window source: {hits}"


def test_gtt14c_no_import_of_key_builder_finish_verify_overlap():
    """GTT-14c: no import of answer_key.build.build_draft, answer_key.finish, .verify or .overlap."""
    banned_mods = {"answer_key.finish", "answer_key.verify", "answer_key.overlap"}
    banned_leaf = {"finish", "verify", "overlap"}
    offenders: list[str] = []
    for f in sorted(SRC_TW.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in banned_mods:
                        offenders.append(f"{f.name}: import {a.name}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                names = {a.name for a in node.names}
                if mod in banned_mods:
                    offenders.append(f"{f.name}: from {mod}")
                if mod == "answer_key" and names & banned_leaf:
                    offenders.append(f"{f.name}: from answer_key import {sorted(names & banned_leaf)}")
                if mod == "answer_key.build" and "build_draft" in names:
                    offenders.append(f"{f.name}: from answer_key.build import build_draft")
                if node.level and mod in banned_leaf | {"build"} and ("build_draft" in names or mod in banned_leaf):
                    offenders.append(f"{f.name}: relative import {mod}")
    assert offenders == [], offenders


def test_gtt14d_gate_half_placeholder():
    """GTT-14d: the src/gate half is built in T6 6.2; same source scan once it exists."""
    gate = REPO / "src" / "gate"
    if not gate.exists():
        pytest.skip("src/gate not built yet (T6 6.2)")
    files = sorted(gate.glob("*.py"))
    assert files
    hits = [f.name for f in files if "ground_truth" in f.read_text(encoding="utf-8")]
    assert hits == [], f"src/gate mentions ground_truth: {hits}"


# ====================================================================================== C. GTA-06

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def collect_refs(obj, path: tuple[str, ...] = ()) -> list[str]:
    """Every 64-hex string anywhere under `obj` (repeats kept), skipping fields whose key path contains 'sha256'."""
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            found += collect_refs(v, path + (str(k),))
    elif isinstance(obj, list):
        for v in obj:
            found += collect_refs(v, path)
    elif isinstance(obj, str) and HEX64.match(obj):
        if not any("sha256" in q.lower() for q in path):
            found.append(obj)
    return found


def collect_uids(obj, path: tuple[str, ...] = ()) -> set[str]:
    """The DISTINCT event uids under `obj` (see `collect_refs`).

    GTA-06 checks every distinct uid; `refs` (the length of `collect_refs`) counts a uid once for every field
    that lists it, so refs >= distinct. Content hashes (key path containing 'sha256') are not event uids.
    """
    return set(collect_refs(obj, path))


def load_key(trial: str) -> dict:
    p = REPO / "ground_truth" / "approved" / f"{trial}.yaml"
    if not p.exists():
        pytest.skip(f"{p} missing")
    return json.loads(p.read_text(encoding="utf-8"))


def db_events(trial: str) -> dict[str, dict]:
    p = PROCESSED / f"{trial}.sqlite3"
    if not p.exists():
        pytest.skip(f"{p} missing")
    con = ak_db.open_ro(p)
    try:
        return {r["event_uid"]: {"uid": r["event_uid"], "host": r["host"], "event_id": r["event_id"],
                                 "t_utc": r["t_utc"]} for r in ak_db.query(con)}
    finally:
        con.close()


def _gta06_one(trial: str, out_dir: Path) -> dict:
    # RAW basis for this test only (spec 02_gate GTA-06, spec 08 4.1 item 6, owner Q7): the keys are in raw time.
    # Output goes to tmp_path: this test never touches data/trial_windows.csv.
    res = tw_main.run(REPO, [trial], REPO / "data" / "operator_times.csv", out_dir / f"{trial}.csv",
                      time_basis="raw")
    if trial not in res["edges"]:
        return {"trial": trial, "skipped": res["skipped"].get(trial, "no window")}
    assert res["rows"][0]["time_basis"] == "raw", "GTA-06 must run on the raw basis"
    e = res["edges"][trial]
    key = load_key(trial)
    ri = key["agent"]["run_interval"]
    events = db_events(trial)
    refs = collect_refs(key["hops"])
    uids = sorted(set(refs))
    missing = [u for u in uids if u not in events]
    lo, hi = parse(e.start_utc), parse(e.end_utc) + timedelta(milliseconds=1)
    outside = [events[u] for u in uids if u in events and not (lo <= parse(events[u]["t_utc"]) < hi)]
    end = parse(e.end_utc)
    gaps = [(end - parse(events[u]["t_utc"])).total_seconds() for u in uids if u in events]
    return {"trial": trial, "key_start": ri["start_utc"], "key_end": ri["end_utc"], "start": e.start_utc,
            "end": e.end_utc, "delta_end_s": (end - parse(ri["end_utc"])).total_seconds(),
            "min_gap_s": min(gaps) if gaps else None, "n_uids": len(uids), "n_refs": len(refs), "missing": missing, "outside": outside}


@pytest.fixture(scope="module")
def gta06(tmp_path_factory):
    """Computes all six trials once, prints the report and writes out/trial_window/gta06.md."""
    out_dir = tmp_path_factory.mktemp("gta06")
    results = {}
    for t in TRIALS:
        if not (PROCESSED / f"{t}.sqlite3").exists() or not (REPO / "ground_truth" / "approved" / f"{t}.yaml").exists():
            continue
        results[t] = _gta06_one(t, out_dir)
    lines = ["| trial | key start | key end | computed start | computed end | delta end s | min end gap s | "
             "key-hop uids (distinct) | key-hop refs | outside |", "|---|---|---|---|---|---|---|---|---|---|"]
    for t in TRIALS:
        r = results.get(t)
        if r is None:
            lines.append(f"| {t} | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |")
        elif "skipped" in r:
            lines.append(f"| {t} | n/a | n/a | SKIPPED: {r['skipped']} | n/a | n/a | n/a | n/a | n/a | n/a |")
        else:
            lines.append(f"| {t} | {r['key_start']} | {r['key_end']} | {r['start']} | {r['end']} | "
                         f"{r['delta_end_s']:+.3f} | {r['min_gap_s']:.1f} | {r['n_uids']} | {r['n_refs']} | "
                         f"{len(r['outside'])} |")
    table = "\n".join(lines)
    print("\nGTA-06 report (report-only: end difference, smallest end gap)\n" + table)
    dest = REPO / "out" / "trial_window" / "gta06.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("# GTA-06 window start and containment (decision 040), RAW basis\n\n"
                    "Computed from the agent process tree on raw times (the keys are in raw time); the key is read by "
                    "the test only. "
                    "End difference and min end gap are report-only. The check uses distinct uids; refs counts "
                    "every listing (a uid in two fields counts twice).\n\n" + table + "\n", encoding="utf-8")
    return results


def _need(gta06: dict, trial: str) -> dict:
    if trial not in gta06:
        pytest.skip(f"real data or approved key for {trial} missing")
    r = gta06[trial]
    assert "skipped" not in r, f"{trial}: no window written: {r.get('skipped')}"
    return r


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta06_1_start_equals_key_run_interval_start(gta06, trial):
    """GTA-06 (1): computed start == the approved key's agent.run_interval start, to the millisecond."""
    r = _need(gta06, trial)
    assert r["start"] == r["key_start"], f"{trial}: computed start {r['start']} != key {r['key_start']}"


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta06_2_every_key_hop_event_inside_window(gta06, trial):
    """GTA-06 (2, pass/fail): every event the key's hops reference exists in the DB and lies in start <= t < end + 1 ms."""
    r = _need(gta06, trial)
    assert r["n_refs"] >= r["n_uids"] > 0, f"{trial}: refs {r['n_refs']} / distinct {r['n_uids']} under the key's hops"
    assert r["missing"] == [], f"{trial}: key hop uids absent from the DB: {r['missing']}"
    detail = "\n".join(f"  uid={o['uid']} host={o['host']} event_id={o['event_id']} t_utc={o['t_utc']}"
                       for o in r["outside"])
    assert r["outside"] == [], (f"{trial}: {len(r['outside'])} key-hop event(s) outside the computed window\n{detail}\n"
                                f"  computed: {r['start']} .. {r['end']}\n  key     : {r['key_start']} .. {r['key_end']}")


@pytest.mark.slow
@pytest.mark.parametrize("trial", TRIALS)
def test_gta06_3_report_end_difference_and_min_gap(gta06, trial):
    """GTA-06 (3, report only): prints the end difference and the smallest key-hop-to-end gap. No value is asserted."""
    r = _need(gta06, trial)
    print(f"{trial}: delta_end_s={r['delta_end_s']:+.3f} min_end_gap_s={r['min_gap_s']:.3f} "
          f"key_hop_uids={r['n_uids']} refs={r['n_refs']} outside={len(r['outside'])}")
    assert r["min_gap_s"] is not None


@pytest.mark.slow
def test_gta06_report_file_holds_six_rows(gta06):
    """GTA-06 (report): out/trial_window/gta06.md has one row per trial."""
    text = (REPO / "out" / "trial_window" / "gta06.md").read_text(encoding="utf-8")
    for t in TRIALS:
        assert f"| {t} |" in text


@pytest.mark.slow
def test_gta06_runs_on_the_raw_basis_and_never_writes_the_real_window_file(gta06):
    """GTA-06 (T6b.2): every result came from a raw-basis window, and the run left data/trial_windows.csv alone (it still
    holds the corrected basis written by the owner step)."""
    assert gta06, "no GTA-06 result"
    path = REPO / "data" / "trial_windows.csv"
    if path.exists():
        with open(path, newline="", encoding="utf-8") as fh:
            bases = {r["time_basis"] for r in csv.DictReader(fh)}
        assert bases <= {"corrected"}, f"data/trial_windows.csv holds {bases}: a raw-basis run wrote it"


@pytest.mark.slow
def test_tw70_a_fresh_corrected_run_reproduces_data_trial_windows_csv(tmp_path):
    """The window file in data/ is what `trial_window` writes today on the corrected basis from the current DBs, clock
    files and manifest (written to tmp_path; the real file is only read)."""
    real = REPO / "data" / "trial_windows.csv"
    if not real.exists() or not all((PROCESSED / f"{t}.sqlite3").exists() for t in TRIALS):
        pytest.skip("data/trial_windows.csv or a t00 DB is missing")
    out = tmp_path / "w.csv"
    res = tw_main.run(REPO, TRIALS, REPO / "data" / "operator_times.csv", out)
    assert res["skipped"] == {}, res["skipped"]
    assert out.read_bytes() == real.read_bytes()
    with open(out, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0]) == EXPECTED_COLUMNS
    for r in rows:
        assert r["time_basis"] == "corrected"
        assert r["offsets_sha256"] == sha(cf.offsets_path(REPO, r["trial_id"]))
        assert r["clock_changes_sha256"] == sha(cf.changes_path(REPO, r["trial_id"]))
        assert r["db_sha256"] == sha(PROCESSED / f"{r['trial_id']}.sqlite3")
        assert r["start_host"] and r["end_host"], r["trial_id"]
