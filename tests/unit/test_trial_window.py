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

from answer_key import build as ak_build  # noqa: E402
from answer_key import db as ak_db  # noqa: E402
from trial_window import __main__ as tw_main  # noqa: E402
from trial_window import params, window  # noqa: E402

PROCESSED = REPO / "data" / "processed"
SRC_TW = REPO / "src" / "trial_window"
TRIALS = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"]
SPLUNKD = r"C:\Users\Public\splunkd.exe"
EDGE_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
EXPECTED_COLUMNS = ["trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s",
                    "rule", "db_sha256", "time_basis"]


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


# ------------------------------------------------------------------------------------------ refusal

def test_tw20_refusal_t00_before_cutoff_is_allowed():
    """TW-20 (spec 2.2): a t00 trial starting before 2026-10-26 gets a window."""
    assert window.refusal("s04_t00", "2026-09-24T10:52:55.893Z") is None


def test_tw21_refusal_non_t00_refused():
    """TW-21 (spec 2.2, GTT-07): while no correction exists, every non-t00 trial is refused."""
    reason = window.refusal("s02_t01", "2026-09-24T05:00:00.000Z")
    assert reason and isinstance(reason, str)


def test_tw22_refusal_cutoff_date_boundary():
    """TW-22 (spec 2.2): a window starting on 2026-10-26T00:00:00.000Z is refused, 2026-10-25T23:59:59.999Z is not."""
    assert window.refusal("s04_t00", "2026-10-26T00:00:00.000Z")
    assert window.refusal("s04_t00", "2026-10-25T23:59:59.999Z") is None
    assert window.refusal("s06_t00", "2026-10-27T08:00:00.000Z")


def test_tw23_refusal_start_none_runs_only_window_free_checks():
    """TW-23: start None -> only the id checks apply (t00 passes, non-t00 is refused)."""
    assert window.refusal("s02_t00", None) is None
    assert window.refusal("s02_t05", None)


def test_tw24_refusal_quarantine_by_trial_id():
    """TW-24 (spec 2, decision 030): s05q_* is refused."""
    assert window.refusal("s05q_t01", "2026-10-12T07:00:00.000Z")
    assert window.refusal("s05q_t00", "2026-10-12T07:00:00.000Z")


def test_tw25_refusal_with_clock_correction_only_quarantine_stays():
    """TW-25 (spec 2.2): with a correction available the non-t00 and date reasons go; quarantine stays."""
    assert window.refusal("s02_t01", "2026-09-24T05:00:00.000Z", clock_correction_available=True) is None
    assert window.refusal("s04_t05", "2026-10-26T04:00:00.000Z", clock_correction_available=True) is None
    assert window.refusal("s05q_t01", "2026-10-12T07:00:00.000Z", clock_correction_available=True)


def test_tw26_refusal_cutoff_date_is_a_parameter():
    """TW-26: the cutoff date argument is honoured."""
    assert window.refusal("s02_t00", "2026-09-24T05:00:00.000Z", raw_time_cutoff_date=date(2026, 9, 24))
    assert window.refusal("s02_t00", "2026-09-23T23:59:59.999Z", raw_time_cutoff_date=date(2026, 9, 24)) is None


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
    """TW-31 (spec 2.1): the header is exactly the nine documented columns in order."""
    assert list(params.COLUMNS) == EXPECTED_COLUMNS


def test_tw32_window_row_keys_margins_basis():
    """TW-32 (spec 2.1, 5): window_row has exactly COLUMNS; margins 60/300; time_basis raw."""
    row = window.window_row("s02_t00", _result(), "computed_agent_run", "rule text", "ab" * 32)
    assert list(row) == EXPECTED_COLUMNS
    assert row["trial_id"] == "s02_t00"
    assert (int(row["margin_start_s"]), int(row["margin_end_s"])) == (60, 300)
    assert row["time_basis"] == "raw"
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
    assert all(r[4] == "60" and r[5] == "300" and r[8] == "raw" for r in body)


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
    assert params.TIME_BASIS == "raw"
    assert params.CLOCK_CORRECTION_AVAILABLE is False
    assert params.RAW_TIME_CUTOFF_DATE == date(2026, 10, 26)
    assert params.AGENT_IMAGE == r"C:\Users\Public\splunkd.exe"
    assert params.AGENT_SERVER == "192.168.50.50:8888"
    assert list(params.DEFAULT_TRIALS) == TRIALS


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


def make_manifest(repo: Path, entries: list[tuple[str, str, str, str]]) -> None:
    """entries: (scenario, trial, first_event_utc, last_event_utc)."""
    (repo / "data").mkdir(parents=True, exist_ok=True)
    with open(repo / "data" / "manifest.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MANIFEST_COLS, lineterminator="\n")
        w.writeheader()
        for sc, tr, a, b in entries:
            w.writerow({"path": f"{sc}/{tr}/ep-01/sysmon.evtx", "sha256": "0" * 64, "size": 1, "scenario": sc,
                        "trial": tr, "host": "ep-01", "channel": "sysmon", "source_path": "x", "date": "2026-09-24",
                        "records": 1, "first_event_utc": a, "last_event_utc": b})


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def temp_repo(tmp_path):
    repo = tmp_path / "repo"
    proc = repo / "data" / "processed"
    # good t00 trial in September
    make_db(proc / "s02_t00.sqlite3", tree_rows(0, 100))
    # t01 (refused: not t00), quarantine id, t00 starting on the cutoff date, t00 with no agent root, S01
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
                         ("s03", "t00", at(-3600), at(3600)), ("s01", "t00", at(-3600), at(3600))])
    return repo


def test_tw40_run_refusals_skip_with_reason_and_write_no_row(temp_repo, tmp_path):
    """TW-40 (spec 2, GTT-07): refused trials write no row and appear in `skipped` with a reason."""
    out = tmp_path / "out" / "trial_windows.csv"
    trials = ["s02_t00", "s02_t01", "s05q_t01", "s04_t00", "s03_t00", "s01_t00"]
    res = tw_main.run(temp_repo, trials, tmp_path / "no_operator_file.csv", out)
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00"]
    assert set(res["skipped"]) == {"s02_t01", "s05q_t01", "s04_t00", "s03_t00", "s01_t00"}
    assert all(isinstance(v, str) and v for v in res["skipped"].values())
    assert set(res["edges"]) == {"s02_t00"}
    with open(out, newline="", encoding="utf-8") as fh:
        written = list(csv.DictReader(fh))
    assert [r["trial_id"] for r in written] == ["s02_t00"]
    assert list(written[0]) == EXPECTED_COLUMNS
    row = written[0]
    assert row["window_source"] == "computed_agent_run"
    assert row["start_utc"] == edge(-60) and row["end_utc"] == edge(400)
    assert row["db_sha256"] == sha(temp_repo / "data" / "processed" / "s02_t00.sqlite3")
    assert row["time_basis"] == "raw" and row["margin_start_s"] == "60" and row["margin_end_s"] == "300"
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


def test_tw43_run_s01_without_operator_file_is_skipped(temp_repo, tmp_path):
    """TW-43 (spec 2.1): S01 has no agent; without an operator-recorded start/end it is skipped with a reason."""
    res = tw_main.run(temp_repo, ["s01_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert res["rows"] == []
    assert res["skipped"]["s01_t00"]


def test_tw44_run_s01_with_operator_file_uses_operator_source(temp_repo, tmp_path):
    """TW-44 (spec 2.1): S01 row has window_source == operator, start - 60 s, end + 300 s."""
    ops = tmp_path / "operator_times.csv"
    ops.write_text("trial_id,start_utc,end_utc\ns01_t00,2026-09-24T05:10:00.000Z,2026-09-24T05:20:00.000Z\n",
                   encoding="utf-8")
    out = tmp_path / "o.csv"
    res = tw_main.run(temp_repo, ["s01_t00"], ops, out)
    assert [r["trial_id"] for r in res["rows"]] == ["s01_t00"]
    row = res["rows"][0]
    assert row["window_source"] == "operator"
    assert row["start_utc"] == "2026-09-24T05:09:00.000Z"
    assert row["end_utc"] == "2026-09-24T05:25:00.000Z"
    assert res["skipped"] == {}


def test_tw45_run_rows_sorted_by_trial_id(temp_repo, tmp_path):
    """TW-45: output rows are sorted by trial id whatever the order asked for."""
    make_db(temp_repo / "data" / "processed" / "s06_t00.sqlite3", tree_rows(0, 100))
    make_manifest(temp_repo, [("s02", "t00", at(-3600), at(3600)), ("s06", "t00", at(-3600), at(3600))])
    res = tw_main.run(temp_repo, ["s06_t00", "s02_t00"], tmp_path / "none.csv", tmp_path / "o.csv")
    assert [r["trial_id"] for r in res["rows"]] == ["s02_t00", "s06_t00"]


def test_tw46_main_cli_flags_write_the_out_file(temp_repo, tmp_path, capsys):
    """TW-46: main(argv) with --trials --repo --operator-times --out writes the CSV and exits 0."""
    out = tmp_path / "cli" / "w.csv"
    rc = tw_main.main(["--trials", "s02_t00", "s02_t01", "--repo", str(temp_repo),
                       "--operator-times", str(tmp_path / "none.csv"), "--out", str(out)])
    assert rc in (0, None)
    with open(out, newline="", encoding="utf-8") as fh:
        assert [r["trial_id"] for r in csv.DictReader(fh)] == ["s02_t00"]
    assert "s02_t01" in capsys.readouterr().out      # a skipped trial is reported, not silently dropped


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


def collect_uids(obj, path: tuple[str, ...] = ()) -> set[str]:
    """Every 64-hex string anywhere under `obj`, skipping fields whose key path contains 'sha256'."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            found |= collect_uids(v, path + (str(k),))
    elif isinstance(obj, list):
        for v in obj:
            found |= collect_uids(v, path)
    elif isinstance(obj, str) and HEX64.match(obj):
        if not any("sha256" in p.lower() for p in path):
            found.add(obj)
    return found


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
    res = tw_main.run(REPO, [trial], REPO / "data" / "operator_times.csv", out_dir / f"{trial}.csv")
    if trial not in res["edges"]:
        return {"trial": trial, "skipped": res["skipped"].get(trial, "no window")}
    e = res["edges"][trial]
    key = load_key(trial)
    ri = key["agent"]["run_interval"]
    events = db_events(trial)
    uids = sorted(collect_uids(key["hops"]))
    missing = [u for u in uids if u not in events]
    lo, hi = parse(e.start_utc), parse(e.end_utc) + timedelta(milliseconds=1)
    outside = [events[u] for u in uids if u in events and not (lo <= parse(events[u]["t_utc"]) < hi)]
    end = parse(e.end_utc)
    gaps = [(end - parse(events[u]["t_utc"])).total_seconds() for u in uids if u in events]
    return {"trial": trial, "key_start": ri["start_utc"], "key_end": ri["end_utc"], "start": e.start_utc,
            "end": e.end_utc, "delta_end_s": (end - parse(ri["end_utc"])).total_seconds(),
            "min_gap_s": min(gaps) if gaps else None, "n_uids": len(uids), "missing": missing, "outside": outside}


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
             "key-hop uids | outside |", "|---|---|---|---|---|---|---|---|---|"]
    for t in TRIALS:
        r = results.get(t)
        if r is None:
            lines.append(f"| {t} | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a |")
        elif "skipped" in r:
            lines.append(f"| {t} | n/a | n/a | SKIPPED: {r['skipped']} | n/a | n/a | n/a | n/a | n/a |")
        else:
            lines.append(f"| {t} | {r['key_start']} | {r['key_end']} | {r['start']} | {r['end']} | "
                         f"{r['delta_end_s']:+.3f} | {r['min_gap_s']:.1f} | {r['n_uids']} | {len(r['outside'])} |")
    table = "\n".join(lines)
    print("\nGTA-06 report (report-only: end difference, smallest end gap)\n" + table)
    dest = REPO / "out" / "trial_window" / "gta06.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("# GTA-06 window start and containment (decision 040)\n\n"
                    "Computed from the agent process tree; the key is read by the test only. "
                    "End difference and min end gap are report-only.\n\n" + table + "\n", encoding="utf-8")
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
    assert r["n_uids"] > 0, f"{trial}: no event uid found under the key's hops"
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
          f"key_hop_uids={r['n_uids']} outside={len(r['outside'])}")
    assert r["min_gap_s"] is not None


@pytest.mark.slow
def test_gta06_report_file_holds_six_rows(gta06):
    """GTA-06 (report): out/trial_window/gta06.md has one row per trial."""
    text = (REPO / "out" / "trial_window" / "gta06.md").read_text(encoding="utf-8")
    for t in TRIALS:
        assert f"| {t} |" in text
