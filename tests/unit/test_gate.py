"""Unit tests for the gate stage (T6 stage B), written from docs/specs/02_gate.md (section 7, GTT-01 .. GTT-14)
and docs/decisions/041-gate-implementation-readings.md, never from the implementation.

Every test builds a small synthetic SQLite DB in tmp_path (table `events` + real row_number dedup view
`events_dedup`), writes a one-row `trial_windows.csv`, runs `gate.run.run_gate` (or `gate.__main__.main`) and reads
the written CSV / JSON files back. No real trial data is touched. No slow tests here.

Test names carry the spec id (gtt05_...) or `d041_...` for the decision 041 readings.
"""
from __future__ import annotations

import ast
import builtins
import csv
import hashlib
import io
import itertools
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from gate import params as gparams  # noqa: E402
from gate.__main__ import main as gate_main  # noqa: E402
from gate.inputs import GateError  # noqa: E402
from gate.run import run_gate  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clock_fixtures as cf  # noqa: E402

SRC_GATE = REPO / "src" / "gate"
SRC_LAB_COMMON = REPO / "src" / "lab_common"
OUT_3389_REASON = "outbound 3389, source side of an RDP connection"   # spec 3 / GT-05, literal

# ------------------------------------------------------------------------------------------ spec literals
CLOCK_COLUMNS = ["clock_flag", "clock_change_in_window", "clock_unreliable"]    # spec 3 (T6b.2, decision 043)
SPEC_TRIGGER_COLUMNS = [
    "trigger_id", "rule", "host", "event_utc", "event_utc_corrected", "trigger_event_uid", "anchor_logon_uid",
    "target_logon_id", "target_logon_id_hex", "logon_type", "source_ip", "ip_kind", "account_name", "domain_short",
    "authentication_package", "machine_account", "supporting_event_uids", "method", "candidate_count",
    "time_delta_ms", "gate_tier", "near_duplicate", "window_source", "time_basis",
] + CLOCK_COLUMNS
SPEC_UNMATCHED_COLUMNS = [c for c in SPEC_TRIGGER_COLUMNS if c != "rule"]
SPEC_DISPOSITION_COLUMNS = ["event_uid", "host", "event_id", "event_utc", "disposition", "reason_detail",
                            "anchor_logon_uid", "event_utc_corrected"] + CLOCK_COLUMNS
SPEC_SUPPORTING_COLUMNS = ["rule", "event_uid", "host", "event_utc", "account_name", "session_id",
                           "event_utc_corrected"] + CLOCK_COLUMNS
SPEC_DISPOSITIONS = ["excluded_source_ip", "excluded_source_ip_session", "interactive_logon", "system_logon_id",
                     "loopback_or_self", "paired_excluded", "trigger", "supporting", "unmatched_remote", "no_rule"]
SPEC_METHODS = {"logon_id", "ip_port_time", "ip_time", "none"}
WINDOW_COLUMNS = ["trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s", "rule",
                  "db_sha256", "time_basis", "offsets_sha256", "clock_changes_sha256", "clock_flag",
                  "clock_change_in_window", "start_host", "end_host"]       # spec 2.1 (T6b.2, decision 043)
OUTPUT_FILES = ["triggers.csv", "unmatched_remote.csv", "dispositions.csv", "supporting.csv", "stats.json",
                "report.md", "run_info.json"]

# The schema columns the gate reads (spec section 2) plus the columns the dedup view / trial need.
EVENT_COLUMNS = [
    "event_uid", "host", "channel", "event_id", "record_id", "event_utc", "logon_type", "source_ip", "source_port",
    "destination_ip", "destination_port", "initiated", "account_name", "domain_short", "target_logon_id", "target_linked_logon_id",
    "subject_logon_id", "session_id", "machine_account", "authentication_package", "image", "parent_image",
    "share_name", "relative_target_name", "service_name", "service_image_path", "target_image", "granted_access",
    "subject_account", "duplicate_content_sha256", "source_relative_path", "source_line", "timestamp_utc", "trial_id",
]
INT_COLUMNS = {"event_id", "record_id", "logon_type", "source_port", "destination_port", "initiated",
               "target_logon_id", "target_linked_logon_id", "subject_logon_id", "session_id", "machine_account",
               "source_line"}

UTC = timezone.utc
T0 = datetime(2026, 9, 24, 10, 30, 0, tzinfo=UTC)
WIN_START = "2026-09-24T10:00:00.000Z"
WIN_END = "2026-09-24T11:00:00.000Z"
TRIAL = "s02_t00"
EXCLUDED_IPS = ["192.168.50.97", "192.168.50.98", "192.168.50.99"]
WSM = r"C:\Windows\System32\wsmprovhost.exe"
LSASS = r"C:\Windows\System32\lsass.exe"


# ------------------------------------------------------------------------------------------ time helpers
def parse(text: str) -> datetime:
    """Independent ISO parser for `...Z` / `...+00:00` strings with any number of fractional digits."""
    m = re.fullmatch(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?(?:Z|\+00:00)", text)
    assert m, f"unexpected time format {text!r}"
    y, mo, d, h, mi, s, frac = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=UTC)


def iso6(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def at(off_s: float) -> str:
    """DB time string `off_s` seconds after T0 (10:30:00), 6 fraction digits like the real DB."""
    return iso6(T0 + timedelta(microseconds=int(round(off_s * 1_000_000))))


# ------------------------------------------------------------------------------------------ event builders
_seq = itertools.count(1)


def ev(uid: str, event_id: int, channel: str, off: float | None = None, *, host: str = "ep-02",
       utc: str | None = None, **kw) -> dict:
    r: dict = dict.fromkeys(EVENT_COLUMNS)
    t = utc if utc is not None else at(off)
    n = next(_seq)
    r.update(event_uid=uid, host=host, channel=channel, event_id=event_id, record_id=n, event_utc=t,
             machine_account=0, duplicate_content_sha256=hashlib.sha256(uid.encode()).hexdigest(),
             source_relative_path=f"{host}/{channel}.jsonl", source_line=n, timestamp_utc=t, trial_id=TRIAL)
    r.update(kw)
    return r


def logon(uid, off, lid, *, ltype=3, ip="192.168.50.21", port=50000, host="ep-02", account="svc_backup",
          domain="LAB", pkg="NTLM", linked=None, **kw) -> dict:
    machine = 1 if (account or "").endswith("$") else 0
    return ev(uid, 4624, "Security", off, host=host, logon_type=ltype, source_ip=ip, source_port=port,
              target_logon_id=lid, target_linked_logon_id=linked, account_name=account, domain_short=domain,
              authentication_package=pkg, machine_account=machine, **kw)


def share(uid, off, lid, eid=5145, *, host="ep-02", **kw) -> dict:
    return ev(uid, eid, "Security", off, host=host, subject_logon_id=lid, share_name="C$",
              relative_target_name="x.txt", **kw)


def svc4697(uid, off, lid, name="PSEXESVC", *, host="ep-02", **kw) -> dict:
    return ev(uid, 4697, "Security", off, host=host, subject_logon_id=lid, service_name=name,
              service_image_path=rf"%SystemRoot%\{name}.exe", **kw)


def svc7045(uid, off, name="PSEXESVC", *, host="ep-02", **kw) -> dict:
    return ev(uid, 7045, "System", off, host=host, service_name=name,
              service_image_path=rf"%SystemRoot%\{name}.exe", **kw)


def wsm(uid, off, sid, *, host="ep-02", image=WSM, parent=r"C:\Windows\System32\svchost.exe", **kw) -> dict:
    return ev(uid, 1, "Sysmon", off, host=host, session_id=sid, image=image, parent_image=parent, **kw)


def w91(uid, off, ip, *, host="ep-02", **kw) -> dict:
    return ev(uid, 91, "WinRM", off, host=host, source_ip=ip, **kw)


def s3(uid, off, ip, port, *, host="ep-02", dport=3389, initiated=0, **kw) -> dict:
    return ev(uid, 3, "Sysmon", off, host=host, source_ip=ip, source_port=port, destination_port=dport,
              initiated=initiated, **kw)


def noise(uid="NOISE", off=5.0) -> dict:
    return ev(uid, 1, "Sysmon", off, image=r"C:\Windows\notepad.exe", parent_image=r"C:\Windows\explorer.exe")


# ------------------------------------------------------------------------------------------ DB / window / run
def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_db(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    cols = ", ".join(f'"{c}" ' + ("INTEGER" if c in INT_COLUMNS else "TEXT") for c in EVENT_COLUMNS)
    con = sqlite3.connect(str(path))
    try:
        con.execute(f'CREATE TABLE events ({cols}, PRIMARY KEY ("event_uid"))')
        con.execute(
            "CREATE VIEW events_dedup AS SELECT * FROM (SELECT e.*, row_number() OVER ("
            "PARTITION BY duplicate_content_sha256 ORDER BY source_relative_path, source_line) AS _rn "
            "FROM events e) WHERE _rn = 1")
        marks = ", ".join("?" for _ in EVENT_COLUMNS)
        con.executemany(f"INSERT INTO events VALUES ({marks})",
                        [tuple(r.get(c) for c in EVENT_COLUMNS) for r in rows])
        con.commit()
    finally:
        con.close()


def write_windows(path: Path, row: dict | None, other_trial: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=WINDOW_COLUMNS)
        w.writeheader()
        if other_trial:
            w.writerow({"trial_id": "s03_t00", "start_utc": WIN_START, "end_utc": WIN_END,
                        "window_source": "computed_agent_run", "margin_start_s": 60, "margin_end_s": 300,
                        "rule": "other", "db_sha256": "0" * 64, "time_basis": "corrected",
                        "offsets_sha256": "0" * 64, "clock_changes_sha256": "0" * 64, "clock_flag": "",
                        "clock_change_in_window": "false", "start_host": "", "end_host": ""})
        if row is not None:
            w.writerow(row)


@dataclass
class Case:
    repo: Path
    trial: str
    db: Path
    windows: Path
    out_root: Path
    # What make_case wrote, so `refresh` can rebuild the clock files and the window row after a change.
    offsets: dict | None = None
    changes: list | None = None
    window_kw: dict | None = None

    @property
    def out_dir(self) -> Path:
        return self.out_root / self.trial

    @property
    def offsets_file(self) -> Path:
        return cf.offsets_path(self.repo, self.trial)

    @property
    def changes_file(self) -> Path:
        return cf.changes_path(self.repo, self.trial)

    def refresh(self, **row_overrides) -> None:
        """Rewrite offsets + changes files for the CURRENT db bytes and the window row from the files on disk.
        `row_overrides` replace window-row cells (e.g. db_sha256 to keep an old one)."""
        db_sha = sha256_of(self.db)
        o_sha, c_sha = cf.write_clock_files(self.repo, self.trial, db_sha, self.offsets, self.changes)
        kw = dict(self.window_kw or {})
        row = {"trial_id": self.trial, "start_utc": kw.get("start", WIN_START), "end_utc": kw.get("end", WIN_END),
               "window_source": kw.get("window_source", "computed_agent_run"), "margin_start_s": 60,
               "margin_end_s": 300, "rule": "synthetic test window", "db_sha256": db_sha,
               "time_basis": kw.get("time_basis", "corrected"), "offsets_sha256": o_sha,
               "clock_changes_sha256": c_sha, "clock_flag": kw.get("clock_flag", ""),
               "clock_change_in_window": kw.get("clock_change_in_window", "false"),
               "start_host": kw.get("start_host", ""), "end_host": kw.get("end_host", "")}
        row.update(row_overrides)
        write_windows(self.windows, row)

    def run(self, **kw) -> "Out":
        run_gate(self.trial, self.db, self.windows, self.out_root, repo=self.repo, **kw)
        return Out(self.out_dir)

    def run_raw(self, **kw) -> dict:
        return run_gate(self.trial, self.db, self.windows, self.out_root, repo=self.repo, **kw)

    def cli(self, extra: list[str] | None = None) -> int:
        argv = ["--trial", self.trial, "--db", str(self.db), "--windows", str(self.windows),
                "--out", str(self.out_root), "--repo", str(self.repo)] + (extra or [])
        return gate_main(argv)


def make_case(tmp_path: Path, rows: list[dict] | None, trial: str = TRIAL, *, start: str = WIN_START,
              end: str = WIN_END, sha: str | None = None, time_basis: str = "corrected",
              window_source: str = "computed_agent_run", db_subdir: str = "", omit_row: bool = False,
              no_windows_file: bool = False, no_db: bool = False, name: str = "repo",
              offsets: dict | None = None, changes: list | None = None, clock_flag: str = "",
              clock_change_in_window: str = "false", start_host: str = "", end_host: str = "",
              no_offsets_file: bool = False, no_changes_file: bool = False, offsets_db_sha: str | None = None,
              row_offsets_sha: str | None = None, row_changes_sha: str | None = None) -> Case:
    """A temp repo with one synthetic trial: DB, valid clock files (ZERO offsets by default, every host `ok`) and a
    window row on the corrected basis with matching SHA-256 values. Keyword arguments break one thing at a time."""
    repo = tmp_path / name
    db = repo / "data" / "processed" / db_subdir / f"{trial}.sqlite3" if db_subdir else         repo / "data" / "processed" / f"{trial}.sqlite3"
    windows = repo / "data" / "trial_windows.csv"
    offsets = cf.default_offsets() if offsets is None else offsets
    case = Case(repo, trial, db, windows, repo / "out" / "gate", offsets, changes,
                dict(start=start, end=end, window_source=window_source, time_basis=time_basis,
                     clock_flag=clock_flag, clock_change_in_window=clock_change_in_window,
                     start_host=start_host, end_host=end_host))
    if not no_db:
        write_db(db, rows if rows else [noise()])
    db_sha = sha256_of(db) if db.exists() else "0" * 64
    o_sha = c_sha = "0" * 64
    if not no_offsets_file:
        o_sha = cf.write_offsets(cf.offsets_path(repo, trial), trial, offsets_db_sha or db_sha, offsets)
    if not no_changes_file:
        c_sha = cf.write_changes(cf.changes_path(repo, trial), changes)
    if not no_windows_file:
        row = None if omit_row else {
            "trial_id": trial, "start_utc": start, "end_utc": end, "window_source": window_source,
            "margin_start_s": 60, "margin_end_s": 300, "rule": "synthetic test window",
            "db_sha256": sha if sha is not None else db_sha, "time_basis": time_basis,
            "offsets_sha256": row_offsets_sha if row_offsets_sha is not None else o_sha,
            "clock_changes_sha256": row_changes_sha if row_changes_sha is not None else c_sha,
            "clock_flag": clock_flag, "clock_change_in_window": clock_change_in_window,
            "start_host": start_host, "end_host": end_host}
        write_windows(windows, row)
    return case


def go(tmp_path: Path, rows: list[dict], **kw) -> "Out":
    return make_case(tmp_path, rows, **kw).run()


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


class Out:
    def __init__(self, d: Path) -> None:
        self.dir = d
        self.trig = read_csv(d / "triggers.csv")
        self.unm = read_csv(d / "unmatched_remote.csv")
        self.disp = read_csv(d / "dispositions.csv")
        self.sup = read_csv(d / "supporting.csv")
        self.stats = json.loads((d / "stats.json").read_text(encoding="utf-8"))

    def rule(self, rule: str) -> list[dict]:
        return [r for r in self.trig if r["rule"] == rule]

    def one(self, rule: str) -> dict:
        rows = self.rule(rule)
        assert len(rows) == 1, f"expected exactly one {rule} row, got {len(rows)}: {rows}"
        return rows[0]

    def d(self, uid: str) -> dict:
        rows = [r for r in self.disp if r["event_uid"] == uid]
        assert len(rows) == 1, f"expected exactly one dispositions row for {uid}, got {len(rows)}"
        return rows[0]

    def has_d(self, uid: str) -> bool:
        return any(r["event_uid"] == uid for r in self.disp)

    def unm_uids(self) -> set[str]:
        return {r["trigger_event_uid"] for r in self.unm} | {r["anchor_logon_uid"] for r in self.unm
                                                              if r["anchor_logon_uid"]}

    def trig_uids(self) -> set[str]:
        return {r["trigger_event_uid"] for r in self.trig} | {r["anchor_logon_uid"] for r in self.trig
                                                               if r["anchor_logon_uid"]}

    def all_text(self) -> str:
        return "\n".join((self.dir / f).read_text(encoding="utf-8") for f in OUTPUT_FILES if f != "run_info.json")


def sup(row: dict) -> set[str]:
    s = row["supporting_event_uids"]
    return set(s.split(";")) if s else set()


# ====================================================================================== contract / columns
def test_gtt08_params_column_lists_equal_spec_lists():
    """GTT-08 (contract): the gate's column lists, dispositions and methods are exactly the spec section 3 lists."""
    assert list(gparams.TRIGGER_COLUMNS) == SPEC_TRIGGER_COLUMNS
    assert list(gparams.UNMATCHED_COLUMNS) == SPEC_UNMATCHED_COLUMNS
    assert list(gparams.DISPOSITION_COLUMNS) == SPEC_DISPOSITION_COLUMNS
    assert list(gparams.SUPPORTING_COLUMNS) == SPEC_SUPPORTING_COLUMNS
    assert list(gparams.DISPOSITIONS) == SPEC_DISPOSITIONS
    assert set(gparams.METHODS) == SPEC_METHODS
    assert "service_name_time" not in gparams.METHODS


def test_gtt08_output_files_exist_and_headers_exact(tmp_path):
    """GTT-08 (contract): the seven files exist; the four CSV headers are the spec section 3 lists in order."""
    c = make_case(tmp_path, [logon("L", 0, 873286), share("S", 1, 873286)])
    c.run()
    for f in OUTPUT_FILES:
        assert (c.out_dir / f).is_file(), f
    def header(name):
        with open(c.out_dir / name, newline="", encoding="utf-8") as fh:
            return next(csv.reader(fh))
    assert header("triggers.csv") == SPEC_TRIGGER_COLUMNS
    assert header("unmatched_remote.csv") == SPEC_UNMATCHED_COLUMNS
    assert header("dispositions.csv") == SPEC_DISPOSITION_COLUMNS
    assert header("supporting.csv") == SPEC_SUPPORTING_COLUMNS


def test_gtt08_empty_result_files_have_header_only(tmp_path):
    """GTT-08: a trial with no trigger still writes all four CSVs with their header and no rows."""
    o = go(tmp_path, [noise()])
    assert o.trig == [] and o.unm == [] and o.disp == [] and o.sup == []


def test_gtt08_second_run_rebuilds_outputs(tmp_path):
    """GTT-08 / spec 3: the output dir is rebuilt on every run (no rows left from an earlier run)."""
    c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)])
    assert len(c.run().trig) == 1
    write_db(c.db, [noise()])
    c.refresh()                       # new DB bytes: offsets file, clock-changes hash and window row follow
    o = c.run()
    assert o.trig == [] and o.disp == []


def test_gtt08_report_md_avoids_forbidden_wording(tmp_path):
    """CLAUDE.md wording rule: report.md never claims to reduce false positives, detect stolen accounts, identify the attacker."""
    c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)])
    c.run()
    text = (c.out_dir / "report.md").read_text(encoding="utf-8").lower()
    assert text.strip()
    for bad in ("reduces false positive", "detects stolen", "identifies the attacker", "identify the attacker"):
        assert bad not in text


def test_spec3_run_info_json_has_time_and_version(tmp_path):
    """Spec 3: run_info.json holds run time and tool version."""
    c = make_case(tmp_path, [noise()])
    c.run()
    info = json.loads((c.out_dir / "run_info.json").read_text(encoding="utf-8"))
    assert isinstance(info, dict) and info
    keys = " ".join(info).lower()
    assert "time" in keys or "utc" in keys or "date" in keys
    assert "version" in keys or "tool" in keys


def test_spec3_run_gate_dict_has_documented_keys(tmp_path):
    """API contract: run_gate returns out_dir, triggers, unmatched, dispositions, supporting, stats, run_info, drafts."""
    res = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)]).run_raw()
    assert set(res) >= {"out_dir", "triggers", "unmatched", "dispositions", "supporting", "stats", "run_info", "drafts"}
    assert len(res["triggers"]) == 1


# ====================================================================================== GTT-01 / GTT-01b
def test_gtt01_events_outside_window_are_in_no_output_file(tmp_path):
    """GTT-01: 1 ms before start / at end + 1 ms (and a far event) appear in no row of any output file."""
    rows = [
        logon("OUT-BEFORE", None, 1, utc="2026-09-24T09:59:59.999000Z"),
        logon("EDGE-START", None, 2, utc="2026-09-24T10:00:00.000000Z", ip="192.168.50.23"),
        logon("EDGE-END", None, 3, utc="2026-09-24T11:00:00.000000Z", ip="192.168.50.10"),
        logon("OUT-AFTER", None, 4, utc="2026-09-24T11:00:00.001000Z", ip="192.168.50.13"),
        logon("OUT-FAR", None, 5, utc="2026-09-24T08:00:00.000000Z"),
        logon("MID", 0, 6, ip="192.168.50.23"),
    ]
    o = go(tmp_path, rows)
    text = o.all_text()
    for uid in ("OUT-BEFORE", "OUT-AFTER", "OUT-FAR"):
        assert uid not in text, uid
    kept = o.unm_uids()
    assert {"EDGE-START", "EDGE-END", "MID"} <= kept


def test_gtt01_exactly_on_edges_kept_and_just_inside_end_kept(tmp_path):
    """GTT-01 / GT-01: start <= t < end + 1 ms: t = end and t = end + 999 us are kept, end + 1 ms is not."""
    rows = [
        logon("AT-START", None, 1, utc="2026-09-24T10:00:00.000000Z", ip="192.168.50.23"),
        logon("AT-END", None, 2, utc="2026-09-24T11:00:00.000000Z", ip="192.168.50.10"),
        logon("END-PLUS-999US", None, 3, utc="2026-09-24T11:00:00.000999Z", ip="192.168.50.11"),
        logon("END-PLUS-1MS", None, 4, utc="2026-09-24T11:00:00.001000Z", ip="192.168.50.12"),
    ]
    o = go(tmp_path, rows)
    assert {"AT-START", "AT-END", "END-PLUS-999US"} <= o.unm_uids()
    assert "END-PLUS-1MS" not in o.all_text()


def test_gtt01_stats_count_removed_and_near_window_without_uids(tmp_path):
    """GTT-01 / spec 3: clipped events are only counted (per host x event id); near_window holds counts, no uids."""
    rows = [
        logon("CLIP-B1", None, 1, utc="2026-09-24T09:59:59.999000Z"),
        logon("CLIP-B2", None, 2, utc="2026-09-24T09:58:00.000000Z"),
        logon("CLIP-A1", None, 3, utc="2026-09-24T11:00:00.001000Z"),
        logon("CLIP-A2", None, 4, utc="2026-09-24T11:03:00.000000Z"),
        logon("CLIP-FAR", None, 5, utc="2026-09-24T07:00:00.000000Z"),
        logon("KEEP", 0, 6, ip="192.168.50.23"),
    ]
    o = go(tmp_path, rows)
    removed = o.stats["removed_by_window"]                          # spec 3.1: host -> channel/event_id -> count
    assert removed == {"ep-02": {"Security/4624": 5}}
    near = o.stats["near_window"]                                   # spec 3.1: host -> {before, after}
    assert near == {"ep-02": {"before": 2, "after": 2}}             # far event (> 300 s) not counted
    blob = json.dumps(o.stats)
    for uid in ("CLIP-B1", "CLIP-B2", "CLIP-A1", "CLIP-A2", "CLIP-FAR"):
        assert uid not in blob


def test_gtt01_anchor_before_window_never_anchors_inside_events(tmp_path):
    """GT-01 / Q3: a 4624 before the window is dropped first; its in-window 5145 finds no anchor (no R4, no row for the 4624)."""
    rows = [logon("PRE", None, 77, utc="2026-09-24T09:50:00.000000Z"), share("S-IN", 5, 77)]
    o = go(tmp_path, rows)
    assert o.trig == [] and o.unm == []
    assert "PRE" not in o.all_text()
    assert o.d("S-IN")["disposition"] == "no_rule"


def test_gtt01b_window_end_ms_and_db_event_microseconds(tmp_path):
    """GTT-01b: window end ...07.787Z, DB event ...07.787007Z is kept (s04_t00 case)."""
    rows = [logon("E-KEPT", None, 1, utc="2026-09-24T10:59:07.787007Z", ip="192.168.50.23"),
            logon("E-GONE", None, 2, utc="2026-09-24T10:59:07.788000Z", ip="192.168.50.10")]
    o = go(tmp_path, rows, start="2026-09-24T10:00:00.000Z", end="2026-09-24T10:59:07.787Z")
    assert "E-KEPT" in o.unm_uids()
    assert "E-GONE" not in o.all_text()


def test_gtt01b_plus_zero_offset_form_of_window_edges_equals_z(tmp_path):
    """GTT-01b: window edges written `+00:00` compare equal to DB `Z` times (edge instants kept)."""
    rows = [logon("AT-S", None, 1, utc="2026-09-24T10:00:00.000000Z", ip="192.168.50.23"),
            logon("AT-E", None, 2, utc="2026-09-24T11:00:00.000000Z", ip="192.168.50.10"),
            logon("PAST-E", None, 3, utc="2026-09-24T11:00:00.001000Z", ip="192.168.50.12")]
    o = go(tmp_path, rows, start="2026-09-24T10:00:00.000+00:00", end="2026-09-24T11:00:00.000+00:00")
    assert {"AT-S", "AT-E"} <= o.unm_uids()
    assert "PAST-E" not in o.all_text()


def test_gtt01b_plus_zero_offset_form_of_db_times_equals_z(tmp_path):
    """GTT-01b: DB event times in `+00:00` form compare as instants against `Z` window edges."""
    rows = [logon("DB-PLUS-IN", None, 1, utc="2026-09-24T10:30:00.000000+00:00", ip="192.168.50.23"),
            logon("DB-PLUS-EDGE", None, 2, utc="2026-09-24T11:00:00.000000+00:00", ip="192.168.50.10"),
            logon("DB-PLUS-OUT", None, 3, utc="2026-09-24T11:00:00.001000+00:00", ip="192.168.50.12")]
    o = go(tmp_path, rows)
    assert {"DB-PLUS-IN", "DB-PLUS-EDGE"} <= o.unm_uids()
    assert "DB-PLUS-OUT" not in o.all_text()


# ====================================================================================== GTT-02 / GTT-03 / GTT-04
def excluded_session_rows(ip: str, lid: int = 2000) -> list[dict]:
    return [
        logon("X-L", 0, lid, ip=ip, account="admin_it"),
        share("X-5145", 1, lid),
        svc4697("X-4697", 2, lid, name="XSVC"),
        svc7045("X-7045", 2.5, name="XSVC"),
        wsm("X-WSM", 3, lid),
    ]


@pytest.mark.parametrize("ip", EXCLUDED_IPS)
def test_gtt02_excluded_ip_session_is_excluded_with_its_artefacts(tmp_path, ip):
    """GTT-02: an excluded-IP 4624 inside the window is excluded with its 5145, 4697, 7045 and wsmprovhost Sysmon 1."""
    o = go(tmp_path, excluded_session_rows(ip))
    assert o.trig == [] and o.unm == [] and o.sup == []
    assert o.d("X-L")["disposition"] == "excluded_source_ip"
    assert o.d("X-5145")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-4697")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-WSM")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-7045")["disposition"] == "paired_excluded"


def test_gtt02_no_output_row_carries_an_excluded_source_ip(tmp_path):
    """GTT-02: no row of triggers.csv / unmatched_remote.csv has an excluded source_ip, with excluded logons mixed with others."""
    rows = []
    for i, ip in enumerate(EXCLUDED_IPS):
        rows += [logon(f"XL{i}", 10 * i, 3000 + i, ip=ip), share(f"XS{i}", 10 * i + 1, 3000 + i)]
    rows += [logon("OK", 100, 3100, ip="192.168.50.21"), share("OKS", 101, 3100)]
    o = go(tmp_path, rows)
    assert [r["trigger_event_uid"] for r in o.trig] == ["OK"]
    for r in o.trig + o.unm:
        assert r["source_ip"] not in EXCLUDED_IPS


def test_gtt02_excluded_session_artefacts_listed_in_stats(tmp_path):
    """GT-02 / spec 3: an excluded session with a service install or share write is listed in excluded_ip_with_artefacts."""
    rows = excluded_session_rows("192.168.50.99", 2000) + [logon("PLAIN-X", 50, 2001, ip="192.168.50.98")]
    o = go(tmp_path, rows)
    listed = o.stats["excluded"]["excluded_ip_with_artefacts"]      # spec 3.1: [{host, logon_id_hex, source_ip, event_uids}]
    assert len(listed) == 1
    entry = listed[0]
    assert set(entry) == {"host", "logon_id_hex", "source_ip", "event_uids"}
    assert entry["host"] == "ep-02" and entry["source_ip"] == "192.168.50.99"
    assert entry["logon_id_hex"].lower() == "0x7d0"
    assert {"X-5145", "X-4697"} <= set(entry["event_uids"])
    assert "PLAIN-X" not in json.dumps(listed)


def test_gtt02_c_winrm91_and_sysmon3_from_excluded_ip_are_excluded(tmp_path):
    """GT-02(c): WinRM 91 / inbound Sysmon 3 from an excluded IP are excluded; an unanchored wsmprovhost whose paired 91
    (0-5 s after it, decision 042) is that 91 too (no R8 row)."""
    rows = [wsm("XWSM", 0, 8888), w91("X91", 0.08, "192.168.50.99"),
            s3("XS3", 20, "192.168.50.97", 50000)]
    o = go(tmp_path, rows)
    assert o.trig == [] and o.sup == []
    assert o.d("X91")["disposition"].startswith("excluded")
    assert o.d("XWSM")["disposition"].startswith("excluded")
    assert o.d("XS3")["disposition"].startswith("excluded")


def test_gtt02_c_excluded_91_more_than_5s_after_wsmprovhost_is_not_paired(tmp_path):
    """GT-02(c) boundary (decision 042): an excluded 91 more than 5 s after the wsmprovhost Sysmon 1 is not its pair (R8 tier D)."""
    rows = [wsm("LATE-WSM", 0, 8889), w91("X91", 5.5, "192.168.50.99")]
    o = go(tmp_path, rows)
    assert o.d("X91")["disposition"].startswith("excluded")
    assert not o.d("LATE-WSM")["disposition"].startswith("excluded")
    assert o.one("R8_winrm")["gate_tier"] == "D"


def test_gtt02_excluded_r8_parent_in_excluded_session_not_listed(tmp_path):
    """GT-16 'listed after GT-02': an R8_parent Sysmon 1 inside an excluded session is not in supporting.csv."""
    rows = [logon("XL", 0, 2000, ip="192.168.50.99"),
            wsm("XPAR", 2, 2000, image=r"C:\Windows\System32\powershell.exe", parent=WSM)]
    o = go(tmp_path, rows)
    assert o.sup == []
    assert o.d("XPAR")["disposition"] == "excluded_source_ip_session"


def test_gtt03_admin_it_from_lab_ip_still_fires_next_to_excluded_admin_it(tmp_path):
    """GTT-03: admin_it 4624 from .21 fires R4 (by IP, not account) while an excluded-IP admin_it logon is excluded."""
    rows = [logon("LAB", 0, 4000, ip="192.168.50.21", account="admin_it"), share("LAB-S", 1, 4000),
            logon("EXC", 10, 4001, ip="192.168.50.99", account="admin_it"), share("EXC-S", 11, 4001)]
    o = go(tmp_path, rows)
    assert [r["trigger_event_uid"] for r in o.trig] == ["LAB"]
    assert o.trig[0]["account_name"] == "admin_it"
    assert o.d("EXC")["disposition"] == "excluded_source_ip"


@pytest.mark.parametrize("case", ["type2", "type11", "lid996", "lid997", "lid999", "loop4", "loop6", "loopmap",
                                  "ownip"])
def test_gtt04_suppressed_logons_never_fire(tmp_path, case):
    """GTT-04: type 2/11, logon IDs 996/997/999, loopback and own-IP logons never fire (even with a share event)."""
    kw = {"type2": dict(ltype=2), "type11": dict(ltype=11), "lid996": dict(lid=996), "lid997": dict(lid=997),
          "lid999": dict(lid=999), "loop4": dict(ip="127.0.0.1"), "loop6": dict(ip="::1"),
          "loopmap": dict(ip="::ffff:127.0.0.1"), "ownip": dict(ip="192.168.50.22")}[case]
    lid = kw.pop("lid", 4100)
    rows = [logon("L", 0, lid, **kw), share("S", 1, lid), svc4697("V", 2, lid, name="ZSVC")]
    o = go(tmp_path, rows)
    assert o.trig == [] or all(r["trigger_event_uid"] != "L" and r["anchor_logon_uid"] != "L" for r in o.trig)
    assert "L" not in o.unm_uids()
    if case not in ("type2", "type11"):
        assert not [r for r in o.trig if r["rule"] in ("R4_smb", "R5_rdp")]


@pytest.mark.parametrize("case,expected", [
    ("type2", "interactive_logon"), ("type11", "interactive_logon"), ("lid996", "system_logon_id"),
    ("lid997", "system_logon_id"), ("lid999", "system_logon_id"), ("loop4", "loopback_or_self"),
    ("loop6", "loopback_or_self"), ("loopmap", "loopback_or_self"), ("ownip", "loopback_or_self")])
def test_gtt04_suppression_dispositions(tmp_path, case, expected):
    """GT-03/04/05: the suppressed 4624 has the matching disposition."""
    kw = {"type2": dict(ltype=2), "type11": dict(ltype=11), "lid996": dict(lid=996), "lid997": dict(lid=997),
          "lid999": dict(lid=999), "loop4": dict(ip="127.0.0.1"), "loop6": dict(ip="::1"),
          "loopmap": dict(ip="::ffff:127.0.0.1"), "ownip": dict(ip="192.168.50.22")}[case]
    lid = kw.pop("lid", 4100)
    o = go(tmp_path, [logon("L", 0, lid, **kw)])
    assert o.d("L")["disposition"] == expected


def test_gtt04_type10_with_system_logon_id_does_not_fire_r5(tmp_path):
    """GT-04: a type 10 4624 with logon id 999 never fires R5."""
    o = go(tmp_path, [logon("L", 0, 999, ltype=10)])
    assert o.trig == [] and o.unm == []
    assert o.d("L")["disposition"] == "system_logon_id"


def test_gtt04_own_ip_is_host_specific(tmp_path):
    """GT-05: 192.168.50.22 is ep-02's own IP only; on ep-03 the same source IP is a normal remote logon."""
    o = go(tmp_path, [logon("ON-EP03", 0, 4101, ip="192.168.50.22", host="ep-03"),
                      logon("ON-EP02", 10, 4102, ip="192.168.50.22", host="ep-02"),
                      logon("DC-OWN", 20, 4103, ip="192.168.50.10", host="dc01")])
    assert o.d("ON-EP03")["disposition"] == "unmatched_remote"
    assert o.d("ON-EP02")["disposition"] == "loopback_or_self"
    assert o.d("DC-OWN")["disposition"] == "loopback_or_self"


def test_gtt04_disposition_precedence(tmp_path):
    """Spec 3 precedence: excluded IP > interactive > system id > loopback."""
    rows = [logon("P1", 0, 5101, ltype=2, ip="192.168.50.99"),         # excluded beats interactive
            logon("P2", 10, 999, ltype=2, ip=None),                    # interactive beats system id
            logon("P3", 20, 999, ltype=3, ip="127.0.0.1"),             # system id beats loopback
            logon("P4", 30, 5104, ltype=11, ip="127.0.0.1")]           # interactive beats loopback
    o = go(tmp_path, rows)
    assert [o.d(u)["disposition"] for u in ("P1", "P2", "P3", "P4")] == [
        "excluded_source_ip", "interactive_logon", "system_logon_id", "interactive_logon"]


# ====================================================================================== GTT-05 R4
def test_gtt05_r4_minimal_positive_row_values(tmp_path):
    """GTT-05 / GT-10: remote type 3 + a 5145 with its logon id -> one R4 row with every field as the spec example."""
    o = go(tmp_path, [logon("L", 0, 873286, account="svc_backup"), share("S", 1, 873286, 5145)])
    r = o.one("R4_smb")
    assert len(o.trig) == 1 and o.unm == []
    assert r["trigger_id"] == f"{TRIAL}-g0001"
    assert r["host"] == "ep-02"
    assert parse(r["event_utc"]) == parse(at(0)) and parse(r["event_utc_corrected"]) == parse(at(0))   # zero offset
    assert "event_utc_raw" not in r                                                       # removed (spec 3, T6b.2)
    assert r["trigger_event_uid"] == "L" and r["anchor_logon_uid"] == "L"
    assert r["target_logon_id"] == "873286" and r["target_logon_id_hex"].lower() == "0xd5346"
    assert r["logon_type"] == "3"
    assert r["source_ip"] == "192.168.50.21" and r["ip_kind"] == "ipv4"
    assert r["account_name"] == "svc_backup" and r["domain_short"] == "LAB"
    assert r["authentication_package"] == "NTLM" and r["machine_account"] == "0"
    assert sup(r) == {"S"}
    assert r["method"] == "logon_id" and r["gate_tier"] == "A"
    assert r["candidate_count"] == "1" and r["time_delta_ms"] == "1000"
    assert r["near_duplicate"] == "0"
    assert r["window_source"] == "computed_agent_run" and r["time_basis"] == "corrected"
    assert r["clock_flag"] == "" and r["clock_change_in_window"] == "false" and r["clock_unreliable"] == "0"
    assert o.d("L")["disposition"] == "trigger" and o.d("S")["disposition"] == "supporting"


R4_NEGATIVE = {
    "no_share_event": lambda: [logon("L", 0, 10)],
    "share_other_logon_id": lambda: [logon("L", 0, 10), share("S", 1, 11)],
    "share_on_other_host": lambda: [logon("L", 0, 10), share("S", 1, 10, host="ep-03")],
    "share_before_logon": lambda: [logon("L", 0, 10), share("S", -1, 10)],
    "null_logon_ids": lambda: [logon("L", 0, None), share("S", 1, None)],
}


@pytest.mark.parametrize("case", sorted(R4_NEGATIVE))
def test_gtt05_r4_without_share_event_goes_to_unmatched(tmp_path, case):
    """GTT-05: R4 does not fire with one condition removed; the remote 4624 goes to unmatched_remote.csv, never lost."""
    o = go(tmp_path, R4_NEGATIVE[case]())
    assert o.rule("R4_smb") == []
    assert "L" in o.unm_uids()
    assert o.d("L")["disposition"] == "unmatched_remote"
    if case != "no_share_event":
        assert o.d("S")["disposition"] == "no_rule"


def test_gtt05_r4_share_event_at_same_instant_fires(tmp_path):
    """GT-10: share event_utc >= logon (equal instant counts)."""
    o = go(tmp_path, [logon("L", 0, 10), share("S", 0, 10)])
    r = o.one("R4_smb")
    assert r["time_delta_ms"] == "0"


def test_gtt05_r4_type10_with_share_event_does_not_fire_r4(tmp_path):
    """GT-10: R4 needs type 3; a type 10 logon with a share event fires R5 only."""
    o = go(tmp_path, [logon("L", 0, 10, ltype=10), share("S", 1, 10)])
    assert o.rule("R4_smb") == [] and len(o.rule("R5_rdp")) == 1


def test_gtt05_r4_supporting_is_all_share_events_and_delta_is_earliest(tmp_path):
    """GT-10 / decision 041: supporting = all matching 5140 and 5145; time_delta_ms = earliest supporting - anchor."""
    o = go(tmp_path, [logon("L", 0, 10), share("S1", 3, 10, 5145), share("S2", 2, 10, 5140),
                      share("S3", 9, 10, 5145), share("S-OTHER", 2, 11, 5145)])
    r = o.one("R4_smb")
    assert sup(r) == {"S1", "S2", "S3"}
    assert r["time_delta_ms"] == "2000" and r["candidate_count"] == "1"
    assert o.d("S-OTHER")["disposition"] == "no_rule"


# ====================================================================================== GTT-05 R5
def r5_pair(dt: float, *, l_port=50000, s_port=50000, l_ip="192.168.50.21", s_ip="192.168.50.21", **s3kw) -> list:
    return [logon("L", 0, 20, port=l_port, ip=l_ip), s3("S3", dt, s_ip, s_port, **s3kw)]


def test_gtt05_r5_type10_fires_as_its_own_anchor(tmp_path):
    """GTT-05 / GT-11: a remote type 10 fires R5, own anchor, method none, tier A, null time_delta, no supporting."""
    o = go(tmp_path, [logon("L", 0, 20, ltype=10)])
    r = o.one("R5_rdp")
    assert r["trigger_event_uid"] == "L" and r["anchor_logon_uid"] == "L"
    assert r["method"] == "none" and r["gate_tier"] == "A"
    assert r["candidate_count"] == "1" and r["time_delta_ms"] == ""
    assert r["supporting_event_uids"] == "" and r["logon_type"] == "10"
    assert o.unm == [] and o.d("L")["disposition"] == "trigger"


def test_gtt05_r5_type3_with_sysmon3_same_ip_and_port_fires_tier_b(tmp_path):
    """GTT-05 / GT-11: type 3 + inbound 3389 Sysmon 3, same IP + port within 5 s -> R5 ip_port_time, tier B."""
    o = go(tmp_path, r5_pair(2.0))
    r = o.one("R5_rdp")
    assert r["trigger_event_uid"] == "L" and r["anchor_logon_uid"] == "L"
    assert sup(r) == {"S3"} and r["method"] == "ip_port_time" and r["gate_tier"] == "B"
    assert r["candidate_count"] == "1" and r["time_delta_ms"] == "2000"
    assert o.d("L")["disposition"] == "trigger" and o.d("S3")["disposition"] == "supporting"


R5_NEGATIVE = {
    "six_seconds": dict(dt=6.0),
    "different_port": dict(dt=1.0, s_port=50001),
    "different_ip": dict(dt=1.0, s_ip="192.168.50.23"),
    "outbound_connection": dict(dt=1.0, initiated=1),
    "other_destination_port": dict(dt=1.0, dport=3390),
    "sysmon3_on_other_host": dict(dt=1.0, host="ep-03"),
    "sysmon3_null_port": dict(dt=1.0, s_port=None),
    "sysmon3_null_ip": dict(dt=1.0, s_ip=None),
}


@pytest.mark.parametrize("case", sorted(R5_NEGATIVE))
def test_gtt05_r5_type3_one_condition_removed_does_not_fire(tmp_path, case):
    """GTT-05: R5 type 3 does not fire with the Sysmon 3 at 6 s, a different port/IP, outbound, other port/host, NULL join."""
    kw = dict(R5_NEGATIVE[case])
    dt = kw.pop("dt")
    o = go(tmp_path, r5_pair(dt, **kw))
    assert o.rule("R5_rdp") == []
    assert "L" in o.unm_uids() and o.d("L")["disposition"] == "unmatched_remote"
    if case != "other_destination_port":          # a Sysmon 3 to another port is not a trigger-type event
        assert o.d("S3")["disposition"] == "no_rule"
    else:
        assert not o.has_d("S3")


@pytest.mark.parametrize("dt,fires", [(5.0, True), (-5.0, True), (4.999, True), (5.001, False), (-5.001, False),
                                      (-1.0, True)])
def test_gtt05_r5_pairing_is_symmetric_and_inclusive(tmp_path, dt, fires):
    """GT-11 / decision 041: |dt| <= 5.000 s pairs, either order; 5.001 s does not."""
    o = go(tmp_path, r5_pair(dt))
    assert bool(o.rule("R5_rdp")) is fires
    if fires:
        assert o.one("R5_rdp")["time_delta_ms"] == str(int(round(dt * 1000)))


@pytest.mark.parametrize("l_port", [0, None])
def test_gtt05_r5_port_zero_or_null_uses_ip_and_time(tmp_path, l_port):
    """GT-11 / decision 015: a 4624 port of 0 or NULL joins by IP + time: method ip_time, tier B (any Sysmon 3 port)."""
    o = go(tmp_path, r5_pair(3.0, l_port=l_port, s_port=61234))
    r = o.one("R5_rdp")
    assert r["method"] == "ip_time" and r["gate_tier"] == "B" and sup(r) == {"S3"}


def test_gtt05_r5_port_zero_still_needs_same_ip_and_time(tmp_path):
    """GT-11: with port 0 the IP and the 5 s still must match."""
    assert go(tmp_path, r5_pair(3.0, l_port=0, s_ip="192.168.50.23")).rule("R5_rdp") == []
    assert go(tmp_path / "b", r5_pair(6.0, l_port=0)).rule("R5_rdp") == []


def test_gtt05_smb_logon_with_other_port_3389_connect_gives_no_r5(tmp_path):
    """Spec 6: SMB logon and RDP connect from one IP within 5 s: R4 only, no R5 unless ports match."""
    rows = [logon("L", 0, 20, port=50000), share("S", 1, 20), s3("S3", 1.5, "192.168.50.21", 50777)]
    o = go(tmp_path, rows)
    assert len(o.rule("R4_smb")) == 1 and o.rule("R5_rdp") == []
    assert o.d("S3")["disposition"] == "no_rule"


def test_gtt05_r5_both_sysmon3_supporting_when_two_match(tmp_path):
    """GT-11: every matching inbound 3389 Sysmon 3 is supporting; time_delta uses the earliest."""
    rows = [logon("L", 0, 20), s3("S3a", 3, "192.168.50.21", 50000), s3("S3b", 1, "192.168.50.21", 50000)]
    o = go(tmp_path, rows)
    r = o.one("R5_rdp")
    assert sup(r) == {"S3a", "S3b"} and r["time_delta_ms"] == "1000"


def test_gtt05_r5_type10_adds_matching_3389_sysmon3_to_supporting(tmp_path):
    """GT-11 (decision 041): a 3389 Sysmon 3 matching a type 10 R5 (same IP and port, <= 5 s) is in its supporting uids and has disposition supporting."""
    o = go(tmp_path, [logon("L", 0, 20, ltype=10), s3("S3", -2.0, "192.168.50.21", 50000)])
    r = o.one("R5_rdp")
    assert sup(r) == {"S3"}
    assert r["method"] == "none" and r["gate_tier"] == "A"
    assert r["time_delta_ms"] == "-2000" and r["candidate_count"] == "1"
    assert o.d("S3")["disposition"] == "supporting"


@pytest.mark.parametrize("kw", [dict(s_port=50001), dict(s_ip="192.168.50.23"), dict(dt=5.001)])
def test_gtt05_r5_type10_non_matching_sysmon3_is_not_supporting(tmp_path, kw):
    """GT-11 (decision 041): a 3389 Sysmon 3 with another port/IP or > 5 s from a type 10 is not supporting; R5 time_delta null."""
    kw = dict(kw)
    dt = kw.pop("dt", 1.0)
    rows = [logon("L", 0, 20, ltype=10), s3("S3", dt, kw.get("s_ip", "192.168.50.21"), kw.get("s_port", 50000))]
    o = go(tmp_path, rows)
    r = o.one("R5_rdp")
    assert sup(r) == set() and r["time_delta_ms"] == ""
    assert o.d("S3")["disposition"] == "no_rule"


def test_gtt05_r5_type10_with_port_zero_matches_sysmon3_by_ip_and_time(tmp_path):
    """GT-11 (decision 041): type 10 with port 0 -> the 3389 Sysmon 3 matches by IP + time."""
    o = go(tmp_path, [logon("L", 0, 20, ltype=10, port=0), s3("S3", 2.0, "192.168.50.21", 61000)])
    assert sup(o.one("R5_rdp")) == {"S3"}
    assert o.d("S3")["disposition"] == "supporting"


def test_gtt05_unmatched_3389_sysmon3_has_disposition_no_rule(tmp_path):
    """Spec 3: an inbound 3389 Sysmon 3 completing no rule is `no_rule`; an outbound one is in the disposition set too."""
    o = go(tmp_path, [s3("IN", 0, "192.168.50.21", 50000),
                      s3("OUT", 10, "192.168.50.22", 50001, initiated=1, destination_ip="192.168.50.23")])
    assert o.d("IN")["disposition"] == "no_rule" and o.d("OUT")["disposition"] == "no_rule"
    assert OUT_3389_REASON in o.d("OUT")["reason_detail"] and OUT_3389_REASON not in o.d("IN")["reason_detail"]


# ====================================================================================== GTT-05 R6
def r6(anchor_off=0.0, i4697=2.0, i7045=2.5, lid=5000, anchor_kw=None):
    rows = [logon("L", anchor_off, lid, **(anchor_kw or {})), svc4697("V4", i4697, lid)]
    if i7045 is not None:
        rows.append(svc7045("V7", i7045))
    return rows


def test_gtt05_r6_anchored_row_values(tmp_path):
    """GTT-05 / GT-12 / decision 041: anchored 4697 + paired 7045 -> one R6 row: trigger 4697, 7045 supporting, logon_id / A, delta = earliest - anchor."""
    o = go(tmp_path, r6())
    r = o.one("R6_service")
    assert len(o.trig) == 1 and o.unm == []
    assert r["trigger_event_uid"] == "V4" and r["anchor_logon_uid"] == "L"
    assert sup(r) == {"V7"} and r["method"] == "logon_id" and r["gate_tier"] == "A"
    assert r["candidate_count"] == "1" and r["time_delta_ms"] == "2000"
    assert r["target_logon_id"] == "5000" and r["logon_type"] == "3" and r["source_ip"] == "192.168.50.21"
    assert r["account_name"] == "svc_backup"
    assert o.d("L")["disposition"] == "trigger" and o.d("V4")["disposition"] == "trigger"
    d7 = o.d("V7")
    assert d7["disposition"] == "supporting" and "service_name_time" in d7["reason_detail"]


def test_gtt05_r6_4697_without_7045_still_has_time_delta(tmp_path):
    """Decision 041: an R6 with a 4697 but no 7045 still has a time_delta (4697 - anchor)."""
    o = go(tmp_path, r6(i7045=None))
    r = o.one("R6_service")
    assert sup(r) == set() and r["time_delta_ms"] == "2000" and r["method"] == "logon_id" and r["gate_tier"] == "A"


def test_gtt05_r6_7045_before_4697_gives_earliest_delta(tmp_path):
    """Decision 041: time_delta_ms = earliest of (4697, 7045) - anchor; a 7045 logged first sets it."""
    o = go(tmp_path, r6(i4697=3.0, i7045=1.0))
    r = o.one("R6_service")
    assert sup(r) == {"V7"} and r["time_delta_ms"] == "1000" and r["trigger_event_uid"] == "V4"


def test_gtt05_r6_no_anchor_is_tier_d_method_none(tmp_path):
    """GT-12 / decision 041: a 4697 with no anchor -> method none, tier D, candidate_count 0, null delta, no anchor."""
    o = go(tmp_path, [svc4697("V4", 2.0, 5001), svc7045("V7", 2.5)])
    r = o.one("R6_service")
    assert r["trigger_event_uid"] == "V4" and r["anchor_logon_uid"] == ""
    assert r["method"] == "none" and r["gate_tier"] == "D"
    assert r["candidate_count"] == "0" and r["time_delta_ms"] == "" and sup(r) == {"V7"}
    assert r["target_logon_id"] == "" and r["logon_type"] == ""


@pytest.mark.parametrize("lid", [996, 997, 999])
def test_gtt05_r6_4697_by_system_logon_id_is_suppressed_and_7045_paired_excluded(tmp_path, lid):
    """GTT-05 / GT-04: a 4697 by 0x3e4/0x3e5/0x3e7 never fires R6; its paired 7045 -> paired_excluded."""
    o = go(tmp_path, [svc4697("V4", 0, lid), svc7045("V7", 0.5)])
    assert o.trig == []
    assert o.d("V4")["disposition"] == "system_logon_id"
    assert o.d("V7")["disposition"] == "paired_excluded"


def test_gtt05_r6_7045_without_4697_is_tier_d_local_install(tmp_path):
    """GT-12: a lone 7045 fires R6 as trigger, no anchor (tier D), counted as a local install."""
    o = go(tmp_path, [svc7045("V7", 0)])
    r = o.one("R6_service")
    assert r["trigger_event_uid"] == "V7" and r["anchor_logon_uid"] == "" and r["gate_tier"] == "D"
    assert r["method"] == "none" and r["candidate_count"] == "0"
    assert o.d("V7")["disposition"] == "trigger"


def test_gtt05_r6_local_installs_counted_in_stats(tmp_path):
    """Spec 3: installs with no anchor are counted as local installs; an anchored install is not."""
    rows = [svc4697("V4a", 0, 6001, "ASVC"), svc7045("V7b", 30, "BSVC"), logon("L", 60, 6003),
            svc4697("V4c", 62, 6003, "CSVC")]
    o = go(tmp_path, rows)
    v = o.stats["local_installs"]                                   # spec 3.1: {count, trigger_ids}
    assert set(v) == {"count", "trigger_ids"}
    no_anchor = sorted(r["trigger_id"] for r in o.rule("R6_service") if r["anchor_logon_uid"] == "")
    assert len(no_anchor) == 2
    assert v["count"] == 2 and sorted(v["trigger_ids"]) == no_anchor


@pytest.mark.parametrize("ltype", [3, 10])
def test_d041_r6_anchor_is_type_3_or_10(tmp_path, ltype):
    """Decision 041 / GT-12: the R6 anchor is a remote 4624 of type 3 or 10."""
    o = go(tmp_path, r6(anchor_kw=dict(ltype=ltype)))
    r = o.one("R6_service")
    assert r["anchor_logon_uid"] == "L" and r["gate_tier"] == "A" and r["method"] == "logon_id"
    assert r["logon_type"] == str(ltype)


def test_d041_r6_anchor_type10_also_fires_r5_on_same_anchor(tmp_path):
    """GT-14: one type 10 anchor gives an R5 row and an R6 row; the 4624 is a trigger, not unmatched."""
    o = go(tmp_path, r6(anchor_kw=dict(ltype=10)))
    assert {r["rule"] for r in o.trig} == {"R5_rdp", "R6_service"}
    assert {r["anchor_logon_uid"] for r in o.trig} == {"L"}
    assert o.unm == [] and o.d("L")["disposition"] == "trigger"


def test_d041_r6_other_logon_type_is_not_an_anchor(tmp_path):
    """Decision 041: a type 9 4624 with the logon id is not an R6 anchor (tier D)."""
    o = go(tmp_path, r6(anchor_kw=dict(ltype=9)))
    r = o.one("R6_service")
    assert r["gate_tier"] == "D" and r["anchor_logon_uid"] == "" and r["method"] == "none"


def test_d041_r6_anchor_after_4697_is_tier_d_and_logon_goes_unmatched(tmp_path):
    """Decision 041: an anchor logged after the 4697 -> tier D, method none, candidate_count 0; the 4624 is unmatched."""
    o = go(tmp_path, r6(anchor_off=3.0, i4697=2.0, i7045=None))
    r = o.one("R6_service")
    assert r["gate_tier"] == "D" and r["method"] == "none" and r["candidate_count"] == "0"
    assert r["anchor_logon_uid"] == "" and r["time_delta_ms"] == ""
    assert "L" in o.unm_uids() and o.d("L")["disposition"] == "unmatched_remote"


def test_d041_r6_anchor_at_same_instant_as_4697_is_allowed(tmp_path):
    """Decision 041: anchor time <= 4697 time (equal counts)."""
    o = go(tmp_path, r6(anchor_off=2.0, i4697=2.0, i7045=None))
    r = o.one("R6_service")
    assert r["gate_tier"] == "A" and r["anchor_logon_uid"] == "L" and r["time_delta_ms"] == "0"


def test_d041_r6_anchor_on_other_host_or_null_id_is_not_an_anchor(tmp_path):
    """GT-12 / GT-18: the anchor must be on the same host; NULL logon ids never match."""
    o = go(tmp_path, [logon("L", 0, 5000, host="ep-03"), svc4697("V4", 2, 5000)])
    assert o.one("R6_service")["gate_tier"] == "D"
    o2 = go(tmp_path / "n", [logon("L", 0, None), svc4697("V4", 2, None)])
    assert o2.one("R6_service")["gate_tier"] == "D"


def test_d041_r6_two_anchors_give_two_rows_with_candidate_count_2(tmp_path):
    """Decision 041: a 4697 matching two anchors (near-duplicate 4624 pair) -> two rows, candidate_count 2 each."""
    rows = [logon("L1", 0, 5000, record_id=900), logon("L2", 0.5, 5000, record_id=900),
            svc4697("V4", 2.0, 5000), svc7045("V7", 2.5)]
    o = go(tmp_path, rows)
    rs = o.rule("R6_service")
    assert len(rs) == 2
    assert {r["anchor_logon_uid"] for r in rs} == {"L1", "L2"}
    assert all(r["candidate_count"] == "2" and r["trigger_event_uid"] == "V4" and r["gate_tier"] == "A" for r in rs)
    assert {r["anchor_logon_uid"]: r["time_delta_ms"] for r in rs} == {"L1": "2000", "L2": "1500"}
    assert o.d("L1")["disposition"] == "trigger" and o.d("L2")["disposition"] == "trigger"


def test_d041_service_name_time_is_never_a_method(tmp_path):
    """Decision 041: `service_name_time` appears as a method in no row of any trigger / unmatched file."""
    rows = r6() + [svc7045("LONE", 50, "OTHER"), svc4697("V4x", 80, 7000, "XSVC"), svc7045("V7x", 80.5, "XSVC")]
    o = go(tmp_path, rows)
    for r in o.trig + o.unm:
        assert r["method"] in SPEC_METHODS | {""}
        assert r["method"] != "service_name_time"
    assert any(r["method"] == "logon_id" for r in o.trig)


# ====================================================================================== GTT-06
def test_gtt06_7045_and_4697_pair_gives_one_row_with_4697_as_trigger(tmp_path):
    """GTT-06: a 7045 + 4697 pair of one name gives one R6 row, 4697 = trigger, 7045 supporting."""
    o = go(tmp_path, [svc4697("V4", 0, 6001), svc7045("V7", 0.5)])
    r = o.one("R6_service")
    assert r["trigger_event_uid"] == "V4" and sup(r) == {"V7"}
    assert o.d("V7")["disposition"] == "supporting"


def test_gtt06_two_installs_of_one_name_20s_apart_give_two_rows(tmp_path):
    """GTT-06: two installs of one name 20 s apart give two rows, each with its own pair."""
    rows = [svc4697("A4", 0, 6001), svc7045("A7", 0.5), svc4697("B4", 20, 6002), svc7045("B7", 20.5)]
    o = go(tmp_path, rows)
    rs = o.rule("R6_service")
    assert len(rs) == 2
    assert {r["trigger_event_uid"]: sup(r) for r in rs} == {"A4": {"A7"}, "B4": {"B7"}}


def test_gtt06_different_service_names_do_not_pair(tmp_path):
    """GT-12: 7045 and 4697 pair only on the same service_name."""
    o = go(tmp_path, [svc4697("V4", 0, 6001, "ONE"), svc7045("V7", 0.5, "TWO")])
    assert len(o.rule("R6_service")) == 2


def test_gtt06_pair_on_other_host_does_not_pair(tmp_path):
    """GT-12: pairing is same host only."""
    o = go(tmp_path, [svc4697("V4", 0, 6001), svc7045("V7", 0.5, host="ep-03")])
    assert len(o.rule("R6_service")) == 2


@pytest.mark.parametrize("dt,pairs", [(5.0, True), (-5.0, True), (5.001, False), (-5.001, False)])
def test_gtt06_pairing_is_symmetric_and_inclusive_at_5s(tmp_path, dt, pairs):
    """GT-12 / decision 041: |7045 - 4697| <= 5.000 s pairs either order; 5.001 s does not."""
    o = go(tmp_path, [svc4697("V4", 10, 6001), svc7045("V7", 10 + dt)])
    assert len(o.rule("R6_service")) == (1 if pairs else 2)


def test_d041_7045_pairs_with_nearest_4697(tmp_path):
    """Decision 041: a 7045 pairs with the nearest 4697 of the same name."""
    rows = [svc4697("A", 0, 6001), svc4697("B", 3, 6002), svc7045("P", 4)]
    o = go(tmp_path, rows)
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R6_service")}
    assert got == {"A": set(), "B": {"P"}}


def test_d041_7045_pairing_is_one_to_one(tmp_path):
    """Decision 041: one 4697 pairs with one 7045; the second 7045 becomes its own R6 row (tier D)."""
    rows = [svc4697("B", 3, 6002), svc7045("P1", 4), svc7045("P2", 4.5)]
    o = go(tmp_path, rows)
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R6_service")}
    assert got == {"B": {"P1"}, "P2": set()}


def test_d041_7045_tie_between_two_4697_broken_by_uid(tmp_path):
    """Decision 041: equal distance -> ties broken by uid (smaller uid wins)."""
    rows = [svc4697("A", 0, 6001), svc4697("B", 8, 6002), svc7045("P", 4)]
    o = go(tmp_path, rows)
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R6_service")}
    assert got == {"A": {"P"}, "B": set()}


# ====================================================================================== GTT-05 R8
def r8(anchor_off=0.0, wsm_off=3.0, sid=7000, anchor_kw=None, extra=None):
    return [logon("L", anchor_off, sid, **(anchor_kw or {})), wsm("W", wsm_off, sid)] + (extra or [])


def test_gtt05_r8_anchored_row_with_winrm91(tmp_path):
    """GTT-05 / GT-13: wsmprovhost Sysmon 1 + anchor 4624 + WinRM 91 of the anchor IP -> R8 row logon_id / A, 91 supporting."""
    o = go(tmp_path, r8(extra=[w91("V91", 1.0, "192.168.50.21")]))
    r = o.one("R8_winrm")
    assert r["trigger_event_uid"] == "W" and r["anchor_logon_uid"] == "L"
    assert sup(r) == {"V91"} and r["method"] == "logon_id" and r["gate_tier"] == "A"
    assert r["candidate_count"] == "1" and r["time_delta_ms"] == "1000"
    assert r["source_ip"] == "192.168.50.21" and r["logon_type"] == "3"
    assert o.d("L")["disposition"] == "trigger" and o.d("W")["disposition"] == "trigger"
    assert o.d("V91")["disposition"] == "supporting"
    assert o.unm == []


def test_d041_r8_anchor_only_4624_is_trigger_not_unmatched(tmp_path):
    """Decision 041 / GT-15: a 4624 that is only the anchor of an R8 row is `trigger` and not in unmatched_remote.csv."""
    o = go(tmp_path, r8())
    assert o.one("R8_winrm")["anchor_logon_uid"] == "L"
    assert o.unm == [] and o.d("L")["disposition"] == "trigger"


def test_d041_r6_anchor_only_4624_is_trigger_not_unmatched(tmp_path):
    """Decision 041 / GT-15: a 4624 that is only the anchor of an R6 (4697) row is `trigger` and not in unmatched_remote.csv."""
    o = go(tmp_path, r6(i7045=None))
    assert o.unm == [] and o.d("L")["disposition"] == "trigger"
    assert o.rule("R4_smb") == [] and o.rule("R5_rdp") == []


def test_gtt05_r8_time_delta_with_91_before_anchor_is_negative(tmp_path):
    """Decision 041: time_delta_ms = earliest of (Sysmon 1, supporting 91) - anchor; a 91 before the anchor gives a negative value."""
    o = go(tmp_path, r8(extra=[w91("V91", -2.0, "192.168.50.21")]))
    r = o.one("R8_winrm")
    assert sup(r) == {"V91"} and r["time_delta_ms"] == "-2000"


def test_gtt05_r8_anchored_without_91_has_delta_from_sysmon1(tmp_path):
    """Decision 041: with no supporting 91 the time_delta is the Sysmon 1 (trigger, not anchor) - anchor."""
    o = go(tmp_path, r8())
    r = o.one("R8_winrm")
    assert sup(r) == set() and r["time_delta_ms"] == "3000" and r["candidate_count"] == "1"


def test_d041_r8_anchor_by_target_linked_logon_id(tmp_path):
    """Decision 041 / GT-13: the anchor may match the Sysmon 1 session_id through target_linked_logon_id."""
    rows = [logon("L", 0, 7001, linked=7000), wsm("W", 3, 7000)]
    o = go(tmp_path, rows)
    r = o.one("R8_winrm")
    assert r["anchor_logon_uid"] == "L" and r["gate_tier"] == "A" and r["method"] == "logon_id"


def test_d041_r8_anchor_after_sysmon1_is_tier_d(tmp_path):
    """Decision 041: the R8 anchor must be at or before the Sysmon 1; a later 4624 -> tier D and unmatched."""
    o = go(tmp_path, r8(anchor_off=4.0, wsm_off=3.0))
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["method"] == "none" and r["anchor_logon_uid"] == "" and r["candidate_count"] == "0"
    assert "L" in o.unm_uids()


def test_d041_r8_anchor_at_same_instant_is_allowed(tmp_path):
    """Decision 041: anchor time <= Sysmon 1 time (equal counts)."""
    o = go(tmp_path, r8(anchor_off=3.0, wsm_off=3.0))
    assert o.one("R8_winrm")["gate_tier"] == "A"


@pytest.mark.parametrize("ltype", [10, 9])
def test_gtt05_r8_anchor_must_be_type3(tmp_path, ltype):
    """GT-13: the R8 anchor is a remote 4624 type 3; other types leave the row tier D."""
    o = go(tmp_path, r8(anchor_kw=dict(ltype=ltype)))
    assert o.one("R8_winrm")["gate_tier"] == "D"


def test_gtt05_r8_image_match_is_case_insensitive_and_exact_leaf(tmp_path):
    """GT-13: image ending `\\wsmprovhost.exe`, any case, fires; `notwsmprovhost.exe` does not."""
    rows = [wsm("UP", 0, 7100, image=r"C:\Windows\System32\WSMPROVHOST.EXE"),
            wsm("NOT", 30, 7101, image=r"C:\Temp\notwsmprovhost.exe")]
    o = go(tmp_path, rows)
    assert [r["trigger_event_uid"] for r in o.rule("R8_winrm")] == ["UP"]


def test_gtt05_r8_system_session_does_not_fire(tmp_path):
    """GT-04: a wsmprovhost Sysmon 1 with session_id 999 is system_logon_id and fires no R8."""
    o = go(tmp_path, [wsm("W", 0, 999)])
    assert o.trig == [] and o.d("W")["disposition"] == "system_logon_id"


def test_gtt05_r8_with_wsmprovhost_as_parent_only_goes_to_r8_parent(tmp_path):
    """GTT-05 / GT-13: wsmprovhost as the parent only -> no R8 row; listed in supporting.csv as R8_parent, disposition supporting."""
    rows = [logon("L", 0, 7200),
            wsm("CHILD", 2, 7200, image=r"C:\Windows\System32\cmd.exe", parent=WSM)]
    o = go(tmp_path, rows)
    assert o.rule("R8_winrm") == []
    assert [(r["rule"], r["event_uid"]) for r in o.sup] == [("R8_parent", "CHILD")]
    assert o.sup[0]["host"] == "ep-02"
    assert o.d("CHILD")["disposition"] == "supporting"
    assert "L" in o.unm_uids()


@pytest.mark.parametrize("dt,used", [(5.0, True), (-5.0, True), (5.001, False), (-5.001, False), (0.0, True)])
def test_d041_r8_anchored_91_window_is_symmetric_inclusive_5s(tmp_path, dt, used):
    """Decision 041: anchored R8: a 91 with the anchor IP and |91 - anchor| <= 5.000 s is supporting, either order."""
    o = go(tmp_path, r8(wsm_off=1.0, extra=[w91("V91", dt, "192.168.50.21")]))
    r = o.one("R8_winrm")
    assert (sup(r) == {"V91"}) is used
    assert o.d("V91")["disposition"] == ("supporting" if used else "no_rule")


def test_d041_r8_anchored_91_other_ip_or_host_not_supporting(tmp_path):
    """Decision 041: the 91 must be on the same host with the anchor's IP."""
    o = go(tmp_path, r8(extra=[w91("V91-IP", 1, "192.168.50.23"), w91("V91-HOST", 1.5, "192.168.50.21", host="ep-03")]))
    assert sup(o.one("R8_winrm")) == set()


def test_d042_r8_tier_d_takes_earliest_91_after_sysmon1_for_source_ip(tmp_path):
    """Decision 042 (replaces decision 041's 'latest 91 before'): tier-D R8: the earliest 91 0-5 s AFTER the Sysmon 1
    gives source_ip and is supporting; a 91 before it and a later 91 are not used."""
    rows = [w91("V91a", -1.0, "192.168.50.23"), w91("V91b", 1.0, "192.168.50.21"),
            w91("V91c", 4.0, "192.168.50.10"), wsm("W", 0.0, 7300)]
    o = go(tmp_path, rows)
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["method"] == "none" and r["anchor_logon_uid"] == ""
    assert r["source_ip"] == "192.168.50.21" and r["ip_kind"] == "ipv4"
    assert sup(r) == {"V91b"} and r["time_delta_ms"] == "" and r["candidate_count"] == "0"
    assert o.d("V91b")["disposition"] == "supporting"


@pytest.mark.parametrize("dt,used", [(0.0, True), (5.0, True), (5.001, False), (-0.5, False), (-5.0, False)])
def test_d042_r8_tier_d_91_window_is_0_to_5s_after(tmp_path, dt, used):
    """Decision 042: tier-D R8 uses a 91 0-5 s after the Sysmon 1 (inclusive); earlier or > 5 s later gives no source_ip."""
    o = go(tmp_path, [w91("V91", dt, "192.168.50.21"), wsm("W", 0.0, 7300)])
    r = o.one("R8_winrm")
    assert (r["source_ip"] == "192.168.50.21") is used
    assert (sup(r) == {"V91"}) is used
    if not used:
        assert r["source_ip"] == ""


def test_d041_r8_two_anchors_two_rows_candidate_count_2(tmp_path):
    """Decision 041: several matching anchors give one R8 row per anchor, candidate_count = their number."""
    rows = [logon("L1", 0, 7000, record_id=950), logon("L2", 0.5, 7000, record_id=950), wsm("W", 3, 7000)]
    o = go(tmp_path, rows)
    rs = o.rule("R8_winrm")
    assert len(rs) == 2 and {r["anchor_logon_uid"] for r in rs} == {"L1", "L2"}
    assert all(r["candidate_count"] == "2" and r["trigger_event_uid"] == "W" for r in rs)


# ====================================================================================== GTT-07 refusals
REFUSALS = {
    "quarantine_path": dict(db_subdir="quarantine"),
    "quarantine_trial_id": dict(trial="s05q_t00"),
    "no_row_for_trial": dict(omit_row=True),
    "no_windows_file": dict(no_windows_file=True),
    "empty_start": dict(start=""),
    "empty_end": dict(end=""),
    "db_sha256_mismatch": dict(sha="0" * 64),
    "time_basis_raw": dict(time_basis="raw"),
    "missing_offsets_file": dict(no_offsets_file=True),
    "missing_clock_changes_file": dict(no_changes_file=True),
    "offsets_db_sha256_not_the_db": dict(offsets_db_sha="1" * 64),
    "row_offsets_sha256_mismatch": dict(row_offsets_sha="2" * 64),
    "row_clock_changes_sha256_mismatch": dict(row_changes_sha="3" * 64),
    "row_offsets_sha256_empty": dict(row_offsets_sha=""),
    "row_clock_changes_sha256_empty": dict(row_changes_sha=""),
    "clock_only_s04_t01": dict(trial="s04_t01"),
    "clock_only_s07_t01": dict(trial="s07_t01"),
    # CO-17: window start on/after 2026-10-26 with a none / stale host that has events
    "co17_none_host_on_cutoff_date": dict(start="2026-10-26T00:00:00.000Z", end="2026-10-26T01:00:00.000Z",
                                          offsets=cf.offsets_spec(ep_01=(None, "none", True))),
    "co17_none_host_after_cutoff_date": dict(start="2026-11-02T08:00:00.000Z", end="2026-11-02T09:00:00.000Z",
                                             offsets=cf.offsets_spec(ep_03=(None, "none", True))),
    "co17_stale_host_after_cutoff_date": dict(start="2026-10-27T08:00:00.000Z", end="2026-10-27T09:00:00.000Z",
                                              offsets=cf.offsets_spec(ep_02=(None, "stale", True))),
}


def _refusal_case(tmp_path: Path, kw: dict) -> Case:
    """make_case with one defect. Window-row cells passed as "" (row_*_sha) are written as an empty cell."""
    return make_case(tmp_path, [noise()], **dict(kw))


@pytest.mark.parametrize("name", sorted(REFUSALS))
def test_gtt07_refused_input_raises_gate_error_writes_nothing_cli_returns_2(tmp_path, capsys, name):
    """GTT-07 (replaced, T6b.2): every refusal raises GateError, creates no output dir, and the CLI returns 2."""
    c = _refusal_case(tmp_path, REFUSALS[name])
    with pytest.raises(GateError):
        c.run_raw()
    assert not c.out_dir.exists(), f"{name}: output dir created"
    assert not (c.repo / "out").exists(), f"{name}: something was written under out/"
    assert c.cli() == 2
    assert not c.out_dir.exists(), f"{name}: output dir created by CLI"
    assert capsys.readouterr().err.strip(), "refusal reason must be printed to stderr"


def test_gtt07_refused_run_leaves_a_previous_output_untouched(tmp_path):
    """GTT-07: a refused run writes nothing and deletes nothing: the previous run's files stay byte-identical."""
    c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)])
    c.run()
    names = [f for f in OUTPUT_FILES if f != "run_info.json"]
    before = {f: (c.out_dir / f).read_bytes() for f in names}
    write_windows(c.windows, None)                                   # now there is no row for the trial
    with pytest.raises(GateError):
        c.run_raw()
    assert {f: (c.out_dir / f).read_bytes() for f in names} == before


@pytest.mark.parametrize("trial", ["s02_t01", "s04_t05", "s03_t10", "s07_t02", "s06_t01"])
def test_gtt07_non_t00_trial_is_no_longer_refused(tmp_path, trial):
    """GTT-07 (T6b.2): a non-t00 trial (not clock-only) is allowed when its clock files are valid."""
    c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)], trial=trial)
    assert c.cli() == 0
    assert len(read_csv(c.out_dir / "triggers.csv")) == 1


def test_gtt07_clock_only_trial_refused_even_with_valid_clock_files(tmp_path):
    """GTT-07 / spec 2: s04_t01 and s07_t01 are refused although every file, hash and row is valid (decision 034)."""
    for i, trial in enumerate(("s04_t01", "s07_t01")):
        c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)], trial=trial, name=f"repo{i}")
        with pytest.raises(GateError) as ei:
            c.run_raw()
        assert "clock-only" in str(ei.value).lower() or "clock only" in str(ei.value).lower(), str(ei.value)
        assert not c.out_dir.exists()


def test_gtt07_refusal_reasons_name_the_cause(tmp_path):
    """GTT-07: the refusal text says what was wrong (offsets, clock changes, hash, basis, CO-17), not a bare error."""
    expect = {
        "missing_offsets_file": ("clock_offsets",), "missing_clock_changes_file": ("clock_changes",),
        "offsets_db_sha256_not_the_db": ("db_sha256",), "row_offsets_sha256_mismatch": ("offsets_sha256",),
        "row_clock_changes_sha256_mismatch": ("clock_changes_sha256",), "time_basis_raw": ("time_basis",),
        "db_sha256_mismatch": ("db_sha256",), "co17_none_host_on_cutoff_date": ("CO-17", "ep-01"),
        "co17_stale_host_after_cutoff_date": ("CO-17", "ep-02"),
    }
    for i, (name, words) in enumerate(sorted(expect.items())):
        c = _refusal_case(tmp_path / f"c{i}", REFUSALS[name])
        with pytest.raises(GateError) as ei:
            c.run_raw()
        for w in words:
            assert w in str(ei.value), f"{name}: {w!r} not in {str(ei.value)!r}"


def test_gtt07_co17_wide_host_runs_and_is_flagged(tmp_path):
    """GTT-07 / CO-17: on or after 2026-10-26 a `wide` host (corrected, flagged) does not refuse the trial; rows with
    events of that host carry clock_unreliable = 1 and the clock_flag."""
    day = "2026-10-26T"
    rows = [logon("L", None, 10, utc=f"{day}10:00:00.000000Z"), share("S", None, 10, utc=f"{day}10:00:01.000000Z")]
    c = make_case(tmp_path, rows, start=f"{day}00:00:00.000Z", end=f"{day}23:00:00.000Z",
                  offsets=cf.offsets_spec(ep_02=(2000, "wide", True)), clock_flag="ep-02")
    o = c.run()
    assert len(o.trig) == 1
    assert o.trig[0]["clock_unreliable"] == "1" and o.trig[0]["clock_flag"] == "ep-02"
    assert parse(o.trig[0]["event_utc_corrected"]) == parse(o.trig[0]["event_utc"]) - timedelta(seconds=2)  # wide is corrected


def test_gtt07_co17_none_host_before_the_date_runs_flagged(tmp_path):
    """GTT-07 / CO-17: before 2026-10-26 a `none` host runs on raw time; the flag is carried, rows of that host are
    clock_unreliable = 1 and event_utc_corrected = event_utc."""
    rows = [logon("L", None, 10, utc="2026-10-25T23:30:00.000000Z"),
            share("S", None, 10, utc="2026-10-25T23:30:01.000000Z")]
    c = make_case(tmp_path, rows, start="2026-10-25T23:00:00.000Z", end="2026-10-25T23:59:59.999Z",
                  offsets=cf.offsets_spec(ep_02=(None, "none", True)), clock_flag="ep-02")
    o = c.run()
    r = o.one("R4_smb")
    assert r["event_utc_corrected"] == r["event_utc"] and r["clock_unreliable"] == "1" and r["clock_flag"] == "ep-02"


def test_gtt07_co17_none_host_without_events_does_not_refuse(tmp_path):
    """CO-17 only concerns hosts WITH events in the window (`host_has_events`): a none host with no events runs."""
    rows = [logon("L", None, 10, utc="2026-10-26T10:00:00.000000Z"),
            share("S", None, 10, utc="2026-10-26T10:00:01.000000Z")]
    c = make_case(tmp_path, rows, start="2026-10-26T00:00:00.000Z", end="2026-10-26T23:00:00.000Z",
                  offsets=cf.offsets_spec(ep_03=(None, "none", False)))
    assert c.cli() == 0


def test_gtt07_missing_db_raises_gate_error_writes_nothing(tmp_path):
    """Spec 2: a trial DB that does not exist is an error and nothing is written."""
    c = make_case(tmp_path, None, no_db=True)
    with pytest.raises(GateError):
        c.run_raw()
    assert not c.out_dir.exists()
    assert c.cli() == 2


def test_gtt07_control_valid_inputs_run_and_cli_returns_0(tmp_path):
    """GTT-07 control: the same inputs without the defect run, and the CLI returns 0."""
    c = make_case(tmp_path, [logon("L", 0, 10), share("S", 1, 10)])
    assert c.cli() == 0
    assert (c.out_dir / "triggers.csv").is_file()
    assert len(read_csv(c.out_dir / "triggers.csv")) == 1


def test_gtt07_start_just_before_cutoff_is_allowed(tmp_path):
    """GTT-07 boundary: window start before 2026-10-26 with a `none` host (it has events) is not refused (CO-17 boundary)."""
    c = make_case(tmp_path, [noise()], start="2026-10-25T23:00:00.000Z", end="2026-10-25T23:59:59.999Z",
                  offsets=cf.offsets_spec(ep_01=(None, "none", True)), clock_flag="ep-01")
    c.run_raw()
    assert c.out_dir.is_dir()


def test_gtt07_db_hash_mismatch_checked_on_actual_file_bytes(tmp_path):
    """Decision 041: a window row made for another version of the DB is refused; the same row after a rewrite is accepted."""
    c = make_case(tmp_path, [noise()])
    c.run_raw()
    old_sha = sha256_of(c.db)
    write_db(c.db, [noise("NOISE2", 8.0)])           # DB changed after the window row was computed
    c.refresh(db_sha256=old_sha)                     # offsets file / hashes follow the new DB; the ROW keeps the old DB hash
    with pytest.raises(GateError) as ei:
        c.run_raw()
    assert "db_sha256" in str(ei.value)
    c.refresh()                                      # the row now describes this DB: accepted
    c.run_raw()


# ====================================================================================== GTT-08
def mixed_rows() -> list[dict]:
    r: list[dict] = []
    r += [logon("M-L-r4", 0, 100), share("M-S-r4a", 1, 100, 5140), share("M-S-r4b", 2, 100)]
    r += [logon("M-L-r5", 10, 101, ltype=10, port=51000), s3("M-S3-r5", 11, "192.168.50.21", 51000)]
    r += [logon("M-L-r5b", 20, 102, ltype=3, port=52000, ip="192.168.50.23"),
          s3("M-S3-r5b", 21, "192.168.50.23", 52000)]
    r += [logon("M-L-r6", 30, 103), svc4697("M-4697", 32, 103, "MSVC"), svc7045("M-7045", 32.5, "MSVC")]
    r += [logon("M-L-r8", 40, 104), w91("M-91", 41, "192.168.50.21"), wsm("M-WSM", 43, 104)]
    r += [wsm("M-WSM-D", 50, 9999)]
    r += [w91("M-91-orphan", 60, "192.168.50.23")]
    r += [logon("M-L-unm", 70, 105, ip="192.168.50.10")]
    r += [logon("M-L-int", 80, 106, ltype=2, ip=None), logon("M-L-int11", 81, 107, ltype=11, ip=None)]
    r += [logon("M-L-sys", 90, 997, ip="192.168.50.23"), logon("M-L-loop", 91, 108, ip="127.0.0.1"),
          logon("M-L-own", 92, 109, ip="192.168.50.22")]
    r += [logon("X-L", 100, 7777, ip="192.168.50.99"), share("X-5145", 101, 7777),
          svc4697("X-4697", 102, 7777, "XSVC"), svc7045("X-7045", 102.5, "XSVC"), wsm("X-WSM", 103, 7777)]
    r += [w91("X-91", 110, "192.168.50.98"), wsm("X-WSM2", 112, 8888), s3("X-S3", 120, "192.168.50.97", 50000)]
    r += [logon("X-L10", 130, 7778, ltype=10, ip="192.168.50.98")]
    r += [svc7045("M-7045-LONE", 140, "LONE"), svc4697("M-4697-LOCAL", 150, 6000, "LOCAL")]
    r += [s3("M-S3-OUT", 160, "192.168.50.21", 50123, initiated=1),
          wsm("M-WSM-PAR", 170, 7400, image=r"C:\Windows\System32\cmd.exe", parent=WSM),
          share("M-S-ORPHAN", 180, 424242)]
    r += [logon("D-L", 0, 200, ip="192.168.50.10", host="dc01", account="ep-01$"), share("D-S", 1, 200, 5140, host="dc01")]
    r += [logon("E-L", 5, 201, ip="192.168.50.21", host="ep-03"), logon("E-L10", 15, 202, ltype=10, host="ep-03")]
    r += [logon("M-L-pre", None, 300, utc="2026-09-24T09:00:00.000000Z"), share("M-S-pre", 190, 300),
          logon("M-L-post", None, 301, utc="2026-09-24T12:00:00.000000Z")]
    # noise: not a trigger-type event
    r += [noise("N-1", 3), ev("N-3", 3, "Sysmon", 4, source_ip="192.168.50.21", destination_port=445, initiated=0),
          logon("N-5", 6, 997, ltype=5, ip=None), ev("N-4648", 4648, "Security", 7, subject_logon_id=100),
          ev("N-10", 10, "Sysmon", 8, target_image=LSASS, granted_access="0x1010", source_ip=None)]
    return r


def is_trigger_type(r: dict) -> bool:
    eid, ch = r["event_id"], r["channel"]
    if ch == "Security" and eid == 4624:
        return r["logon_type"] in (2, 3, 10, 11)
    if ch == "Security" and eid in (5140, 5145, 4697):
        return True
    if ch == "System" and eid == 7045:
        return True
    if ch == "Sysmon" and eid == 1:
        return any((r[c] or "").lower().endswith("\\wsmprovhost.exe") for c in ("image", "parent_image"))
    if ch == "WinRM" and eid == 91:
        return True
    return ch == "Sysmon" and eid == 3 and r["destination_port"] == 3389


def in_window(r: dict, start=WIN_START, end=WIN_END) -> bool:
    t = parse(r["event_utc"])
    return parse(start) <= t < parse(end) + timedelta(milliseconds=1)


def test_gtt08_db_hash_unchanged_and_no_side_files(tmp_path):
    """GTT-08: the DB is opened read-only: its SHA-256 is the same after the run, no -journal/-wal/-shm file appears, and stats record the hash."""
    c = make_case(tmp_path, mixed_rows())
    before = sha256_of(c.db)
    names = sorted(p.name for p in c.db.parent.iterdir())
    c.run()
    assert sha256_of(c.db) == before
    assert sorted(p.name for p in c.db.parent.iterdir()) == names
    assert before in (c.out_dir / "stats.json").read_text(encoding="utf-8")


def test_gtt08_two_runs_are_byte_identical_except_run_info(tmp_path):
    """GTT-08 / spec 3: two runs on the same inputs give byte-identical files (all but run_info.json)."""
    c = make_case(tmp_path, mixed_rows())
    c.run()
    first = {f: (c.out_dir / f).read_bytes() for f in OUTPUT_FILES}
    c.run()
    second = {f: (c.out_dir / f).read_bytes() for f in OUTPUT_FILES}
    for f in OUTPUT_FILES:
        if f != "run_info.json":
            assert first[f] == second[f], f


def test_gtt08_byte_identical_across_output_roots(tmp_path):
    """GTT-08: the files do not depend on where they are written (same inputs, other --out root)."""
    c = make_case(tmp_path, mixed_rows())
    c.run()
    first = {f: (c.out_dir / f).read_bytes() for f in OUTPUT_FILES if f != "run_info.json"}
    c2 = Case(c.repo, c.trial, c.db, c.windows, tmp_path / "elsewhere" / "deep")
    c2.run()
    for f, b in first.items():
        assert (c2.out_dir / f).read_bytes() == b, f


def test_gtt08_files_are_utf8_without_bom_and_lf_only(tmp_path):
    """GTT-08: files are UTF-8, no BOM, `\\n` line endings only (a non-ASCII account name is written as UTF-8)."""
    rows = [logon("L", 0, 10, account="jos\u00e9_\u0e17\u0e14\u0e2a\u0e2d\u0e1a"), share("S", 1, 10)]
    c = make_case(tmp_path, rows)
    c.run()
    for f in OUTPUT_FILES:
        b = (c.out_dir / f).read_bytes()
        assert not b.startswith(b"\xef\xbb\xbf"), f
        assert b"\r" not in b, f
        b.decode("utf-8")
    t = (c.out_dir / "triggers.csv").read_bytes()
    assert "jos\u00e9".encode("utf-8") in t and t.endswith(b"\n")
    assert read_csv(c.out_dir / "triggers.csv")[0]["account_name"].startswith("jos\u00e9")


def _key_utc(s: str) -> datetime:
    return parse(s)


def test_gtt08_rows_sorted_by_event_utc_uid_rule_and_trigger_ids_follow(tmp_path):
    """GTT-08 / spec 3: rows sorted by (event_utc, event_uid, rule); trigger_id = <trial>-g0001.. in that order."""
    o = go(tmp_path, mixed_rows() + [logon("M-L-both", 200, 400, port=53000), share("M-S-both", 201, 400),
                                    s3("M-S3-both", 202, "192.168.50.21", 53000)])
    keys = [(_key_utc(r["event_utc"]), r["trigger_event_uid"], r["rule"]) for r in o.trig]
    assert keys == sorted(keys) and len(keys) > 8
    assert [r["trigger_id"] for r in o.trig] == [f"{TRIAL}-g{i:04d}" for i in range(1, len(o.trig) + 1)]
    ukeys = [(_key_utc(r["event_utc"]), r["trigger_event_uid"]) for r in o.unm]
    assert ukeys == sorted(ukeys) and len(ukeys) >= 2
    dkeys = [(_key_utc(r["event_utc"]), r["event_uid"]) for r in o.disp]
    assert dkeys == sorted(dkeys)
    skeys = [(_key_utc(r["event_utc"]), r["event_uid"], r["rule"]) for r in o.sup]
    assert skeys == sorted(skeys) and skeys
    both = [r for r in o.trig if r["trigger_event_uid"] == "M-L-both"]
    assert [r["rule"] for r in both] == ["R4_smb", "R5_rdp"]          # tie on time and uid -> rule order


def test_gtt08_event_utc_corrected_equals_event_utc_with_zero_offsets_and_basis_is_corrected(tmp_path):
    """Spec 3 (T6b.2): with zero offsets event_utc_corrected equals event_utc as an instant; time_basis says corrected;
    event_utc_raw no longer exists in any CSV."""
    o = go(tmp_path, mixed_rows())
    assert o.trig
    for r in o.trig:
        assert parse(r["event_utc_corrected"]) == parse(r["event_utc"]) and r["time_basis"] == "corrected"
        assert "event_utc_raw" not in r


def test_gtt08_window_source_copied_from_window_row(tmp_path):
    """Spec 3: window_source is copied from data/trial_windows.csv (triggers and unmatched)."""
    o = go(tmp_path, [logon("L", 0, 10), share("S", 1, 10), logon("U", 20, 11)], window_source="operator")
    assert o.trig and o.unm
    assert all(r["window_source"] == "operator" for r in o.trig + o.unm)


def test_gtt08_stats_json_has_spec3_content(tmp_path):
    """Spec 3: stats.json holds the trial id, DB hash before/after, the window row (all columns) and file hash, parameters."""
    c = make_case(tmp_path, mixed_rows())
    o = c.run()
    text = json.dumps(o.stats)
    assert TRIAL in text
    assert sha256_of(c.db) in text
    assert sha256_of(c.windows) in text
    for col in WINDOW_COLUMNS:
        assert col in text, f"window column {col} missing from stats.json"
    params_v = o.stats["parameters"]
    assert isinstance(params_v, dict) and params_v
    pt = json.dumps(params_v)
    assert "192.168.50.97" in pt and "996" in pt
    assert "near_window" in o.stats
    assert o.stats["trial_id"] == TRIAL
    assert set(o.stats["db"]) == {"path", "sha256_before", "sha256_after"}
    assert o.stats["db"]["sha256_before"] == o.stats["db"]["sha256_after"] == sha256_of(c.db)
    assert set(o.stats["window"]) == {"row", "file", "file_sha256"}
    assert o.stats["window"]["file_sha256"] == sha256_of(c.windows)
    assert set(o.stats["window"]["row"]) == set(WINDOW_COLUMNS)
    assert o.stats["window"]["row"]["trial_id"] == TRIAL and o.stats["window"]["row"]["start_utc"] == WIN_START


def test_spec5_sensitivity_counts_at_2s_and_10s_are_reported(tmp_path):
    """Spec 5 / 3.1: rdp_pairs at "2", "5", "10"; a 7 s pair shows only at "10" and never fires the rule."""
    o = go(tmp_path, r5_pair(7.0))
    assert o.rule("R5_rdp") == []
    assert o.stats["sensitivity"]["rdp_pairs"] == {"2": 0, "5": 0, "10": 1}


def test_gtt08_tier_d_rows_report_logon_id_ip_lookup_from_unclipped_db(tmp_path):
    """Spec 3: for every tier-D row the IP of its logon id is looked up in the unclipped DB (here a pre-window 4624 from .23)."""
    rows = [logon("PRE", None, 5001, utc="2026-09-24T09:00:00.000000Z", ip="192.168.50.23"),
            svc4697("V4", 2, 5001)]
    o = go(tmp_path, rows)
    r = o.one("R6_service")
    assert r["gate_tier"] == "D"
    v = o.stats["tier_d_ip_lookup"]                 # spec 3.1: [{trigger_id, rule, host, logon_id_hex, logon_found, source_ips}]
    assert len(v) == 1
    assert set(v[0]) == {"trigger_id", "rule", "host", "logon_id_hex", "logon_found", "source_ips"}
    assert v[0]["trigger_id"] == r["trigger_id"] and v[0]["rule"] == "R6_service" and v[0]["host"] == "ep-02"
    assert v[0]["logon_found"] is True and v[0]["source_ips"] == ["192.168.50.23"]
    assert v[0]["logon_id_hex"].lower() == "0x1389"


def test_gtt08_machine_account_and_hex_display_columns(tmp_path):
    """Spec 3: machine_account = 1 if the account ends in `$`; target_logon_id_hex shows the original hex (D1)."""
    o = go(tmp_path, [logon("L", 0, 255, account="ep-01$"), share("S", 1, 255)])
    r = o.one("R4_smb")
    assert r["machine_account"] == "1" and r["target_logon_id"] == "255" and r["target_logon_id_hex"].lower() == "0xff"


# ====================================================================================== GTT-09
def test_gtt09_excluded_4624_before_window_wsmprovhost_inside_is_excluded(tmp_path):
    """GTT-09: excluded-IP 4624 outside the window + wsmprovhost inside -> excluded_source_ip_session via the unclipped lookup, no tier-D R8."""
    rows = [logon("X-PRE", None, 8000, utc="2026-09-24T09:30:00.000000Z", ip="192.168.50.99"),
            wsm("X-WSM", 0, 8000)]
    o = go(tmp_path, rows)
    assert o.rule("R8_winrm") == [] and o.trig == [] and o.unm == []
    assert o.d("X-WSM")["disposition"] == "excluded_source_ip_session"
    assert "X-PRE" not in o.all_text()


def test_gtt09_control_non_excluded_pre_window_session_gives_tier_d_r8(tmp_path):
    """GTT-09 control: the same layout from a lab IP gives a tier-D R8 row (so the exclusion above comes from the IP)."""
    rows = [logon("PRE", None, 8000, utc="2026-09-24T09:30:00.000000Z", ip="192.168.50.21"),
            wsm("W", 0, 8000)]
    o = go(tmp_path, rows)
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["anchor_logon_uid"] == ""


def test_gtt09_excluded_session_share_and_4697_before_4624_window_lookup(tmp_path):
    """GT-02(b): 5145 and 4697 of an excluded session whose 4624 is pre-window are excluded; the 7045 -> paired_excluded."""
    rows = [logon("X-PRE", None, 8001, utc="2026-09-24T09:30:00.000000Z", ip="192.168.50.98"),
            share("X-S", 1, 8001), svc4697("X-4", 2, 8001, "ZSVC"), svc7045("X-7", 2.5, "ZSVC")]
    o = go(tmp_path, rows)
    assert o.trig == [] and o.unm == []
    assert o.d("X-S")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-4")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-7")["disposition"] == "paired_excluded"


def test_gtt09_7045_paired_with_system_4697_is_paired_excluded_even_5s_apart(tmp_path):
    """GT-04 / GT-12(d): the 7045 paired (|dt| <= 5 s, either order) with a system-logon 4697 -> paired_excluded."""
    o = go(tmp_path, [svc4697("V4", 10, 999), svc7045("V7", 5.0)])
    assert o.d("V7")["disposition"] == "paired_excluded" and o.trig == []


# ====================================================================================== GTT-10
@pytest.mark.parametrize("ip", [None, "", "-"])
def test_gtt10_blank_ip_type3_with_5145_fires_r4(tmp_path, ip):
    """GTT-10: a blank / `-` IP type 3 logon with a 5145 fires R4 with ip_kind = blank (source_ip null)."""
    o = go(tmp_path, [logon("L", 0, 10, ip=ip, pkg="Kerberos", port=0), share("S", 1, 10)])
    r = o.one("R4_smb")
    assert r["ip_kind"] == "blank" and r["source_ip"] == "" and r["authentication_package"] == "Kerberos"


@pytest.mark.parametrize("ip", [None, "", "-"])
def test_gtt10_blank_ip_type10_fires_r5(tmp_path, ip):
    """GTT-10: a blank-IP type 10 logon fires R5 with ip_kind = blank."""
    o = go(tmp_path, [logon("L", 0, 10, ltype=10, ip=ip, port=0)])
    r = o.one("R5_rdp")
    assert r["ip_kind"] == "blank" and r["source_ip"] == ""


def test_gtt10_link_local_ipv6_fires_with_ip_kind_link_local(tmp_path):
    """GT-06: an IPv6 link-local source can fire a rule; ip_kind = link_local."""
    o = go(tmp_path, [logon("L", 0, 10, ip="fe80::1ff:fe23:4567:890a"), share("S", 1, 10)])
    assert o.one("R4_smb")["ip_kind"] == "link_local"


def test_gtt10_global_ipv6_is_ipv6_kind(tmp_path):
    """GT-06: a parseable non-link-local IPv6 address has ip_kind = ipv6."""
    o = go(tmp_path, [logon("L", 0, 10, ip="2001:db8::5"), share("S", 1, 10)])
    assert o.one("R4_smb")["ip_kind"] == "ipv6"


def test_gtt10_blank_ip_logon_without_rule_is_unmatched_not_lost(tmp_path):
    """GT-06 / GT-15: a blank-IP remote logon with no rule is in unmatched_remote.csv."""
    o = go(tmp_path, [logon("L", 0, 10, ip=None, ltype=3)])
    assert "L" in o.unm_uids() and o.unm[0]["ip_kind"] == "blank"


def test_gtt10_blank_ip_type3_is_not_paired_with_3389_sysmon3_with_null_ip(tmp_path):
    """GT-18: NULL never joins: a blank-IP type 3 logon and a NULL-IP Sysmon 3 do not give R5."""
    o = go(tmp_path, [logon("L", 0, 10, ip=None, port=None), s3("S3", 1, None, None)])
    assert o.rule("R5_rdp") == []


# ====================================================================================== GTT-11
def test_gtt11_every_in_window_trigger_type_event_has_exactly_one_disposition_row(tmp_path):
    """GTT-11: dispositions.csv has exactly one row per in-window trigger-type event (incl. 4624 type 2/11), no other events."""
    rows = mixed_rows()
    o = go(tmp_path, rows)
    expected = {r["event_uid"] for r in rows if is_trigger_type(r) and in_window(r)}
    got = [r["event_uid"] for r in o.disp]
    assert len(got) == len(set(got)), "duplicate dispositions rows"
    assert set(got) == expected
    for r in o.disp:
        assert r["disposition"] in SPEC_DISPOSITIONS


def test_gtt11_disposition_counts_sum_to_trigger_type_count_per_host(tmp_path):
    """GTT-11: per host, disposition rows = in-window trigger-type events of that host."""
    rows = mixed_rows()
    o = go(tmp_path, rows)
    for host in ("dc01", "ep-02", "ep-03"):
        exp = sum(1 for r in rows if r["host"] == host and is_trigger_type(r) and in_window(r))
        assert exp > 0
        assert sum(1 for r in o.disp if r["host"] == host) == exp


def test_gtt11_stats_disposition_counts_equal_file_counts(tmp_path):
    """GTT-11 / GTA-04: stats.json counts per disposition equal the dispositions.csv counts."""
    o = go(tmp_path, mixed_rows())
    v = o.stats["dispositions"]                      # spec 3.1: {total: disposition -> count (zeros included), per_host}
    assert set(v) == {"total", "per_host"}
    assert set(v["total"]) == set(SPEC_DISPOSITIONS)
    for d in SPEC_DISPOSITIONS:
        in_file = sum(1 for r in o.disp if r["disposition"] == d)
        assert v["total"][d] == in_file, d
        for host, counts in v["per_host"].items():
            assert counts.get(d, 0) == sum(1 for r in o.disp if r["disposition"] == d and r["host"] == host), (d, host)


def test_gtt11_mixed_scenario_covers_each_disposition(tmp_path):
    """GTT-11: the mixed scenario exercises every disposition value (so the partition test is meaningful)."""
    o = go(tmp_path, mixed_rows())
    assert {r["disposition"] for r in o.disp} == set(SPEC_DISPOSITIONS)


def test_gtt11_outside_window_events_have_no_disposition_row(tmp_path):
    """GTT-11 / GT-01: events outside the window (even trigger-type) have no dispositions row."""
    o = go(tmp_path, mixed_rows())
    for uid in ("M-L-pre", "M-L-post"):
        assert not o.has_d(uid)


def test_gtt11_non_trigger_type_events_have_no_disposition_row(tmp_path):
    """Spec 3: Sysmon 1 (other), Sysmon 3 (other port), 4624 type 5, 4648, Sysmon 10 are not in dispositions.csv."""
    o = go(tmp_path, mixed_rows())
    for uid in ("N-1", "N-3", "N-5", "N-4648", "N-10"):
        assert not o.has_d(uid), uid


def test_gtt11_interactive_logons_get_interactive_logon_rows(tmp_path):
    """Decision 041 / GT-03: 4624 type 2 and 11 in the window get a dispositions row `interactive_logon`."""
    o = go(tmp_path, [logon("I2", 0, 10, ltype=2, ip=None), logon("I11", 5, 11, ltype=11, ip=None)])
    assert o.d("I2")["disposition"] == "interactive_logon" and o.d("I11")["disposition"] == "interactive_logon"
    assert o.trig == [] and o.unm == []


def test_gtt11_no_rule_dispositions(tmp_path):
    """Spec 3: a share event, WinRM 91 or 3389 Sysmon 3 that completes no rule is `no_rule`; a lone 7045 / 4697 is a trigger."""
    o = go(tmp_path, [share("S", 0, 99), w91("V91", 10, "192.168.50.21"), s3("S3", 20, "192.168.50.21", 5),
                      svc7045("V7", 30), svc4697("V4", 60, 6009, "OTHER")])
    assert [o.d(u)["disposition"] for u in ("S", "V91", "S3")] == ["no_rule"] * 3
    assert o.d("V7")["disposition"] == "trigger" and o.d("V4")["disposition"] == "trigger"


# ====================================================================================== decision 041 partition
def test_d041_every_remote_type_3_10_logon_in_exactly_one_of_triggers_or_unmatched(tmp_path):
    """Decision 041 / GT-15: every remote type 3/10 logon is in exactly one of triggers.csv (trigger or anchor) or unmatched_remote.csv."""
    rows = mixed_rows()
    o = go(tmp_path, rows)
    excluded = set(EXCLUDED_IPS)
    own = {"dc01": "192.168.50.10", "ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23"}
    remote = [r["event_uid"] for r in rows
              if r["event_id"] == 4624 and r["logon_type"] in (3, 10) and in_window(r)
              and r["source_ip"] not in excluded | {"127.0.0.1", "::1", "::ffff:127.0.0.1", own[r["host"]]}
              and r["target_logon_id"] not in (996, 997, 999)]
    assert len(remote) >= 8
    in_trig, in_unm = o.trig_uids(), o.unm_uids()
    for uid in remote:
        assert (uid in in_trig) != (uid in in_unm), f"{uid}: trigger={uid in in_trig} unmatched={uid in in_unm}"
        assert o.d(uid)["disposition"] == ("trigger" if uid in in_trig else "unmatched_remote")


def test_d041_unmatched_rows_not_in_triggers(tmp_path):
    """Decision 041: no uid is both an `unmatched_remote.csv` logon and a trigger / anchor."""
    o = go(tmp_path, mixed_rows())
    assert o.unm_uids().isdisjoint(o.trig_uids())


def test_d041_r4_and_r5_rows_on_one_anchor_both_kept(tmp_path):
    """GT-14: several rules on one anchor give several rows; nothing merged or dropped; not in unmatched."""
    rows = [logon("L", 0, 20, port=50000), share("S", 1, 20), s3("S3", 2, "192.168.50.21", 50000)]
    o = go(tmp_path, rows)
    assert [r["rule"] for r in o.trig] == ["R4_smb", "R5_rdp"]
    assert {r["anchor_logon_uid"] for r in o.trig} == {"L"} and o.unm == []
    assert o.d("S")["disposition"] == "supporting" and o.d("S3")["disposition"] == "supporting"


# ====================================================================================== GTT-12 / candidate_count
def test_gtt12_null_logon_ids_never_match(tmp_path):
    """GTT-12: two rows with NULL logon IDs never match (R4 share, R6 4697, R8 Sysmon 1)."""
    rows = [logon("L1", 0, None), share("S1", 1, None),
            logon("L2", 30, None), svc4697("V4", 31, None), wsm("W", 60, None)]
    o = go(tmp_path, rows)
    assert o.rule("R4_smb") == []
    assert o.one("R6_service")["gate_tier"] == "D" and o.one("R8_winrm")["gate_tier"] == "D"
    assert {"L1", "L2"} <= o.unm_uids()
    assert o.d("S1")["disposition"] == "no_rule"


def test_gtt12_near_duplicate_4624_pair_flagged_on_both_rows(tmp_path):
    """GTT-12 / GT-18: a near-duplicate 4624 pair (same host, channel, record_id, different uid) -> both R4 rows flagged, candidate_count 2."""
    rows = [logon("L1", 0, 4000, record_id=777), logon("L2", 0.2, 4000, record_id=777), share("S", 1, 4000)]
    o = go(tmp_path, rows)
    rs = o.rule("R4_smb")
    assert len(rs) == 2 and {r["trigger_event_uid"] for r in rs} == {"L1", "L2"}
    assert all(r["near_duplicate"] == "1" and r["candidate_count"] == "2" for r in rs)
    assert o.stats["near_duplicate_uids"] == ["L1", "L2"]            # spec 3.1: sorted list of flagged in-window uids


def test_gtt12_same_record_id_on_other_host_or_channel_is_not_near_duplicate(tmp_path):
    """GT-18: near duplicate needs the same host, channel and record_id."""
    rows = [logon("A", 0, 10, record_id=500), logon("B", 10, 11, record_id=500, host="ep-03"),
            ev("C-sysmon", 1, "Sysmon", 20, record_id=500, image=WSM, session_id=12, parent_image="x"),
            logon("D", 30, 13, record_id=501)]
    o = go(tmp_path, rows)
    for r in o.unm + o.trig:
        assert r["near_duplicate"] == "0", r["trigger_event_uid"]


def test_gtt12_non_flagged_rows_have_near_duplicate_zero(tmp_path):
    """GT-18: rows with unique (host, channel, record_id) have near_duplicate 0."""
    o = go(tmp_path, mixed_rows())
    assert o.trig and all(r["near_duplicate"] == "0" for r in o.trig + o.unm)


def test_gtt12_events_dedup_view_is_used_not_events(tmp_path):
    """CLAUDE.md data rule: rows removed by `events_dedup` (same duplicate_content_sha256) are never seen: one R4 row only."""
    dup = hashlib.sha256(b"same").hexdigest()
    rows = [logon("L", 0, 10, duplicate_content_sha256=dup, source_line=1, source_relative_path="a.jsonl"),
            logon("L-DUP", 0, 10, duplicate_content_sha256=dup, source_line=2, source_relative_path="a.jsonl"),
            share("S", 1, 10)]
    o = go(tmp_path, rows)
    r = o.one("R4_smb")
    assert r["trigger_event_uid"] == "L" and r["candidate_count"] == "1" and r["near_duplicate"] == "0"
    assert "L-DUP" not in o.all_text()


def test_d041_r4_candidate_count_near_duplicate_pair_is_2_on_both(tmp_path):
    """Decision 041: R4 candidate_count = max over supporting events of distinct anchors per event -> 2 on both rows of a pair."""
    rows = [logon("L1", 0, 4000, record_id=777), logon("L2", 0.5, 4000, record_id=777),
            share("S1", 1, 4000, 5140), share("S2", 2, 4000)]
    o = go(tmp_path, rows)
    assert [r["candidate_count"] for r in o.rule("R4_smb")] == ["2", "2"]


def test_d041_r5_candidate_count_is_number_of_4624_matching_the_sysmon3(tmp_path):
    """GT-11: candidate_count = number of 4624s matching the Sysmon 3 (two logons from one IP with port 0, ip_time -> 2 each)."""
    rows = [logon("L1", 0, 30, port=0), logon("L2", 1, 31, port=None), s3("S3", 0.5, "192.168.50.21", 50000)]
    o = go(tmp_path, rows)
    rs = o.rule("R5_rdp")
    assert len(rs) == 2 and all(r["candidate_count"] == "2" and r["method"] == "ip_time" for r in rs)
    assert {r["trigger_event_uid"] for r in rs} == {"L1", "L2"}


def test_d041_r5_candidate_count_counts_anchors_per_method(tmp_path):
    """Decision 041: candidate_count counts distinct anchors matched by the SAME method: one by ip_port_time, one by ip_time -> 1 each."""
    rows = [logon("LA", 0, 40, port=50000), logon("LB", 1, 41, port=0), s3("S3", 0.5, "192.168.50.21", 50000)]
    o = go(tmp_path, rows)
    by = {r["trigger_event_uid"]: r for r in o.rule("R5_rdp")}
    assert set(by) == {"LA", "LB"}
    assert by["LA"]["method"] == "ip_port_time" and by["LA"]["candidate_count"] == "1"
    assert by["LB"]["method"] == "ip_time" and by["LB"]["candidate_count"] == "1"


def test_d041_r5_candidate_count_near_duplicate_pair_with_ports(tmp_path):
    """Decision 041: a near-duplicate type 3 pair with the same port both match the Sysmon 3 by ip_port_time -> 2 on both."""
    rows = [logon("L1", 0, 30, port=50000, record_id=1234), logon("L2", 0.3, 30, port=50000, record_id=1234),
            s3("S3", 1.0, "192.168.50.21", 50000)]
    o = go(tmp_path, rows)
    rs = o.rule("R5_rdp")
    assert len(rs) == 2 and all(r["candidate_count"] == "2" and r["near_duplicate"] == "1" for r in rs)


def test_d041_row_without_supporting_event_candidate_count_one_when_own_anchor(tmp_path):
    """Spec 3: a row with no supporting event has candidate_count 1 if the event is its own anchor."""
    o = go(tmp_path, [logon("L", 0, 20, ltype=10)])
    assert o.one("R5_rdp")["candidate_count"] == "1"


# ====================================================================================== time_delta_ms (decision 041)
def test_d041_time_delta_r5_type3_uses_supporting_minus_anchor(tmp_path):
    """Decision 041: R5 type 3 time_delta = (earliest supporting Sysmon 3) - anchor, in ms."""
    o = go(tmp_path, r5_pair(2.345))
    assert o.one("R5_rdp")["time_delta_ms"] == "2345"


def test_d041_time_delta_null_when_tier_d(tmp_path):
    """Decision 041: no anchor -> null time_delta_ms (R6 and R8 tier D)."""
    o = go(tmp_path, [svc4697("V4", 0, 5555), wsm("W", 40, 5556), w91("V91", 39, "192.168.50.21")])
    assert o.one("R6_service")["time_delta_ms"] == "" and o.one("R8_winrm")["time_delta_ms"] == ""


def test_d041_time_delta_is_integer_ms(tmp_path):
    """Spec 3: time_delta_ms is an int (ms), never a float string."""
    o = go(tmp_path, [logon("L", 0, 10), share("S", 1.2345, 10)])
    v = o.one("R4_smb")["time_delta_ms"]
    assert re.fullmatch(r"-?\d+", v) and abs(int(v) - 1234.5) <= 1


# ====================================================================================== supporting.csv / R1 / R3
def test_gt16_r1_lsass_access_listed_in_supporting_not_trigger(tmp_path):
    """GT-16: Sysmon 10 on lsass.exe with an R1 access mask is listed in supporting.csv as R1_lsass, never a trigger."""
    rows = [ev("R1", 10, "Sysmon", 0, target_image=LSASS, granted_access="0x1010", host="ep-01")]
    o = go(tmp_path, rows)
    assert [(r["rule"], r["event_uid"], r["host"]) for r in o.sup] == [("R1_lsass", "R1", "ep-01")]
    assert o.trig == [] and o.unm == []


@pytest.mark.parametrize("mask", ["0x1010", "0x1410", "0x143a", "0x143A", "0x1fffff", "0x00001410"])
def test_gt16_r1_masks_in_the_set_are_listed(tmp_path, mask):
    """Spec 5: R1_ACCESS_MASKS 0x1010, 0x1410, 0x143a, 0x1fffff (hex case / leading zeros ignored)."""
    o = go(tmp_path, [ev("R1", 10, "Sysmon", 0, target_image=LSASS, granted_access=mask)])
    assert [r["rule"] for r in o.sup] == ["R1_lsass"]


@pytest.mark.parametrize("img,mask", [(LSASS, "0x1000"), (LSASS, None), (r"C:\Windows\notepad.exe", "0x1010"),
                                      (r"C:\Temp\notlsass.exe", "0x1010")])
def test_gt16_r1_not_listed_without_lsass_or_mask(tmp_path, img, mask):
    """GT-16: no R1 for another target image, an access mask outside the set, or a NULL mask."""
    o = go(tmp_path, [ev("R1", 10, "Sysmon", 0, target_image=img, granted_access=mask)])
    assert o.sup == []


def test_gt16_r3_explicit_credentials_listed_in_supporting(tmp_path):
    """GT-16: a 4648 is listed as R3_explicit in supporting.csv, never a trigger."""
    o = go(tmp_path, [ev("R3", 4648, "Security", 0, host="ep-01", subject_logon_id=900, account_name="admin_it")])
    assert [(r["rule"], r["event_uid"]) for r in o.sup] == [("R3_explicit", "R3")]
    assert o.trig == [] and o.unm == []


def test_gt16_supporting_signals_outside_window_not_listed(tmp_path):
    """GT-16 / GT-01: R1, R3 and R8_parent outside the window are not listed."""
    rows = [ev("R1", 10, "Sysmon", None, utc="2026-09-24T09:00:00.000000Z", target_image=LSASS,
               granted_access="0x1010"),
            ev("R3", 4648, "Security", None, utc="2026-09-24T12:00:00.000000Z", subject_logon_id=900),
            wsm("PAR", None, 7400, image=r"C:\Windows\System32\cmd.exe", parent=WSM,
                utc="2026-09-24T09:00:00.000000Z")]
    o = go(tmp_path, rows)
    assert o.sup == []


def test_gt16_supporting_rows_sorted_and_listed_for_all_three_rules(tmp_path):
    """GT-16: R1_lsass, R3_explicit and R8_parent all appear in supporting.csv with the spec columns filled for uid/host/utc."""
    rows = [ev("R1", 10, "Sysmon", 0, target_image=LSASS, granted_access="0x1410"),
            ev("R3", 4648, "Security", 5, subject_logon_id=900),
            wsm("PAR", 10, 7400, image=r"C:\Windows\System32\cmd.exe", parent=WSM)]
    o = go(tmp_path, rows)
    assert [r["rule"] for r in o.sup] == ["R1_lsass", "R3_explicit", "R8_parent"]
    for r in o.sup:
        assert r["event_uid"] and r["host"] and parse(r["event_utc"])


# ====================================================================================== GTT-13
def test_gtt13_machine_account_type3_with_5140_fires_r4_flagged_and_counted(tmp_path):
    """GTT-13 / GT-07: a machine-account type 3 with a 5140 fires R4 with machine_account = 1 and is counted per host in stats."""
    rows = [logon("DL", 0, 300, host="dc01", account="ep-01$", ip="192.168.50.21"),
            share("DS", 1, 300, 5140, host="dc01"),
            logon("DL2", 10, 301, host="dc01", account="ep-02$", ip="192.168.50.22"),
            share("DS2", 11, 301, 5140, host="dc01"),
            logon("OL", 20, 302, host="dc01", account="svc_backup", ip="192.168.50.23"),
            share("OS", 21, 302, 5140, host="dc01")]
    o = go(tmp_path, rows)
    rs = o.rule("R4_smb")
    assert len(rs) == 3
    flags = {r["trigger_event_uid"]: r["machine_account"] for r in rs}
    assert flags == {"DL": "1", "DL2": "1", "OL": "0"}
    assert rs[0]["account_name"] == "ep-01$"
    assert o.stats["machine_account_triggers_per_host"] == {"dc01": 2}


def test_gtt13_machine_account_logon_without_rule_is_still_kept_in_unmatched(tmp_path):
    """GT-07: machine accounts are kept; with no rule the logon is in unmatched_remote.csv with machine_account 1."""
    o = go(tmp_path, [logon("DL", 0, 300, host="dc01", account="ep-01$")])
    assert o.unm[0]["machine_account"] == "1" and o.d("DL")["disposition"] == "unmatched_remote"


# ====================================================================================== GTT-14 (gate half)
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


def test_gtt14_gate_recorder_sees_opens(tmp_path, monkeypatch):
    """GTT-14 (self-check): the recording wrappers really record opens, so 'no ground_truth path' is meaningful."""
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    p = tmp_path / "x.txt"
    p.write_text("a", encoding="utf-8")
    with open(p, encoding="utf-8") as fh:
        fh.read()
    assert any(Path(x) == p for x in rec.paths)


def _gt_repo(tmp_path: Path) -> Case:
    c = make_case(tmp_path, mixed_rows())
    gt = c.repo / "ground_truth" / "approved"
    gt.mkdir(parents=True)
    (gt / "s02_t00.yaml").write_text("decoy: true\n", encoding="utf-8")
    return c


def test_gtt14_run_gate_never_opens_ground_truth(tmp_path, monkeypatch):
    """GTT-14 (gate half): run_gate on a temp repo with a decoy ground_truth/approved/s02_t00.yaml opens no path under ground_truth/."""
    c = _gt_repo(tmp_path)
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    c.run_raw()
    assert any(Path(x).name == "s02_t00.sqlite3" for x in rec.paths), "recorder did not see the DB open"
    assert any(Path(x).name == "trial_windows.csv" for x in rec.paths)
    assert any(Path(x).name == f"{TRIAL}.clock_offsets.csv" for x in rec.paths), "recorder did not see the offsets file"
    assert any(Path(x).name == f"{TRIAL}.clock_changes.csv" for x in rec.paths), "recorder did not see the changes file"
    bad = [p for p in rec.paths if _under(p, c.repo / "ground_truth")]
    assert bad == [], f"run_gate opened ground_truth paths: {bad}"


def test_gtt14_main_never_opens_ground_truth_with_default_paths(tmp_path, monkeypatch):
    """GTT-14 (gate half): main() with only --trial / --repo (default DB, window and out paths) opens no path under ground_truth/."""
    c = _gt_repo(tmp_path)
    rec = _Recorder()
    _install_recorders(monkeypatch, rec)
    rc = gate_main(["--trial", TRIAL, "--repo", str(c.repo)])
    assert rc == 0
    assert any(Path(x).name == "s02_t00.sqlite3" for x in rec.paths), "recorder did not see the DB open"
    bad = [p for p in rec.paths if _under(p, c.repo / "ground_truth")]
    assert bad == [], f"main opened ground_truth paths: {bad}"
    assert (c.repo / "out" / "gate" / TRIAL / "triggers.csv").is_file()


def test_gtt14_source_text_has_no_forbidden_strings():
    """GTT-14: no src/gate/*.py mentions ground_truth, build_draft, intended_steps, owner_reviews, provisional_windows."""
    forbidden = ["ground_truth", "build_draft", "intended_steps", "owner_reviews", "provisional_windows"]
    files = sorted(SRC_GATE.glob("*.py"))
    assert files, "src/gate has no python files"
    assert "clock.py" in {f.name for f in files}, "the T6b.2 module gate/clock.py must be covered by the scan"
    hits = [(f.name, s) for f in files for s in forbidden if s in f.read_text(encoding="utf-8")]
    assert hits == [], f"forbidden strings in gate source: {hits}"


def test_gtt14_no_direct_import_of_key_builder_finish_verify_overlap():
    """GTT-14: no src/gate file directly imports answer_key.build, .finish, .verify or .overlap (trial_window.params is allowed)."""
    banned = {"build", "finish", "verify", "overlap"}
    offenders: list[str] = []
    for f in sorted(SRC_GATE.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    parts = a.name.split(".")
                    if parts[0] == "answer_key" and len(parts) > 1 and parts[1] in banned:
                        offenders.append(f"{f.name}: import {a.name}")
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                parts = mod.split(".")
                names = {a.name for a in node.names}
                if parts[0] == "answer_key" and len(parts) > 1 and parts[1] in banned:
                    offenders.append(f"{f.name}: from {mod} import ...")
                if mod == "answer_key" and names & banned:
                    offenders.append(f"{f.name}: from answer_key import {sorted(names & banned)}")
                if node.level and (parts[0] in banned or names & banned) and "answer_key" in str(f):
                    offenders.append(f"{f.name}: relative import")
    assert offenders == [], offenders


# ====================================================================================== GTT-15 outbound 3389
def out3389(uid, off, dest, *, host="ep-01", src="192.168.50.21", port=49999, initiated=1, **kw) -> dict:
    """Sysmon 3 to port 3389 logged on `host` (default ep-01, own IP 192.168.50.21); `dest` = destination_ip."""
    return s3(uid, off, src, port, host=host, initiated=initiated, destination_ip=dest, **kw)


def in_any_gate_row(o: "Out", uid: str) -> bool:
    """True if `uid` is a trigger, an anchor, a supporting uid of a trigger row, in supporting.csv or unmatched."""
    return (uid in o.trig_uids() or any(uid in sup(r) for r in o.trig) or any(r["event_uid"] == uid for r in o.sup)
            or uid in o.unm_uids())


@pytest.mark.parametrize("dest,expected", [
    ("192.168.50.22", "no_rule"),
    ("10.9.8.7", "no_rule"),
    ("192.168.50.99", "excluded_source_ip"),
    ("192.168.50.97", "excluded_source_ip"),
    ("192.168.50.98", "excluded_source_ip"),
    ("::ffff:192.168.50.99", "excluded_source_ip"),
    ("127.0.0.1", "loopback_or_self"),
    ("::1", "loopback_or_self"),
    ("::ffff:127.0.0.1", "loopback_or_self"),
    ("192.168.50.21", "loopback_or_self"),
    ("::ffff:192.168.50.21", "loopback_or_self"),
])
def test_gtt15_outbound_3389_disposition_follows_destination_ip(tmp_path, dest, expected):
    """GTT-15 / GT-05: outbound (initiated = 1) 3389 Sysmon 3 on ep-01 is judged by destination_ip, not by source_ip (own IP)."""
    o = go(tmp_path, [out3389("O", 0, dest)])
    assert o.d("O")["disposition"] == expected
    assert o.trig == [] and o.unm == [] and o.sup == []
    if expected == "no_rule":
        assert OUT_3389_REASON in o.d("O")["reason_detail"]
    else:
        assert OUT_3389_REASON not in o.d("O")["reason_detail"]


def test_gtt15_outbound_3389_reason_text_is_exact_and_in_no_rule_row(tmp_path):
    """GTT-15 / GT-05: reason_detail holds exactly the spec text; the event is in no triggers / supporting / unmatched row."""
    rows = [out3389("O", 0, "192.168.50.22"), logon("L", 5, 20, host="ep-01", ip="192.168.50.22", port=50000)]
    o = go(tmp_path, rows)
    d = o.d("O")
    assert d["disposition"] == "no_rule" and d["reason_detail"] == OUT_3389_REASON
    assert not in_any_gate_row(o, "O")
    assert o.d("L")["disposition"] == "unmatched_remote"           # the 4624 is not affected by the outbound event


def test_gtt15_outbound_3389_with_null_destination_is_not_excluded_or_loopback(tmp_path):
    """Spec 2 (NULL / blank never compares equal) + GT-05: an outbound 3389 with no destination_ip is `no_rule`."""
    o = go(tmp_path, [out3389("O1", 0, None), out3389("O2", 10, "-"), out3389("O3", 20, "")])
    assert [o.d(u)["disposition"] for u in ("O1", "O2", "O3")] == ["no_rule"] * 3


def test_gtt15_outbound_3389_other_host_own_ip_is_host_specific(tmp_path):
    """GT-05: 'the host's own IP' is per host: destination 192.168.50.22 is own on ep-02 (loopback_or_self), not on ep-01."""
    o = go(tmp_path, [out3389("ON-EP01", 0, "192.168.50.22"),
                      out3389("ON-EP02", 10, "192.168.50.22", host="ep-02", src="192.168.50.22")])
    assert o.d("ON-EP01")["disposition"] == "no_rule"
    assert o.d("ON-EP02")["disposition"] == "loopback_or_self"


@pytest.mark.parametrize("src,dest,expected", [
    ("192.168.50.22", "192.168.50.21", "no_rule"),            # normal inbound: judged by source_ip
    ("192.168.50.21", "192.168.50.22", "loopback_or_self"),   # source_ip = ep-01's own IP -> self, destination ignored
    ("192.168.50.99", "192.168.50.21", "excluded_source_ip"),
    ("192.168.50.22", "192.168.50.99", "no_rule"),            # excluded destination on an INBOUND event is not judged
    ("192.168.50.22", "127.0.0.1", "no_rule"),
    ("::ffff:192.168.50.99", None, "excluded_source_ip"),
    ("127.0.0.1", None, "loopback_or_self"),
])
def test_gtt15_inbound_3389_still_judged_by_source_ip(tmp_path, src, dest, expected):
    """GTT-15: the same events with initiated = 0 behave as before (inbound, judged by source_ip)."""
    o = go(tmp_path, [out3389("I", 0, dest, src=src, initiated=0)])
    assert o.d("I")["disposition"] == expected
    assert OUT_3389_REASON not in o.d("I")["reason_detail"]


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "::ffff:127.0.0.1", "192.168.50.21", "::ffff:192.168.50.21"])
def test_gtt15_loopback_and_own_ip_4624_stay_loopback_or_self(tmp_path, ip):
    """GTT-15: a loopback 4624 and an own-IP 4624 (on ep-01) stay `loopback_or_self`; they never fire."""
    o = go(tmp_path, [logon("L", 0, 20, host="ep-01", ip=ip), share("S", 1, 20, host="ep-01")])
    assert o.d("L")["disposition"] == "loopback_or_self"
    assert o.trig == [] and o.unm == []


def test_gtt15_outbound_3389_never_pairs_for_r5(tmp_path):
    """GTT-15 / GT-11: an outbound 3389 Sysmon 3 never pairs with a type 3 4624 or supports a type 10 R5, whatever its fields."""
    rows = [
        # type 3 logon from .21 (port 50000); outbound events carry the same port / the same IP in source_ip or destination
        logon("L3", 0, 20, ip="192.168.50.21", port=50000),
        s3("OUT-A", 1, "192.168.50.22", 50000, initiated=1, destination_ip="192.168.50.21"),
        s3("OUT-B", 2, "192.168.50.21", 50000, initiated=1, destination_ip="192.168.50.23"),
        # type 10 logon from .23 (port 51000) with outbound look-alikes
        logon("L10", 100, 21, ltype=10, ip="192.168.50.23", port=51000),
        s3("OUT-C", 101, "192.168.50.23", 51000, initiated=1, destination_ip="192.168.50.10"),
        s3("OUT-D", 102, "192.168.50.22", 51000, initiated=1, destination_ip="192.168.50.23"),
    ]
    o = go(tmp_path, rows)
    assert [r["trigger_event_uid"] for r in o.rule("R5_rdp")] == ["L10"]       # only the type 10 own-anchor row
    assert sup(o.one("R5_rdp")) == set()
    for uid in ("OUT-A", "OUT-B", "OUT-C", "OUT-D"):
        assert o.d(uid)["disposition"] == "no_rule", uid
        assert not in_any_gate_row(o, uid), uid
    assert o.d("L3")["disposition"] == "unmatched_remote"


# ====================================================================================== GTT-16 IPv4-mapped
MAPPED_99 = "::ffff:192.168.50.99"


def test_gtt16_mapped_excluded_4624_excludes_its_session(tmp_path):
    """GTT-16 / GT-02: 4624 type 3 from ::ffff:192.168.50.99 is excluded; its 5145 and 4697 (by subject_logon_id) are session-excluded; its 7045 is paired_excluded."""
    rows = [logon("X-L", 0, 2000, ip=MAPPED_99, account="admin_it"), share("X-5145", 1, 2000),
            svc4697("X-4697", 2, 2000, "XSVC"), svc7045("X-7045", 2.5, "XSVC")]
    o = go(tmp_path, rows)
    assert o.trig == [] and o.unm == [] and o.sup == []
    assert o.d("X-L")["disposition"] == "excluded_source_ip"
    assert o.d("X-5145")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-4697")["disposition"] == "excluded_source_ip_session"
    assert o.d("X-7045")["disposition"] == "paired_excluded"


def test_gtt16_mapped_excluded_session_with_pre_window_4624_still_excludes(tmp_path):
    """GT-02(b) + IP normalisation: the unclipped logon-ID map also normalises: a pre-window 4624 from ::ffff:.99 excludes the in-window 5145."""
    rows = [logon("X-PRE", None, 2100, utc="2026-09-24T09:30:00.000000Z", ip=MAPPED_99), share("X-S", 1, 2100)]
    o = go(tmp_path, rows)
    assert o.d("X-S")["disposition"] == "excluded_source_ip_session"


def test_gtt16_mapped_excluded_winrm91_and_wsmprovhost(tmp_path):
    """GTT-16 / GT-02(c): WinRM 91 from ::ffff:192.168.50.97 -> excluded_source_ip; the wsmprovhost 2 s before it (its pair,
    decision 042) -> excluded; no R8 row."""
    o = go(tmp_path, [wsm("XWSM", 0, 8888), w91("X91", 2, "::ffff:192.168.50.97")])
    assert o.trig == [] and o.sup == []
    assert o.d("X91")["disposition"] == "excluded_source_ip"
    assert o.d("XWSM")["disposition"].startswith("excluded")


def test_gtt16_mapped_excluded_inbound_sysmon3_is_excluded(tmp_path):
    """GT-02(c): an inbound 3389 Sysmon 3 whose source_ip is ::ffff:192.168.50.98 is excluded."""
    o = go(tmp_path, [s3("XS3", 0, "::ffff:192.168.50.98", 50000)])
    assert o.d("XS3")["disposition"] == "excluded_source_ip"


@pytest.mark.parametrize("ip", ["::ffff:127.0.0.1", "::ffff:192.168.50.22"])
def test_gtt16_mapped_loopback_and_own_ip_4624_are_loopback_or_self(tmp_path, ip):
    """GTT-16 / GT-05: ::ffff:127.0.0.1 and ::ffff:<own IP of ep-02> are `loopback_or_self`."""
    o = go(tmp_path, [logon("L", 0, 20, ip=ip), share("S", 1, 20)])
    assert o.d("L")["disposition"] == "loopback_or_self"
    assert o.trig == [] and o.unm == []


@pytest.mark.parametrize("l_ip,s_ip", [("::ffff:192.168.50.21", "192.168.50.21"),
                                       ("192.168.50.21", "::ffff:192.168.50.21"),
                                       ("::ffff:192.168.50.21", "::ffff:192.168.50.21")])
def test_gtt16_r5_pairs_mapped_and_plain_forms_by_ip_and_port(tmp_path, l_ip, s_ip):
    """GTT-16 / GT-11: a 4624 and an inbound 3389 Sysmon 3 of the same IPv4 in either form (same port, <= 5 s) pair: R5 ip_port_time."""
    o = go(tmp_path, [logon("L", 0, 20, port=50001, ip=l_ip), s3("S3", 2.0, s_ip, 50001)])
    r = o.one("R5_rdp")
    assert r["method"] == "ip_port_time" and r["gate_tier"] == "B" and sup(r) == {"S3"}
    assert o.d("S3")["disposition"] == "supporting"


def test_gtt16_r5_mapped_port_zero_uses_ip_time(tmp_path):
    """GT-11 + normalisation: with the 4624 port 0, a mapped 4624 IP still pairs by IP + time with a plain Sysmon 3 IP."""
    o = go(tmp_path, [logon("L", 0, 20, port=0, ip="::ffff:192.168.50.21"), s3("S3", 2.0, "192.168.50.21", 61234)])
    assert o.one("R5_rdp")["method"] == "ip_time"


def test_gtt16_r5_mapped_other_ip_or_port_does_not_pair(tmp_path):
    """Negative controls: a mapped address of a different IPv4, a different port, or > 5 s does not pair."""
    assert go(tmp_path / "a", [logon("L", 0, 20, port=50001, ip="::ffff:192.168.50.21"),
                               s3("S3", 1, "192.168.50.23", 50001)]).rule("R5_rdp") == []
    assert go(tmp_path / "b", [logon("L", 0, 20, port=50001, ip="::ffff:192.168.50.21"),
                               s3("S3", 1, "192.168.50.21", 50002)]).rule("R5_rdp") == []
    assert go(tmp_path / "c", [logon("L", 0, 20, port=50001, ip="::ffff:192.168.50.21"),
                               s3("S3", 6, "192.168.50.21", 50001)]).rule("R5_rdp") == []


def test_gtt16_r5_type10_supporting_sysmon3_mapped_forms(tmp_path):
    """GT-11: a 3389 Sysmon 3 in the other IP form is added to a type 10 R5 row's supporting uids."""
    o = go(tmp_path, [logon("L", 0, 20, ltype=10, port=50000, ip="::ffff:192.168.50.21"),
                      s3("S3", 1, "192.168.50.21", 50000)])
    assert sup(o.one("R5_rdp")) == {"S3"} and o.d("S3")["disposition"] == "supporting"


def test_gtt16_r8_winrm91_mapped_supports_plain_anchor(tmp_path):
    """GTT-16 / GT-13: a WinRM 91 with clientIP ::ffff:192.168.50.21 within 5 s of an anchor 4624 from 192.168.50.21 is supporting."""
    o = go(tmp_path, r8(extra=[w91("V91", 1.0, "::ffff:192.168.50.21")]))
    r = o.one("R8_winrm")
    assert sup(r) == {"V91"} and r["gate_tier"] == "A" and o.d("V91")["disposition"] == "supporting"


def test_gtt16_r8_winrm91_plain_supports_mapped_anchor_and_keeps_original_text(tmp_path):
    """GT-13 reverse: anchor 4624 IP ::ffff:192.168.50.21, plain 91 -> supporting; the row's source_ip keeps the anchor's original text."""
    o = go(tmp_path, r8(anchor_kw=dict(ip="::ffff:192.168.50.21"), extra=[w91("V91", -1.0, "192.168.50.21")]))
    r = o.one("R8_winrm")
    assert sup(r) == {"V91"}
    assert r["source_ip"] == "::ffff:192.168.50.21" and r["ip_kind"] == "ipv4"


def test_gtt16_r8_tier_d_mapped_91_gives_original_text_and_ipv4_kind(tmp_path):
    """GT-13 tier D + normalisation: the tier-D row's source_ip is the 91's original text, ip_kind = ipv4."""
    o = go(tmp_path, [w91("V91", 1.0, "::ffff:192.168.50.21"), wsm("W", 0.0, 7300)])
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["source_ip"] == "::ffff:192.168.50.21" and r["ip_kind"] == "ipv4"
    assert sup(r) == {"V91"}


def test_gtt16_mapped_other_ip_91_is_not_supporting(tmp_path):
    """Negative control: a mapped 91 of another IPv4 is not supporting an anchored R8 row."""
    o = go(tmp_path, r8(extra=[w91("V91", 1.0, "::ffff:192.168.50.23")]))
    assert sup(o.one("R8_winrm")) == set()


def test_gtt16_csv_source_ip_keeps_original_text_and_ip_kind_ipv4(tmp_path):
    """GTT-16 / spec 2: triggers.csv and unmatched_remote.csv keep `::ffff:192.168.50.21` in source_ip; ip_kind = ipv4; stats keyed ipv4."""
    rows = [logon("L", 0, 20, ip="::ffff:192.168.50.21"), share("S", 1, 20),
            logon("U", 50, 21, ip="::ffff:192.168.50.23")]
    o = go(tmp_path, rows)
    r = o.one("R4_smb")
    assert r["source_ip"] == "::ffff:192.168.50.21" and r["ip_kind"] == "ipv4"
    assert o.unm[0]["source_ip"] == "::ffff:192.168.50.23" and o.unm[0]["ip_kind"] == "ipv4"
    assert o.stats["remote_logons_per_ip_kind"] == {"ipv4": 2}


def test_gtt16_stats_excluded_per_ip_keyed_by_normalised_address(tmp_path):
    """GTT-16 / spec 3.1: excluded.per_ip has one key `192.168.50.99` that counts the mapped and the plain events together."""
    rows = [logon("XM", 0, 2000, ip=MAPPED_99), logon("XP", 10, 2001, ip="192.168.50.99"),
            w91("X91", 20, MAPPED_99)]
    o = go(tmp_path, rows)
    assert o.stats["excluded"]["per_ip"] == {"192.168.50.99": 3}


def test_gtt16_tier_d_lookup_source_ips_keep_original_text(tmp_path):
    """GTT-16 / spec 3.1: tier_d_ip_lookup[].source_ips are the original texts from the unclipped DB."""
    rows = [logon("PRE", None, 5001, utc="2026-09-24T09:00:00.000000Z", ip="::ffff:192.168.50.21"),
            svc4697("V4", 2, 5001)]
    o = go(tmp_path, rows)
    v = o.stats["tier_d_ip_lookup"]
    assert len(v) == 1 and v[0]["logon_found"] is True
    assert v[0]["source_ips"] == ["::ffff:192.168.50.21"]


# ====================================================================================== GTT-17 near_duplicate follows trigger uid
def test_gtt17_r6_duplicate_on_the_4697_flags_both_rows(tmp_path):
    """GTT-17: a near-duplicate pair on the 4697 (same host, channel, record_id, different uid) -> both R6 rows near_duplicate = 1."""
    o = go(tmp_path, [logon("L", 0, 5000), svc4697("V4a", 2.0, 5000, record_id=800),
                      svc4697("V4b", 2.5, 5000, record_id=800)])
    rs = o.rule("R6_service")
    assert {r["trigger_event_uid"] for r in rs} == {"V4a", "V4b"} and len(rs) == 2
    assert all(r["near_duplicate"] == "1" for r in rs)
    assert all(r["anchor_logon_uid"] == "L" for r in rs)


def test_gtt17_r6_duplicate_only_on_anchor_does_not_flag_the_row(tmp_path):
    """GTT-17: duplicate only on the anchor 4624 (single 4697) -> the R6 rows have near_duplicate = 0 (the flag follows trigger_event_uid)."""
    o = go(tmp_path, [logon("L1", 0, 5000, record_id=900), logon("L2", 0.5, 5000, record_id=900),
                      svc4697("V4", 2.0, 5000)])
    rs = o.rule("R6_service")
    assert len(rs) == 2 and {r["anchor_logon_uid"] for r in rs} == {"L1", "L2"}
    assert all(r["trigger_event_uid"] == "V4" and r["near_duplicate"] == "0" for r in rs)


def test_gtt17_anchor_duplicate_uids_are_still_listed_in_stats(tmp_path):
    """GT-18 / spec 3.1: the in-window duplicates (even those that are only anchors) are listed in near_duplicate_uids."""
    o = go(tmp_path, [logon("L1", 0, 5000, record_id=900), logon("L2", 0.5, 5000, record_id=900),
                      svc4697("V4", 2.0, 5000)])
    assert o.stats["near_duplicate_uids"] == ["L1", "L2"]


def test_gtt17_r6_duplicate_on_the_supporting_7045_flags_only_the_row_of_its_own_trigger(tmp_path):
    """GTT-17: duplicate 7045s: the 7045 that pairs (nearest, one-to-one) is only supporting -> its 4697 row = 0; the unpaired 7045 is its own trigger row = 1."""
    o = go(tmp_path, [logon("L", 0, 5000), svc4697("V4", 2.0, 5000),
                      svc7045("P1", 2.5, record_id=801), svc7045("P2", 3.0, record_id=801)])
    by = {r["trigger_event_uid"]: r for r in o.rule("R6_service")}
    assert set(by) == {"V4", "P2"}
    assert sup(by["V4"]) == {"P1"} and by["V4"]["near_duplicate"] == "0"
    assert by["P2"]["near_duplicate"] == "1"


def test_gtt17_r8_duplicate_on_the_wsmprovhost_flags_both_rows(tmp_path):
    """GTT-17: a near-duplicate pair of wsmprovhost Sysmon 1 -> both R8 rows near_duplicate = 1."""
    o = go(tmp_path, [logon("L", 0, 7000), wsm("W1", 3.0, 7000, record_id=810), wsm("W2", 3.5, 7000, record_id=810)])
    rs = o.rule("R8_winrm")
    assert {r["trigger_event_uid"] for r in rs} == {"W1", "W2"} and len(rs) == 2
    assert all(r["near_duplicate"] == "1" for r in rs)


def test_gtt17_r8_duplicate_only_on_anchor_does_not_flag_the_row(tmp_path):
    """GTT-17: duplicate only on the anchor 4624 (single wsmprovhost) -> the R8 rows have near_duplicate = 0."""
    o = go(tmp_path, [logon("L1", 0, 7000, record_id=811), logon("L2", 0.5, 7000, record_id=811), wsm("W", 3.0, 7000)])
    rs = o.rule("R8_winrm")
    assert len(rs) == 2 and {r["anchor_logon_uid"] for r in rs} == {"L1", "L2"}
    assert all(r["trigger_event_uid"] == "W" and r["near_duplicate"] == "0" for r in rs)


def test_gtt17_r4_flag_still_follows_the_anchor_4624(tmp_path):
    """Control (GT-18): for R4 the trigger event is the 4624, so a duplicate 4624 pair flags both R4 rows."""
    o = go(tmp_path, [logon("L1", 0, 4000, record_id=777), logon("L2", 0.2, 4000, record_id=777), share("S", 1, 4000)])
    assert [r["near_duplicate"] for r in o.rule("R4_smb")] == ["1", "1"]


# ====================================================================================== GTT-18 stats keys + sensitivity
STATS_TOP_KEYS = {"trial_id", "db", "window", "time_basis", "clock", "events", "removed_by_window", "near_window",
                  "dispositions", "triggers", "unmatched_remote", "supporting", "remote_logons_per_ip_kind",
                  "machine_account_triggers_per_host", "local_installs", "excluded", "near_duplicate_uids",
                  "tier_d_ip_lookup", "own_link_local", "sensitivity", "parameters"}
CLOCK_STATS_KEYS = {"offsets_file", "offsets_sha256", "clock_changes_file", "clock_changes_sha256", "clock_flag",
                    "clock_change_in_window", "offsets", "unreliable_rows"}
SENS_NAMES = {"rdp_pairs", "service_pairs", "winrm_91_anchor_pairs", "winrm_91_to_wsmprovhost_pairs"}
SENS_TOLS = {"2", "5", "10"}


def _check_stats_shape(st: dict) -> None:
    assert set(st) == STATS_TOP_KEYS, (sorted(set(st) - STATS_TOP_KEYS), sorted(STATS_TOP_KEYS - set(st)))
    assert set(st["db"]) == {"path", "sha256_before", "sha256_after"}
    assert set(st["window"]) == {"row", "file", "file_sha256"}
    assert set(st["clock"]) == CLOCK_STATS_KEYS
    assert set(st["clock"]["unreliable_rows"]) == {"triggers", "unmatched_remote", "dispositions", "supporting"}
    assert set(st["events"]) == {"loaded_total", "in_window_total", "trigger_type_in_window",
                                 "trigger_type_in_window_per_host"}
    assert set(st["dispositions"]) == {"total", "per_host"}
    assert set(st["dispositions"]["total"]) == set(SPEC_DISPOSITIONS)
    assert set(st["triggers"]) == {"total", "per_rule", "per_rule_host_tier"}
    assert set(st["unmatched_remote"]) == {"total", "per_host"}
    assert set(st["supporting"]) == {"total", "per_rule"}
    assert set(st["supporting"]["per_rule"]) == {"R1_lsass", "R3_explicit", "R8_parent"}
    assert set(st["local_installs"]) == {"count", "trigger_ids"}
    assert set(st["excluded"]) == {"per_ip", "excluded_ip_with_artefacts"}
    assert isinstance(st["near_duplicate_uids"], list) and isinstance(st["tier_d_ip_lookup"], list)
    assert set(st["own_link_local"]) == {"per_host", "conflicts", "machine_accounts", "e2_rejected"}
    assert set(st["sensitivity"]) == SENS_NAMES
    for name, per_tol in st["sensitivity"].items():
        assert set(per_tol) == SENS_TOLS, name
        assert all(isinstance(v, int) for v in per_tol.values()), name


def test_gtt18_stats_top_level_keys_are_exactly_spec_3_1(tmp_path):
    """GTT-18 / spec 3.1: stats.json has exactly the 20 listed top-level keys (own_link_local: decision 042), with the documented sub-keys."""
    o = go(tmp_path, mixed_rows())
    _check_stats_shape(o.stats)
    assert o.stats["time_basis"] == "corrected" and o.stats["trial_id"] == TRIAL


def test_gtt18_stats_keys_are_present_on_a_trial_with_no_events_of_interest(tmp_path):
    """GTT-18: the same exact keys exist when nothing fires (zeros / empties, never missing keys)."""
    o = go(tmp_path, [noise()])
    _check_stats_shape(o.stats)
    assert o.stats["triggers"]["total"] == 0 and o.stats["unmatched_remote"]["total"] == 0
    assert all(v == 0 for v in o.stats["dispositions"]["total"].values())
    assert all(v == 0 for per in o.stats["sensitivity"].values() for v in per.values())
    assert o.stats["local_installs"]["count"] == 0 and o.stats["local_installs"]["trigger_ids"] == []


def test_gtt18_stats_events_counts_and_triggers_equal_file_counts(tmp_path):
    """GTT-18 / GTA-04: events.* and triggers.* / unmatched_remote.* / supporting.* counts equal the file counts."""
    rows = mixed_rows()
    o = go(tmp_path, rows)
    st = o.stats
    assert st["events"]["loaded_total"] == len(rows)
    assert st["events"]["in_window_total"] == sum(1 for r in rows if in_window(r))
    tt = sum(1 for r in rows if is_trigger_type(r) and in_window(r))
    assert st["events"]["trigger_type_in_window"] == tt == len(o.disp)
    assert sum(st["events"]["trigger_type_in_window_per_host"].values()) == tt
    assert st["triggers"]["total"] == len(o.trig)
    for rule in ("R4_smb", "R5_rdp", "R6_service", "R8_winrm"):
        assert st["triggers"]["per_rule"].get(rule, 0) == len(o.rule(rule)), rule
        for host, tiers in st["triggers"]["per_rule_host_tier"].get(rule, {}).items():
            for tier, n in tiers.items():
                assert n == sum(1 for r in o.rule(rule) if r["host"] == host and r["gate_tier"] == tier)
    assert st["unmatched_remote"]["total"] == len(o.unm)
    assert st["supporting"]["total"] == len(o.sup)
    for rule in ("R1_lsass", "R3_explicit", "R8_parent"):
        assert st["supporting"]["per_rule"][rule] == sum(1 for r in o.sup if r["rule"] == rule)


def test_gtt18_stats_json_keys_sorted(tmp_path):
    """Spec 3.1: 'JSON object, keys sorted, indent fixed': every object's keys appear in sorted order in the file text."""
    c = make_case(tmp_path, mixed_rows())
    c.run()
    text = (c.out_dir / "stats.json").read_text(encoding="utf-8")

    def check(obj):
        if isinstance(obj, list):
            for v in obj:
                check(v)
        elif isinstance(obj, dict):
            assert list(obj) == sorted(obj), list(obj)
            for v in obj.values():
                check(v)
    check(json.loads(text, object_pairs_hook=lambda pairs: dict(pairs)))
    indents = {len(m.group(1)) for m in re.finditer(r"^( +)\S", text, flags=re.M)}
    unit = min(indents)
    assert all(i % unit == 0 for i in indents)


def test_gtt18_sensitivity_rdp_pairs_by_tolerance_rows_unchanged(tmp_path):
    """GTT-18: three (4624, 3389 Sysmon 3) pairs 1.5 s, 4 s and 8 s apart -> rdp_pairs {2:1, 5:2, 10:3}; R5 fires for the first two only (5 s)."""
    rows = []
    for i, d in enumerate((1.5, 4.0, 8.0)):
        rows += [logon(f"L{i}", 100 * i, 20 + i, port=50000 + i), s3(f"S{i}", 100 * i + d, "192.168.50.21", 50000 + i)]
    o = go(tmp_path, rows)
    assert o.stats["sensitivity"]["rdp_pairs"] == {"2": 1, "5": 2, "10": 3}
    assert sorted(r["trigger_event_uid"] for r in o.rule("R5_rdp")) == ["L0", "L1"]
    assert "L2" in o.unm_uids()
    assert o.stats["sensitivity"]["service_pairs"] == {"2": 0, "5": 0, "10": 0}


def test_gtt18_sensitivity_service_pairs_by_tolerance_rows_unchanged(tmp_path):
    """GTT-18: three installs (different names) with 7045 at 1.5 s, 4 s and 8 s from the 4697 -> service_pairs {2:1, 5:2, 10:3}; the 8 s one stays two rows."""
    rows = [svc4697("A4", 0, 6001, "SA"), svc7045("A7", 1.5, "SA"),
            svc4697("B4", 100, 6002, "SB"), svc7045("B7", 104, "SB"),
            svc4697("C4", 200, 6003, "SC"), svc7045("C7", 208, "SC")]
    o = go(tmp_path, rows)
    assert o.stats["sensitivity"]["service_pairs"] == {"2": 1, "5": 2, "10": 3}
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R6_service")}
    assert got == {"A4": {"A7"}, "B4": {"B7"}, "C4": set(), "C7": set()}


def test_gtt18_sensitivity_winrm_91_anchor_pairs_by_tolerance_rows_unchanged(tmp_path):
    """GTT-18: R8 anchors with a same-IP WinRM 91 1.5 s, 4 s and 8 s after the anchor -> winrm_91_anchor_pairs {2:1, 5:2, 10:3}; the 91 at 8 s is not supporting."""
    rows = []
    for i, d in enumerate((1.5, 4.0, 8.0)):
        base = 100 * i
        rows += [logon(f"L{i}", base, 7000 + i), wsm(f"W{i}", base + 0.5, 7000 + i),
                 w91(f"V{i}", base + d, "192.168.50.21")]
    o = go(tmp_path, rows)
    assert o.stats["sensitivity"]["winrm_91_anchor_pairs"] == {"2": 1, "5": 2, "10": 3}
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R8_winrm")}
    assert got == {"W0": {"V0"}, "W1": {"V1"}, "W2": set()}
    # decision 042: each Sysmon 1 is 1.0 / 3.5 / 7.5 s BEFORE its 91, the counted direction
    assert o.stats["sensitivity"]["winrm_91_to_wsmprovhost_pairs"] == {"2": 1, "5": 2, "10": 3}


def test_gtt18_sensitivity_winrm_91_to_wsmprovhost_pairs_91_after_only(tmp_path):
    """GTT-18 (decision 042): a wsmprovhost Sysmon 1 followed by its 91 1.5 s, 4 s and 8 s later -> {2:1, 5:2, 10:3};
    a 91 2 s BEFORE its Sysmon 1 counts at no tolerance and is never paired."""
    rows = []
    for i, d in enumerate((1.5, 4.0, 8.0)):
        base = 100 * i
        rows += [wsm(f"W{i}", base, 7100 + i), w91(f"V{i}", base + d, "192.168.50.21")]
    rows += [w91("V-BEFORE", 298, "192.168.50.21"), wsm("W-BEFORE", 300, 7110)]
    o = go(tmp_path, rows)
    assert o.stats["sensitivity"]["winrm_91_to_wsmprovhost_pairs"] == {"2": 1, "5": 2, "10": 3}
    assert o.stats["sensitivity"]["winrm_91_anchor_pairs"] == {"2": 0, "5": 0, "10": 0}
    got = {r["trigger_event_uid"]: sup(r) for r in o.rule("R8_winrm")}      # rules use 5 s, 0-5 s after the Sysmon 1
    assert got == {"W0": {"V0"}, "W1": {"V1"}, "W2": set(), "W-BEFORE": set()}


def _boundary_rows(kind: str, d: float) -> list[dict]:
    if kind == "rdp_pairs":
        return r5_pair(d)
    if kind == "service_pairs":
        return [svc4697("V4", 0, 6001), svc7045("V7", d)]
    if kind == "winrm_91_anchor_pairs":
        return [logon("L", 0, 7000), wsm("W", 0.0, 7000), w91("V91", d, "192.168.50.21")]
    return [wsm("W", 0.0, 7100), w91("V91", d, "192.168.50.21")]


@pytest.mark.parametrize("kind", sorted(SENS_NAMES))
@pytest.mark.parametrize("d", [2.0, 5.0, 10.0, 10.001])
def test_gtt18_sensitivity_tolerance_is_inclusive(tmp_path, kind, d):
    """Spec 3.1 / 5: a pair exactly t s apart is found at tolerance t (|dt| <= t); 10.001 s is found at none."""
    o = go(tmp_path, _boundary_rows(kind, d))
    assert o.stats["sensitivity"][kind] == {"2": int(d <= 2.0), "5": int(d <= 5.0), "10": int(d <= 10.0)}


# ====================================================================================== missing column
SPEC_COLUMNS_USED = [
    "event_uid", "host", "channel", "event_id", "record_id", "event_utc", "logon_type", "source_ip", "source_port",
    "destination_ip", "destination_port", "initiated", "account_name", "domain_short", "target_logon_id",
    "target_linked_logon_id", "subject_logon_id", "session_id", "machine_account", "authentication_package", "image",
    "parent_image", "share_name", "relative_target_name", "service_name", "service_image_path", "target_image",
    "granted_access", "subject_account",   # subject_account: added by the owner 2026-11-12, decision 042 (E2)
]


def write_db_missing(path: Path, rows: list[dict], missing: str, *, hide_in_view_only: bool = False) -> None:
    """Like write_db, but the table (or only the `events_dedup` view) lacks column `missing`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    table_cols = [c for c in EVENT_COLUMNS if hide_in_view_only or c != missing]
    view_cols = [c for c in table_cols if c != missing]
    ddl = ", ".join(f'"{c}" ' + ("INTEGER" if c in INT_COLUMNS else "TEXT") for c in table_cols)
    con = sqlite3.connect(str(path))
    try:
        con.execute(f"CREATE TABLE events ({ddl})")
        con.execute(
            "CREATE VIEW events_dedup AS SELECT " + ", ".join(f'"{c}"' for c in view_cols) +
            " FROM (SELECT e.*, row_number() OVER (PARTITION BY duplicate_content_sha256 "
            "ORDER BY source_relative_path, source_line) AS _rn FROM events e) WHERE _rn = 1")
        marks = ", ".join("?" for _ in table_cols)
        con.executemany(f"INSERT INTO events VALUES ({marks})", [tuple(r.get(c) for c in table_cols) for r in rows])
        con.commit()
    finally:
        con.close()


def _missing_case(tmp_path: Path, missing: str, *, view_only: bool = False) -> Case:
    c = make_case(tmp_path, [noise()])
    write_db_missing(c.db, [noise()], missing, hide_in_view_only=view_only)
    c.refresh()
    return c


def test_missing_destination_ip_raises_gate_error_naming_column_nothing_written(tmp_path, capsys):
    """Spec 2 (destination_ip added 2026-11-12): a DB whose view lacks destination_ip -> GateError naming it, nothing written, CLI returns 2."""
    c = _missing_case(tmp_path, "destination_ip")
    with pytest.raises(GateError) as ei:
        c.run_raw()
    assert "destination_ip" in str(ei.value)
    assert not c.out_dir.exists()
    assert c.cli() == 2
    assert not c.out_dir.exists()
    assert "destination_ip" in capsys.readouterr().err


def test_missing_destination_ip_only_in_the_view_is_also_refused(tmp_path):
    """The check is on the `events_dedup` view the gate reads: a base table with the column but a view without it is refused."""
    c = _missing_case(tmp_path, "destination_ip", view_only=True)
    with pytest.raises(GateError) as ei:
        c.run_raw()
    assert "destination_ip" in str(ei.value)
    assert not c.out_dir.exists()


@pytest.mark.parametrize("col", SPEC_COLUMNS_USED)
def test_missing_any_required_column_is_refused_naming_it(tmp_path, col):
    """Spec 2 'Columns used': a DB lacking any of the listed columns is refused with GateError naming the column; nothing written; CLI 2."""
    c = _missing_case(tmp_path, col)
    with pytest.raises(GateError) as ei:
        c.run_raw()
    assert col in str(ei.value)
    assert not c.out_dir.exists()
    assert c.cli() == 2


# ====================================================================================== GTT-14 extension
def _fresh_interpreter(code: str) -> dict:
    proc = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120,
                          cwd=str(REPO / "tests"))
    assert proc.returncode == 0, f"fresh interpreter failed:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


ANSWER_KEY_BANNED = ["answer_key.build", "answer_key.finish", "answer_key.verify", "answer_key.overlap"]


def test_gtt14_fresh_interpreter_importing_gate_and_trial_window_loads_no_key_builder_module():
    """GTT-14 (extension, decision 041): a fresh interpreter importing every module of gate and trial_window (+ their __main__) has none of answer_key.build / finish / verify / overlap in sys.modules."""
    code = f"""
import sys, json, pkgutil, importlib
sys.path.insert(0, {str(REPO / "src")!r})
loaded = []
for name in ("gate", "trial_window"):
    pkg = importlib.import_module(name)
    loaded.append(name)
    for m in pkgutil.walk_packages(pkg.__path__, name + "."):
        importlib.import_module(m.name)
        loaded.append(m.name)
for name in ("gate.__main__", "trial_window.__main__"):
    importlib.import_module(name)
    loaded.append(name)
banned = {ANSWER_KEY_BANNED!r}
print(json.dumps({{"banned": [b for b in banned if b in sys.modules], "loaded": loaded,
                   "margins": "lab_common.margins" in sys.modules}}))
"""
    res = _fresh_interpreter(code)
    assert {"gate.run", "gate.rules", "gate.__main__", "gate.clock", "trial_window.window", "trial_window.params",
            "trial_window.__main__"} <= set(res["loaded"]), res["loaded"]
    assert res["banned"] == [], f"key-builder modules loaded by gate / trial_window: {res['banned']}"
    assert res["margins"] is True, "trial_window does not take its margins from lab_common.margins"


def test_gtt14_fresh_interpreter_probe_selfcheck_sees_answer_key_build():
    """GTT-14 self-check: in the same style, importing answer_key.build DOES show up in sys.modules, so the probe above is meaningful."""
    code = f"""
import sys, json, importlib
sys.path.insert(0, {str(REPO / "src")!r})
importlib.import_module("answer_key.build")
banned = {ANSWER_KEY_BANNED!r}
print(json.dumps({{"banned": [b for b in banned if b in sys.modules]}}))
"""
    assert "answer_key.build" in _fresh_interpreter(code)["banned"]


def test_gtt14_source_text_of_lab_common_has_no_forbidden_strings():
    """GTT-14 (extension): no src/lab_common/*.py mentions ground_truth, build_draft, intended_steps, owner_reviews, provisional_windows."""
    forbidden = ["ground_truth", "build_draft", "intended_steps", "owner_reviews", "provisional_windows"]
    files = sorted(SRC_LAB_COMMON.glob("*.py"))
    assert files, "src/lab_common has no python files"
    hits = [(f.name, w) for f in files for w in forbidden if w in f.read_text(encoding="utf-8")]
    assert hits == [], f"forbidden strings in lab_common source: {hits}"


def test_gtt14_trial_window_margins_are_imported_from_lab_common_not_defined_locally():
    """GTT-14: src/trial_window/params.py imports its margins from lab_common.margins."""
    text = (REPO / "src" / "trial_window" / "params.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert any(isinstance(n, ast.ImportFrom) and n.module == "lab_common.margins" for n in ast.walk(tree))


# ====================================================================================== GTT-19 own link-local (decision 042)
PRE = "2026-09-24T09:00:00.000000Z"          # before the window: evidence is read from the unclipped DB


def sys_logon(uid, host, machine, *, utc=PRE, lid=900001):
    """A 4624 opened by SYSTEM (subject 0x3e7) on `host`: its subject account is the host's own machine account."""
    return ev(uid, 4624, "Security", None, utc=utc, host=host, logon_type=5, target_logon_id=lid,
              subject_logon_id=999, subject_account=machine, account_name="system", domain_short="nt authority")


def out_s3(uid, host, src, *, utc=PRE, dest="fe80::99", dport=445):
    """Outbound Sysmon 3 (initiated = 1) logged on `host`: its source_ip is an address of `host` itself (E1)."""
    return ev(uid, 3, "Sysmon", None, utc=utc, host=host, source_ip=src, source_port=50123, destination_ip=dest,
              destination_port=dport, initiated=1)


def ll_smb(uid, off, lid, ip, *, host, account="admin_it"):
    """A type 3 4624 from `ip` with one 5145: fires R4 unless the address is suppressed."""
    return [logon(uid, off, lid, ip=ip, host=host, account=account), share(f"{uid}-S", off + 0.1, lid, host=host)]


def test_gtt19_e2_dc01_self_logon_over_own_link_local_is_loopback_or_self(tmp_path):
    """GTT-19 / decision 042 E2: dc01 4624 from fe80::f374:... as its own machine account (read from dc01's SYSTEM 4624s)
    -> loopback_or_self 'own link-local (E2)'; no trigger, no unmatched row; listed in stats."""
    ip = "fe80::f374:6da8:f7ba:1a61"
    rows = [sys_logon("SYS", "dc01", r"LAB\dc-01$")] + ll_smb("SELF", 1, 4001, ip, host="dc01", account="dc-01$")
    o = go(tmp_path, rows)
    assert o.trig == [] and o.unm == []
    d = o.d("SELF")
    assert d["disposition"] == "loopback_or_self" and d["reason_detail"].endswith("own link-local (E2)")
    st = o.stats["own_link_local"]
    assert st["per_host"] == {"dc01": [{"address": ip, "evidence": "E2", "e1_sysmon3": 0, "e2_4624": 1}]}
    assert st["machine_accounts"] == {"dc01": ["dc-01$"]} and st["conflicts"] == [] and st["e2_rejected"] == []


def test_gtt19_e1_outbound_sysmon3_before_window_marks_own_address_any_text_form(tmp_path):
    """GTT-19 E1: an outbound Sysmon 3 on ep-02 (before the window) from fe80::2 makes fe80::2 ep-02's own address;
    an in-window 4624 on ep-02 logged as `fe80:0:0:0:0:0:0:2%12` is loopback_or_self 'own link-local (E1)'."""
    rows = [out_s3("E1", "ep-02", "fe80::2")] + ll_smb("SELF", 1, 4002, "fe80:0:0:0:0:0:0:2%12", host="ep-02")
    o = go(tmp_path, rows)
    assert o.trig == [] and o.unm == []
    assert o.d("SELF")["reason_detail"].endswith("own link-local (E1)")
    assert o.stats["own_link_local"]["per_host"]["ep-02"] == [
        {"address": "fe80::2", "evidence": "E1", "e1_sysmon3": 1, "e2_4624": 0}]


def test_gtt19_both_evidences_give_e1_e2(tmp_path):
    """GTT-19: an address with E1 and E2 on the same host is recognised with evidence `E1/E2`."""
    rows = [sys_logon("SYS", "ep-02", r"LAB\endpoint-02$"), out_s3("E1", "ep-02", "fe80::2")] + \
        ll_smb("SELF", 1, 4003, "fe80::2", host="ep-02", account="endpoint-02$")
    o = go(tmp_path, rows)
    assert o.d("SELF")["reason_detail"].endswith("own link-local (E1/E2)")
    assert o.stats["own_link_local"]["per_host"]["ep-02"][0]["evidence"] == "E1/E2"


def test_gtt19_cross_host_link_local_logon_stays_remote(tmp_path):
    """GTT-19: fe80::3 is ep-03's own address (E1 on ep-03). A 4624 on ep-02 from fe80::3 is a cross-host logon:
    it is NOT suppressed and fires R4 with ip_kind link_local."""
    rows = [out_s3("E1", "ep-03", "fe80::3")] + ll_smb("XH", 1, 4004, "fe80::3", host="ep-02")
    o = go(tmp_path, rows)
    r = o.one("R4_smb")
    assert r["anchor_logon_uid"] == "XH" and r["ip_kind"] == "link_local" and r["source_ip"] == "fe80::3"
    assert o.d("XH")["disposition"] == "trigger"
    assert o.stats["own_link_local"]["per_host"] == {"ep-03": [
        {"address": "fe80::3", "evidence": "E1", "e1_sysmon3": 1, "e2_4624": 0}]}


def test_gtt19_link_local_with_no_evidence_stays_remote(tmp_path):
    """GTT-19: never all link-local: a link-local source with no E1/E2 evidence is still remote (GT-06) and fires."""
    o = go(tmp_path, ll_smb("LL", 1, 4005, "fe80::5", host="ep-02"))
    assert o.one("R4_smb")["ip_kind"] == "link_local"
    assert o.stats["own_link_local"]["per_host"] == {}


def test_gtt19_conflict_address_seen_as_own_on_two_hosts_is_recognised_for_none(tmp_path):
    """GTT-19 conflict rule: fe80::4 has evidence on ep-02 (E1) and on ep-03 (E1) -> recognised for neither host;
    logons from it on both hosts still fire; stats lists the conflict."""
    rows = [out_s3("E1a", "ep-02", "fe80::4"), out_s3("E1b", "ep-03", "fe80::4")] + \
        ll_smb("A", 1, 4006, "fe80::4", host="ep-02") + ll_smb("B", 2, 4007, "fe80::4", host="ep-03")
    o = go(tmp_path, rows)
    assert sorted(r["anchor_logon_uid"] for r in o.rule("R4_smb")) == ["A", "B"]
    st = o.stats["own_link_local"]
    assert st["per_host"] == {}
    assert st["conflicts"] == [{"address": "fe80::4", "hosts": ["ep-02", "ep-03"],
                                "evidence": {"ep-02": "E1", "ep-03": "E1"}}]


def test_gtt19_conflict_between_e1_and_e2_on_two_hosts(tmp_path):
    """GTT-19 conflict rule across evidence kinds: E2 on dc01 and E1 on ep-02 for one address -> recognised for none."""
    rows = [sys_logon("SYS", "dc01", r"LAB\dc-01$"), out_s3("E1", "ep-02", "fe80::7")] + \
        ll_smb("D", 1, 4008, "fe80::7", host="dc01", account="dc-01$")
    o = go(tmp_path, rows)
    assert o.one("R4_smb")["anchor_logon_uid"] == "D"
    assert o.stats["own_link_local"]["conflicts"][0]["evidence"] == {"dc01": "E2", "ep-02": "E1"}


def test_gtt19_e2_guard_other_account_from_the_address_rejects_it(tmp_path):
    """GTT-19 E2 guard: if any 4624 on dc01 from the address uses another account, E2 does not recognise it;
    both logons stay remote and stats lists the rejection."""
    rows = [sys_logon("SYS", "dc01", r"LAB\dc-01$")] + ll_smb("M", 1, 4009, "fe80::8", host="dc01", account="dc-01$") + \
        ll_smb("U", 2, 4010, "fe80::8", host="dc01", account="admin_it")
    o = go(tmp_path, rows)
    assert sorted(r["anchor_logon_uid"] for r in o.rule("R4_smb")) == ["M", "U"]
    st = o.stats["own_link_local"]
    assert st["per_host"] == {}
    assert st["e2_rejected"] == [{"host": "dc01", "address": "fe80::8", "machine_account": "dc-01$",
                                  "other_accounts": ["admin_it"]}]


def test_gtt19_e2_needs_the_hosts_own_machine_account(tmp_path):
    """GTT-19 E2: the account must be the RECEIVING host's own machine account: dc-01$ logging on to ep-02 from a
    link-local address is not ep-02's own address (ep-02's account is endpoint-02$); it fires."""
    rows = [sys_logon("SYS", "ep-02", r"LAB\endpoint-02$")] + ll_smb("DC", 1, 4011, "fe80::9", host="ep-02", account="dc-01$")
    o = go(tmp_path, rows)
    assert o.one("R4_smb")["anchor_logon_uid"] == "DC"
    assert o.stats["own_link_local"]["per_host"] == {}


def test_gtt19_e2_needs_exactly_one_machine_account_on_the_host(tmp_path):
    """GTT-19 E2: a host whose SYSTEM-opened 4624s name two machine accounts gives no E2 evidence."""
    rows = [sys_logon("SYS1", "dc01", r"LAB\dc-01$"), sys_logon("SYS2", "dc01", r"LAB\other$", lid=900002)] + \
        ll_smb("D", 1, 4012, "fe80::a", host="dc01", account="dc-01$")
    o = go(tmp_path, rows)
    assert o.one("R4_smb")["anchor_logon_uid"] == "D"
    assert o.stats["own_link_local"]["machine_accounts"] == {"dc01": ["dc-01$", "other$"]}
    assert o.stats["own_link_local"]["per_host"] == {}


def test_gtt19_e1_needs_initiated_1_inbound_sysmon3_is_no_evidence(tmp_path):
    """GTT-19 E1: an inbound Sysmon 3 (initiated = 0) with a link-local source is the OTHER end, never own evidence."""
    rows = [ev("IN", 3, "Sysmon", None, utc=PRE, host="ep-02", source_ip="fe80::b", source_port=1,
               destination_ip="fe80::c", destination_port=445, initiated=0)] + ll_smb("L", 1, 4013, "fe80::b", host="ep-02")
    o = go(tmp_path, rows)
    assert o.one("R4_smb")["anchor_logon_uid"] == "L"
    assert o.stats["own_link_local"]["per_host"] == {}


def test_gtt19_own_link_local_winrm91_is_loopback_or_self(tmp_path):
    """GTT-19: GT-05 applies to every event judged by its remote address: a WinRM 91 on ep-02 from its own link-local
    address is loopback_or_self."""
    rows = [out_s3("E1", "ep-02", "fe80::2"), w91("V91", 1, "fe80::2")]
    o = go(tmp_path, rows)
    assert o.d("V91")["disposition"] == "loopback_or_self"
    assert o.d("V91")["reason_detail"].endswith("own link-local (E1)")


# ====================================================================================== GTT-20 WinRM 91 pairing (decision 042)
def test_gtt20_excluded_91_before_unanchored_wsmprovhost_does_not_pair_or_exclude(tmp_path):
    """GTT-20: a WinRM 91 BEFORE the wsmprovhost Sysmon 1 never pairs (decision 042): an excluded 91 1 s before an
    unanchored wsmprovhost excludes only itself; the wsmprovhost fires R8 tier D with a blank source_ip."""
    rows = [w91("X91", -1.0, "192.168.50.99"), wsm("W", 0.0, 8100)]
    o = go(tmp_path, rows)
    assert o.d("X91")["disposition"] == "excluded_source_ip"
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["source_ip"] == "" and sup(r) == set()
    assert o.stats["sensitivity"]["winrm_91_to_wsmprovhost_pairs"] == {"2": 0, "5": 0, "10": 0}


def test_gtt20_lab_91_before_wsmprovhost_is_not_its_tier_d_source(tmp_path):
    """GTT-20: a lab-IP 91 before the Sysmon 1 is not used by tier D (source_ip blank, the 91 is no_rule)."""
    o = go(tmp_path, [w91("V91", -0.08, "192.168.50.21"), wsm("W", 0.0, 8101)])
    r = o.one("R8_winrm")
    assert r["source_ip"] == "" and sup(r) == set()
    assert o.d("V91")["disposition"] == "no_rule"


def test_gtt20_excluded_paired_91_with_lab_tier_a_anchor_does_not_exclude_wsmprovhost(tmp_path):
    """GTT-20 / GT-02(c): a wsmprovhost with a tier-A anchor from 192.168.50.21 is not excluded even though its paired
    91 (0.1 s after) comes from .99: the anchor decides, never the time pairing alone."""
    rows = [logon("L", 0, 8200), wsm("W", 0.5, 8200), w91("X91", 0.6, "192.168.50.99")]
    o = go(tmp_path, rows)
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "A" and r["anchor_logon_uid"] == "L" and r["source_ip"] == "192.168.50.21"
    assert o.d("W")["disposition"] == "trigger"
    assert o.d("X91")["disposition"] == "excluded_source_ip"


def test_gtt20_suppressed_anchor_is_not_a_tier_a_anchor_for_gt02c(tmp_path):
    """GTT-20 / GT-02(c): an anchor removed by GT-05 (own lab IP) is not a tier-A anchor, so a paired excluded 91
    excludes the wsmprovhost."""
    rows = [logon("SELF", 0, 8300, ip="192.168.50.22"), wsm("W", 0.5, 8300), w91("X91", 0.6, "192.168.50.98")]
    o = go(tmp_path, rows)
    assert o.d("SELF")["disposition"] == "loopback_or_self"
    assert o.d("W")["disposition"] == "excluded_source_ip_session"
    assert "winrm91=X91" in o.d("W")["reason_detail"]
    assert o.rule("R8_winrm") == []


def test_gtt20_pairing_is_one_to_one_earliest_first(tmp_path):
    """GTT-20: two wsmprovhost starts (0 s, 1 s) and two 91s (2 s, 3 s): the earlier start takes the earlier 91,
    the second start the next one; each 91 is used once."""
    rows = [wsm("W1", 0.0, 8401), wsm("W2", 1.0, 8402),
            w91("V1", 2.0, "192.168.50.21"), w91("V2", 3.0, "192.168.50.23")]
    o = go(tmp_path, rows)
    got = {r["trigger_event_uid"]: (r["source_ip"], sup(r)) for r in o.rule("R8_winrm")}
    assert got == {"W1": ("192.168.50.21", {"V1"}), "W2": ("192.168.50.23", {"V2"})}


def test_gtt20_one_91_serves_only_one_start(tmp_path):
    """GTT-20: one 91 after two starts goes to the earlier start only; the later start gets no 91."""
    rows = [wsm("W1", 0.0, 8411), wsm("W2", 1.0, 8412), w91("V1", 2.0, "192.168.50.21")]
    o = go(tmp_path, rows)
    got = {r["trigger_event_uid"]: (r["source_ip"], sup(r)) for r in o.rule("R8_winrm")}
    assert got == {"W1": ("192.168.50.21", {"V1"}), "W2": ("", set())}


def test_gtt20_one_excluded_91_excludes_only_the_start_it_is_paired_with(tmp_path):
    """GTT-20 / GT-02(c): with 1:1 pairing an excluded 91 excludes one unanchored start, not every start within 5 s."""
    rows = [wsm("W1", 0.0, 8421), wsm("W2", 1.0, 8422), w91("X91", 2.0, "192.168.50.99")]
    o = go(tmp_path, rows)
    assert o.d("W1")["disposition"] == "excluded_source_ip_session"
    assert [r["trigger_event_uid"] for r in o.rule("R8_winrm")] == ["W2"]


def test_gtt20_pairing_is_per_host(tmp_path):
    """GTT-20: a 91 on another host is never paired."""
    o = go(tmp_path, [wsm("W", 0.0, 8431), w91("V91", 0.5, "192.168.50.21", host="ep-03")])
    assert o.one("R8_winrm")["source_ip"] == ""


def test_gtt20_paired_91_removed_by_gt05_is_not_used_for_tier_d(tmp_path):
    """GTT-20 (decision 042 reading): a paired 91 from loopback is loopback_or_self and gives the tier-D row no IP."""
    o = go(tmp_path, [wsm("W", 0.0, 8441), w91("V91", 0.1, "127.0.0.1")])
    r = o.one("R8_winrm")
    assert r["gate_tier"] == "D" and r["source_ip"] == "" and sup(r) == set()
    assert o.d("V91")["disposition"] == "loopback_or_self"


# ====================================================================================== GTT-21 corrected times (T6b.2)
# Offsets follow spec 08 CO-09: event_utc_corrected = event_utc - offset_ms(host). A host ahead of dc01 has a POSITIVE
# offset, so its corrected time is earlier. A `none` / `stale` host keeps its raw time.
def _all_rows(o: "Out") -> list[tuple[str, dict]]:
    """(file label, row) for every row of the four CSV outputs."""
    return [(label, r) for label, rows in (("triggers", o.trig), ("unmatched", o.unm), ("dispositions", o.disp),
                                           ("supporting", o.sup)) for r in rows]


def _uid_of(label: str, r: dict) -> str:
    return r["event_uid"] if label in ("dispositions", "supporting") else r["trigger_event_uid"]


def _ms(n: float) -> timedelta:
    return timedelta(milliseconds=n)


def test_gtt21_clip_uses_corrected_time_inside_raw_outside_corrected_and_reverse(tmp_path):
    """GTT-21 / GT-01: ep-02 +7 s (ahead): a logon at raw 10:00:03 (inside the raw window) is at 09:59:56 corrected, so it
    is clipped; one at raw 11:00:03 (outside raw) is at 10:59:56 corrected, so it is kept. ep-03 -7 s (behind) is the
    mirror image. Clipped events are in no output file and only counted; near_window counts follow the corrected time."""
    rows = [
        logon("A-RAWIN-CORROUT", None, 1, host="ep-02", utc="2026-09-24T10:00:03.000000Z", ip="192.168.50.11"),
        logon("B-RAWOUT-CORRIN", None, 2, host="ep-02", utc="2026-09-24T11:00:03.000000Z", ip="192.168.50.12"),
        logon("C-RAWOUT-CORRIN", None, 3, host="ep-03", utc="2026-09-24T09:59:55.000000Z", ip="192.168.50.13"),
        logon("D-RAWIN-CORROUT", None, 4, host="ep-03", utc="2026-09-24T10:59:55.000000Z", ip="192.168.50.14"),
        logon("E-MID", 0, 5, host="ep-01", ip="192.168.50.15"),
    ]
    c = make_case(tmp_path, rows, offsets=cf.offsets_spec(ep_02=(7000, "ok", True), ep_03=(-7000, "ok", True)))
    o = c.run()
    text = o.all_text()
    assert "A-RAWIN-CORROUT" not in text and "D-RAWIN-CORROUT" not in text
    assert {"B-RAWOUT-CORRIN", "C-RAWOUT-CORRIN", "E-MID"} <= o.unm_uids()
    st = o.stats
    assert st["removed_by_window"]["ep-02"] == {"Security/4624": 1}      # A only
    assert st["removed_by_window"]["ep-03"] == {"Security/4624": 1}      # D only
    assert st["near_window"]["ep-02"] == {"before": 1, "after": 0}       # A, 4 s before the corrected start
    assert st["near_window"]["ep-03"] == {"before": 0, "after": 1}       # D, 2 s after the corrected end
    assert st["events"]["loaded_total"] == 5 and st["events"]["in_window_total"] == 3
    b = next(r for r in o.unm if r["trigger_event_uid"] == "B-RAWOUT-CORRIN")
    assert parse(b["event_utc"]) == parse("2026-09-24T11:00:03.000000Z")
    assert parse(b["event_utc_corrected"]) == parse("2026-09-24T10:59:56.000000Z")


@pytest.mark.parametrize("offset_ms,raw,kept", [
    (7000, "2026-09-24T10:00:07.000000Z", True),         # corrected = start exactly
    (7000, "2026-09-24T10:00:06.999000Z", False),        # 1 ms before the corrected start
    (7000, "2026-09-24T11:00:07.000999Z", True),         # corrected = end + 999 us
    (7000, "2026-09-24T11:00:07.001000Z", False),        # corrected = end + 1 ms
    (-2500, "2026-09-24T09:59:57.500000Z", True),        # behind host: corrected = raw + 2.5 s = start
    (-2500, "2026-09-24T09:59:57.499000Z", False),
])
def test_gtt21_gt01_edges_are_judged_on_the_corrected_instant(tmp_path, offset_ms, raw, kept):
    """GTT-01 x GTT-21: start <= corrected < end + 1 ms, exactly at the edges, for an ahead and a behind host."""
    c = make_case(tmp_path, [logon("EDGE", None, 1, host="ep-02", utc=raw)],
                  offsets=cf.offsets_spec(ep_02=(offset_ms, "ok", True)))
    o = c.run()
    assert ("EDGE" in o.unm_uids()) is kept


def _clock_event_rows() -> list[dict]:
    """Per host: an R4 hop (4624 + 5145), an unmatched logon, and an R1 lsass access; microsecond times."""
    rows: list[dict] = []
    for i, h in enumerate(cf.HOSTS):
        base = 100.0 + 10 * i
        rows += [logon(f"{h}-L", base + 0.123456, 1000 + i, host=h, ip="192.168.50.60"),
                 share(f"{h}-S", base + 1.654321, 1000 + i, host=h),
                 logon(f"{h}-U", base + 3.000001, 2000 + i, host=h, ip="192.168.50.61"),
                 ev(f"{h}-R1", 10, "Sysmon", base + 5.5, host=h, target_image=LSASS, granted_access="0x1010")]
    return rows


CLOCK_OFFSETS_MS = {"dc01": 0, "ep-01": 1676, "ep-02": -2500, "ep-03": 7000}


def test_gtt21_event_utc_is_original_and_corrected_is_original_minus_offset_in_all_four_csvs(tmp_path):
    """GTT-21 / CO-09: in triggers, unmatched_remote, dispositions and supporting, event_utc is the logged time and
    event_utc_corrected = event_utc - offset_ms(host), to the microsecond; ep-02 is behind (negative offset)."""
    spec = {"dc01": (0, "reference", True), "ep-01": (1676, "ok", True), "ep-02": (-2500, "ok", True),
            "ep-03": (7000, "ok", True)}
    rows = _clock_event_rows()
    db_time = {r["event_uid"]: r["event_utc"] for r in rows}
    o = go(tmp_path, rows, offsets=spec)
    seen = {"triggers": 0, "unmatched": 0, "dispositions": 0, "supporting": 0}
    for label, r in _all_rows(o):
        uid = _uid_of(label, r)
        assert parse(r["event_utc"]) == parse(db_time[uid]), f"{label} {uid}: event_utc is not the logged time"
        want = parse(db_time[uid]) - _ms(CLOCK_OFFSETS_MS[r["host"]])
        assert parse(r["event_utc_corrected"]) == want, f"{label} {uid} ({r['host']}): {r['event_utc_corrected']}"
        seen[label] += 1
    assert all(n >= 4 for n in seen.values()), seen        # every file had rows for every host


def test_gtt21_none_and_stale_hosts_keep_raw_time(tmp_path):
    """GTT-21 / CO-09: a `none` host and a `stale` host (even with an offset value) are not corrected:
    event_utc_corrected = event_utc; their rows are clock_unreliable = 1; a corrected `ok` host's rows are 0."""
    spec = {"dc01": (0, "reference", True), "ep-01": (3000, "ok", True), "ep-02": (None, "none", True),
            "ep-03": (5000, "stale", True)}
    o = go(tmp_path, _clock_event_rows(), offsets=spec, clock_flag="ep-02;ep-03")
    for label, r in _all_rows(o):
        if r["host"] in ("ep-02", "ep-03"):
            assert parse(r["event_utc_corrected"]) == parse(r["event_utc"]), (label, r["host"])
            assert r["clock_unreliable"] == "1", (label, r["host"])
        elif r["host"] == "ep-01":
            assert parse(r["event_utc_corrected"]) == parse(r["event_utc"]) - _ms(3000), label
            assert r["clock_unreliable"] == "0", (label, r["host"])
        else:
            assert r["clock_unreliable"] == "0", (label, r["host"])


def test_gtt21_wide_host_is_corrected_and_clock_unreliable(tmp_path):
    """GTT-21 / CO-06, CO-09: a `wide` host is corrected (offset applied) and its rows are clock_unreliable = 1."""
    spec = cf.offsets_spec(ep_02=(2000, "wide", True))
    rows = [logon("W-L", 0, 1, host="ep-02"), share("W-S", 1, 1, host="ep-02"),
            logon("OK-L", 0, 2, host="ep-01", ip="192.168.50.23"), share("OK-S", 1, 2, host="ep-01")]
    o = go(tmp_path, rows, offsets=spec, clock_flag="ep-02")
    by_host = {r["host"]: r for r in o.trig}
    assert by_host["ep-02"]["clock_unreliable"] == "1"
    assert parse(by_host["ep-02"]["event_utc_corrected"]) == parse(at(0)) - _ms(2000)
    assert by_host["ep-01"]["clock_unreliable"] == "0"
    for r in o.disp:
        assert r["clock_unreliable"] == ("1" if r["host"] == "ep-02" else "0"), r["event_uid"]


def test_gtt21_reference_and_ok_hosts_are_not_unreliable_with_zero_flags(tmp_path):
    """GTT-21: with every host `reference`/`ok`, no changes and no edge host, clock_unreliable is 0 in all four CSVs and
    the stats count is 0."""
    o = go(tmp_path, _clock_event_rows())
    assert all(r["clock_unreliable"] == "0" for _, r in _all_rows(o))
    assert o.stats["clock"]["unreliable_rows"] == {"triggers": 0, "unmatched_remote": 0, "dispositions": 0,
                                                    "supporting": 0}


# -- events logged before a counted clock change (spec 08 CO-15, D4/D5) --------------------------------------------
# ep-02 clock stepped forward: previous time 10:30:12, new time 10:30:20.48, recorded (change_utc) 10:30:20.48.
# "Logged before" = recorded time in [last boot before, max(previous, change)) = [-inf, 10:30:20.48).
CHG = at(20.48)


def _change(host="ep-02", *, counted=True, prev=at(12), new=at(20.48), at_utc=CHG, boot=None, shift=8480,
            cls="expected_before_first_pair"):
    return cf.change(TRIAL, host, at_utc, previous_time=prev, new_time=new, shift_ms=shift, counted=counted,
                     classification=cls if counted else "routine", last_boot_before_utc=boot)


def test_gtt21_event_logged_before_a_counted_change_is_clock_unreliable_in_every_file(tmp_path):
    """GTT-21 / CO-15: on the host with a counted change, an R4 hop recorded before the change and a supporting R1 event
    recorded before it are clock_unreliable = 1 in triggers, unmatched, dispositions and supporting; a hop after the
    change and the same events on another host are 0. The host status is `ok`, so only the change causes the flag."""
    rows = [logon("PRE-L", 5, 1, host="ep-02"), share("PRE-S", 6, 1, host="ep-02"),
            ev("PRE-R1", 10, "Sysmon", 8, host="ep-02", target_image=LSASS, granted_access="0x1010"),
            logon("PRE-U", 9, 3, host="ep-02", ip="192.168.50.23"),
            logon("POST-L", 25, 2, host="ep-02", ip="192.168.50.60"), share("POST-S", 26, 2, host="ep-02"),
            ev("POST-R1", 10, "Sysmon", 30, host="ep-02", target_image=LSASS, granted_access="0x1010"),
            logon("OTHER-L", 5, 4, host="ep-01", ip="192.168.50.24"), share("OTHER-S", 6, 4, host="ep-01"),
            ev("OTHER-R1", 10, "Sysmon", 8, host="ep-01", target_image=LSASS, granted_access="0x1010")]
    o = go(tmp_path, rows, changes=[_change()], clock_change_in_window="true")
    t = {r["anchor_logon_uid"]: r for r in o.trig}
    assert t["PRE-L"]["clock_unreliable"] == "1"
    assert t["POST-L"]["clock_unreliable"] == "0"
    assert t["OTHER-L"]["clock_unreliable"] == "0"
    assert {r["trigger_event_uid"]: r["clock_unreliable"] for r in o.unm} == {"PRE-U": "1"}
    d = {r["event_uid"]: r["clock_unreliable"] for r in o.disp}
    assert d["PRE-L"] == "1" and d["PRE-S"] == "1" and d["PRE-U"] == "1"
    assert d["POST-L"] == "0" and d["POST-S"] == "0" and d["OTHER-L"] == "0" and d["OTHER-S"] == "0"
    s = {r["event_uid"]: r["clock_unreliable"] for r in o.sup}
    assert s == {"PRE-R1": "1", "POST-R1": "0", "OTHER-R1": "0"}
    assert o.stats["clock"]["unreliable_rows"] == {"triggers": 1, "unmatched_remote": 1, "dispositions": 3,
                                                    "supporting": 1}


def test_gtt21_row_is_unreliable_when_only_a_supporting_event_was_logged_before_the_change(tmp_path):
    """GTT-21 / spec 3: the row flag looks at the trigger, the anchor AND every supporting event. An R5 type 3 hop whose
    4624 is after the change but whose paired inbound 3389 Sysmon 3 (3 s earlier) is before it is clock_unreliable = 1."""
    rows = [logon("L", 22, 7, ltype=3, port=51000, host="ep-02"),
            s3("S3", 19, "192.168.50.21", 51000, host="ep-02")]
    o = go(tmp_path, rows, changes=[_change()])
    r = o.one("R5_rdp")
    assert sup(r) == {"S3"} and r["trigger_event_uid"] == "L"
    assert r["clock_unreliable"] == "1"
    # control: the same hop entirely after the change
    rows2 = [logon("L", 24, 7, ltype=3, port=51000, host="ep-02"), s3("S3", 23, "192.168.50.21", 51000, host="ep-02")]
    assert go(tmp_path / "c", rows2, changes=[_change()]).one("R5_rdp")["clock_unreliable"] == "0"


def test_gtt21_change_interval_ends_at_max_of_previous_and_change_time(tmp_path):
    """CO-15 / D4: the 'logged before' interval is [last boot, max(previous_time, change time)). For a BACKWARD step
    (previous 10:30:30 after the change at 10:30:20) the whole overlap up to previous_time is unreliable; later events are
    not. The exact previous_time instant is not asserted: spec 08 writes the end half-open, the code and the clock_offset
    test D5 treat previous_time itself as before the change (reported to the owner)."""
    chg = _change(prev=at(30), new=at(20), at_utc=at(20), shift=-10000)
    rows = [logon("IN-OVERLAP", None, 1, host="ep-02", utc=at(29.999999), ip="192.168.50.11"),
            logon("MID-OVERLAP", None, 2, host="ep-02", utc=at(25), ip="192.168.50.12"),
            logon("BEFORE-CHANGE", None, 3, host="ep-02", utc=at(19), ip="192.168.50.13"),
            logon("LATER", None, 4, host="ep-02", utc=at(31), ip="192.168.50.14")]
    o = go(tmp_path, rows, changes=[chg])
    got = {r["trigger_event_uid"]: r["clock_unreliable"] for r in o.unm}
    assert got == {"IN-OVERLAP": "1", "MID-OVERLAP": "1", "BEFORE-CHANGE": "1", "LATER": "0"}


def test_gtt21_forward_step_event_exactly_at_the_change_time_is_not_before_it(tmp_path):
    """CO-15 / D4: forward step: an event recorded at the change time is not 'before' it (the interval is half open)."""
    rows = [logon("AT", None, 1, host="ep-02", utc=CHG, ip="192.168.50.11"),
            logon("JUST-BEFORE", None, 2, host="ep-02", utc=at(20.479999), ip="192.168.50.12")]
    o = go(tmp_path, rows, changes=[_change()])
    got = {r["trigger_event_uid"]: r["clock_unreliable"] for r in o.unm}
    assert got == {"AT": "0", "JUST-BEFORE": "1"}


def test_gtt21_events_before_the_hosts_last_boot_are_outside_the_interval(tmp_path):
    """CO-15 / D4: the interval starts at the host's last boot before the change (`last_boot_before_utc`); an event
    recorded before that boot belongs to another boot and is not flagged by this change."""
    chg = _change(boot=at(2))
    rows = [logon("BEFORE-BOOT", None, 1, host="ep-02", utc=at(1), ip="192.168.50.11"),
            logon("AFTER-BOOT", None, 2, host="ep-02", utc=at(3), ip="192.168.50.12")]
    o = go(tmp_path, rows, changes=[chg])
    got = {r["trigger_event_uid"]: r["clock_unreliable"] for r in o.unm}
    assert got == {"BEFORE-BOOT": "0", "AFTER-BOOT": "1"}


def test_gtt21_uncounted_routine_change_does_not_flag_events(tmp_path):
    """CO-15: a change with counted = false (routine, |shift| < 1 s) changes nothing, even for events before it."""
    chg = _change(counted=False, shift=1, prev=at(20), new=at(20.001), at_utc=at(20.001))
    o = go(tmp_path, [logon("PRE", 5, 1, host="ep-02", ip="192.168.50.11")], changes=[chg])
    assert [r["clock_unreliable"] for r in o.unm] == ["0"]


def test_gtt21_change_on_another_host_does_not_flag_this_host(tmp_path):
    """CO-15: the interval is per host: a counted change on ep-03 does not mark ep-02 events."""
    o = go(tmp_path, [logon("PRE", 5, 1, host="ep-02", ip="192.168.50.11")], changes=[_change(host="ep-03")])
    assert [r["clock_unreliable"] for r in o.unm] == ["0"]


def test_gtt21_change_is_judged_on_recorded_time_not_corrected_time(tmp_path):
    """CO-15 / D5: the changes file is in recorded time. ep-02 offset +7 s: an event recorded at 10:30:22 is at 10:30:15
    corrected, i.e. before the change at 10:30:20.48 on the corrected clock but AFTER it as recorded -> not flagged; an
    event recorded at 10:30:15 is before it -> flagged."""
    rows = [logon("REC-AFTER", None, 1, host="ep-02", utc=at(22), ip="192.168.50.11"),
            logon("REC-BEFORE", None, 2, host="ep-02", utc=at(15), ip="192.168.50.12")]
    o = go(tmp_path, rows, offsets=cf.offsets_spec(ep_02=(7000, "ok", True)), changes=[_change()])
    got = {r["trigger_event_uid"]: r["clock_unreliable"] for r in o.unm}
    assert got == {"REC-AFTER": "0", "REC-BEFORE": "1"}


@pytest.mark.parametrize("edge,host,status,expect", [
    ("start_host", "ep-03", "wide", "1"), ("end_host", "ep-03", "wide", "1"),
    ("start_host", "ep-03", "none", "1"), ("end_host", "ep-03", "stale", "1"),
    ("start_host", "ep-03", "ok", "0"), ("end_host", "dc01", "reference", "0"),
])
def test_gtt21_every_row_is_unreliable_when_a_window_edge_host_is_wide_none_or_stale(tmp_path, edge, host, status,
                                                                                    expect):
    """GTT-21 / spec 3: the clip compares against the edge host clock, so with an edge host (start_host / end_host) that
    is wide / none / stale EVERY row of all four CSVs is clock_unreliable = 1, even rows of healthy hosts."""
    offs = {"wide": 2000, "none": None, "stale": None, "ok": 0, "reference": 0}[status]
    spec = cf.offsets_spec(**{host.replace("-", "_"): (offs, status, True)})
    kw = {edge: host}
    o = go(tmp_path, _clock_event_rows()[:12], offsets=spec, **kw)       # dc01, ep-01, ep-02 events only
    rows = _all_rows(o)
    assert rows
    healthy = [r for _, r in rows if r["host"] != host]
    assert healthy, "the test needs rows on a healthy host"
    assert {r["clock_unreliable"] for r in healthy} == {expect}
    assert {label for label, _ in rows} == {"triggers", "unmatched", "dispositions", "supporting"}
    if expect == "1":
        assert o.stats["clock"]["unreliable_rows"] == {
            "triggers": len(o.trig), "unmatched_remote": len(o.unm), "dispositions": len(o.disp),
            "supporting": len(o.sup)}


def test_gtt21_clock_flag_and_clock_change_in_window_are_copied_from_the_window_row(tmp_path):
    """GTT-21 / spec 3: clock_flag and clock_change_in_window are trial-level; every row of the four CSVs carries the
    window row values."""
    spec = cf.offsets_spec(ep_03=(None, "none", True), ep_02=(2000, "wide", True))
    o = go(tmp_path, _clock_event_rows(), offsets=spec, clock_flag="ep-02;ep-03", clock_change_in_window="true")
    rows = _all_rows(o)
    assert {label for label, _ in rows} == {"triggers", "unmatched", "dispositions", "supporting"}
    assert {r["clock_flag"] for _, r in rows} == {"ep-02;ep-03"}
    assert {r["clock_change_in_window"] for _, r in rows} == {"true"}
    o2 = go(tmp_path / "f", _clock_event_rows())
    assert {r["clock_flag"] for _, r in _all_rows(o2)} == {""}
    assert {r["clock_change_in_window"] for _, r in _all_rows(o2)} == {"false"}


def test_gtt21_same_host_pairings_give_identical_rows_with_offset_plus_7s_and_zero(tmp_path):
    """GTT-21 / spec 2.2: every pairing is same-host, so a host offset of +7 s moves times only: every output row (R4, R5,
    R6, R8 and their dispositions, unmatched, supporting) is identical to the zero-offset run except
    event_utc_corrected, which is 7 s earlier; sensitivity counts and the trigger ids are equal."""
    rows = [r for r in mixed_rows() + [logon("M-L-both", 200, 400, port=53000), share("M-S-both", 201, 400),
                                       s3("M-S3-both", 202, "192.168.50.21", 53000)] if r["host"] == "ep-02"]
    z = make_case(tmp_path / "zero", rows).run()
    p = make_case(tmp_path / "plus", rows, offsets=cf.offsets_spec(ep_02=(7000, "ok", True))).run()
    assert {r["rule"] for r in z.trig} >= {"R4_smb", "R5_rdp", "R6_service", "R8_winrm"}
    for label, rz, rp in (("triggers", z.trig, p.trig), ("unmatched", z.unm, p.unm), ("dispositions", z.disp, p.disp),
                          ("supporting", z.sup, p.sup)):
        assert len(rz) == len(rp), label
        for a, b in zip(rz, rp):
            assert {k: v for k, v in a.items() if k != "event_utc_corrected"} == \
                   {k: v for k, v in b.items() if k != "event_utc_corrected"}, f"{label}: {a} != {b}"
            assert parse(b["event_utc_corrected"]) == parse(a["event_utc_corrected"]) - timedelta(seconds=7)
    assert z.stats["sensitivity"] == p.stats["sensitivity"]
    assert z.stats["triggers"] == p.stats["triggers"] and z.stats["dispositions"] == p.stats["dispositions"]


def test_gtt21_rows_are_sorted_by_corrected_time_then_uid_then_rule_in_all_four_csvs(tmp_path):
    """GTT-21 / spec 3: rows are sorted by (event_utc_corrected, uid, rule), not by the original time. ep-02 is 10 s
    ahead: its R4 hop logged at raw 10:30:12 is at 10:30:02 corrected and sorts BEFORE an ep-03 hop at 10:30:05."""
    spec = cf.offsets_spec(ep_02=(10000, "ok", True))
    rows = [logon("X-L", 12, 1, host="ep-02"), share("X-S", 13, 1, host="ep-02"),
            logon("Y-L", 5, 2, host="ep-03", ip="192.168.50.60"), share("Y-S", 6, 2, host="ep-03"),
            ev("X-R1", 10, "Sysmon", 14, host="ep-02", target_image=LSASS, granted_access="0x1010"),
            ev("Y-R1", 10, "Sysmon", 7, host="ep-03", target_image=LSASS, granted_access="0x1010"),
            # unmatched pair with a tie on corrected time (10:30:00): uid order decides, not the raw order
            logon("U-a", 10, 3, host="ep-02", ip="192.168.50.31"), logon("U-b", 0, 4, host="ep-03", ip="192.168.50.32")]
    o = go(tmp_path, rows, offsets=spec)
    assert [r["anchor_logon_uid"] for r in o.trig] == ["X-L", "Y-L"]
    assert [r["trigger_id"] for r in o.trig] == [f"{TRIAL}-g0001", f"{TRIAL}-g0002"]
    assert [r["trigger_event_uid"] for r in o.unm] == ["U-a", "U-b"]
    assert [r["trigger_id"] for r in o.unm] == [f"{TRIAL}-u0001", f"{TRIAL}-u0002"]
    assert [r["event_uid"] for r in o.sup] == ["X-R1", "Y-R1"]
    for label, key, rows_ in (("triggers", "trigger_event_uid", o.trig), ("unmatched", "trigger_event_uid", o.unm),
                              ("dispositions", "event_uid", o.disp), ("supporting", "event_uid", o.sup)):
        keys = [(parse(r["event_utc_corrected"]), r[key]) for r in rows_]
        assert keys == sorted(keys), label
    raw_keys = [parse(r["event_utc"]) for r in o.disp]
    assert raw_keys != sorted(raw_keys), "the test data must make raw order differ from corrected order"


def test_gtt21_stats_clock_key_has_exactly_the_spec_31_fields(tmp_path):
    """GTT-21 / spec 3.1: stats.json `clock` = {offsets_file, offsets_sha256, clock_changes_file, clock_changes_sha256,
    clock_flag, clock_change_in_window, offsets: host -> {offset_ms, offset_status, offset_unc_ms}, unreliable_rows}. The
    hashes are the SHA-256 of the files, flag and change flag come from the window row, the row counts equal the CSV
    counts."""
    spec = {"dc01": (0, "reference", True), "ep-01": (1676, "ok", True), "ep-02": (2000, "wide", True),
            "ep-03": (None, "none", True)}
    rows = _clock_event_rows() + [logon("PRE", 5, 9, host="ep-01", ip="192.168.50.44")]
    c = make_case(tmp_path, rows, offsets=spec, changes=[_change(host="ep-01")], clock_flag="ep-02;ep-03",
                  clock_change_in_window="true")
    o = c.run()
    ck = o.stats["clock"]
    assert set(ck) == CLOCK_STATS_KEYS
    assert ck["offsets_sha256"] == sha256_of(c.offsets_file) and ck["clock_changes_sha256"] == sha256_of(c.changes_file)
    assert ck["offsets_file"].replace("\\", "/").endswith(f"data/processed/{TRIAL}.clock_offsets.csv")
    assert ck["clock_changes_file"].replace("\\", "/").endswith(f"data/processed/{TRIAL}.clock_changes.csv")
    assert ck["clock_flag"] == "ep-02;ep-03" and str(ck["clock_change_in_window"]).lower() == "true"
    assert set(ck["offsets"]) == set(spec)
    for h, (off, status, _) in spec.items():
        assert set(ck["offsets"][h]) == {"offset_ms", "offset_status", "offset_unc_ms"}, h
        assert ck["offsets"][h]["offset_ms"] == off and ck["offsets"][h]["offset_status"] == status, h
    assert ck["offsets"]["ep-03"]["offset_ms"] is None
    ur = ck["unreliable_rows"]
    assert set(ur) == {"triggers", "unmatched_remote", "dispositions", "supporting"}
    assert ur == {"triggers": sum(r["clock_unreliable"] == "1" for r in o.trig),
                  "unmatched_remote": sum(r["clock_unreliable"] == "1" for r in o.unm),
                  "dispositions": sum(r["clock_unreliable"] == "1" for r in o.disp),
                  "supporting": sum(r["clock_unreliable"] == "1" for r in o.sup)}
    assert ur["triggers"] > 0 and ur["dispositions"] > 0 and ur["supporting"] > 0
    row = o.stats["window"]["row"]
    assert row["offsets_sha256"] == ck["offsets_sha256"] and row["clock_changes_sha256"] == ck["clock_changes_sha256"]


def test_gtt21_two_runs_with_clock_files_are_byte_identical_except_run_info(tmp_path):
    """GTT-08 x GTT-21: with non-zero offsets and a clock change the outputs are still byte-identical on a rerun."""
    c = make_case(tmp_path, _clock_event_rows(), offsets=cf.offsets_spec(ep_02=(7000, "ok", True)),
                  changes=[_change()])
    c.run()
    first = {f: (c.out_dir / f).read_bytes() for f in OUTPUT_FILES if f != "run_info.json"}
    c.run()
    assert {f: (c.out_dir / f).read_bytes() for f in first} == first


def test_gtt21_db_and_clock_files_are_not_modified_by_a_run(tmp_path):
    """GTT-08: the DB, the offsets file, the clock-changes file and the window file are byte-identical after a run."""
    c = make_case(tmp_path, _clock_event_rows(), changes=[_change()])
    paths = [c.db, c.offsets_file, c.changes_file, c.windows]
    before = [sha256_of(p) for p in paths]
    c.run()
    assert [sha256_of(p) for p in paths] == before


def test_gtt21_clock_fixture_headers_equal_the_code_lists():
    """Self-check of the fixtures: their literal copies of the spec 08 section 3 headers equal the code lists."""
    from clock_offset.changes import CLOCK_CHANGES_COLUMNS
    from clock_offset.params import OFFSETS_COLUMNS
    assert list(OFFSETS_COLUMNS) == cf.OFFSETS_COLUMNS
    assert list(CLOCK_CHANGES_COLUMNS) == cf.CHANGES_COLUMNS


# ====================================================================================== spec 5 parameters (T6b.2)
def test_spec5_gate_clock_parameters_values():
    """Spec 5 (T6b.2): CLOCK_CORRECTION_AVAILABLE true, TIME_BASIS corrected, RAW_TIME_CUTOFF_DATE 2026-10-26 (the CO-17
    date), CLOCK_ONLY_TRIALS s04_t01 and s07_t01; GateParams defaults carry them."""
    from datetime import date
    from clock_offset import params as co_params
    assert gparams.CLOCK_CORRECTION_AVAILABLE is True
    assert gparams.TIME_BASIS == "corrected"
    assert gparams.RAW_TIME_CUTOFF_DATE == date(2026, 10, 26)
    assert tuple(gparams.CLOCK_ONLY_TRIALS) == ("s04_t01", "s07_t01")
    assert tuple(gparams.CLOCK_ONLY_TRIALS) == tuple(co_params.CLOCK_ONLY_TRIALS)
    p = gparams.GateParams()
    assert p.clock_correction_available is True and p.time_basis == "corrected"
    assert p.raw_time_cutoff_date == date(2026, 10, 26)
    assert tuple(p.clock_only_trials) == ("s04_t01", "s07_t01")


def test_spec5_clock_parameters_are_written_into_stats_parameters(tmp_path):
    """Spec 3.1: stats.json `parameters` carries every spec 5 parameter, including the clock ones."""
    pr = go(tmp_path, [noise()]).stats["parameters"]
    assert pr["time_basis"] == "corrected" and pr["clock_correction_available"] is True
    assert pr["raw_time_cutoff_date"] == "2026-10-26"
    assert list(pr["clock_only_trials"]) == ["s04_t01", "s07_t01"]


def test_spec2_window_row_columns_are_all_kept_in_stats_window_row(tmp_path):
    """Spec 3.1: stats `window.row` holds all 15 columns of the window row, with the clock cells as written."""
    c = make_case(tmp_path, [noise()], clock_flag="ep-02", clock_change_in_window="true", start_host="ep-02",
                  end_host="ep-01", offsets=cf.offsets_spec(ep_02=(2000, "wide", True)))
    row = c.run().stats["window"]["row"]
    assert list(row) == WINDOW_COLUMNS or set(row) == set(WINDOW_COLUMNS)
    assert row["clock_flag"] == "ep-02" and row["clock_change_in_window"] == "true"
    assert row["start_host"] == "ep-02" and row["end_host"] == "ep-01"
    assert row["offsets_sha256"] == sha256_of(c.offsets_file) and row["clock_changes_sha256"] == sha256_of(c.changes_file)
