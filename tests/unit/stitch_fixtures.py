"""Synthetic fake repo for the stitcher input tests (T7.2 task 2).

Written from docs/specs/03_stitch.md section 2 (input contract), the T7.2 plan and decisions 046 and 047, not from the
implementation. Everything lives in a pytest `tmp_path`: a fake repo with `data/processed/<trial>.sqlite3` (a table
named `events_dedup` with every spec section 2 column), the two clock files, `data/trial_windows.csv` and the five
gate files under `out/gate/<trial>/`. The real `data/processed`, `out/gate` and `ground_truth` are never opened.

Command text: a `command_line` cell, when a test needs one, is a neutral placeholder string.
"""
from __future__ import annotations

import csv
import hashlib
import itertools
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
from stitch.inputs import trial_paths  # noqa: E402
from stitch.params import GATE_FILES, SPEC_DB_COLUMNS  # noqa: E402

UTC = timezone.utc
TRIAL = "s04_t00"                      # an allowlisted id (decision 046)
T0 = datetime(2026, 9, 24, 10, 30, 0, tzinfo=UTC)
WIN_START = "2026-09-24T10:00:00.000Z"
WIN_END = "2026-09-24T11:00:00.000Z"
PLACEHOLDER_COMMAND = "PLACEHOLDER-COMMAND-TEXT-0123456789"

# spec 02_gate 2.1 (literal copy, as in test_gate.py)
WINDOW_COLUMNS = ["trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s", "rule",
                  "db_sha256", "time_basis", "offsets_sha256", "clock_changes_sha256", "clock_flag",
                  "clock_change_in_window", "start_host", "end_host"]

# Columns that hold integers in the real DB; every other spec column is TEXT.
INT_COLUMNS = {"event_id", "record_id", "logon_type", "source_port", "destination_port", "initiated",
               "target_logon_id", "target_linked_logon_id", "subject_logon_id", "session_id", "machine_account",
               "process_id"}

_seq = itertools.count(1)


# ------------------------------------------------------------------------------------------------ time helpers
def iso6(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def at(off_s: float) -> str:
    """DB time string `off_s` seconds after T0 (10:30:00), 6 fraction digits like the real DB."""
    return iso6(T0 + timedelta(microseconds=int(round(off_s * 1_000_000))))


def sha256_of(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# ------------------------------------------------------------------------------------------------ event builders
def ev(uid: str, channel: str, event_id: int, *, host: str = "ep-02", off: float | None = None,
       utc: str | None = None, record_id: int | None | str = "auto", **kw: Any) -> dict:
    """One event row with every spec column present (None where unset). `record_id` is unique unless given."""
    row: dict = dict.fromkeys(SPEC_DB_COLUMNS)
    n = next(_seq)
    row.update(event_uid=uid, host=host, channel=channel, event_id=event_id,
               record_id=n if record_id == "auto" else record_id,
               event_utc=utc if utc is not None else at(off if off is not None else 0.0), machine_account=0)
    row.update(kw)
    return row


def logon(uid: str, off: float | None = None, lid: int = 1000, *, host: str = "ep-02", **kw: Any) -> dict:
    return ev(uid, "Security", 4624, host=host, off=off, logon_type=3, target_logon_id=lid, account_name="acct_a",
              source_ip="192.168.50.21", source_port=50000, **kw)


# ------------------------------------------------------------------------------------------------ the fake repo
@dataclass
class FakeRepo:
    repo: Path
    trial: str
    paths: Any                                   # stitch.inputs.TrialPaths
    window_row: dict[str, str]
    stats: dict[str, Any]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def stats_path(self) -> Path:
        return self.paths.gate_dir / "stats.json"


def write_events_db(path: Path, rows: Sequence[Mapping], *, drop_columns: Sequence[str] = (),
                    as_view: bool = False) -> None:
    """A DB whose `events_dedup` is a table (or a view over a base table) with every SPEC_DB_COLUMNS column,
    except `drop_columns`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    cols = [c for c in SPEC_DB_COLUMNS if c not in set(drop_columns)]
    decl = ", ".join(f'"{c}" ' + ("INTEGER" if c in INT_COLUMNS else "TEXT") for c in cols)
    con = sqlite3.connect(str(path))
    try:
        name = "events" if as_view else "events_dedup"
        con.execute(f"CREATE TABLE {name} ({decl})")
        if as_view:
            con.execute("CREATE VIEW events_dedup AS SELECT * FROM events")
        marks = ", ".join("?" for _ in cols)
        con.executemany(f"INSERT INTO {name} VALUES ({marks})", [tuple(r.get(c) for c in cols) for r in rows])
        con.commit()
    finally:
        con.close()


def write_windows_csv(path: Path, row: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    other = dict(row, trial_id="s99_t99")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=WINDOW_COLUMNS)
        w.writeheader()
        w.writerow(other)
        w.writerow(row)


def make_repo(tmp_path: Path, rows: Sequence[Mapping] | None = None, trial: str = TRIAL, *, name: str = "repo",
              offsets: dict | None = None, changes: list | None = None, start: str = WIN_START,
              end: str = WIN_END, drop_columns: Sequence[str] = (), as_view: bool = False,
              skip_gate_file: str | None = None, time_basis: str = "corrected",
              stats_offsets_sha: str | None = None, stats_changes_sha: str | None = None,
              stats_db_sha_after: str | None = None, stats_window_changes: Mapping[str, str] | None = None,
              ) -> FakeRepo:
    """A temp repo with one allowlisted synthetic trial that passes ST-00; keyword arguments break one thing
    at a time. ZERO clock offsets by default (every host `ok`)."""
    repo = tmp_path / name
    paths = trial_paths(repo, trial)
    write_events_db(paths.db, rows if rows is not None else [logon("E0", 1.0, 1000)], drop_columns=drop_columns,
                    as_view=as_view)
    db_sha = sha256_of(paths.db)
    o_sha, c_sha = cf.write_clock_files(repo, trial, db_sha, cf.default_offsets() if offsets is None else offsets,
                                        changes)
    row = {"trial_id": trial, "start_utc": start, "end_utc": end, "window_source": "computed_agent_run",
           "margin_start_s": "60", "margin_end_s": "300", "rule": "synthetic test window", "db_sha256": db_sha,
           "time_basis": "corrected", "offsets_sha256": o_sha, "clock_changes_sha256": c_sha, "clock_flag": "",
           "clock_change_in_window": "false", "start_host": "", "end_host": ""}
    write_windows_csv(paths.windows_csv, row)
    gate_row = dict(row)
    gate_row.update(stats_window_changes or {})
    stats = {"time_basis": time_basis, "window": {"row": gate_row},
             "clock": {"offsets_sha256": stats_offsets_sha if stats_offsets_sha is not None else o_sha,
                       "clock_changes_sha256": stats_changes_sha if stats_changes_sha is not None else c_sha},
             "db": {"sha256_before": db_sha,
                    "sha256_after": stats_db_sha_after if stats_db_sha_after is not None else db_sha}}
    paths.gate_dir.mkdir(parents=True, exist_ok=True)
    for fname in GATE_FILES:
        if fname == skip_gate_file:
            continue
        if fname == "stats.json":
            (paths.gate_dir / fname).write_text(json.dumps(stats, sort_keys=True), encoding="utf-8")
        else:
            (paths.gate_dir / fname).write_text("event_uid\n", encoding="utf-8")
    return FakeRepo(repo, trial, paths, row, stats)


def snapshot(root: Path) -> dict[str, str]:
    """Every file (as its SHA-256) and every folder under `root`, by relative path: to prove nothing was created,
    removed or changed."""
    out: dict[str, str] = {}
    root = Path(root)
    if not root.exists():
        return out
    for p in sorted(root.rglob("*")):
        out[p.relative_to(root).as_posix()] = "<dir>" if p.is_dir() else sha256_of(p)
    return out


# ------------------------------------------------------------------------------------------------ STT-13 scan helper
# Owner ruling (T7.5): an IPv4 address is exempt from the "no part of a command line" scan ONLY as a bare address.
# A command window (12 characters, case-folded) found in an output text is exempt only if, at EVERY position where it
# occurs, the window lies wholly inside one bare IPv4 literal: the full dotted quad (each octet 0-255), bounded by the
# start / end of the text or by a character that is neither a digit nor '.'. Anything longer (an IP plus a share path,
# a port, a prefix, extra digits, a second address) is not exempt.
import re as _re  # noqa: E402

GRAM = 12
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_TOKEN = _re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d.])")


def command_grams(commands: Sequence[str]) -> set[str]:
    """Every 12-character window of every command, case-folded."""
    out: set[str] = set()
    for c in commands:
        c = c.casefold()
        out.update(c[i:i + GRAM] for i in range(len(c) - GRAM + 1))
    return out


def window_is_exempt(spans: Sequence[tuple[int, int]], start: int) -> bool:
    """True when the window [start, start + GRAM) lies wholly inside one bare IPv4 token span."""
    return any(s <= start and start + GRAM <= e for s, e in spans)


def non_exempt_hits(text: str, grams: set[str]) -> list[int]:
    """Start positions of the command windows found in `text` (case-folded) that are NOT exempt (see above). One
    call = one cell piece or one line, so 'start / end of the text' is the piece's own start / end. Every position is
    checked, so a window that is exempt at one occurrence and not at another is reported at the second."""
    t = text.casefold()
    spans = [m.span() for m in IPV4_TOKEN.finditer(t)]
    return [i for i in range(len(t) - GRAM + 1) if t[i:i + GRAM] in grams and not window_is_exempt(spans, i)]
