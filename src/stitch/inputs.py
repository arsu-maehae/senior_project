"""Stitcher inputs: ST-00 refusals (spec 03_stitch section 2; decision 046) and the read-only DB scan.

WHY separate from the index code: ST-00 must run before any event is read, the development allowlist
(decision 046) before any file is even looked at, and the DB must be provably untouched (SHA-256 before =
after = the gate's ``db.sha256_after``). Every check that the gate or the window step also makes goes
through their shared functions, so a stale gate folder cannot be stitched (spec 2).
"""
from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, TypeVar

from answer_key.db import open_ro, sha256_file
from gate import inputs as gate_inputs
from gate.inputs import GateError
from gate.params import GateParams
from gate.timeutil import fmt_us
from trial_window.params import PROCESSED_REL, TIME_BASIS, WINDOWS_REL
from trial_window.window import (ClockFiles, clock_changes_path, clock_refusal, id_refusal, is_quarantined,
                                 offsets_path, refusal)

from .errors import StitchError
from .params import ALLOWED_TRIALS, GATE_FILES, GATE_OUT_REL, SCAN_COLUMNS, SPEC_DB_COLUMNS, VIEW, StitchParams
from .scan import ScanResult, scan_rows

__all__ = ["StitchError", "TrialPaths", "CheckedInputs", "GateRows", "trial_paths", "check_allowed", "load_scan",
           "load_link_inputs", "read_gate_rows", "read_gate_csv", "check_allowlist", "missing_gate_files",
           "window_row_differences", "missing_db_columns"]

T = TypeVar("T")

# WHY the gate's defaults: the clock-only list and the CO-17 date must be exactly what the gate refused with.
_GATE = GateParams()


@dataclass(frozen=True)
class TrialPaths:
    """Every input path of one trial. Built by ``trial_paths`` without touching the disk."""
    trial_id: str
    repo: Path
    db: Path
    gate_dir: Path
    windows_csv: Path
    offsets_csv: Path
    changes_csv: Path


@dataclass
class CheckedInputs:
    """What ST-00 established: the gate stats (and their hash), the window row and edges, the clock files."""
    trial_id: str
    gate_stats: dict[str, Any]
    gate_stats_sha256: str
    window_row: dict[str, str]
    start_us: int
    end_us: int
    clock: ClockFiles


def trial_paths(repo: Path, trial_id: str) -> TrialPaths:
    """Default input paths (spec 2): DB and clock files under data/processed, gate folder, window file.

    WHY pure: the allowlist test points these at files that do not exist and still expects the allowlist
    refusal, so building them must never stat or open anything.
    """
    r = Path(repo)
    return TrialPaths(trial_id=trial_id, repo=r, db=r / PROCESSED_REL / f"{trial_id}.sqlite3",
                      gate_dir=r / GATE_OUT_REL / trial_id, windows_csv=r / WINDOWS_REL,
                      offsets_csv=offsets_path(r, trial_id), changes_csv=clock_changes_path(r, trial_id))


# ---------------------------------------------------------------- ST-00 steps

def _gate_call(fn, *args, **kwargs):
    """Call a shared gate check and turn its GateError into a StitchError (one refusal type for the stitcher)."""
    try:
        return fn(*args, **kwargs)
    except GateError as exc:
        raise StitchError(str(exc)) from exc


def check_allowlist(trial_id: str) -> None:
    """Decision 046: refuse every trial outside ``ALLOWED_TRIALS`` (the development trials) BEFORE any file
    is opened or stat-ed, so test data (t02-t10) can never be read while T7 is built.

    The id-only reason of the window step (quarantine 030, split exclusion 019, clock-only 034) is added
    when one applies; it needs no file either.
    """
    if trial_id in ALLOWED_TRIALS:
        return
    extra = id_refusal(trial_id, clock_only_trials=_GATE.clock_only_trials)
    detail = f"; also {extra}" if extra else ""
    raise StitchError(f"refused: {trial_id!r} is not a development trial; the stitcher runs on "
                      f"{', '.join(ALLOWED_TRIALS)} only until T10 (decision 046){detail}")


def check_id_refusals(paths: TrialPaths) -> None:
    """ST-00 / spec 2: the window step's id refusals and the quarantine path rule, as the gate applies them."""
    reason = refusal(paths.trial_id, None, clock_only_trials=_GATE.clock_only_trials,
                     co17_date=_GATE.raw_time_cutoff_date)
    if reason:
        raise StitchError(f"refused: {reason}")
    if is_quarantined(paths.trial_id, paths.db, paths.repo):
        raise StitchError(f"refused: quarantined trial or DB path ({paths.trial_id}, {paths.db}; decision 030)")


def missing_gate_files(gate_dir: Path) -> list[str]:
    """The ``GATE_FILES`` absent from the gate folder, in ``GATE_FILES`` order (empty when all present)."""
    return [name for name in GATE_FILES if not (Path(gate_dir) / name).is_file()]


def read_gate_stats(path: Path) -> tuple[dict[str, Any], str]:
    """Parse the gate ``stats.json`` and hash the exact bytes read (so the hash describes what was parsed)."""
    try:
        data = Path(path).read_bytes()
        stats = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise StitchError(f"refused: cannot read gate stats {path}: {exc}") from exc
    if not isinstance(stats, dict):
        raise StitchError(f"refused: gate stats {path} is not a JSON object")
    return stats, hashlib.sha256(data).hexdigest()


def _stats_value(stats: Mapping[str, Any], *keys: str) -> Any:
    """Nested ``stats.json`` value; StitchError naming the path when it is missing (wrong or old gate output)."""
    cur: Any = stats
    for k in keys:
        if not isinstance(cur, Mapping) or k not in cur:
            raise StitchError(f"refused: gate stats.json lacks {'.'.join(keys)}")
        cur = cur[k]
    return cur


def check_time_basis(stats: Mapping[str, Any]) -> None:
    """Spec 2: the gate outputs must be on the corrected time basis (decision 043), the basis of every
    cross-host comparison the stitcher makes (ST-02)."""
    basis = _stats_value(stats, "time_basis")
    if basis != TIME_BASIS:
        raise StitchError(f"refused: gate stats.json time_basis {basis!r} is not {TIME_BASIS!r}")


def _cell(value: Any) -> str:
    """A window cell as a stripped string (CSV text and JSON values compared the same way)."""
    return "" if value is None else str(value).strip()


def window_row_differences(gate_row: Mapping[str, Any], file_row: Mapping[str, Any]) -> list[str]:
    """Columns whose stripped values differ between the gate's ``window.row`` and the window file's row,
    sorted; a column present on one side only counts as different."""
    return sorted(k for k in set(gate_row) | set(file_row) if _cell(gate_row.get(k)) != _cell(file_row.get(k)))


def check_window_row(stats: Mapping[str, Any], windows_csv: Path, trial_id: str) -> dict[str, str]:
    """Spec 2: the window the gate clipped with must be the trial's current row; the stitcher never computes
    a window. Returns the file's row."""
    gate_row = _stats_value(stats, "window", "row")
    if not isinstance(gate_row, Mapping):
        raise StitchError("refused: gate stats.json window.row is not an object")
    file_row = _gate_call(gate_inputs.read_window_row, windows_csv, trial_id)
    diff = window_row_differences(gate_row, file_row)
    if diff:
        raise StitchError(f"refused: gate window row differs from {Path(windows_csv).name} in column(s): "
                          f"{', '.join(diff)}")
    return file_row


def check_clock_files(stats: Mapping[str, Any], clock: ClockFiles, trial_id: str) -> None:
    """Spec 2: the clock files must pass the shared clock refusals and be the very files the gate used
    (``stats.clock.offsets_sha256`` / ``clock_changes_sha256``)."""
    reason = clock_refusal(clock, None, None, _GATE.raw_time_cutoff_date, trial_id=trial_id)
    if reason:
        raise StitchError(f"refused: {reason}")
    assert clock.offsets is not None and clock.changes is not None   # clock_refusal refused otherwise
    for key, file_sha, path in (("offsets_sha256", clock.offsets.file_sha256, clock.offsets_path),
                                ("clock_changes_sha256", clock.changes.file_sha256, clock.changes_path)):
        want = _cell(_stats_value(stats, "clock", key)).lower()
        if want != file_sha.lower():
            raise StitchError(f"refused: gate stats.json clock.{key} {want!r} differs from the SHA-256 of "
                              f"{Path(path).name} {file_sha!r}")


def check_co17(trial_id: str, start_us: int, clock: ClockFiles) -> None:
    """CO-17 on the window start through the shared ``refusal``, exactly as ``gate.run.check_allowed`` does."""
    reason = refusal(trial_id, fmt_us(start_us), clock_only_trials=_GATE.clock_only_trials, clock=clock,
                     co17_date=_GATE.raw_time_cutoff_date)
    if reason:
        raise StitchError(f"refused: {reason}")


def check_allowed(paths: TrialPaths, params: StitchParams = StitchParams()) -> CheckedInputs:
    """ST-00 before any event is read (spec 2; decision 046), in this order: trial id format; development
    allowlist (no file touched before it); id refusals and quarantine; all gate files present; gate
    ``time_basis`` corrected; gate window row equals the window file's row; clock files load, pass the
    shared clock refusals and match the gate's hashes; CO-17 on the window start.

    ``params`` is accepted for a uniform signature; no ST-00 check depends on a section 5 value. Raises
    StitchError on any refusal.
    """
    _gate_call(gate_inputs.check_trial_id, paths.trial_id)
    check_allowlist(paths.trial_id)
    check_id_refusals(paths)
    missing = missing_gate_files(paths.gate_dir)
    if missing:
        raise StitchError(f"refused: gate output(s) missing in {paths.gate_dir}: {', '.join(missing)}")
    stats, stats_sha = read_gate_stats(paths.gate_dir / "stats.json")
    check_time_basis(stats)
    row = check_window_row(stats, paths.windows_csv, paths.trial_id)
    start_us, end_us = _gate_call(gate_inputs.window_edges_us, row)
    clock = _gate_call(gate_inputs.load_clock, paths.offsets_csv, paths.changes_csv)
    check_clock_files(stats, clock, paths.trial_id)
    check_co17(paths.trial_id, start_us, clock)
    return CheckedInputs(trial_id=paths.trial_id, gate_stats=stats, gate_stats_sha256=stats_sha,
                         window_row=dict(row), start_us=start_us, end_us=end_us, clock=clock)


# ---------------------------------------------------------------- gate rows (T7.3)

# The three gate files T7.3 reads (spec 2). WHY not dispositions.csv / stats.json: ST-00 already checked
# that they exist and read stats.json; hops need only the remote logons (ST-03) and supporting rows.
GATE_ROW_FILES: tuple[str, ...] = ("triggers.csv", "unmatched_remote.csv", "supporting.csv")


@dataclass
class GateRows:
    """The rows of the gate's ``triggers.csv``, ``unmatched_remote.csv`` and ``supporting.csv``, as text.

    WHY plain dicts of text: the hop builder (``hops.remote_logons``) converts each value it uses with the
    gate's own functions (``norm_ip``, ``logon_id``), so the stitcher reads a gate row exactly as the gate
    meant it, and a test can build these rows by hand.
    """
    triggers: list[dict[str, str]] = field(default_factory=list)
    unmatched: list[dict[str, str]] = field(default_factory=list)
    supporting: list[dict[str, str]] = field(default_factory=list)


def read_gate_csv(path: Path) -> list[dict[str, str]]:
    """All rows of one gate CSV (utf-8, ``newline=''`` as the csv module requires); StitchError if unreadable.

    WHY refuse and not skip: a gate file that cannot be read would silently drop remote logons, and every
    remote logon must become a hop member or a follow-up (ST-03, STA-01).
    """
    try:
        with Path(path).open("r", encoding="utf-8", newline="") as fh:
            return [dict(r) for r in csv.DictReader(fh)]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise StitchError(f"refused: cannot read gate file {path}: {exc}") from exc


def read_gate_rows(gate_dir: Path) -> GateRows:
    """The three gate files of ``GATE_ROW_FILES`` from ``gate_dir`` (spec 2). Call after ``check_allowed``,
    which refused a trial with any gate file missing; the allowlist is therefore checked before this opens
    anything."""
    d = Path(gate_dir)
    trig, unm, sup = (read_gate_csv(d / name) for name in GATE_ROW_FILES)
    return GateRows(triggers=trig, unmatched=unm, supporting=sup)


# ---------------------------------------------------------------- DB scan

def missing_db_columns(available: Iterator[str] | list[str]) -> list[str]:
    """Spec section 2 columns absent from the view, in ``SPEC_DB_COLUMNS`` order (empty when all present)."""
    have = set(available)
    return [c for c in SPEC_DB_COLUMNS if c not in have]


def check_db_columns(con: sqlite3.Connection) -> None:
    """Refuse a view lacking any spec 2 column, naming every missing one (not just the first SQLite hits)."""
    missing = missing_db_columns([r[1] for r in con.execute(f"PRAGMA table_info({VIEW})")])
    if missing:
        raise StitchError(f"refused: {VIEW} lacks required column(s): {', '.join(missing)}")


def iter_scan_rows(con: sqlite3.Connection) -> Iterator[dict[str, Any]]:
    """Stream only ``SCAN_COLUMNS`` from ``events_dedup`` (never ``events``; never command text)."""
    for rec in con.execute(f"SELECT {', '.join(SCAN_COLUMNS)} FROM {VIEW}"):
        yield dict(zip(SCAN_COLUMNS, tuple(rec)))


def check_db_hash(db_sha: str, stats: Mapping[str, Any], clock: ClockFiles) -> None:
    """Spec 2: the DB must be the one the gate read (``db.sha256_after``) and the one the offsets were
    computed from (the offsets file's ``db_sha256``, through the shared ``clock_refusal``)."""
    want = _cell(_stats_value(stats, "db", "sha256_after")).lower()
    if want != db_sha.lower():
        raise StitchError(f"refused: DB SHA-256 {db_sha!r} differs from gate stats.json db.sha256_after {want!r}")
    reason = clock_refusal(clock, None, db_sha)
    if reason:
        raise StitchError(f"refused: {reason}")


def _read_db(checked: CheckedInputs, paths: TrialPaths,
             extra: Callable[[sqlite3.Connection, ScanResult], T] | None) -> tuple[ScanResult, T | None, str, str]:
    """The one hash bracket around every DB read: hash and check (spec 2), open read-only, check the
    columns, scan, run ``extra`` on the same open connection, close, and prove the DB unchanged.

    WHY ``extra`` runs inside: T7.3 reads command text by uid (``cmdtext``, decision 048 item 1) for uids
    it only knows after the scan; reading them in the same read-only connection, between the same two
    hashes, means every byte the stitcher read comes from the DB the gate read.
    """
    db = Path(paths.db)
    if not db.is_file():
        raise StitchError(f"refused: trial DB not found: {db}")
    before = sha256_file(db)
    check_db_hash(before, checked.gate_stats, checked.clock)
    result: T | None = None
    try:
        con = open_ro(db)
        try:
            check_db_columns(con)
            scan = scan_rows(iter_scan_rows(con), checked.start_us, checked.end_us, checked.clock.offsets,
                             checked.clock.changes if checked.clock.changes is not None else ())
            if extra is not None:
                result = extra(con, scan)
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise StitchError(f"cannot read {VIEW} from {db}: {exc}") from exc
    after = sha256_file(db)
    if after != before:
        raise StitchError(f"trial DB changed while open: {db}")
    return scan, result, before, after


def load_scan(checked: CheckedInputs, paths: TrialPaths,
              params: StitchParams = StitchParams()) -> tuple[ScanResult, str, str]:
    """Hash the DB and check it (spec 2), open it read-only, check its columns, stream ``SCAN_COLUMNS``
    through ``scan.scan_rows``, and prove the DB unchanged.

    Returns (scan, sha256 before, sha256 after). Raises StitchError on a missing DB, a hash mismatch, a
    missing column, any SQLite error, or a DB whose hash changed while open.
    """
    scan, _, before, after = _read_db(checked, paths, None)
    return scan, before, after


def load_link_inputs(checked: CheckedInputs, paths: TrialPaths,
                     extra: Callable[[sqlite3.Connection, ScanResult], T],
                     params: StitchParams = StitchParams()) -> tuple[ScanResult, T, str, str]:
    """``load_scan`` plus ``extra(con, scan)`` on the same read-only connection, inside the same hash
    bracket (T7.3; decision 048 item 1).

    ``extra`` typically builds the index and hop probes from ``scan`` and calls
    ``cmdtext.read_command_results`` / ``read_4648_targets``. Returns (scan, extra's result, sha256 before,
    sha256 after). Same refusals as ``load_scan``; an SQLite error raised inside ``extra`` is a StitchError
    too, and the connection is closed in every case.
    """
    scan, result, before, after = _read_db(checked, paths, extra)
    return scan, result, before, after  # type: ignore[return-value]  # extra is not None here
