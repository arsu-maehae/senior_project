"""Gate inputs: the refusal checks (GT-00), the window row, and the read-only event scan (spec 02_gate 2, 2.1).

WHY separate from the rules: GT-00 must run before any event is read, and the DB must be
provably untouched (SHA-256 before = after). Everything here that touches a file takes an
explicit path; the scan itself (``scan_events``) is pure and works on any iterable of rows.
"""
from __future__ import annotations

import csv
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from answer_key.db import open_ro, sha256_file
from clock_offset.correct import Offsets, corrected_us
from trial_window.params import COLUMNS as WINDOW_COLUMNS
from trial_window.window import ClockFiles, clock_refusal, is_quarantined, load_clock_files, refusal

from . import classify
from .params import DB_COLUMNS, VIEW, GateParams
from .timeutil import fmt_us, seconds_to_us, to_us, US_PER_MS

Row = dict[str, Any]

# WHY: the trial id names the output folder that is emptied on every run; a value with path
# separators or dots could point the clean-up outside out/gate/.
_TRIAL_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class GateError(Exception):
    """Refusal or error that stops the gate before anything is written (spec 2: refused inputs).

    WHY one exception type: the CLI maps it to exit code 2 with the reason, and a test can assert
    that nothing was written whatever the cause.
    """


def check_trial_id(trial_id: str) -> None:
    """Refuse a trial id that cannot safely name the output folder."""
    if not trial_id or not _TRIAL_ID_RE.match(trial_id):
        raise GateError(f"invalid trial id {trial_id!r}")


def check_not_quarantined(trial_id: str, db_path: Path, repo: Path | None) -> None:
    """GT-00 / decision 030: quarantined id (``s05q_*``) or a ``quarantine`` path part below the repo."""
    if is_quarantined(trial_id, Path(db_path), repo):
        raise GateError(f"refused: quarantined trial or DB path ({trial_id}, {db_path}; decision 030)")


def read_window_row(windows_csv: Path, trial_id: str) -> dict[str, str]:
    """The trial's row of data/trial_windows.csv; GateError if the file, the row or an edge is missing.

    WHY refuse an empty edge: a window with no start or end would clip nothing or everything, and
    either would silently change which hops reach T7 (spec 2).
    """
    path = Path(windows_csv)
    if not path.is_file():
        raise GateError(f"refused: trial window file not found: {path}")
    with open(path, newline="", encoding="utf-8-sig") as fh:
        rows = [r for r in csv.DictReader(fh) if (r.get("trial_id") or "").strip() == trial_id]
    if not rows:
        raise GateError(f"refused: no row for {trial_id} in {path.name}")
    if len(rows) > 1:
        raise GateError(f"refused: {len(rows)} rows for {trial_id} in {path.name}")
    row = {k: (rows[0].get(k) or "").strip() for k in WINDOW_COLUMNS}
    if not row["start_utc"] or not row["end_utc"]:
        raise GateError(f"refused: empty start_utc or end_utc for {trial_id} in {path.name}")
    return row


def window_edges_us(row: Mapping[str, str]) -> tuple[int, int]:
    """(start, end) as microsecond instants; GateError if unparseable or start >= end."""
    try:
        start, end = to_us(row["start_utc"]), to_us(row["end_utc"])
    except ValueError as exc:
        raise GateError(f"refused: unparseable window edge ({exc})") from exc
    if start >= end:
        raise GateError(f"refused: window start {row['start_utc']} is not before end {row['end_utc']}")
    return start, end


def check_clock(trial_id: str, start_us: int | None, params: GateParams, clock: ClockFiles | None = None) -> None:
    """GT-00 clock rule (spec 2, 2.2 as amended in T6b.2, decision 043) via the trial window step's own
    ``refusal``, so the window step and the gate refuse exactly the same trials.

    Always: quarantined id, decision-019 exclusion, clock-only trial. With ``clock``: a missing offsets or
    clock-changes file, and (with ``start_us``) CO-17 on the window start. WHY the start is reformatted to
    ``...Z``: the gate has already parsed the instant itself; one text form keeps ``refusal`` simple.
    """
    start_text = fmt_us(start_us) if start_us is not None else None
    reason = refusal(trial_id, start_text, clock_only_trials=params.clock_only_trials, clock=clock,
                     co17_date=params.raw_time_cutoff_date)
    if reason:
        raise GateError(f"refused: {reason}")


def load_clock(offsets_csv: Path, changes_csv: Path) -> ClockFiles:
    """Read the trial's offsets and clock-changes files (a missing one is refused later by ``check_clock``).

    WHY GateError on a parse error: a file that exists but does not match spec 08 section 3 is wrong data;
    the gate must stop and write nothing rather than correct times with a misread offset.
    """
    try:
        return load_clock_files(Path(offsets_csv), Path(changes_csv))
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise GateError(f"refused: cannot read the clock files {Path(offsets_csv).name} / "
                        f"{Path(changes_csv).name}: {exc}") from exc


def check_clock_hashes(row: Mapping[str, str], clock: ClockFiles) -> None:
    """Refuse a window row whose ``offsets_sha256`` / ``clock_changes_sha256`` differ from the files' SHA-256
    (spec 2 as amended in T6b.2, decision 043).

    WHY: the window edges were corrected with those exact files; other offsets would clip with a different
    clock than the edges were taken on. Call only after ``check_clock`` has confirmed both files exist.
    """
    assert clock.offsets is not None and clock.changes is not None
    for column, file_sha, path in (("offsets_sha256", clock.offsets.file_sha256, clock.offsets_path),
                                   ("clock_changes_sha256", clock.changes.file_sha256, clock.changes_path)):
        if (row.get(column) or "").strip().lower() != file_sha.lower():
            raise GateError(f"refused: window {column} {row.get(column)!r} differs from the SHA-256 of "
                            f"{Path(path).name} {file_sha!r}")


def check_offsets_db(clock: ClockFiles, db_sha: str) -> None:
    """Refuse offsets computed from another version of the DB (spec 2 as amended in T6b.2, spec 08 4.1 item 3)."""
    reason = clock_refusal(clock, None, db_sha)
    if reason:
        raise GateError(f"refused: {reason}")


def missing_columns(available: Iterable[str]) -> list[str]:
    """Spec section 2 columns absent from the view, in ``DB_COLUMNS`` order (empty when all present)."""
    have = set(available)
    return [c for c in DB_COLUMNS if c not in have]


def check_columns(con: sqlite3.Connection) -> None:
    """Refuse a DB whose ``events_dedup`` view lacks any required column, naming every missing one.

    WHY before the scan: without the check, SQLite fails on the first unknown column only, so the
    message names one column at a time; a NULL fallback would silently change dispositions
    (e.g. an outbound 3389 Sysmon 3 with no ``destination_ip``, decision 041).
    """
    missing = missing_columns(r[1] for r in con.execute(f"PRAGMA table_info({VIEW})"))
    if missing:
        raise GateError(f"{VIEW} lacks required column(s): {', '.join(missing)}")


def iter_events(con: sqlite3.Connection) -> Iterator[Row]:
    """Stream the spec section 2 columns of ``events_dedup`` (never ``events``) as dicts.

    WHY streaming: a trial DB holds far more events than the gate keeps; only rows the rules or
    the stats need are retained by ``scan_events``.
    """
    sql = f"SELECT {', '.join(DB_COLUMNS)} FROM {VIEW}"
    cur = con.execute(sql)
    for rec in cur:
        yield dict(zip(DB_COLUMNS, rec))


@dataclass
class ScanResult:
    """What one pass over the DB yields: in-window rule events, all 4624s (unclipped), window counts.

    Every row carries ``us_raw`` (its logged ``event_utc``) and ``us`` (its corrected instant, T6b.2): the
    clip, the near-window counts, every rule and the sort use ``us``. ``logons_all`` is used only for the
    GT-02(b) excluded-logon map and the tier-D IP lookup (spec 3), never as an anchor or trigger. ``near_dup_groups`` holds the uids of in-window events
    sharing (host, channel, record_id).
    """
    in_window: list[Row] = field(default_factory=list)
    logons_all: list[Row] = field(default_factory=list)
    # Decision 042: outbound Sysmon 3 with a link-local source_ip, unclipped (evidence E1 only).
    own_ll_sysmon3_all: list[Row] = field(default_factory=list)
    loaded_total: int = 0
    in_window_total: int = 0
    removed_by_window: dict[str, dict[str, int]] = field(default_factory=dict)
    near_window: dict[str, dict[str, int]] = field(default_factory=dict)
    near_dup_groups: dict[tuple, list[str]] = field(default_factory=dict)


def _bump(table: dict[str, dict[str, int]], host: str, key: str) -> None:
    """Increment a host x key counter."""
    inner = table.setdefault(host, {})
    inner[key] = inner.get(key, 0) + 1


def event_key(row: Mapping) -> str:
    """``<channel>/<event_id>`` count key: event ids alone collide across channels (Sysmon 1 vs System 1)."""
    return f"{row.get('channel')}/{row.get('event_id')}"


def _near_side(us: int, start_us: int, end_excl_us: int, near_us: int) -> str | None:
    """'before' / 'after' if an out-of-window instant is within NEAR_WINDOW_S of an edge, else None."""
    if start_us - near_us <= us < start_us:
        return "before"
    if end_excl_us <= us < end_excl_us + near_us:
        return "after"
    return None


def scan_events(rows: Iterable[Mapping], start_us: int, end_us: int, params: GateParams,
                offsets: Offsets | None = None) -> ScanResult:
    """GT-01 window clip in one pass: keep in-window rule events, count what the window removed.

    Window: ``start <= t < end + 1 ms`` (the window file has ms, the DB µs), on the corrected time
    ``us`` = ``corrected_us(us_raw, host, offsets)`` (spec 08 CO-09, T6b.2); ``us_raw`` keeps the logged
    time for the output ``event_utc`` and the clock-change check. ``offsets`` None applies no correction
    (``us`` = ``us_raw``; ``run_gate`` always passes the trial's offsets). Out-of-window events are only
    counted (per host x event, and near-window trigger-type counts), except 4624s, which are also kept in
    ``logons_all`` for the unclipped lookups. Raises GateError for an event with no parseable
    ``event_utc`` (data wrong; the gate does not guess a time).
    """
    end_excl = end_us + US_PER_MS
    near_us = seconds_to_us(params.near_window_s)
    res = ScanResult()
    for raw in rows:
        row = dict(raw)
        res.loaded_total += 1
        try:
            row["us_raw"] = to_us(row["event_utc"])
        except (TypeError, ValueError) as exc:
            raise GateError(f"event {row.get('event_uid')} has no valid event_utc ({exc})") from exc
        row["us"] = row["us_raw"] if offsets is None else corrected_us(row["us_raw"], str(row.get("host")), offsets)
        if classify.is_4624(row):
            res.logons_all.append(row)
        elif classify.is_own_link_local_sysmon3(row):
            res.own_ll_sysmon3_all.append(row)
        if not (start_us <= row["us"] < end_excl):
            _bump(res.removed_by_window, str(row.get("host")), event_key(row))
            side = _near_side(row["us"], start_us, end_excl, near_us)
            if side and classify.is_trigger_type(row):
                _bump(res.near_window, str(row.get("host")), side)
            continue
        res.in_window_total += 1
        if row.get("record_id") is not None:
            res.near_dup_groups.setdefault((row.get("host"), row.get("channel"), row["record_id"]),
                                           []).append(row["event_uid"])
        if classify.is_kept_type(row):
            res.in_window.append(row)
    return res


def check_time_basis(row: Mapping[str, str], params: GateParams) -> None:
    """Refuse a window computed on a different time basis than the gate uses (spec 2, decision 041).

    WHY: a raw-time window clipping corrected times (or the reverse) can shift the edges by the
    clock offset (decision 032), so the clip would no longer mean what the window file says.
    """
    if row.get("time_basis") != params.time_basis:
        raise GateError(f"refused: window time_basis {row.get('time_basis')!r} differs from the gate's "
                        f"TIME_BASIS {params.time_basis!r}")


def check_db_hash(window_sha: str, db_sha: str, db_path: Path) -> None:
    """Refuse a DB whose SHA-256 is not the ``db_sha256`` the window was computed from (spec 2, decision 041).

    WHY: the window edges come from this DB's agent tree; a different or re-imported DB may hold
    other events, so its window is not known to fit.
    """
    if (window_sha or "").strip().lower() != db_sha.lower():
        raise GateError(f"refused: window db_sha256 {window_sha!r} differs from the SHA-256 of {Path(db_path).name} "
                        f"{db_sha!r}")


def load_events(db_path: Path, start_us: int, end_us: int, params: GateParams,
                expected_sha256: str | None = None, clock: ClockFiles | None = None) -> tuple[ScanResult, str, str]:
    """Hash the DB, check it against the window row's ``db_sha256`` and the offsets' ``db_sha256``, then open
    it read-only and scan it on corrected times.

    Returns (scan, sha256 before, sha256 after). Raises GateError if the DB is missing, if its hash
    differs from ``expected_sha256`` or from the offsets file's ``db_sha256`` (both checked before any
    event row is read; None skips the check), if the view lacks a required column (all missing ones
    named), or if its hash changed while open (it must never be written).
    """
    path = Path(db_path)
    if not path.is_file():
        raise GateError(f"trial DB not found: {path}")
    before = sha256_file(path)
    if expected_sha256 is not None:
        check_db_hash(expected_sha256, before, path)
    if clock is not None:
        check_offsets_db(clock, before)
    offsets = clock.offsets if clock is not None else None
    try:
        con = open_ro(path)
        try:
            check_columns(con)
            scan = scan_events(iter_events(con), start_us, end_us, params, offsets)
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise GateError(f"cannot read {VIEW} from {path}: {exc}") from exc
    after = sha256_file(path)
    if after != before:
        raise GateError(f"trial DB changed while open: {path}")
    return scan, before, after
