"""Labeller inputs: the spec 04_label section 2 refusals, the stitch outputs and the read-only DB pass.

WHY every check goes through the stitcher's functions: the labeller must refuse exactly what the gate and the
stitcher refuse (allowlist 046 / 053, quarantine, CO-17, window row, clock files, DB hash), and must read the very
DB the stitcher read. ``stitch.inputs`` already does each check; this module only turns its StitchError into a
LabelError and adds the two labeller checks: the stitch outputs exist, and the DB SHA-256 equals the stitch
``run_info.json`` ``db.sha256_after``. The allowlist is checked before any file is opened (LB-00).

``src/label`` never opens a path under ``ground_truth/`` (spec 2).
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from answer_key.db import open_ro, sha256_file
from stitch import inputs as st_inputs
from stitch.errors import StitchError
from stitch.inputs import CheckedInputs, TrialPaths

from .errors import LabelError
from .events import EventScan, scan_events
from .params import DB_COLUMNS, STITCH_CSV_COLUMNS, STITCH_FILES, STITCH_OUT_REL, VIEW

__all__ = ["StitchData", "DbRead", "stitch_call", "check_allowlist", "trial_paths", "stitch_dir", "check_allowed",
           "missing_stitch_files", "read_json", "read_csv_rows", "check_stitch_file_hashes", "load_stitch",
           "check_stitch_fresh", "check_stitch_db", "check_columns", "read_events"]


def stitch_call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call a shared stitch check and turn its StitchError into a LabelError (one refusal type for the labeller)."""
    try:
        return fn(*args, **kwargs)
    except StitchError as exc:
        text = str(exc)
        raise LabelError(text if text.startswith("refused") else f"refused: {text}") from exc


def check_allowlist(trial_id: str) -> None:
    """LB-00 / decisions 046, 053: refuse a trial outside ``clock_offset.params.DEVELOPMENT_TRIALS`` before any file
    is opened or stat-ed (``stitch.inputs.check_allowlist``)."""
    stitch_call(st_inputs.check_allowlist, trial_id)


def trial_paths(repo: Path, trial_id: str) -> TrialPaths:
    """The stitcher's input paths (DB, gate folder, window file, clock files); builds paths only, touches nothing."""
    return st_inputs.trial_paths(Path(repo), trial_id)


def stitch_dir(repo: Path, trial_id: str) -> Path:
    """``out/stitch/<trial_id>`` (spec 2)."""
    return Path(repo) / STITCH_OUT_REL / trial_id


def check_allowed(paths: TrialPaths) -> CheckedInputs:
    """Every gate-side refusal of spec 2 through ``stitch.inputs.check_allowed`` (id format, allowlist, id refusals
    and quarantine, gate files, time basis, window row, clock files and their hashes, CO-17)."""
    return stitch_call(st_inputs.check_allowed, paths)


def missing_stitch_files(folder: Path) -> list[str]:
    """The ``STITCH_FILES`` absent from the stitch folder, in ``STITCH_FILES`` order."""
    return [n for n in STITCH_FILES if not (Path(folder) / n).is_file()]


def read_json(path: Path) -> tuple[dict[str, Any], str]:
    """Parse a JSON object and hash the exact bytes read."""
    try:
        data = Path(path).read_bytes()
        obj = json.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise LabelError(f"refused: cannot read {path}: {exc}") from exc
    if not isinstance(obj, dict):
        raise LabelError(f"refused: {path} is not a JSON object")
    return obj, hashlib.sha256(data).hexdigest()


def read_csv_rows(path: Path, required: Sequence[str] = ()) -> tuple[list[dict[str, str]], str]:
    """All rows of a stitch CSV as text, and the SHA-256 of the bytes read (recorded in run_info.json).

    Refused when the header lacks a ``required`` column or a row's field count differs from the header (stage
    review S05 c). WHY: the join must never read a missing column as empty text, which would quietly turn into
    zero counts or unlabelled nodes."""
    try:
        data = Path(path).read_bytes()
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""))
        rows = [dict(r) for r in reader]
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        raise LabelError(f"refused: cannot read {path}: {exc}") from exc
    missing = [c for c in required if c not in (reader.fieldnames or [])]
    if missing:
        raise LabelError(f"refused: {Path(path).name} lacks required column(s): {', '.join(missing)}")
    for i, r in enumerate(rows, start=1):
        if None in r or any(v is None for v in r.values()):
            raise LabelError(f"refused: {Path(path).name} data row {i} has a field count that differs from the header")
    return rows, hashlib.sha256(data).hexdigest()


@dataclass
class StitchData:
    """The stitch outputs the node join reads (spec 2), with the SHA-256 of every file read."""
    path_nodes: list[dict[str, str]] = field(default_factory=list)
    hops: list[dict[str, str]] = field(default_factory=list)
    hop_artefacts: list[dict[str, str]] = field(default_factory=list)
    hop_identity: list[dict[str, str]] = field(default_factory=list)
    run_info: dict[str, Any] = field(default_factory=dict)
    file_sha256: dict[str, str] = field(default_factory=dict)


def check_stitch_file_hashes(run_info: Mapping[str, Any], file_sha256: Mapping[str, str]) -> None:
    """Stage review S05 b (replaces decision 058 point 10): every stitch CSV read must have the SHA-256 that the
    stitch ``run_info.json`` records for it. WHY: the stitcher writes run_info last with every file's hash, so a
    file regenerated or edited afterwards belongs to another stitch run and must not be joined. Pure."""
    files = run_info.get("files")
    for name, sha in sorted(file_sha256.items()):
        if name == "run_info.json":
            continue
        rec = files.get(name) if isinstance(files, Mapping) else None
        want = rec.get("sha256") if isinstance(rec, Mapping) else None
        if not isinstance(want, str) or not want:
            raise LabelError(f"refused: stitch run_info.json records no SHA-256 for {name}")
        if want.lower() != sha.lower():
            raise LabelError(f"refused: stitch {name} SHA-256 {sha} differs from stitch run_info.json {want}")


def load_stitch(folder: Path) -> StitchData:
    """Read the five stitch files (spec 2); LabelError naming every missing one, a CSV lacking a column the join
    reads (``STITCH_CSV_COLUMNS``), or a CSV whose hash differs from the stitch run_info (S05 b, c)."""
    missing = missing_stitch_files(folder)
    if missing:
        raise LabelError(f"refused: stitch output(s) missing in {folder}: {', '.join(missing)}")
    d = Path(folder)
    data = StitchData()
    data.run_info, data.file_sha256["run_info.json"] = read_json(d / "run_info.json")
    for name, attr in (("path_nodes.csv", "path_nodes"), ("hops.csv", "hops"),
                       ("hop_artefacts.csv", "hop_artefacts"), ("hop_identity.csv", "hop_identity")):
        rows, sha = read_csv_rows(d / name, STITCH_CSV_COLUMNS[name])
        setattr(data, attr, rows)
        data.file_sha256[name] = sha
    check_stitch_file_hashes(data.run_info, data.file_sha256)
    return data


def _recorded(run_info: Mapping[str, Any], *path: str) -> str:
    """A non-empty text value at ``path`` of the stitch run_info, lower-cased; LabelError when absent."""
    cur: Any = run_info
    for p in path:
        cur = cur.get(p) if isinstance(cur, Mapping) else None
    if not isinstance(cur, str) or not cur.strip():
        raise LabelError(f"refused: stitch run_info.json lacks {'.'.join(path)}")
    return cur.strip().lower()


def check_stitch_fresh(run_info: Mapping[str, Any], checked: CheckedInputs) -> None:
    """Stage review S05 a: the stitch run must have read the current gate stats and clock files. Its run_info
    ``gate_stats_sha256`` must equal the SHA-256 of the current gate ``stats.json``, and its ``window``
    ``offsets_sha256`` / ``clock_changes_sha256`` the SHA-256 of the current clock files. WHY: after a gate or clock
    re-run the stitch outputs are stale, and joining labels to them would mix two input states. Pure."""
    want = _recorded(run_info, "gate_stats_sha256")
    if want != checked.gate_stats_sha256.lower():
        raise LabelError(f"refused: stitch run_info.json gate_stats_sha256 {want} differs from the current gate "
                         f"stats.json {checked.gate_stats_sha256}; re-run the stitcher")
    clock = checked.clock
    for key, current in (("offsets_sha256", clock.offsets.file_sha256 if clock.offsets else ""),
                         ("clock_changes_sha256", clock.changes.file_sha256 if clock.changes else "")):
        want = _recorded(run_info, "window", key)
        if want != str(current).lower():
            raise LabelError(f"refused: stitch run_info.json window.{key} {want} differs from the current clock file "
                             f"{current!r}; re-run the stitcher")


def check_stitch_db(run_info: Mapping[str, Any], db_sha: str) -> None:
    """Spec 2: the DB must be the one the stitcher read (``run_info.json`` ``db.sha256_after``)."""
    db = run_info.get("db")
    want = str(db.get("sha256_after", "")).strip().lower() if isinstance(db, Mapping) else ""
    if not want:
        raise LabelError("refused: stitch run_info.json lacks db.sha256_after")
    if want != db_sha.lower():
        raise LabelError(f"refused: DB SHA-256 {db_sha!r} differs from stitch run_info.json db.sha256_after {want!r}")


def check_columns(con: sqlite3.Connection) -> None:
    """Refuse a view lacking any column the labeller selects, naming every missing one."""
    have = {r[1] for r in con.execute(f"PRAGMA table_info({VIEW})")}
    missing = [c for c in DB_COLUMNS if c not in have]
    if missing:
        raise LabelError(f"refused: {VIEW} lacks required column(s): {', '.join(missing)}")


def _iter_rows(con: sqlite3.Connection) -> Iterator[dict[str, Any]]:
    """Stream ``DB_COLUMNS`` from ``events_dedup`` (never ``events``)."""
    for rec in con.execute(f"SELECT {', '.join(DB_COLUMNS)} FROM {VIEW}"):
        yield dict(zip(DB_COLUMNS, tuple(rec)))


@dataclass
class DbRead:
    """The event scan and the DB SHA-256 before and after the read."""
    scan: EventScan
    sha_before: str
    sha_after: str


def read_events(checked: CheckedInputs, paths: TrialPaths, stitch_run_info: Mapping[str, Any],
                keep_json: Callable[[str, int], bool]) -> DbRead:
    """The one hash bracket around the DB read: hash, check against the gate stats and the offsets file
    (``stitch.inputs.check_db_hash``) and the stitch run_info, open read-only, scan (``events.scan_events``), close,
    hash again. LabelError when the DB is missing, a hash differs, a column is missing, SQLite fails, or the DB
    changed while open (spec 2: hash before = hash after)."""
    db = Path(paths.db)
    if not db.is_file():
        raise LabelError(f"refused: trial DB not found: {db}")
    before = sha256_file(db)
    stitch_call(st_inputs.check_db_hash, before, checked.gate_stats, checked.clock)
    check_stitch_db(stitch_run_info, before)
    changes = checked.clock.changes if checked.clock.changes is not None else ()
    try:
        con = open_ro(db)
        try:
            check_columns(con)
            scan = scan_events(_iter_rows(con), checked.start_us, checked.end_us, checked.clock.offsets, changes,
                               keep_json)
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise LabelError(f"refused: cannot read {VIEW} from {db}: {exc}") from exc
    after = sha256_file(db)
    if after != before:
        raise LabelError(f"refused: trial DB changed while open: {db}")
    return DbRead(scan=scan, sha_before=before, sha_after=after)
