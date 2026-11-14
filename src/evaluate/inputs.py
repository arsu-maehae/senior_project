"""Inputs of the link accuracy module: refusals, stitch files, approved key, key lock, read-only DB (decision 051
items 1, 2 and 9).

WHY every check refuses instead of warning: an accuracy number is only meaningful for exactly the stitch output,
key and DB it names. A changed stitch file, a key of another trial or a DB that differs from the one the stitcher
read would give numbers about something else, so the run stops and writes nothing (051 item 2). Nothing here
imports ``stitch`` (051 item 1); the DB opener is this package's own.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import sqlite3
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .params import (APPROVED_KEYS_REL, BOOT_CHANNEL, BOOT_SHUTDOWN_IDS, BOOT_STARTUP_IDS, DB_REL, DB_SUFFIX,
                     DEVELOPMENT_TRIALS, KEY_LOCK_HEADER, KEY_LOCK_REL, PROTOCOL_GROUPS, SPLIT_DEVELOPMENT,
                     SPLIT_TEST, STITCH_FILES, STITCH_RUN_INFO, TRIAL_ID_PATTERN)

__all__ = ["EvalError", "StitchData", "KeyData", "EventRow", "LogonRow", "BootRow", "check_trial_allowed",
           "sha256_file", "sha256_bytes", "load_stitch", "key_path", "load_key", "check_key_lock", "db_path",
           "open_db_ro", "check_db_hash", "check_db_unchanged", "query_events", "query_logons", "query_boots",
           "repo_relative", "validate_stitch_rows", "validate_key_data"]

_TRIAL_RE = re.compile(TRIAL_ID_PATTERN)
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_INT_RE = re.compile(r"-?[0-9]+")
_HEX_RE = re.compile(r"(0[xX])?[0-9a-fA-F]+")  # what keys.parse_hex accepts
# The stitch columns the evaluation reads (spec 03 section 3); a header without one of them is refused.
_HOP_COLUMNS: tuple[str, ...] = ("hop_id", "target_host", "source_host", "member_count", "member_logon_uids",
                                 "member_logon_ids", "member_accounts", "protocol", "is_seed", "in_path",
                                 "candidate_count", "best_tier", "evidence_before_range", "evidence_after_range",
                                 "clock_unreliable")
_LINK_COLUMNS: tuple[str, ...] = ("hop_id", "method", "session_methods", "source_host", "source_session_id",
                                  "source_session_logon_uid", "confidence_tier", "link_rank", "tie",
                                  "target_only_reason")
_IDENTITY_COLUMNS: tuple[str, ...] = ("hop_id", "account", "dump_event_uid", "dump_account", "gap_ms", "order_ok",
                                      "order_within_tolerance", "order_within_uncertainty", "open_session_uids",
                                      "end_unknown_session_uids", "not_applicable")
_VIEW = "events_dedup"
_CHUNK = 500  # WHY: SQLite's default limit on bound parameters is 999; 500 leaves room.


class EvalError(Exception):
    """A refusal: the run stops before anything is written (decision 051 items 2 and 9).

    WHY one type: the CLI maps it to exit code 2 with the reason, and a test can assert "nothing written"
    whatever the cause.
    """


# ---------------------------------------------------------------- data holders

@dataclass(frozen=True)
class StitchData:
    """The ten stitch files of one trial, checked against the stitch ``run_info.json`` and parsed.

    CSV rows are kept as the text the stitcher wrote (dicts of str), so no value is reinterpreted on reading.
    """
    stitch_dir: Path
    file_sha256: Mapping[str, str]          # every one of the ten files, run_info.json included
    hops: tuple[Mapping[str, str], ...]
    links: tuple[Mapping[str, str], ...]
    hop_artefacts: tuple[Mapping[str, str], ...]
    hop_identity: tuple[Mapping[str, str], ...]
    paths: tuple[Mapping[str, str], ...]
    path_edges: tuple[Mapping[str, str], ...]
    path_nodes: tuple[Mapping[str, str], ...]
    stats: Mapping[str, Any]
    run_info: Mapping[str, Any]


@dataclass(frozen=True)
class KeyData:
    """The approved key of one trial: its parsed content, repo-relative path, SHA-256 and lock status."""
    path_rel: str
    sha256: str
    lock: str                               # "not_required" (development) or "locked" (test)
    data: Mapping[str, Any]


@dataclass(frozen=True)
class EventRow:
    """The few DB columns the evaluation needs for one event (never the command line or the field JSON)."""
    event_uid: str
    host: str
    channel: str
    event_id: int
    event_utc: str
    session_id: int | None


@dataclass(frozen=True)
class LogonRow:
    """A Security 4624 of one host and logon ID: the opening event of a session."""
    event_uid: str
    event_utc: str
    target_logon_id: int


@dataclass(frozen=True)
class BootRow:
    """A System boot / shutdown event of one host (decision 047 item 3)."""
    event_uid: str
    event_id: int
    event_utc: str


# ---------------------------------------------------------------- allowlist (decision 046 style)

def check_trial_allowed(trial: str) -> None:
    """Refuse a malformed trial id or one outside ``DEVELOPMENT_TRIALS``; touches no file.

    WHY before any file access: decision 051 item 1 keeps 046's rule that test trials cannot be read by
    mistake while the module is being built; lifting it at T10 needs the owner's approval.
    """
    if not isinstance(trial, str) or not _TRIAL_RE.fullmatch(trial):
        raise EvalError(f"refused: malformed trial id {trial!r} (expected s<NN>_t<NN>)")
    if trial not in DEVELOPMENT_TRIALS:
        raise EvalError(f"refused: trial {trial} is not a development trial (decisions 019, 046, 051 item 1)")


# ---------------------------------------------------------------- hashing and paths

def sha256_bytes(data: bytes) -> str:
    """Lower-case hex SHA-256 of bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Lower-case hex SHA-256 of a file, read in blocks (DBs are large)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def repo_relative(path: Path, repo: Path) -> str:
    """POSIX path relative to the repo when below it, else the absolute POSIX path.

    WHY: written paths must not depend on where the repo lives, so outputs stay byte-identical.
    """
    p = Path(path).resolve()
    try:
        return p.relative_to(Path(repo).resolve()).as_posix()
    except ValueError:
        return p.as_posix()


# ---------------------------------------------------------------- stitch files (051 item 2)

def _parse_csv(name: str, data: bytes) -> tuple[dict[str, str], ...]:
    """CSV bytes (UTF-8) to a tuple of row dicts, text as written; EvalError for undecodable text, a CSV syntax
    error, or a row whose field count differs from the header (DictReader would give a ``None`` key or value)."""
    try:
        rows = tuple(dict(r) for r in csv.DictReader(io.StringIO(data.decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise EvalError(f"refused: stitch file {name} is not readable CSV ({exc})") from None
    for i, r in enumerate(rows, start=1):
        if None in r or any(v is None for v in r.values()):
            raise EvalError(f"refused: stitch file {name} data row {i} has a field count that differs from the "
                            f"header")
    return rows


def _expected_sha(run_info: Mapping[str, Any], name: str) -> str:
    """The SHA-256 the stitch ``run_info.json`` records for ``name``; EvalError when it records none."""
    try:
        sha = run_info["files"][name]["sha256"]
    except (KeyError, TypeError):
        raise EvalError(f"refused: stitch run_info.json records no SHA-256 for {name}") from None
    if not isinstance(sha, str):
        raise EvalError(f"refused: stitch run_info.json SHA-256 of {name} is not text")
    return sha


def load_stitch(stitch_dir: Path) -> StitchData:
    """Read and check the ten stitch files of one trial (spec 03 section 3; 051 item 2).

    Every file must exist; every file other than ``run_info.json`` must have the SHA-256 that ``run_info.json``
    records for it. WHY the hash check: the stitcher writes ``run_info.json`` last with the hash of every file,
    so a file edited or regenerated afterwards (a different stitch run) is caught before it is evaluated.
    """
    d = Path(stitch_dir)
    missing = [n for n in STITCH_FILES if not (d / n).is_file()]
    if missing:
        raise EvalError(f"refused: stitch file(s) missing in {d.as_posix()}: {', '.join(missing)}")
    raw = {n: (d / n).read_bytes() for n in STITCH_FILES}
    try:
        run_info = json.loads(raw[STITCH_RUN_INFO].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvalError(f"refused: stitch run_info.json is not JSON ({exc})") from None
    if not isinstance(run_info, dict) or not isinstance(run_info.get("files"), dict):
        raise EvalError("refused: stitch run_info.json is not an object with a files map")
    shas = {n: sha256_bytes(b) for n, b in raw.items()}
    for name in STITCH_FILES:
        if name == STITCH_RUN_INFO:
            continue
        if shas[name] != _expected_sha(run_info, name):
            raise EvalError(f"refused: stitch file {name} SHA-256 {shas[name]} differs from run_info.json")
    try:
        stats = json.loads(raw["stats.json"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvalError(f"refused: stitch stats.json is not JSON ({exc})") from None
    csvs = {n: _parse_csv(n, raw[n]) for n in STITCH_FILES if n.endswith(".csv")}
    validate_stitch_rows(csvs["hops.csv"], csvs["links.csv"], csvs["hop_identity.csv"])
    return StitchData(stitch_dir=d, file_sha256=dict(sorted(shas.items())), hops=csvs["hops.csv"],
                      links=csvs["links.csv"], hop_artefacts=csvs["hop_artefacts.csv"],
                      hop_identity=csvs["hop_identity.csv"], paths=csvs["paths.csv"],
                      path_edges=csvs["path_edges.csv"], path_nodes=csvs["path_nodes.csv"],
                      stats=stats, run_info=run_info)


# ---------------------------------------------------------------- stitch row contract (051 item 2, reading 10)

def _need_columns(name: str, header: Sequence[str] | None, columns: Sequence[str]) -> None:
    """Every column the evaluation reads must be in the file's header."""
    if header is None:
        return
    missing = [c for c in columns if c not in header]
    if missing:
        raise EvalError(f"refused: stitch file {name} lacks column(s) {', '.join(missing)}")


def _is_int(cell: str) -> bool:
    """True when the text is a (signed) decimal integer."""
    return _INT_RE.fullmatch(cell) is not None


def _bad(name: str, row_no: int, column: str, value: str, want: str) -> EvalError:
    """A refusal naming the file, data row, column and the expected form (values here are ids or numbers)."""
    return EvalError(f"refused: stitch file {name} data row {row_no}: {column} {value!r} is not {want}")


def _check_int_cells(name: str, i: int, row: Mapping[str, str], columns: Sequence[str]) -> None:
    """Integer-or-empty cells."""
    for c in columns:
        if row[c] != "" and not _is_int(row[c]):
            raise _bad(name, i, c, row[c], "an integer or empty")


def _check_hops(rows: Sequence[Mapping[str, str]]) -> None:
    """hops.csv: unique hop ids, a protocol of the ST-22 vocabulary, integer range counts, and parallel member
    lists with decimal logon IDs (the ST-25 match reads them pairwise)."""
    name = "hops.csv"
    _need_columns(name, list(rows[0]) if rows else None, _HOP_COLUMNS)
    seen: set[str] = set()
    for i, r in enumerate(rows, start=1):
        if r["hop_id"] == "" or r["hop_id"] in seen:
            raise _bad(name, i, "hop_id", r["hop_id"], "a unique non-empty id")
        seen.add(r["hop_id"])
        if r["protocol"] not in PROTOCOL_GROUPS:
            raise _bad(name, i, "protocol", r["protocol"],
                       "a protocol of the ST-22 vocabulary (" + ", ".join(PROTOCOL_GROUPS) + ")")
        _check_int_cells(name, i, r, ("evidence_before_range", "evidence_after_range"))
        uids = [x for x in r["member_logon_uids"].split(";") if x]
        ids = [x for x in r["member_logon_ids"].split(";") if x]
        if len(uids) != len(ids) or not all(_is_int(x) for x in ids):
            raise _bad(name, i, "member_logon_ids", r["member_logon_ids"],
                       "a list of decimal ids parallel to member_logon_uids")


def _check_links(rows: Sequence[Mapping[str, str]]) -> None:
    """links.csv: a session id is decimal or empty (it is compared as an integer)."""
    name = "links.csv"
    _need_columns(name, list(rows[0]) if rows else None, _LINK_COLUMNS)
    for i, r in enumerate(rows, start=1):
        _check_int_cells(name, i, r, ("source_session_id",))


def _check_identity(rows: Sequence[Mapping[str, str]]) -> None:
    """hop_identity.csv: integer gap and order flags where present, and a gap on every row the key rule can
    select (a dump row with ``order_ok`` = 1)."""
    name = "hop_identity.csv"
    _need_columns(name, list(rows[0]) if rows else None, _IDENTITY_COLUMNS)
    for i, r in enumerate(rows, start=1):
        _check_int_cells(name, i, r, ("gap_ms", "order_within_tolerance", "order_within_uncertainty"))
        if r["dump_event_uid"] and r["order_ok"] == "1" and r["gap_ms"] == "":
            raise _bad(name, i, "gap_ms", "", "set (a dump row with order_ok = 1 needs a gap)")


def validate_stitch_rows(hops: Sequence[Mapping[str, str]], links: Sequence[Mapping[str, str]],
                         identity: Sequence[Mapping[str, str]]) -> None:
    """Refuse stitch rows the evaluation cannot read, before any analysis (051 item 2; reading 10).

    WHY here and not in the pure modules: a value outside the spec 03 contract (an unknown protocol, a
    non-numeric logon ID) means the folder is not what the evaluation was written for. The run must stop with a
    refusal and write nothing, not crash halfway with a traceback. The pure modules keep their own ValueError as
    a last guard for callers that skip this check.
    """
    _check_hops(hops)
    _check_links(links)
    _check_identity(identity)


# ---------------------------------------------------------------- key and key lock (051 items 2, 9)

def key_path(repo: Path, trial: str) -> Path:
    """``ground_truth/approved/<trial>.yaml``: the only place a key is read from (drafts never, 051 item 2)."""
    return Path(repo) / APPROVED_KEYS_REL / f"{trial}.yaml"


def _read_lock_rows(manifest: Path) -> list[list[str]]:
    """The manifest's rows (header included) as lists of text; EvalError when it is missing or unreadable."""
    if not manifest.is_file():
        raise EvalError(f"refused: key lock manifest {manifest.as_posix()} is missing (decision 051 item 9)")
    try:
        text = manifest.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise EvalError(f"refused: key lock manifest unreadable ({exc})") from None
    try:
        return [r for r in csv.reader(io.StringIO(text, newline=""))]
    except csv.Error as exc:
        raise EvalError(f"refused: key lock manifest malformed ({exc})") from None


def check_key_lock(manifest: Path, trial: str, key_sha256: str) -> None:
    """Split = test only: the owner's manifest must lock this trial's key at exactly this SHA-256 (051 item 9).

    Refused when: the manifest is missing; its header is not exactly ``trial_id,key_path,sha256``; a row has
    another column count; the trial has no row or more than one; the row's sha256 is not 64 lower-case hex
    digits; or it differs from the key file's SHA-256. WHY: a test key edited after the owner locked it must not
    produce a test number. Reads the manifest only; never writes it.
    """
    rows = _read_lock_rows(Path(manifest))
    if not rows or tuple(rows[0]) != KEY_LOCK_HEADER:
        raise EvalError(f"refused: key lock manifest header must be exactly {','.join(KEY_LOCK_HEADER)}")
    body = rows[1:]
    if any(len(r) != len(KEY_LOCK_HEADER) for r in body):
        raise EvalError("refused: key lock manifest has a row with the wrong number of columns")
    mine = [r for r in body if r[0] == trial]
    if len(mine) != 1:
        raise EvalError(f"refused: key lock manifest has {len(mine)} rows for {trial} (exactly 1 required)")
    sha = mine[0][2]
    if not _SHA_RE.fullmatch(sha):
        raise EvalError(f"refused: key lock sha256 for {trial} is not 64 lower-case hex digits")
    if sha != key_sha256:
        raise EvalError(f"refused: key of {trial} has SHA-256 {key_sha256}, the key lock says {sha}")


def load_key(repo: Path, trial: str, split: str, key_lock_path: Path | None = None) -> KeyData | None:
    """The approved key of ``trial`` with path, SHA-256 and lock status; None for an unkeyed development trial.

    - The key is JSON text in a ``.yaml`` file (the answer-key writer's format) and is read as JSON.
    - Its ``trial_id`` must equal the trial (051 item 2).
    - split = test: a missing key is a refusal, and the key lock must hold (``check_key_lock``).
    - split = development: the manifest is neither required nor read; lock = ``not_required``.
    """
    if split not in (SPLIT_DEVELOPMENT, SPLIT_TEST):
        raise EvalError(f"refused: unknown split {split!r}")
    path = key_path(repo, trial)
    if not path.is_file():
        if split == SPLIT_TEST:
            raise EvalError(f"refused: no approved key for test trial {trial}")
        return None
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvalError(f"refused: approved key of {trial} is not readable JSON ({exc})") from None
    if not isinstance(data, dict) or data.get("trial_id") != trial:
        got = data.get("trial_id") if isinstance(data, dict) else None
        raise EvalError(f"refused: approved key trial_id {got!r} differs from the trial {trial}")
    validate_key_data(data)
    sha = sha256_bytes(raw)
    lock = "not_required"
    if split == SPLIT_TEST:
        manifest = Path(key_lock_path) if key_lock_path is not None else Path(repo) / KEY_LOCK_REL
        check_key_lock(manifest, trial, sha)
        lock = "locked"
    rel = (APPROVED_KEYS_REL / f"{trial}.yaml").as_posix()
    return KeyData(path_rel=rel, sha256=sha, lock=lock, data=data)


def _key_bad(where: str, what: str) -> EvalError:
    """A refusal for a key field the evaluation cannot read (no value text: keys hold command text)."""
    return EvalError(f"refused: approved key {where}: {what}")


def _is_hex(value: Any) -> bool:
    """A logon ID as the key writes it (``0x...`` text) or an integer."""
    if isinstance(value, int) and not isinstance(value, bool):
        return True
    return isinstance(value, str) and _HEX_RE.fullmatch(value.strip()) is not None


def _is_uid_list(value: Any) -> bool:
    """A list of uid strings."""
    return isinstance(value, list) and all(isinstance(u, str) for u in value)


def _is_iso_utc(value: Any) -> bool:
    """ISO-8601 text with a zone (what ``keys.iso_to_us`` accepts)."""
    if not isinstance(value, str):
        return False
    try:
        dt = datetime.fromisoformat(value.strip())
    except ValueError:
        return False
    return dt.tzinfo is not None and dt.utcoffset() is not None


def _check_key_hop(i: int, kh: Any) -> None:
    """One key hop: the fields the ST-25 match and the key-session reading parse (051 items 3, 4)."""
    where = f"hop {i}"
    if not isinstance(kh, dict):
        raise _key_bad(where, "not an object")
    if not _is_hex(kh.get("target_logon_id")):
        raise _key_bad(where, "target_logon_id is not a hex logon ID")
    if not _is_uid_list(kh.get("target_event_uids", [])):
        raise _key_bad(where, "target_event_uids is not a list of uids")
    if kh.get("agent_event_uids") is not None and not _is_uid_list(kh["agent_event_uids"]):
        raise _key_bad(where, "agent_event_uids is not a list of uids")
    if kh.get("source_session_logon_id") and not _is_hex(kh["source_session_logon_id"]):
        raise _key_bad(where, "source_session_logon_id is not a hex logon ID")
    se = kh.get("session_evidence")
    if se is not None:
        if not isinstance(se, dict):
            raise _key_bad(where, "session_evidence is not an object")
        if se.get("session_id") and not _is_hex(se["session_id"]):
            raise _key_bad(where, "session_evidence.session_id is not a hex logon ID")
        if se.get("command_event_uids") is not None and not _is_uid_list(se["command_event_uids"]):
            raise _key_bad(where, "session_evidence.command_event_uids is not a list of uids")
    ie = kh.get("identity_expected")
    if ie is not None and (isinstance(ie, bool) or ie not in (0, 1)):
        raise _key_bad(where, "identity_expected is not 0, 1 or null")


def validate_key_data(data: Mapping[str, Any]) -> None:
    """Refuse a key the evaluation cannot read, before any DB access (051 item 2 spirit; reading 10).

    WHY: a malformed key (a logon ID that is not hex, an event time with no zone) would otherwise stop the run
    halfway with a traceback; a refusal says which field and writes nothing. Values are not echoed, because key
    fields can hold command text.
    """
    hops = data.get("hops", [])
    if not isinstance(hops, list):
        raise _key_bad("hops", "not a list")
    ek = data.get("event_keys", {})
    if not isinstance(ek, dict):
        raise _key_bad("event_keys", "not an object")
    for i, kh in enumerate(hops, start=1):
        _check_key_hop(i, kh)
    for uid, e in ek.items():
        if not isinstance(e, dict):
            raise _key_bad(f"event_keys[{uid}]", "not an object")
        if "time_utc" in e and not _is_iso_utc(e["time_utc"]):
            raise _key_bad(f"event_keys[{uid}]", "time_utc is not ISO-8601 text with a zone")


# ---------------------------------------------------------------- DB (read-only)

def db_path(repo: Path, trial: str) -> Path:
    """``data/processed/<trial>.sqlite3``: the trial DB the stitcher read."""
    return Path(repo) / DB_REL / f"{trial}{DB_SUFFIX}"


def open_db_ro(path: Path) -> sqlite3.Connection:
    """Open a DB read-only (``mode=ro`` URI). WHY our own opener: 051 item 1 forbids importing the stitcher's,
    and ``mode=ro`` makes any write attempt fail instead of changing the DB."""
    p = Path(path)
    if not p.is_file():
        raise EvalError(f"refused: DB {p.as_posix()} is missing")
    try:
        return sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise EvalError(f"refused: DB {p.as_posix()} cannot be opened read-only ({exc})") from None


def check_db_hash(sha: str, stitch_run_info: Mapping[str, Any], key: KeyData | None) -> None:
    """The DB must be the one the stitcher read (``run_info.db.sha256_after``) and, if keyed, the one the key was
    built from (``db_sha256``) (051 item 2). Pure."""
    db = stitch_run_info.get("db")
    want = db.get("sha256_after") if isinstance(db, Mapping) else None
    if sha != want:
        raise EvalError(f"refused: DB SHA-256 {sha} differs from stitch run_info db.sha256_after {want}")
    if key is not None and sha != key.data.get("db_sha256"):
        raise EvalError(f"refused: DB SHA-256 {sha} differs from the key's db_sha256 {key.data.get('db_sha256')}")


def check_db_unchanged(before: str, after: str) -> None:
    """The DB must not change while it is read (051 item 2). Pure."""
    if before != after:
        raise EvalError(f"refused: DB SHA-256 changed during the run (before {before}, after {after})")


def _chunks(items: list[str]) -> Iterable[list[str]]:
    """Fixed-size slices, so an IN list never exceeds SQLite's parameter limit."""
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


def _rows(conn: sqlite3.Connection, query: str, params: Sequence[Any]) -> list[tuple]:
    """Run one read-only query; a SQLite error (no ``events_dedup`` view, a damaged file) is a refusal."""
    try:
        return conn.execute(query, list(params)).fetchall()
    except sqlite3.Error as exc:
        raise EvalError(f"refused: DB query failed ({exc})") from None


def _db_time(utc: Any, uid: Any) -> str:
    """A DB ``event_utc`` the evaluation can parse (ISO text with a zone); else a refusal naming the uid."""
    if not _is_iso_utc(utc):
        raise EvalError(f"refused: DB event {uid} has an unreadable event_utc")
    return str(utc)


def _db_int(value: Any, column: str, uid: Any) -> int:
    """A DB integer column (the view types it INTEGER); else a refusal naming the uid."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise EvalError(f"refused: DB event {uid} has a non-integer {column}")
    return value


def query_events(conn: sqlite3.Connection, uids: Iterable[str]) -> dict[str, EventRow]:
    """uid -> (host, channel, event_id, event_utc, session_id) from ``events_dedup``; absent uids are absent.

    WHY these columns only: outputs must hold no command text, so the command line and the field JSON are never
    even selected (051 item 8).
    """
    wanted = sorted({str(u) for u in uids if u})
    out: dict[str, EventRow] = {}
    for part in _chunks(wanted):
        q = (f"SELECT event_uid, host, channel, event_id, event_utc, session_id FROM {_VIEW} "
             f"WHERE event_uid IN ({','.join('?' * len(part))}) ORDER BY event_uid")
        for uid, host, channel, eid, utc, sid in _rows(conn, q, part):
            out.setdefault(uid, EventRow(uid, host, channel, _db_int(eid, "event_id", uid), _db_time(utc, uid),
                                         None if sid is None else _db_int(sid, "session_id", uid)))
    return out


def query_logons(conn: sqlite3.Connection, host: str, logon_id: int) -> list[LogonRow]:
    """Every Security 4624 of ``host`` that opens ``logon_id`` (``target_logon_id``), in logged-time order."""
    q = (f"SELECT event_uid, event_utc, target_logon_id FROM {_VIEW} WHERE host = ? AND channel = 'Security' "
         f"AND event_id = 4624 AND target_logon_id = ? ORDER BY event_utc, event_uid")
    return [LogonRow(u, _db_time(t, u), _db_int(lid, "target_logon_id", u))
            for u, t, lid in _rows(conn, q, (host, int(logon_id)))]


def query_boots(conn: sqlite3.Connection, host: str) -> list[BootRow]:
    """Every System boot / shutdown event of ``host`` (decision 047 item 3), in logged-time order."""
    ids = sorted(BOOT_STARTUP_IDS | BOOT_SHUTDOWN_IDS)
    q = (f"SELECT event_uid, event_id, event_utc FROM {_VIEW} WHERE host = ? AND channel = ? "
         f"AND event_id IN ({','.join('?' * len(ids))}) ORDER BY event_utc, event_uid")
    return [BootRow(u, _db_int(e, "event_id", u), _db_time(t, u))
            for u, e, t in _rows(conn, q, (host, BOOT_CHANNEL, *ids))]
