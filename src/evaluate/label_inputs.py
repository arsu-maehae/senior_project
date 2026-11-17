"""Inputs of the labelling recall (PLAN T8.3): the label stage files and the two share facts of the key's SMB events.

WHY refusals like ``inputs``: a recall number is only meaningful for exactly the label output, key and DB it names.
``event_labels.csv`` must have the SHA-256 that the label ``run_info.json`` records, and the DB must be the one the
label stage read and the key was built from. Anything else stops the run before a file is written. Nothing here
imports ``label``; the label stage never imports ``evaluate`` (it must not read keys, spec 04 §2).
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .inputs import EvalError, KeyData, sha256_bytes
from .label_recall import ShareFacts

__all__ = ["LabelData", "LABEL_EVENTS_FILE", "LABEL_RUN_INFO", "LABEL_COLUMNS", "load_labels", "check_label_db",
           "query_share_facts"]

LABEL_EVENTS_FILE = "event_labels.csv"
LABEL_RUN_INFO = "run_info.json"
# The event_labels.csv columns the recall reads (spec 04 §3.4).
LABEL_COLUMNS: tuple[str, ...] = ("trial_id", "event_uid", "dup_uids", "rule_id", "technique", "techniques")
_VIEW = "events_dedup"
_CHUNK = 500  # SQLite's default bound-parameter limit is 999.


@dataclass(frozen=True)
class LabelData:
    """``event_labels.csv`` of one trial (rows as written) with the hashes that pin it."""
    label_dir: Path
    rows: tuple[Mapping[str, str], ...]
    event_labels_sha256: str
    run_info_sha256: str
    db_sha256_after: str


def _read(path: Path, what: str) -> bytes:
    """File bytes; EvalError when the file is missing."""
    if not path.is_file():
        raise EvalError(f"refused: label {what} {path.as_posix()} is missing")
    return path.read_bytes()


def _run_info(raw: bytes) -> dict[str, Any]:
    """The label ``run_info.json`` as a dict; EvalError when it is not a JSON object."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvalError(f"refused: label run_info.json is not JSON ({exc})") from None
    if not isinstance(data, dict):
        raise EvalError("refused: label run_info.json is not an object")
    return data


def _recorded(info: Mapping[str, Any], *path: str) -> str:
    """A text value at ``path`` in the label run_info; EvalError when absent."""
    cur: Any = info
    for p in path:
        cur = cur.get(p) if isinstance(cur, Mapping) else None
    if not isinstance(cur, str) or not cur:
        raise EvalError(f"refused: label run_info.json records no {'.'.join(path)}")
    return cur


def _parse_rows(data: bytes, trial: str) -> tuple[dict[str, str], ...]:
    """event_labels.csv bytes to row dicts; EvalError on bad text, a missing column, a ragged row or a row of
    another trial."""
    try:
        reader = csv.DictReader(io.StringIO(data.decode("utf-8"), newline=""))
        rows = tuple(dict(r) for r in reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise EvalError(f"refused: label {LABEL_EVENTS_FILE} is not readable CSV ({exc})") from None
    missing = [c for c in LABEL_COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        raise EvalError(f"refused: label {LABEL_EVENTS_FILE} lacks column(s) {', '.join(missing)}")
    for i, r in enumerate(rows, start=1):
        if None in r or any(v is None for v in r.values()):
            raise EvalError(f"refused: label {LABEL_EVENTS_FILE} data row {i} has a field count that differs "
                            "from the header")
        if r["trial_id"] != trial or not r["event_uid"] or not r["rule_id"]:
            raise EvalError(f"refused: label {LABEL_EVENTS_FILE} data row {i} is not a label row of {trial}")
    return rows


def load_labels(label_dir: Path, trial: str) -> LabelData:
    """Read and check ``event_labels.csv`` of one trial against its label ``run_info.json`` (trial id, file hash)."""
    d = Path(label_dir)
    raw_info = _read(d / LABEL_RUN_INFO, LABEL_RUN_INFO)
    raw_events = _read(d / LABEL_EVENTS_FILE, LABEL_EVENTS_FILE)
    info = _run_info(raw_info)
    if info.get("trial_id") != trial:
        raise EvalError(f"refused: label run_info.json trial_id {info.get('trial_id')!r} differs from the trial "
                        f"{trial}")
    sha = sha256_bytes(raw_events)
    want = _recorded(info, "files", LABEL_EVENTS_FILE, "sha256")
    if sha != want:
        raise EvalError(f"refused: label {LABEL_EVENTS_FILE} SHA-256 {sha} differs from its run_info.json")
    return LabelData(label_dir=d, rows=_parse_rows(raw_events, trial), event_labels_sha256=sha,
                     run_info_sha256=sha256_bytes(raw_info), db_sha256_after=_recorded(info, "db", "sha256_after"))


def check_label_db(sha: str, labels: LabelData, key: KeyData | None) -> None:
    """The DB must be the one the label stage read and, if keyed, the one the key was built from. Pure."""
    if sha != labels.db_sha256_after:
        raise EvalError(f"refused: DB SHA-256 {sha} differs from label run_info db.sha256_after "
                        f"{labels.db_sha256_after}")
    if key is not None and sha != key.data.get("db_sha256"):
        raise EvalError(f"refused: DB SHA-256 {sha} differs from the key's db_sha256 {key.data.get('db_sha256')}")


def _chunks(items: list[str]) -> Iterable[list[str]]:
    """Fixed-size slices for IN lists."""
    for i in range(0, len(items), _CHUNK):
        yield items[i:i + _CHUNK]


def query_share_facts(conn: sqlite3.Connection, uids: Iterable[str]) -> dict[str, ShareFacts]:
    """uid -> ShareFacts (``share_name``, ``relative_target_name``) from ``events_dedup`` for the key's SMB
    5140 / 5145 uids.

    WHY these two columns only: they name a share and a file, never command text, and no SQL in ``src/evaluate``
    names the field JSON (test ``test_src_evaluate_never_selects_command_text_or_field_json``, guarding decision 051
    item 8). A key uid absent from the view is refused (EvalError, a count
    only): the key and the DB (whose hashes match) would disagree, and skipping it would silently drop a key event
    from the recall (as review ATK-24 for links).
    """
    wanted = sorted({u for u in uids if u})
    out: dict[str, ShareFacts] = {}
    for part in _chunks(wanted):
        q = (f"SELECT event_uid, share_name, relative_target_name FROM {_VIEW} "
             f"WHERE event_uid IN ({','.join('?' * len(part))}) AND event_id IN (5140, 5145) ORDER BY event_uid")
        try:
            got = conn.execute(q, part).fetchall()
        except sqlite3.Error as exc:
            raise EvalError(f"refused: DB query failed ({exc})") from None
        for uid, share, target in got:
            out.setdefault(uid, ShareFacts(share_name="" if share is None else str(share),
                                           target_name="" if target is None else str(target)))
    missing = len(set(wanted) - set(out))
    if missing:
        raise EvalError(f"refused: {missing} key 5140 / 5145 event(s) are not in the DB view {_VIEW}")
    return out
