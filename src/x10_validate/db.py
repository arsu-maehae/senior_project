"""Read-only access to one trial DB (view ``events_dedup`` only).

WHY its own opener: the validator must not import the answer-key or log-check DB helpers
(decision 029, independence), and it must never be able to write to ``data/`` (mode=ro URI).
"""
from __future__ import annotations

import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path

COLUMNS: tuple[str, ...] = (
    "event_uid", "host", "channel", "event_id", "event_utc", "record_id", "account_name", "subject_account",
    "session_id", "subject_logon_id", "target_logon_id", "logon_guid", "logon_type", "authentication_package",
    "source_ip", "source_port", "image", "parent_image", "process_guid", "parent_process_guid", "process_id",
    "parent_process_id", "command_line", "destination_ip", "destination_port", "source_image", "target_image",
    "granted_access", "service_name", "service_image_path", "share_name", "relative_target_name",
    "field_values_json",
)

# Only the event types any criterion reads; everything else is never loaded.
_WHERE = (
    "(channel = 'Sysmon' AND event_id IN (1, 3, 10)) OR "
    "(channel = 'Security' AND event_id IN (4624, 4688, 4697, 5145, 4769)) OR "
    "(channel = 'System' AND event_id = 7045) OR "
    "(channel = 'WinRM' AND event_id = 91)"
)


def open_ro(path: Path) -> sqlite3.Connection:
    """Open a DB read-only through a ``file:...?mode=ro`` URI so no write can reach ``data/``."""
    if not path.is_file():
        raise FileNotFoundError(path)
    con = sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def parse_ts(text: str | None) -> float | None:
    """ISO UTC text (``...Z``) to epoch seconds; None stays None."""
    if not text:
        return None
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def iso(ts: float | None) -> str | None:
    """Epoch seconds back to ISO UTC with milliseconds, for evidence."""
    if ts is None:
        return None
    from datetime import timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def load_rows(con: sqlite3.Connection) -> list[dict]:
    """All rows the criteria need, as dicts with an added epoch ``ts``; rows without a time are dropped."""
    sql = f"SELECT {', '.join(COLUMNS)} FROM events_dedup WHERE {_WHERE}"
    out: list[dict] = []
    for row in con.execute(sql):
        rec = dict(row)
        rec["ts"] = parse_ts(rec["event_utc"])
        if rec["ts"] is not None:
            out.append(rec)
    return out


def host_channel_counts(con: sqlite3.Connection) -> dict[str, dict[str, int]]:
    """Row counts per host and lower-case channel (evidence for a; basis of a for t00)."""
    out: dict[str, dict[str, int]] = {}
    for host, channel, n in con.execute("SELECT host, channel, COUNT(*) FROM events_dedup GROUP BY host, channel"):
        out.setdefault(str(host), {})[str(channel).lower()] = int(n)
    return out


def db_span(con: sqlite3.Connection) -> tuple[str | None, str | None]:
    """First and last event time in the DB (the run is the last anchor cluster before the last event)."""
    lo, hi = con.execute("SELECT MIN(event_utc), MAX(event_utc) FROM events_dedup").fetchone()
    return lo, hi


def sha256_file(path: Path) -> str:
    """Hash of the DB file, so a validation result names exactly the bytes it was computed on."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
