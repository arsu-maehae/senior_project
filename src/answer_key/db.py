"""Read-only trial-DB opener shared by the key builder and verify.py (AK-06, AK-14).

WHY a private opener: the answer key must not reuse any parser or stitcher join
helper, and it must provably never write to a DB. The connection is opened with
``mode=ro`` and the SHA-256 of the file is taken before and after use.
"""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

VIEW = "events_dedup"


def sha256_file(path: Path) -> str:
    """Hash a file in chunks; used to prove the DB was not modified."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def open_ro(path: Path) -> sqlite3.Connection:
    """Open the DB read-only with dict-like rows (``mode=ro`` is enforced by SQLite)."""
    uri = "file:" + Path(path).resolve().as_posix() + "?mode=ro"
    con = sqlite3.connect(uri, uri=True)
    con.row_factory = sqlite3.Row
    return con


def query(con: sqlite3.Connection, where: str = "1=1", params: Sequence = ()) -> list[sqlite3.Row]:
    """Select rows from ``events_dedup`` only (never ``events``), ordered by event time."""
    sql = (f"SELECT *, COALESCE(event_utc, timestamp_utc) AS t_utc FROM {VIEW} "
           f"WHERE {where} ORDER BY t_utc, host, record_id")
    return con.execute(sql, tuple(params)).fetchall()


def load_events(con: sqlite3.Connection) -> list[dict]:
    """All ``events_dedup`` rows as dicts, with ``t_utc`` (event time) and ``ts`` (epoch s).

    WHY: one pass over the view, then pure-Python indexing; the time used is
    ``event_utc`` (Sysmon UtcTime, decision 010) falling back to the record time.
    """
    from .timeutil import parse_utc
    out: list[dict] = []
    for r in query(con):
        d = dict(r)
        d["ts"] = parse_utc(d["t_utc"]).timestamp() if d["t_utc"] else 0.0
        out.append(d)
    return out


@contextmanager
def guarded(path: Path) -> Iterator[tuple[sqlite3.Connection, str]]:
    """Yield (connection, sha256-before) and assert the hash is unchanged on exit (AK-14)."""
    before = sha256_file(path)
    con = open_ro(path)
    try:
        yield con, before
    finally:
        con.close()
        after = sha256_file(path)
        if after != before:  # pragma: no cover - would mean a bug elsewhere
            raise RuntimeError(f"DB changed while open: {path}")
