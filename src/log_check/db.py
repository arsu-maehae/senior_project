"""Read-only database access with SQL recording (LC-11).

Why a small wrapper: every check must store the SQL it ran, and the script must never
write to the trial DB. Opening with `mode=ro` makes writes impossible at the SQLite level;
the sha256 before/after comparison proves it to a reviewer.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence


def connect_ro(db_path: Path) -> sqlite3.Connection:
    """Open the trial DB read-only via a URI so an accidental write raises instead of landing."""
    uri = f"file:{db_path.resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def sha256_file(path: Path) -> str:
    """Hash of the DB file; compared before and after the run (LC-11)."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalise_sql(sql: str) -> str:
    """Strip common indentation so the stored SQL is readable in report.json."""
    lines = [line.rstrip() for line in sql.strip("\n").splitlines()]
    indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    cut = min(indents) if indents else 0
    return "\n".join(l[cut:] for l in lines).strip()


@dataclass
class Db:
    """Runs SQL, records the SQL text per check id, and caches identical queries.

    The cache lets several checks share one load (e.g. all 4624 rows) while each check
    still records the SQL it depends on, which is what LC-11 asks for.
    """

    conn: sqlite3.Connection
    sql_log: dict[str, list[str]] = field(default_factory=dict)
    _cache: dict[tuple[str, tuple], list[dict[str, Any]]] = field(default_factory=dict)

    def query(self, check_id: str, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        """Run `sql` (or reuse a cached result) and record it under `check_id`."""
        text = normalise_sql(sql)
        self.record(check_id, text)
        key = (text, tuple(params))
        if key not in self._cache:
            self._cache[key] = [dict(row) for row in self.conn.execute(text, tuple(params))]
        return self._cache[key]

    def record(self, check_id: str, sql: str) -> None:
        """Store SQL text once per check (parameters are shown as `?`)."""
        bucket = self.sql_log.setdefault(check_id, [])
        if sql not in bucket:
            bucket.append(sql)

    def share(self, check_id: str, *source_ids: str) -> None:
        """Copy the SQL of checks whose results `check_id` reuses (derived checks such as LC-04d)."""
        for source in source_ids:
            for sql in self.sql_log.get(source, []):
                self.record(check_id, sql)


def in_list(values: Iterable[Any]) -> str:
    """`(?, ?, ?)` placeholder list for an IN clause; parameters are passed separately."""
    items = list(values)
    return "(" + ", ".join("?" for _ in items) + ")" if items else "(NULL)"
