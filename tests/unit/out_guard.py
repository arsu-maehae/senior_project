"""The `out/` guard (T7.7, decision 054): the test suite must not write anywhere under `out/`.

`out/` holds pipeline outputs that other stages read with recorded hashes (evaluate records the SHA-256 of each
`out/stitch/<trial>/run_info.json`), so a test that rewrites a file there, even with the same bytes, leaves the
recorded state stale or hides which run produced it. Real-data tests write to tmp folders instead (`--out`).

The root `conftest.py` takes a `snapshot` of `out/` when the session starts and again when it ends, and fails the
session with `report(diff(...))` if anything was added, removed, changed or rewritten. Pure functions apart from the
reads of `snapshot`; messages carry relative paths only, never file contents.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

__all__ = ["DIR_MARK", "Entry", "OutDiff", "snapshot", "diff", "report"]

DIR_MARK = "<dir>"


@dataclass(frozen=True)
class Entry:
    """One path under the root: a folder (`sha256` = DIR_MARK, `mtime_ns` = 0) or a file with its content hash and
    modification time. WHY the time as well as the hash: a rewrite with identical bytes is still a write."""
    sha256: str
    mtime_ns: int


@dataclass(frozen=True)
class OutDiff:
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    rewritten: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed or self.rewritten)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root: Path) -> dict[str, Entry]:
    """Every folder and file under `root` by POSIX relative path (empty for a missing root). Folder times are not
    kept: they change whenever an entry changes, which the entries themselves already show."""
    root = Path(root)
    out: dict[str, Entry] = {}
    if not root.is_dir():
        return out
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_dir():
            out[rel] = Entry(DIR_MARK, 0)
        elif p.is_file():
            out[rel] = Entry(_sha256(p), p.stat().st_mtime_ns)
    return out


def diff(before: dict[str, Entry], after: dict[str, Entry]) -> OutDiff:
    """What changed between two snapshots, each list sorted. `changed` = other content (or a file became a folder);
    `rewritten` = same content, new modification time."""
    added = tuple(sorted(set(after) - set(before)))
    removed = tuple(sorted(set(before) - set(after)))
    common = sorted(set(before) & set(after))
    changed = tuple(k for k in common if before[k].sha256 != after[k].sha256)
    rewritten = tuple(k for k in common if before[k].sha256 == after[k].sha256 and before[k].mtime_ns != after[k].mtime_ns)
    return OutDiff(added, removed, changed, rewritten)


def report(d: OutDiff, root_name: str = "out", limit: int = 40) -> str:
    """A readable failure text: counts per kind, then up to `limit` paths per kind (relative to `root_name`)."""
    lines = [f"the test session wrote under {root_name}/ (decision 054: tests write to tmp folders only):"]
    for kind in ("added", "removed", "changed", "rewritten"):
        paths = getattr(d, kind)
        if paths:
            lines.append(f"  {kind}: {len(paths)}")
            lines.extend(f"    {root_name}/{p}" for p in paths[:limit])
            if len(paths) > limit:
                lines.append(f"    ... {len(paths) - limit} more")
    return "\n".join(lines)
