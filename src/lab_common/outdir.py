"""Checks on an output folder given with ``--out`` (decision 054), shared by ``python -m stitch``, the stitch check
CLIs and ``python -m evaluate``.

WHY here: stitch and evaluate must never import each other (decision 051 item 1), and both CLIs rebuild their folder
by swapping a new folder in and deleting the old one, so a wrong ``--out`` would delete whatever was there. These pure
functions return a refusal reason (or None); each CLI raises its own error type. Two cases are refused before
anything is written: a target inside the repository but not strictly below its ``out/`` folder (the only repo folder
the pipeline writes, CLAUDE.md data rules), and, for a folder that is replaced whole, an existing target holding
anything the CLI would not write itself. The only disk access is ``exists`` / ``is_dir`` / ``iterdir`` on the target.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

__all__ = ["OUT_REL", "protected_reason", "foreign_entries", "out_target_refusal"]

# The one repo folder a pipeline CLI may write below. A target outside the repository (a test's tmp folder) is free.
OUT_REL = "out"


def _inside(path: Path, folder: Path) -> bool:
    """True when ``path`` is ``folder`` or lies below it (both resolved by the caller)."""
    return path == folder or folder in path.parents


def protected_reason(target: Path, repo: Path) -> str | None:
    """Why ``target`` may not be written, else None: inside the repository it must lie strictly below ``out/``
    (not ``out/`` itself, not the root, not any other folder). Both paths are resolved first, so ``..`` and
    symlinked or junction spellings cannot slip past."""
    t, r = Path(target).resolve(), Path(repo).resolve()
    if not _inside(t, r):
        return None
    if (r / OUT_REL) in t.parents:
        return None
    return f"--out lies inside the repository but not below {OUT_REL}/, the only repo folder the pipeline writes"


def foreign_entries(target: Path, allowed: Iterable[str]) -> list[str]:
    """Names in an existing folder ``target`` that are not in ``allowed`` (sub-folders always count), sorted.
    Empty for a missing target. WHY: these are the entries a folder swap would delete."""
    t = Path(target)
    if not t.exists():
        return []
    names = set(allowed)
    return sorted(p.name for p in t.iterdir() if p.is_dir() or p.name not in names)


def out_target_refusal(target: Path, repo: Path, allowed: Iterable[str] | None) -> str | None:
    """The refusal reason for a ``--out`` target, or None when it may be written: protected (``protected_reason``),
    an existing file, or (when ``allowed`` is given, i.e. the folder is replaced whole) an existing folder holding
    entries outside ``allowed``. The text names at most three entries, never their content."""
    reason = protected_reason(target, repo)
    if reason:
        return reason
    t = Path(target)
    if t.exists() and not t.is_dir():
        return "--out names an existing file, not a folder"
    if allowed is not None:
        extra = foreign_entries(t, allowed)
        if extra:
            shown = ", ".join(extra[:3]) + (", ..." if len(extra) > 3 else "")
            noun = "entry" if len(extra) == 1 else "entries"
            return f"--out folder already holds {len(extra)} {noun} this CLI does not write ({shown}); it would be deleted"
    return None
