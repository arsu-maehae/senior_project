"""The runner's own refusals: RT-01 allowlist, RT-08 repo shape, RT-02 upstream presence.

WHY these are the only checks the runner makes (RT-04): every stage keeps its own refusals, and a second copy of
them here could drift. The allowlist is needed here because gate has no allowlist and the t02-t10 DBs exist in
``data/processed/`` (RT-01); the presence check exists so that a missing input is answered with the exact command
that creates it, instead of a gate refusal half-way through (owner 2026-11-18).

Pure functions take the facts as arguments; ``presence_facts`` and ``window_trial_ids`` are the only readers.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from . import params as p

__all__ = ["allowlist_refusal", "is_under", "repo_refusal", "PresenceFacts", "presence_facts", "window_trial_ids",
           "presence_problems", "create_commands", "presence_refusal"]


def allowlist_refusal(trial: str, allowed: Sequence[str] = p.DEVELOPMENT_TRIALS) -> str | None:
    """RT-01: the refusal text for a trial not in ``DEVELOPMENT_TRIALS``, else None. Pure: decided on the id alone,
    so it runs before any file of the trial is opened and before any folder is created."""
    if trial in allowed:
        return None
    return (f"refused: trial {trial!r} is not in the development allowlist "
            f"(clock_offset.params.DEVELOPMENT_TRIALS; decisions 019, 046; spec 06 RT-01); "
            f"no file of it was opened and no stage was started")


def is_under(path: Path | str, root: Path | str) -> bool:
    """True iff ``path`` equals or lies under ``root`` after ``os.path.realpath`` (links and junctions resolved;
    case-insensitive on Windows via ``normcase``)."""
    a = os.path.normcase(os.path.realpath(path))
    b = os.path.normcase(os.path.realpath(root))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def repo_refusal(repo: Path, real_repo: Path = p.REPO) -> str | None:
    """RT-08: ``--repo`` must be an existing directory holding ``data/`` and ``out/``; refusal text or None.

    ATK-EV-25: a ``--repo`` other than the real repository is refused when the realpath of its ``out/`` or
    ``data/`` lies inside the real repository (a folder below it, or a link / junction into it), because the stages
    would then write the committed ``out/`` or read the real ``data/`` while the caller believes it is isolated."""
    r = Path(repo)
    if not r.is_dir():
        return f"refused: --repo {r.as_posix()} is not an existing directory (RT-08)"
    missing = [d for d in ("data", "out") if not (r / d).is_dir()]
    if missing:
        return f"refused: --repo {r.as_posix()} has no {' and no '.join(m + '/' for m in missing)} folder (RT-08)"
    if is_under(r, real_repo) and is_under(real_repo, r):
        return None                                # the real repository itself
    inside = [d for d in ("out", "data") if is_under(r / d, real_repo)]
    if inside:
        return (f"refused: --repo {r.as_posix()} is not the real repository, but its "
                f"{' and '.join(d + '/' for d in inside)} resolves inside it (RT-08, ATK-EV-25)")
    return None


@dataclass(frozen=True)
class PresenceFacts:
    """What RT-02 looks at, read once: which input files exist and the trial ids in ``trial_windows.csv``
    (one entry per row, so duplicates stay visible; None when the file is missing)."""
    db: bool
    offsets: bool
    changes: bool
    window_ids: tuple[str, ...] | None


def window_trial_ids(windows_csv: Path) -> tuple[str, ...] | None:
    """The ``trial_id`` of every row of ``trial_windows.csv`` in file order, or None if the file is missing.
    Presence only: no other column is read (hashes and consistency stay in gate, RT-02)."""
    path = Path(windows_csv)
    if not path.is_file():
        return None
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return tuple((r.get("trial_id") or "").strip() for r in csv.DictReader(fh))


def presence_facts(repo: Path, trial: str) -> PresenceFacts:
    """Stat the trial's DB and clock files and read the window file's trial ids. Never opens the DB (RT-02:
    presence only). Only called after RT-01 accepted the trial."""
    proc = Path(repo) / p.PROCESSED_REL
    return PresenceFacts(db=(proc / f"{trial}{p.DB_SUFFIX}").is_file(),
                         offsets=(proc / f"{trial}{p.OFFSETS_SUFFIX}").is_file(),
                         changes=(proc / f"{trial}{p.CHANGES_SUFFIX}").is_file(),
                         window_ids=window_trial_ids(Path(repo) / p.WINDOWS_REL))


def presence_problems(trial: str, facts: PresenceFacts) -> list[str]:
    """Human-readable list of what RT-02 found missing (empty = all present). Pure."""
    proc = p.PROCESSED_REL.as_posix()
    out: list[str] = []
    if not facts.db:
        out.append(f"{proc}/{trial}{p.DB_SUFFIX} is missing")
    if not facts.offsets:
        out.append(f"{proc}/{trial}{p.OFFSETS_SUFFIX} is missing")
    if not facts.changes:
        out.append(f"{proc}/{trial}{p.CHANGES_SUFFIX} is missing")
    if facts.window_ids is None:
        out.append(f"{p.WINDOWS_REL.as_posix()} is missing")
    else:
        n = facts.window_ids.count(trial)
        if n != 1:
            out.append(f"{p.WINDOWS_REL.as_posix()} has {n} rows for {trial} (exactly one needed)")
    return out


def create_commands(trial: str, facts: PresenceFacts) -> list[str]:
    """RT-02: the exact commands that create what is missing, in the order they must run (DB -> clock files ->
    window row). Pure.

    WHY the trial_window list holds every id already in the file: ``trial_window`` rewrites the whole
    ``data/trial_windows.csv``, so a command naming only the new trial would drop every other row. S01 rows take
    their window from ``data/operator_times.csv`` (trial_window's default ``--operator-times``), hence the note.
    """
    cmds: list[str] = []
    if not facts.db:
        cmds.append(f"python -m data_layout.batch --only {trial}")
    if not facts.offsets or not facts.changes:
        cmds.append(f"python -m clock_offset --trials {trial}")
    ids = facts.window_ids
    if ids is None or ids.count(trial) != 1:
        wanted = sorted({i for i in (ids or ()) if i} | {trial})
        cmd = f"python -m trial_window --trials {' '.join(wanted)}"
        if any(i.lower().startswith("s01_") for i in wanted):
            cmd += "  (S01 windows come from data/operator_times.csv, trial_window's default --operator-times)"
        cmds.append(cmd + "  # rewrites the whole data/trial_windows.csv; the list keeps every existing row")
    return cmds


def presence_refusal(trial: str, facts: PresenceFacts) -> str | None:
    """RT-02 refusal text (problems, then the create commands), or None when everything is present. Pure."""
    problems = presence_problems(trial, facts)
    if not problems:
        return None
    lines = [f"refused: upstream inputs of {trial} are not all present (spec 06 RT-02); no stage was started:"]
    lines += [f"  - {x}" for x in problems]
    lines.append("create them with (run from the repository root, add --repo <R> for another repo):")
    lines += [f"  {c}" for c in create_commands(trial, facts)]
    return "\n".join(lines)
