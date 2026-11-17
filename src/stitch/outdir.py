"""``--out`` checks for ``python -m stitch``, ``stitch.check_index`` and ``stitch.check_links`` (decision 054).

The rules live in ``lab_common.outdir`` (shared with ``python -m evaluate``, which may not import stitch, decision
051): inside the repository the target must lie strictly below ``out/``; an existing file is refused; a folder that is
replaced whole may hold only the names the CLI writes. This module turns a refusal reason into a StitchError. It is
called only after ST-00 has passed, so a refused trial still touches no file (decision 046).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from lab_common.outdir import OUT_REL, foreign_entries, out_target_refusal, protected_reason

from .errors import StitchError

__all__ = ["OUT_REL", "protected_reason", "foreign_entries", "check_out_target"]


def check_out_target(target: Path, repo: Path, allowed: Iterable[str] | None) -> None:
    """Raise StitchError (``refused: ...``) when ``lab_common.outdir.out_target_refusal`` refuses ``target``."""
    reason = out_target_refusal(target, repo, allowed)
    if reason:
        raise StitchError(f"refused: {reason}")
