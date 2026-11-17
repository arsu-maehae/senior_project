"""The one exception of the score stage (spec 05_score sections 2 and 4: SC-01, SC-02, SC-10, SC-60).

WHY a module of its own: the pure modules (``order``, ``nodes``, ``identity``) and the file-reading module
(``inputs``) all raise it, and a pure module must not import file-reading code to get the type.
"""
from __future__ import annotations

__all__ = ["ScoreError"]


class ScoreError(Exception):
    """Refusal or input error that stops the scorer before anything is written.

    WHY one type: the CLI maps it to ``refused: <reason>`` and exit code 2 (SC-60), and a test can assert that nothing
    was written whatever the cause (allowlist, stale label run, missing column, order table hash).
    """
