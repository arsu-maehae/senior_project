"""The one exception of the labeller (spec 04_label section 2: refused inputs).

WHY a module of its own: the pure modules (``matcher``, ``rules``) and the file-reading module (``inputs``) all raise
it, and a pure module must not import file-reading code to get the type.
"""
from __future__ import annotations

__all__ = ["LabelError"]


class LabelError(Exception):
    """Refusal or input error that stops the labeller before anything is written (spec 2, LB-00, LB-10).

    WHY one type: the CLI maps it to exit code 2 with the reason, and a test can assert that nothing was written
    whatever the cause (allowlist, missing stitch file, hash mismatch, a rule outside the Sigma subset).
    """
