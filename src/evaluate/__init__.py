"""Link accuracy against the approved keys (PLAN T7.6; decision 051); the T10 evaluation stage folder.

Reads only the stitch output files, the approved key and the trial DB, read-only. It never imports ``stitch``,
and ``stitch`` never imports it (051 item 1), so no accuracy value can feed back into the linker.
Modules: ``params`` (constants), ``inputs`` (refusals, files, key lock, read-only DB), ``keys`` (ST-25 match and
key source session, pure), ``link_accuracy`` (verdicts, facts, totals, pure), ``writers`` (texts, folder swap),
``run`` (``evaluate_trial``: all reads and checks, then the texts; writes nothing), ``__main__`` (CLI).
"""
from __future__ import annotations

from .inputs import EvalError
from .run import TrialResult, evaluate_trial

__all__ = ["EvalError", "TrialResult", "evaluate_trial"]
