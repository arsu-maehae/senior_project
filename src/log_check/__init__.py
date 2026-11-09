"""T4 log check (spec docs/specs/00_log_check.md): read-only measurement of the linking and
identity evidence in one trial DB, plus a provisional anchor-derived window."""

from .params import DEFAULT_PARAMS, Params
from .runner import LogCheckError, run_log_check

__all__ = ["DEFAULT_PARAMS", "LogCheckError", "Params", "run_log_check"]
