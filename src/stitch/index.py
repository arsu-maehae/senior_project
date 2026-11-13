"""The T7.2 trial index: sessions (ST-10) and processes (ST-11) of one trial, and its counts-only summary
(plan section 3 ``t72_index.json`` keys).

WHY counts only: the summary is a development check that a reviewer reads; it carries no account names, no
images and no command text (spec 00 LC-13), so it can be shared and byte-compared between runs. Pure: the
caller (``check_index``, task 5) supplies the file-level facts (DB path and hashes, window row, parameters)
through ``extra``.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Mapping

from .params import TOOL_VERSION, StitchParams
from .processes import ProcessIndex, build_processes
from .scan import ScanResult
from .sessions import SessionIndex, build_sessions

__all__ = ["TrialIndex", "build_index", "index_counts", "scan_counts", "params_dict", "jsonable"]


@dataclass
class TrialIndex:
    """Sessions, processes and the scan's counts of one trial (in memory; T7.3+ read it)."""
    trial_id: str
    sessions: SessionIndex
    processes: ProcessIndex
    scan_counts: dict[str, Any]


def _clock_unreliable_events(scan: ScanResult) -> dict[str, int]:
    """Host -> in-window kept rows flagged ``clock_unreliable`` (ST-02); hosts with none are omitted."""
    out: dict[str, int] = {}
    for r in scan.in_window:
        if r.get("clock_unreliable"):
            h = str(r.get("host"))
            out[h] = out.get(h, 0) + 1
    return dict(sorted(out.items()))


def scan_counts(scan: ScanResult) -> dict[str, Any]:
    """The ``events`` block (plan section 3) plus ``clock_unreliable_events``, taken from one scan."""
    return {
        "loaded": scan.loaded_total,
        "kept_in_window": len(scan.in_window),
        "kept_lookback": len(scan.lookback),
        "kept_lookback_by_type": dict(scan.kept_lookback_by_type),
        "removed_by_window": {h: dict(c) for h, c in scan.removed_by_window.items()},
        "near_duplicate_groups": scan.near_duplicate_groups,
        "near_duplicate_split_by_window": scan.near_duplicate_split_by_window,
        "clock_unreliable_events": _clock_unreliable_events(scan),
    }


def build_index(trial_id: str, scan: ScanResult, params: StitchParams = StitchParams()) -> TrialIndex:
    """Sessions from ``scan.in_window + scan.lookback`` (identity may need pre-window opens, ST-63), then
    processes from the in-window rows only (ST-01, Q13b); processes add referenced and unknown-open sessions."""
    sessions = build_sessions(scan.in_window + scan.lookback, params)
    processes = build_processes(scan.in_window, sessions, params)
    return TrialIndex(trial_id=trial_id, sessions=sessions, processes=processes, scan_counts=scan_counts(scan))


def params_dict(params: StitchParams) -> dict[str, Any]:
    """Parameters as JSON-ready values (sets sorted, tuples as lists, mappings as sorted dicts)."""
    return {f.name: jsonable(getattr(params, f.name)) for f in fields(params)}


def jsonable(value: Any) -> Any:
    """Recursively JSON-ready with sorted keys: mappings -> dicts with str keys, sets sorted, tuples as lists.

    WHY sorted: the check file must be byte-identical between two runs on the same inputs.
    """
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (set, frozenset)):
        return [jsonable(v) for v in sorted(value)]
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    return value


def index_counts(index: TrialIndex, extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The plan section 3 ``t72_index.json`` structure: ``extra`` (``db``, ``gate_stats_sha256``, ``window_row``,
    ``parameters``, supplied by the caller) plus ``trial_id``, ``tool_version``, ``events``, ``sessions``,
    ``processes``, ``attached`` and ``clock_unreliable_events``. Counts only; JSON-ready, keys sorted."""
    sc = dict(index.scan_counts)
    clock = sc.pop("clock_unreliable_events", {})
    proc = dict(index.processes.counts)
    attached = proc.pop("attached", {})
    out: dict[str, Any] = dict(extra or {})
    out.update({
        "trial_id": index.trial_id,
        "tool_version": TOOL_VERSION,
        "events": sc,
        "sessions": index.sessions.counts,
        "processes": proc,
        "attached": attached,
        "clock_unreliable_events": clock,
    })
    return jsonable(out)
