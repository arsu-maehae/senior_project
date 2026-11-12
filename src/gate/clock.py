"""Clock context of one gate run: corrected-time text, row-level ``clock_unreliable`` and the stats ``clock`` key
(spec 02_gate sections 3 and 3.1 as amended in T6b.2, decision 043; spec 08 CO-09, CO-15).

WHY a module of its own: every output file (triggers, unmatched, dispositions, supporting) carries the same
four clock cells, and they must be computed one way. The corrected time and the event-level unreliability come
from the one shared implementation in ``clock_offset.correct`` (CO-09); nothing here re-implements them.
Everything is pure: the files were read by ``gate.inputs``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from clock_offset.correct import ClockChanges, Offsets, event_unreliable, is_unreliable

from .timeutil import fmt_us


@dataclass(frozen=True)
class ClockContext:
    """What the outputs need about the trial's clocks.

    ``clock_flag`` / ``clock_change_in_window`` are copied from the window row (trial level, spec 3).
    ``edge_hosts`` are the window row's non-empty ``start_host`` / ``end_host``: the GT-01 clip compares every
    event with edges taken on those hosts' clocks. ``offsets_file`` / ``changes_file`` are display paths.
    """
    offsets: Offsets
    changes: ClockChanges
    offsets_file: str
    changes_file: str
    clock_flag: str
    clock_change_in_window: str
    edge_hosts: tuple[str, ...]

    @property
    def edge_unreliable(self) -> bool:
        """True when a window edge host is none/wide/stale/unknown: then every row's clip is in doubt (spec 3)."""
        return any(is_unreliable(h, self.offsets) for h in self.edge_hosts)


def context_from_row(window_row: Mapping[str, str], offsets: Offsets, changes: ClockChanges,
                     offsets_file: str, changes_file: str) -> ClockContext:
    """ClockContext from the trial's window row and its (hash-checked) clock files."""
    edges = tuple(h for h in (window_row.get("start_host", ""), window_row.get("end_host", "")) if h)
    return ClockContext(offsets, changes, offsets_file, changes_file, window_row.get("clock_flag", ""),
                        window_row.get("clock_change_in_window", ""), edges)


def corrected_text(ev: Mapping) -> str:
    """``event_utc_corrected`` cell: the event's corrected instant (``us``) as ``...ffffffZ`` text (CO-09)."""
    return fmt_us(ev["us"])


def event_is_unreliable(ev: Mapping, ctx: ClockContext) -> bool:
    """Event-level clock doubt (spec 08 CO-15 D5): host none/wide/stale/unknown, or logged before a counted
    clock change on its host. Judged on the RECORDED time ``us_raw``: the changes file is in recorded time."""
    return event_unreliable(str(ev["host"]), ev["us_raw"], ctx.offsets, ctx.changes)


def row_unreliable(events: Iterable[Mapping | None], ctx: ClockContext) -> int:
    """Row ``clock_unreliable`` (spec 3): 1 if any event of the row is unreliable or a window edge host is."""
    if ctx.edge_unreliable:
        return 1
    return int(any(event_is_unreliable(e, ctx) for e in events if e is not None))


def clock_cells(events: Iterable[Mapping | None], ctx: ClockContext) -> dict[str, Any]:
    """The three clock columns of an output row (``event_utc_corrected`` is added by the caller)."""
    return {"clock_flag": ctx.clock_flag, "clock_change_in_window": ctx.clock_change_in_window,
            "clock_unreliable": row_unreliable(events, ctx)}


def _count(rows: Sequence[Mapping]) -> int:
    """Rows with ``clock_unreliable`` = 1."""
    return sum(1 for r in rows if r.get("clock_unreliable") == 1)


def clock_stats(ctx: ClockContext, triggers: Sequence[Mapping], unmatched: Sequence[Mapping],
                dispositions: Sequence[Mapping], supporting: Sequence[Mapping]) -> dict[str, Any]:
    """The stats.json ``clock`` key, exactly as spec 3.1 lists it."""
    return {
        "offsets_file": ctx.offsets_file, "offsets_sha256": ctx.offsets.file_sha256,
        "clock_changes_file": ctx.changes_file, "clock_changes_sha256": ctx.changes.file_sha256,
        "clock_flag": ctx.clock_flag, "clock_change_in_window": ctx.clock_change_in_window,
        "offsets": {h: {"offset_ms": o.offset_ms, "offset_status": o.status, "offset_unc_ms": o.offset_unc_ms}
                    for h, o in sorted(ctx.offsets.hosts.items())},
        "unreliable_rows": {"triggers": _count(triggers), "unmatched_remote": _count(unmatched),
                            "dispositions": _count(dispositions), "supporting": _count(supporting)},
    }
