"""Trial run window from design anchors (decision 029, criterion f; implementation note N1).

WHY: the endpoint logs were not cleared between trials (029, B1 scan note), so each DB holds older
trials' events. The trial's own run is the last cluster of anchors; older clusters are evidence for
the WARN of criterion f, and every other criterion only looks inside the window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .agent import Execution
from .db import iso
from .events import Dump
from .params import MARGIN_AFTER_S, MARGIN_BEFORE_S, TRIAL_GAP_S


@dataclass(frozen=True)
class Anchor:
    """One time point that marks design activity, with its kind and evidence uid."""
    ts: float
    kind: str              # agent_command | dump | remote_4624
    host: str
    event_uid: str


@dataclass
class Cluster:
    """Anchors no more than 30 min apart."""
    anchors: list[Anchor] = field(default_factory=list)

    @property
    def first(self) -> float:
        return self.anchors[0].ts

    @property
    def last(self) -> float:
        return self.anchors[-1].ts

    def summary(self) -> dict:
        """Counts per kind and first/last times (evidence for f)."""
        kinds: dict[str, int] = {}
        for a in self.anchors:
            kinds[a.kind] = kinds.get(a.kind, 0) + 1
        return {"first_utc": iso(self.first), "last_utc": iso(self.last), "counts": kinds,
                "hosts": sorted({a.host for a in self.anchors}),
                "example_event_uids": [a.event_uid for a in self.anchors[:3]]}


def anchors_of(executions: Sequence[Execution], dumps: Sequence[Dump], logons: Sequence[Mapping],
               rdp_conns: Sequence[Mapping] = ()) -> list[Anchor]:
    """All anchors: agent executions naming an endpoint, user-token dumps, remote endpoint 4624s.

    ``rdp_conns`` (mstsc -> 3389 Sysmon 3 of a design RDP hop, decision 035) are anchors of their own
    kind, because a manual RDP trial has no agent command (S01 has a dump, decision 036).
    """
    out = [Anchor(e.ts_first, "agent_command", e.host, e.procs[0].event_uid) for e in executions if e.lane == "agent"]
    out += [Anchor(d.ts, "dump", d.host, d.event_uids[0]) for d in dumps if d.user_token]
    out += [Anchor(r["ts"], "remote_4624", r["host"], r["event_uid"]) for r in logons]
    out += [Anchor(r["ts"], "rdp_source", r["host"], r["event_uid"]) for r in rdp_conns]
    return sorted(out, key=lambda a: a.ts)


def clusters_of(anchors: Sequence[Anchor], gap_s: float = TRIAL_GAP_S) -> list[Cluster]:
    """Split time-sorted anchors where consecutive anchors are more than ``gap_s`` apart."""
    out: list[Cluster] = []
    for a in anchors:
        if not out or a.ts - out[-1].last > gap_s:
            out.append(Cluster())
        out[-1].anchors.append(a)
    return out


def window_of(cluster: Cluster) -> tuple[float, float]:
    """[first anchor - 60 s, last anchor + 300 s] (decision 029, f)."""
    return cluster.first - MARGIN_BEFORE_S, cluster.last + MARGIN_AFTER_S


def design_window(times: Sequence[float]) -> tuple[float, float] | None:
    """029 literal window: [first design anchor - 60 s, last + 300 s] over design anchors only.

    WHY both windows exist: 029 (f) names the anchors "agent-child commands of the design, rundll32 ->
    lsass dumps, target 4624 of design hops"; the broad cluster anchors (N1) also include background
    endpoint logons, which in back-to-back x10 trials stretch the window into the next trial.
    """
    ts = [t for t in times if t is not None]
    if not ts:
        return None
    return min(ts) - MARGIN_BEFORE_S, max(ts) + MARGIN_AFTER_S


def run_start(first_anchor: float, floor: float | None, agent_times: Sequence[float], gap_s: float = TRIAL_GAP_S) -> float:
    """Walk back from the first anchor through agent starts and beacons while gaps are <= ``gap_s``.

    WHY (criterion e): the agent beacons once at its start, minutes before the first ability, so the
    "trial run" for agent evidence must reach back to the agent start of this run, but never into the
    previous trial (``floor`` = end of the previous cluster's window).
    """
    start = first_anchor
    for t in sorted((t for t in agent_times if t < first_anchor), reverse=True):
        if floor is not None and t < floor:
            break
        if start - t > gap_s:
            break
        start = t
    return start
