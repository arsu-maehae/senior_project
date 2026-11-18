"""LengthScore of a path (spec 05_score SC-21b, SC-22, SC-23; TPPR Eq. 5, 6, 7; decision 062 item 5).

LengthScore = (1 - e^(-len/lambda)) * EdgeScore, len = number of transitions of the technique sequence, EdgeScore =
mean ScoreE over the transitions. **Stated substitution (review ATK-SC-11):** TPPR runs Eq. 6/7 over the candidate
path's provenance-graph edges; here the "edges" are the transitions of the path's technique sequence. All pure.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Collection, Mapping, Sequence

from gate.timeutil import delta_ms

from .order import OrderReference, StepScore, hop_chain_step, score_step
from .params import ScoreParams
from .sequence import SeqItem

__all__ = ["Step", "first_time_us", "transitions", "LengthResult", "length_score"]


@dataclass(frozen=True)
class Step:
    """One transition u -> v of a path's sequence (one ``path_steps.csv`` row)."""
    step: int
    src: SeqItem
    dst: SeqItem
    score: StepScore
    time_delta_ms: int | None


@dataclass(frozen=True)
class LengthResult:
    """SC-23 outputs of one path."""
    length_score: float
    edge_score: float
    seq_len: int


def first_time_us(uids: Sequence[str], event_us: Mapping[str, int]) -> int | None:
    """Earliest corrected time among ``uids`` (the "first event" of a technique in its hop), None if none known."""
    times = [event_us[u] for u in uids if u in event_us]
    return min(times) if times else None


def transitions(seq: Sequence[SeqItem], ref: OrderReference, params: ScoreParams,
                event_us: Mapping[str, int],
                chain_edges: Collection[tuple[str, str]] = frozenset()) -> list[Step]:
    """Score every consecutive pair of the sequence (SC-21b, SC-22).

    A pair whose hops are joined by a real chain edge (``chain_edges`` holds ``(from_hop_id, to_hop_id)`` of the
    path's ``path_edges``) is a ``hop_chain`` step (direct), because the stitcher's edge (ST-72) fixes that order.
    Every other pair is scored against the templates (``score_step``): a pair from one hop, and a pair across a
    boundary between hops with no chain edge between them (siblings of a merged path that only follow each other in
    the topological order). WHY (ATK-SC-17, decision 069 item 1, amends 067 item 4): giving siblings a 1.0 step would
    reward a merged path for an order no edge supports. ``time_delta_ms`` = first event of ``to`` minus first event
    of ``from`` on every hop boundary (chain or sibling); within a hop it is empty, because within-hop order is the
    template stage, not event time (SC-21). An empty ``chain_edges`` means no boundary is a chain edge."""
    edges = frozenset(chain_edges)
    out: list[Step] = []
    for i in range(len(seq) - 1):
        u, v = seq[i], seq[i + 1]
        if u.hop_id == v.hop_id:
            out.append(Step(i + 1, u, v, score_step(ref, u.technique, v.technique, params), None))
            continue
        tu, tv = first_time_us(u.event_uids, event_us), first_time_us(v.event_uids, event_us)
        dt = delta_ms(tv, tu) if tu is not None and tv is not None else None
        if (u.hop_id, v.hop_id) in edges:
            score = hop_chain_step(ref, u.technique, v.technique, params)
        else:                                          # ATK-SC-17: sibling boundary, no chain edge
            score = score_step(ref, u.technique, v.technique, params)
        out.append(Step(i + 1, u, v, score, dt))
    return out


def length_score(steps: Sequence[Step], lam: float) -> LengthResult:
    """SC-23 / TPPR Eq. 6, 7: (1 - e^(-len/lambda)) * mean ScoreE. Fewer than two techniques -> no transition ->
    len 0, EdgeScore 0, LengthScore 0. ``math.fsum`` keeps the mean independent of summation order."""
    n = len(steps)
    if n == 0:
        return LengthResult(0.0, 0.0, 0)
    edge = math.fsum(s.score.score_e for s in steps) / n
    return LengthResult(length_score=(1.0 - math.exp(-n / lam)) * edge, edge_score=edge, seq_len=n)
