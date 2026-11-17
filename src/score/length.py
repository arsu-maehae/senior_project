"""LengthScore of a path (spec 05_score SC-21b, SC-22, SC-23; TPPR Eq. 5, 6, 7; decision 062 item 4).

LengthScore = (1 - e^(-len/lambda)) * EdgeScore, len = number of transitions of the technique sequence, EdgeScore =
mean ScoreE over the transitions. **Stated substitution (review ATK-SC-11):** TPPR runs Eq. 6/7 over the candidate
path's provenance-graph edges; here the "edges" are the transitions of the path's technique sequence. All pure.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Mapping, Sequence

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
                event_us: Mapping[str, int]) -> list[Step]:
    """Score every consecutive pair of the sequence (SC-21b, SC-22).

    A pair from the same hop is scored against the templates (``score_step``). A pair whose items come from two
    different hops crosses a hop boundary: it is a ``hop_chain`` step (direct), because the chain order of the hops
    is the stitcher's (ST-72), and its ``time_delta_ms`` = first event of ``to`` minus first event of ``from``. Within a
    hop ``time_delta_ms`` is empty: within-hop order is the template stage, not event time (SC-21)."""
    out: list[Step] = []
    for i in range(len(seq) - 1):
        u, v = seq[i], seq[i + 1]
        if u.hop_id == v.hop_id:
            out.append(Step(i + 1, u, v, score_step(ref, u.technique, v.technique, params), None))
            continue
        tu, tv = first_time_us(u.event_uids, event_us), first_time_us(v.event_uids, event_us)
        dt = delta_ms(tv, tu) if tu is not None and tv is not None else None
        out.append(Step(i + 1, u, v, hop_chain_step(ref, u.technique, v.technique, params), dt))
    return out


def length_score(steps: Sequence[Step], lam: float) -> LengthResult:
    """SC-23 / TPPR Eq. 6, 7: (1 - e^(-len/lambda)) * mean ScoreE. Fewer than two techniques -> no transition ->
    len 0, EdgeScore 0, LengthScore 0. ``math.fsum`` keeps the mean independent of summation order."""
    n = len(steps)
    if n == 0:
        return LengthResult(0.0, 0.0, 0)
    edge = math.fsum(s.score.score_e for s in steps) / n
    return LengthResult(length_score=(1.0 - math.exp(-n / lam)) * edge, edge_score=edge, seq_len=n)
