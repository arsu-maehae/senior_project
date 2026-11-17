"""Score combination and ranking (spec 05_score SC-40, SC-41; Correction J; decisions 018, 021, 065).

Every candidate is ranked, highest score first; no threshold theta (Correction J). Equal scores share the best rank
(competition ranking 1, 1, 3) and carry ``tie_size``. Inside a tie the listing order is the candidate id, for display
only: no metric may use it (review ATK-SC-01; ties are read by expected rank, decision 065). All pure.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

from .params import TIE_DECIMALS

__all__ = ["Ranked", "combine", "tie_value", "competition_ranks"]


@dataclass(frozen=True)
class Ranked:
    """One ranked candidate: its id, unrounded score, competition rank and the size of its tie group."""
    item_id: str
    score: float
    rank: int
    tie_size: int


def combine(weights: Sequence[float], components: Sequence[float]) -> float:
    """sum(w_i * c_i) with ``math.fsum`` over the components in the given fixed order (SC-41, review ATK-SC-13).
    WHY fsum: plain float addition depends on the order of terms; fsum is exact up to the final rounding, so two
    paths with equal components get bit-equal scores."""
    if len(weights) != len(components):
        raise ValueError("weights and components differ in length")
    return math.fsum(w * c for w, c in zip(weights, components))


def tie_value(score: float) -> float:
    """The value ties are decided on: the score rounded to 12 decimals (SC-41), so float noise far below any real
    difference cannot split a tie."""
    return round(score, TIE_DECIMALS)


def competition_ranks(items: Iterable[tuple[str, float]]) -> list[Ranked]:
    """Rank (id, score) pairs: descending ``tie_value``; equal values share the best rank (1, 1, 3, ...) and their
    ``tie_size``; listing order inside a tie = id (display only). Every item appears exactly once (SC-04)."""
    ordered = sorted(items, key=lambda it: (-tie_value(it[1]), it[0]))
    sizes: dict[float, int] = {}
    for _id, s in ordered:
        sizes[tie_value(s)] = sizes.get(tie_value(s), 0) + 1
    out: list[Ranked] = []
    rank = 0
    prev: float | None = None
    for pos, (item_id, s) in enumerate(ordered, start=1):
        v = tie_value(s)
        if v != prev:
            rank, prev = pos, v
        out.append(Ranked(item_id=item_id, score=s, rank=rank, tie_size=sizes[v]))
    return out
