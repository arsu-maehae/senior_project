"""Variants and baselines (spec 05_score section 3.6; decision 065). One scorer, one ranker, a ``variant`` switch only.

- ``full`` = w1*L + w2*N + w3*I (SC-40).
- ``b1`` = (w1*L + w2*N) / (w1 + w2): linking without IdentityCoherence (handoff B3, "w3 = 0"), renormalised so
  scores stay in [0, 1] and comparable across trials (S06 check).
- ``b2`` = NodeScore only (w = 0, 1, 0): order-blind (handoff B2, HADES-style).
- ``b0`` = no linking: one candidate per labelled event unit (``count_key``) of the trial window, any host, any
  ``context``; score = the unit's level / 4 (L and I are 0 by construction). ``event_labels.csv`` holds only events
  inside the trial window (spec 04 LB-01), so no further clipping is needed here.
All pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .errors import ScoreError
from .params import LEVEL_MAX, ScoreParams
from .rank import combine

__all__ = ["variant_weights", "variant_score", "B0Unit", "b0_units"]


def variant_weights(variant: str, params: ScoreParams) -> tuple[float, float, float]:
    """(weight of L, of N, of I) for a path variant. ``b1`` divides by w1 + w2 (both > 0 under the frozen values)."""
    if variant == "full":
        return (params.w1, params.w2, params.w3)
    if variant == "b1":
        s = params.w1 + params.w2
        if s <= 0:
            raise ValueError("b1 needs w1 + w2 > 0")
        return (params.w1 / s, params.w2 / s, 0.0)
    if variant == "b2":
        return (0.0, 1.0, 0.0)
    raise ValueError(f"unknown path variant {variant!r}")


def variant_score(variant: str, params: ScoreParams, length: float, node: float, identity: float) -> float:
    """The variant's score: ``combine`` over the components in the fixed order L, N, I (SC-41)."""
    return combine(variant_weights(variant, params), (length, node, identity))


@dataclass(frozen=True)
class B0Unit:
    """One ``b0`` candidate: a labelled event unit of the whole trial label file."""
    unit_id: str                     # = count_key
    event_uids: tuple[str, ...]
    hosts: tuple[str, ...]
    techniques: tuple[str, ...]
    level_value: int

    @property
    def score(self) -> float:
        """NodeScore of the one unit: level / 4 (SC-31 applied to a single unit)."""
        return self.level_value / LEVEL_MAX


def _level(text: str) -> int:
    """``level_value`` of an event label row as int 0..4; ScoreError otherwise."""
    try:
        v = int(text)
    except ValueError as exc:
        raise ScoreError(f"refused: event_labels.csv level_value {text!r} is not an integer") from exc
    if not 0 <= v <= LEVEL_MAX:
        raise ScoreError(f"refused: event_labels.csv level_value {v} outside 0..{LEVEL_MAX}")
    return v


def b0_units(event_rows: Iterable[Mapping[str, str]]) -> list[B0Unit]:
    """Every labelled unit of the trial (``count_key``), any host and context: its event uids, hosts, primary
    techniques and highest level over all its rows and rules. Sorted by unit id."""
    uids: dict[str, set[str]] = {}
    hosts: dict[str, set[str]] = {}
    techs: dict[str, set[str]] = {}
    level: dict[str, int] = {}
    for r in event_rows:
        k = r["count_key"] or r["event_uid"]
        uids.setdefault(k, set()).add(r["event_uid"])
        hosts.setdefault(k, set()).add(r["host"])
        if r["technique"]:
            techs.setdefault(k, set()).add(r["technique"])
        level[k] = max(level.get(k, 0), _level(r["level_value"]))
    return [B0Unit(unit_id=k, event_uids=tuple(sorted(uids[k])), hosts=tuple(sorted(hosts[k])),
                   techniques=tuple(sorted(techs.get(k, ()))), level_value=level[k]) for k in sorted(uids)]
