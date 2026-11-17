"""NodeScore of a path (spec 05_score SC-30..SC-33; decision 063; Correction G.1).

NodeScore = mean over the path's ``count_key`` units of labelled ``context`` = 0 nodes, each unit at its highest
``level_value``, divided by 4 (critical). One action logged twice (Sysmon 1 + 4688, 4697 + 7045) shares one
``count_key`` (LB-11) and so counts once. A path with no unit scores 0 with ``n_node_units`` = 0 (SC-32, Q2 (a)).
``context`` = 1 nodes (session context, where the LSASS dump lands) are out of the score (056 item 7); the same
mean with them included is ``node_score_ctx1``, reported only (SC-30, review ATK-SC-03). All pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Collection, Iterable, Mapping

from .errors import ScoreError
from .params import LEVEL_MAX
from .sequence import split_list

__all__ = ["Unit", "count_key_map", "node_units", "node_score"]


@dataclass(frozen=True)
class Unit:
    """One NodeScore unit (one ``path_node_units.csv`` row): one action counted once."""
    count_key: str
    event_uids: tuple[str, ...]
    hop_ids: tuple[str, ...]
    techniques: tuple[str, ...]
    level_value: int


def count_key_map(event_rows: Iterable[Mapping[str, str]]) -> dict[str, str]:
    """event_uid -> count_key from ``event_labels.csv``. Refused when one uid carries two keys: LB-11 gives every
    event exactly one key, so two would mean the label file is inconsistent and a unit count could be wrong."""
    out: dict[str, str] = {}
    for r in event_rows:
        uid, key = r["event_uid"], r["count_key"] or r["event_uid"]
        if out.setdefault(uid, key) != key:
            raise ScoreError(f"refused: event_labels.csv gives event {uid} two count_keys ({out[uid]}, {key})")
    return out


def _level(text: str, uid: str) -> int:
    """A node's ``max_level_value`` as an int in 0..4 (SC-33); ScoreError otherwise (a labelled node needs one)."""
    try:
        v = int(text)
    except ValueError as exc:
        raise ScoreError(f"refused: labelled node {uid} has no valid max_level_value {text!r}") from exc
    if not 0 <= v <= LEVEL_MAX:
        raise ScoreError(f"refused: labelled node {uid} max_level_value {v} outside 0..{LEVEL_MAX}")
    return v


def node_units(node_rows: Iterable[Mapping[str, str]], keys: Mapping[str, str],
               contexts: Collection[str] = ("0",)) -> list[Unit]:
    """The units of one path (SC-31): labelled node rows of the given ``contexts`` grouped by ``count_key``; a unit's
    level = highest ``max_level_value`` over its node rows (each row already holds the highest level over its rules).

    A labelled node whose uid has no ``event_labels.csv`` row is refused: the label stage writes a row for every
    labelled event (LB-01, spec 04 section 3.4), so a gap means the two label files disagree. Sorted by count_key."""
    uids: dict[str, set[str]] = {}
    hops: dict[str, set[str]] = {}
    techs: dict[str, set[str]] = {}
    level: dict[str, int] = {}
    for r in node_rows:
        if r["labelled"] != "1" or r["context"] not in contexts:
            continue
        uid = r["event_uid"]
        if uid not in keys:
            raise ScoreError(f"refused: labelled node {uid} has no row in event_labels.csv")
        k = keys[uid]
        uids.setdefault(k, set()).add(uid)
        hops.setdefault(k, set()).add(r["hop_id"])
        techs.setdefault(k, set()).update(split_list(r["techniques"]))
        level[k] = max(level.get(k, 0), _level(r["max_level_value"], uid))
    return [Unit(count_key=k, event_uids=tuple(sorted(uids[k])), hop_ids=tuple(sorted(hops[k])),
                 techniques=tuple(sorted(techs[k])), level_value=level[k]) for k in sorted(uids)]


def node_score(units: Iterable[Unit]) -> float:
    """SC-31 / SC-32: mean unit level / 4; 0 for a path with no unit (Q2 (a): all scores on one scale)."""
    levels = [u.level_value for u in units]
    if not levels:
        return 0.0
    return sum(levels) / (len(levels) * LEVEL_MAX)
