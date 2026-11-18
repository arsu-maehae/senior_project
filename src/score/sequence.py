"""Technique sequence of a path (spec 05_score SC-20, SC-21, SC-21b; decision 062 item 4, option S1).

A path's "edges" for TPPR Eq. 5-7 are the transitions of its technique sequence (SC-23 substitution). The sequence:
hops in chain order (``path_edges``, then ``first_utc_corrected``, then ``hop_id``); within a hop its technique set
sorted by the order table's stage, then technique ID; across the path the first appearance of each technique is kept
(TPPR §3.3.1: ATT-SPT order = first appearance). Within-hop order never uses event times, because inside one WinRM
hop the 4648 (T1078) and ``wsmprovhost`` (T1021.006) events alternate at sub-second spacing (s03_t01: 6 alternations).

All functions are pure.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .params import DUMP_TECHNIQUE

__all__ = ["SeqItem", "split_list", "chain_order", "hop_technique_uids", "technique_sort_key", "sort_techniques",
           "technique_sequence"]


@dataclass(frozen=True)
class SeqItem:
    """One technique of a path's sequence: where it first appeared and the node events that carry it there."""
    technique: str
    hop_id: str
    event_uids: tuple[str, ...]


def split_list(text: str, sep: str = ";") -> list[str]:
    """``a;b;;c`` -> ``[a, b, c]`` (empty items dropped)."""
    return [x for x in (text or "").split(sep) if x]


def chain_order(hop_ids: Iterable[str], edges: Iterable[tuple[str, str]],
                first_us: Mapping[str, int | None]) -> list[str]:
    """Hops of one path in chain order (SC-21): a topological order of the ``path_edges`` (from -> to); among hops that
    are free at the same moment, earliest ``first_utc_corrected`` first, then ``hop_id``.

    WHY a topological order and not time alone: the stitcher's chain edge (ST-72) fixes which hop came first; time
    and id only break ties, so the result does not depend on the order of the path's ``hop_ids`` list (SC-21b test).
    A cycle (never written by the stitcher) cannot block: the remaining hops follow in (time, id) order."""
    hops = sorted(set(hop_ids))
    key = {h: (first_us.get(h) is None, first_us.get(h) or 0, h) for h in hops}
    parents: dict[str, set[str]] = {h: set() for h in hops}
    kids: dict[str, set[str]] = {h: set() for h in hops}
    for a, b in edges:
        if a in parents and b in parents and a != b:
            parents[b].add(a)
            kids[a].add(b)
    heap = [key[h] for h in hops if not parents[h]]
    heapq.heapify(heap)
    order: list[str] = []
    done: set[str] = set()
    while len(order) < len(hops):
        if not heap:                                   # cycle: release the earliest remaining hop
            heap = [min(key[h] for h in hops if h not in done)]
        h = heapq.heappop(heap)[2]
        if h in done:
            continue
        done.add(h)
        order.append(h)
        for k in sorted(kids[h]):
            if k not in done and parents[k] <= done:
                heapq.heappush(heap, key[k])
    return order


def hop_technique_uids(node_rows: Iterable[Mapping[str, str]]) -> dict[str, dict[str, tuple[str, ...]]]:
    """hop_id -> technique -> sorted node event uids, from one path's ``node_labels.csv`` rows (SC-20).

    Only labelled ``context`` = 0 rows; ``techniques`` there are primary techniques (secondary tags excluded, 056 Q3).
    T1003.001 never enters: the dump counts only through identity (056 item 7)."""
    acc: dict[str, dict[str, set[str]]] = {}
    for r in node_rows:
        if r["context"] != "0" or r["labelled"] != "1":
            continue
        for t in split_list(r["techniques"]):
            if t != DUMP_TECHNIQUE:
                acc.setdefault(r["hop_id"], {}).setdefault(t, set()).add(r["event_uid"])
    return {h: {t: tuple(sorted(u)) for t, u in sorted(ts.items())} for h, ts in sorted(acc.items())}


def technique_sort_key(technique: str, stage: Mapping[str, int]) -> tuple[int, int, str]:
    """SC-21 within-hop key: template techniques by stage then ID; techniques in no template after them, by ID."""
    if technique in stage:
        return (0, stage[technique], technique)
    return (1, 0, technique)


def sort_techniques(techniques: Iterable[str], stage: Mapping[str, int]) -> list[str]:
    """A hop's technique set in SC-21 order."""
    return sorted(set(techniques), key=lambda t: technique_sort_key(t, stage))


def technique_sequence(chain: Sequence[str], hop_techs: Mapping[str, Mapping[str, tuple[str, ...]]],
                       stage: Mapping[str, int]) -> tuple[SeqItem, ...]:
    """The path's technique sequence (SC-21): hops in ``chain`` order, each hop's set sorted, first appearance kept.
    Each item remembers its hop, so SC-21b can tell a chain-edge boundary from a within-hop or sibling one."""
    seen: set[str] = set()
    out: list[SeqItem] = []
    for hop in chain:
        techs = hop_techs.get(hop, {})
        for t in sort_techniques(techs, stage):
            if t not in seen:
                seen.add(t)
                out.append(SeqItem(technique=t, hop_id=hop, event_uids=techs[t]))
    return tuple(out)
