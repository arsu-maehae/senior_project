"""Development ranking check, pure part (PLAN T9.5; spec 05_score SCA-06, section 7.3; decisions 065, 066; handoff
section 14.2).

Which candidate path "is" a key attack path, where the first such candidate sits in a ranked list, and what that
position is worth under the tie readings of decision 065. Everything here works on rows already read and checked
(``rank_inputs``), so a test can drive it with synthetic rows and no file.

Readings (stated in rank.md and in the T9.5 report):
- **Key attack paths** = key ``paths`` with ``role`` ``attack`` or ``attack_pair`` (``benign_paths`` never).
- **Hop reading**: a candidate matches a key attack path when the Jaccard index of its ``hop_ids`` and the stitch
  hops mapped from the key path's hops is >= 0.5. A key hop maps to every stitch hop that has its target 4624 as a
  member (``keys.match_key_hop``, ST-25, decision 051 item 3), so the mapping is the one link accuracy uses.
- **Node reading** (handoff section 14.2): Jaccard >= 0.5 between the candidate's ``context`` = 0 event uids
  (``path_nodes.csv``) and the key path's node set = the union over its key hops of the uid lists the key writes on
  the hop as evidence of the move (``KEY_NODE_FIELDS``). The key's ``steps`` are not read: on every development key
  the ``move`` / ``service_exec`` step uids are already inside these fields, and the ``lsass_dump`` steps are source
  session context (``context`` = 1, decision 056 item 7) that no candidate's ``context`` = 0 set can hold.
  **Anchor (ATK-SC-16, decision 069 item 7):** a node match also needs the candidate to hold at least one of the key
  path's target logon uids = the key hops' ``target_event_uids`` that are target 4624 members of a stitch hop
  (``hops.csv`` ``member_logon_uids``). WHY: without it a candidate made of artefacts and source events alone could
  match a key path whose move it does not contain. **ST-05 copies:** a ``member_logon_uids`` item ``rep|copy|...``
  holds one 4624 and its near-duplicate copies (decision 055); every uid on both sides is replaced by the item's
  first uid (``copy_alias_map``) before any comparison, as the hop reading matches a member on any of its copies.
- **Ties** (065): the first match lies in the tie group (competition rank r, size t) holding the best-ranked match;
  with m matches in that group, a uniformly random order inside the group gives expected rank r - 1 + (t+1)/(m+1)
  (= r + (t-1)/2 when m = 1, the 065 formula), optimistic r, pessimistic r + t - m; top-1 credit m/t when r = 1.
  Reciprocal rank = 1 / rank of the reading (065: a 2-way tie at the top = rank 1.5, RR 1/1.5). ``path_id`` order
  is never used.
- **Chance line** (065): the same expectation with all n candidates in one tie group (top-1 m/n, rank (n+1)/(m+1),
  RR its inverse); ``chance_rr_mean`` = E[1 / rank] of a random order, given beside it. Reported beside, primary
  unchanged (ATK-SC-21): the same chance line over the candidates with score > 0 only, and the observed E[1 / rank]
  inside the first match's tie group (``Placement.rr_mean``) beside 1 / E[rank].
- **Score gap** (handoff 14.2): lowest score of the key attack paths' first matches - highest score of the
  candidates that match no key attack path (> 0 = clean separation).
- **Node recall at an equal node budget** (H4, 065): ``full``'s top-k paths (k = number of key attack paths), a tie
  group at the cut read by expectation (each of its paths is in the top k with probability slots / t, node coverage
  exact by inclusion probability); budget B = expected number of distinct ``context`` = 0 nodes of the top k.
  ``b0`` takes its units in rank order until it holds B event nodes; the tie group at the cut is read by expectation
  at node level (each new node of that group is held with probability remaining budget / new nodes of the group).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Iterable, Mapping, Sequence

from .inputs import EvalError
from .keys import MatchResult, match_key_hop, member_uid_set, split_list

__all__ = ["ATTACK_ROLES", "MATCH_THRESHOLD", "READING_HOP", "READING_NODE", "READINGS", "KEY_NODE_FIELDS",
           "Candidate", "KeyPath", "Placement", "jaccard", "copy_alias_map", "canonical", "member_logon_uid_set",
           "key_attack_paths", "key_hop_node_uids", "build_key_paths", "positive_ids", "first_rr_mean",
           "check_groups", "candidates_of", "path_node_sets", "unit_node_sets", "matches", "placement", "chance_line",
           "score_gap", "inclusion_probabilities", "expected_coverage", "b0_recall", "distribution"]

ATTACK_ROLES: frozenset[str] = frozenset({"attack", "attack_pair"})
MATCH_THRESHOLD = 0.5            # handoff 14.2, spec 05 section 7.3
READING_HOP, READING_NODE = "hop", "node"
READINGS: tuple[str, ...] = (READING_HOP, READING_NODE)
# The uid lists a key hop holds as evidence of the move itself (spec 07: target_event_uids = target 4624s and their
# artefacts; agent_event_uids / agent_corroboration_4688_uids = the source command, Sysmon 1 / 4688;
# port_join_event_uids = the source Sysmon 3 of a port join; credential_logon_uids = further target logons of the same
# command, AK-16). ``related_logon_uids`` (same-account logons not tied to the command, AK-16), ``identity_basis``
# (the dump: identity only, 056 item 7) and ``candidates`` (alternatives the key rejected) are left out.
KEY_NODE_FIELDS: tuple[str, ...] = ("target_event_uids", "agent_event_uids", "agent_corroboration_4688_uids",
                                    "port_join_event_uids", "credential_logon_uids")


# ---------------------------------------------------------------- data holders

@dataclass(frozen=True)
class Candidate:
    """One ranked candidate of one variant: id, competition rank, tie size, written score, hop ids."""
    path_id: str
    rank: int
    tie_size: int
    score: float
    hop_ids: frozenset[str]


@dataclass(frozen=True)
class KeyPath:
    """One key attack path read against the stitch hops: its key hops, the stitch hops they map to, the target 4624
    uids that anchor the mapping, and its node set."""
    path_id: str
    role: str
    key_hop_ids: tuple[str, ...]
    mapped_hop_ids: frozenset[str]
    anchor_uids: tuple[str, ...]
    node_uids: frozenset[str]
    unmatched_key_hops: tuple[str, ...]
    target_logon_uids: frozenset[str] = frozenset()     # ATK-SC-16 node-reading anchor (canonical uids)


@dataclass(frozen=True)
class Placement:
    """Where the first match of a key attack path (or of any of them) sits, under the three tie readings."""
    matched: tuple[str, ...]            # every matching candidate, sorted
    first_group: tuple[str, ...]        # the matching members of the best-ranked group, sorted
    first_rank: int | None
    tie_size: int | None
    rank_expected: float | None
    rank_optimistic: int | None
    rank_pessimistic: int | None
    top1_expected: float
    top1_optimistic: float
    top1_pessimistic: float
    first_score: float | None

    def rr(self, reading: str) -> float:
        """Reciprocal rank of a reading (expected / optimistic / pessimistic); 0 when nothing matches (handoff
        14.2 MRR: a missing attack path contributes 0)."""
        value = {"expected": self.rank_expected, "optimistic": self.rank_optimistic,
                 "pessimistic": self.rank_pessimistic}[reading]
        return 0.0 if value is None else 1.0 / value

    def rr_mean(self) -> float:
        """E[1 / rank of the first match] under a random order inside its tie group (ATK-SC-21, reported beside
        1 / E[rank]); 0 when nothing matches."""
        if self.first_rank is None or self.tie_size is None:
            return 0.0
        return first_rr_mean(self.first_rank, self.tie_size, len(self.first_group))


# ---------------------------------------------------------------- key side

def jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    """|A ∩ B| / |A ∪ B|; 0 when both are empty (an empty key side matches nothing)."""
    sa, sb = set(a), set(b)
    union = sa | sb
    return len(sa & sb) / len(union) if union else 0.0


def first_rr_mean(rank: int, tie: int, m: int) -> float:
    """E[1 / position of the first of m matches] when they lie in a tie group of size ``tie`` starting at competition
    rank ``rank`` and the order inside the group is uniformly random: P(first at rank - 1 + i) = C(tie - i, m - 1) /
    C(tie, m) (exact with fractions)."""
    if m <= 0 or tie <= 0 or m > tie:
        return 0.0
    total = math.comb(tie, m)
    return float(sum(Fraction(math.comb(tie - i, m - 1), total) / (rank - 1 + i) for i in range(1, tie - m + 2)))


def copy_alias_map(stitch_hops: Sequence[Mapping[str, str]]) -> dict[str, str]:
    """uid -> canonical uid for every uid in a ``member_logon_uids`` item: the item's first uid (the representative)
    for itself and each of its ST-05 copies (``keys.member_uid_set``, decision 055). A uid in no item is not listed
    and stays itself (``canonical``)."""
    out: dict[str, str] = {}
    for hop in stitch_hops:
        for item in split_list(hop.get("member_logon_uids")):
            parts = [u for u in item.split("|") if u != ""]
            for u in sorted(member_uid_set(item)):
                out.setdefault(u, parts[0])
    return dict(sorted(out.items()))


def canonical(uids: Iterable[str], alias: Mapping[str, str]) -> frozenset[str]:
    """The uids with every ST-05 copy replaced by its representative (``copy_alias_map``)."""
    return frozenset(alias.get(u, u) for u in uids)


def member_logon_uid_set(stitch_hops: Sequence[Mapping[str, str]], alias: Mapping[str, str]) -> frozenset[str]:
    """Canonical uids of every target 4624 member of any stitch hop: the uids that are target logons."""
    return canonical((u for h in stitch_hops for item in split_list(h.get("member_logon_uids"))
                      for u in member_uid_set(item)), alias)


def key_attack_paths(key_data: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The key's attack paths in key order: ``paths`` entries whose ``role`` is attack or attack_pair."""
    return [p for p in key_data.get("paths") or [] if isinstance(p, Mapping) and p.get("role") in ATTACK_ROLES]


def key_hop_node_uids(key_hop: Mapping[str, Any]) -> frozenset[str]:
    """The node set of one key hop: the union of its ``KEY_NODE_FIELDS`` uid lists."""
    out: set[str] = set()
    for name in KEY_NODE_FIELDS:
        value = key_hop.get(name) or []
        if not isinstance(value, list) or not all(isinstance(u, str) for u in value):
            raise EvalError(f"refused: approved key hop {key_hop.get('hop_id', '?')}: {name} is not a list of uids")
        out.update(value)
    return frozenset(out)


def build_key_paths(key_data: Mapping[str, Any], stitch_hops: Sequence[Mapping[str, str]]) -> list[KeyPath]:
    """Every key attack path with its mapped stitch hops (ST-25 per key hop), its node set and its target logon uids,
    both with ST-05 copies replaced by their representative (ATK-SC-16). A key path naming a hop id the key does not
    define is refused: the key would be internally inconsistent."""
    by_id = {str(h.get("hop_id")): h for h in key_data.get("hops") or [] if isinstance(h, Mapping)}
    alias = copy_alias_map(stitch_hops)
    logons = member_logon_uid_set(stitch_hops, alias)
    out: list[KeyPath] = []
    for kp in key_attack_paths(key_data):
        hop_ids = tuple(str(h) for h in kp.get("hop_ids") or [])
        mapped: set[str] = set()
        anchors: list[str] = []
        nodes: set[str] = set()
        targets: set[str] = set()
        unmatched: list[str] = []
        for hid in hop_ids:
            if hid not in by_id:
                raise EvalError(f"refused: approved key path {kp.get('path_id', '?')} names an undefined hop")
            m: MatchResult = match_key_hop(by_id[hid], stitch_hops)
            mapped.update(m.hop_ids)
            anchors.extend(m.member_uids)
            if not m.hop_ids:
                unmatched.append(hid)
            nodes |= key_hop_node_uids(by_id[hid])
            targets |= canonical(by_id[hid].get("target_event_uids") or [], alias) & logons
        out.append(KeyPath(path_id=str(kp.get("path_id", "")), role=str(kp.get("role")), key_hop_ids=hop_ids,
                           mapped_hop_ids=frozenset(mapped), anchor_uids=tuple(sorted(set(anchors))),
                           node_uids=canonical(nodes, alias), unmatched_key_hops=tuple(unmatched),
                           target_logon_uids=frozenset(targets)))
    return out


# ---------------------------------------------------------------- candidate side

def _num(cell: str, what: str) -> float:
    """A numeric score cell; EvalError otherwise."""
    try:
        return float(cell)
    except (TypeError, ValueError):
        raise EvalError(f"refused: score {what} {cell!r} is not a number") from None


def _int(cell: str, what: str) -> int:
    """An integer score cell; EvalError otherwise."""
    try:
        return int(cell)
    except (TypeError, ValueError):
        raise EvalError(f"refused: score {what} {cell!r} is not an integer") from None


def check_groups(items: Sequence[tuple[str, int, int]], what: str) -> None:
    """Competition ranks must be consistent: exactly ``tie_size`` rows share a rank, and the next rank is rank +
    tie_size (SC-41). WHY: every tie reading is computed from these two columns."""
    by_rank: dict[int, list[int]] = {}
    for _id, rank, size in items:
        by_rank.setdefault(rank, []).append(size)
    expect = 1
    for rank in sorted(by_rank):
        sizes = by_rank[rank]
        if rank != expect or any(s != len(sizes) for s in sizes):
            raise EvalError(f"refused: {what} has inconsistent rank / tie_size columns at rank {rank}")
        expect = rank + len(sizes)


def candidates_of(ranked: Sequence[Mapping[str, str]], variant: str) -> list[Candidate]:
    """The candidates of one variant in rank order (then ``path_id``, display only), ranks checked."""
    out = [Candidate(path_id=r["path_id"], rank=_int(r["rank"], "rank"), tie_size=_int(r["tie_size"], "tie_size"),
                     score=_num(r["score"], "score"), hop_ids=frozenset(split_list(r["hop_ids"])))
           for r in ranked if r["variant"] == variant]
    check_groups([(c.path_id, c.rank, c.tie_size) for c in out], f"ranked_paths.csv variant {variant}")
    return sorted(out, key=lambda c: (c.rank, c.path_id))


def path_node_sets(path_nodes: Sequence[Mapping[str, str]],
                   alias: Mapping[str, str] | None = None) -> dict[str, frozenset[str]]:
    """path_id -> its ``context`` = 0 event uids (stitch ``path_nodes.csv``), ST-05 copies replaced by their
    representative when ``alias`` is given (ATK-SC-16). WHY ``context`` = 0: those are the path's own nodes;
    ``context`` = 1 rows are session context (ST-71, decision 056 item 7)."""
    out: dict[str, set[str]] = {}
    for r in path_nodes:
        if r.get("context") == "0" and r.get("event_uid"):
            out.setdefault(r["path_id"], set()).add(r["event_uid"])
    return {k: canonical(v, alias or {}) for k, v in sorted(out.items())}


def unit_node_sets(units: Sequence[Mapping[str, str]],
                   alias: Mapping[str, str] | None = None) -> dict[str, frozenset[str]]:
    """path_id -> the event uids of its labelled ``context`` = 0 NodeScore units (score ``path_node_units.csv``),
    ST-05 copies replaced when ``alias`` is given."""
    out: dict[str, set[str]] = {}
    for r in units:
        out.setdefault(r["path_id"], set()).update(split_list(r["event_uids"]))
    return {k: canonical(v, alias or {}) for k, v in sorted(out.items())}


def positive_ids(candidates: Sequence[Candidate]) -> frozenset[str]:
    """Ids of the candidates with score > 0 (the ATK-SC-21 second chance line)."""
    return frozenset(c.path_id for c in candidates if c.score > 0)


# ---------------------------------------------------------------- matching and placement

def matches(key_path: KeyPath, candidates: Sequence[Candidate], nodes: Mapping[str, frozenset[str]],
            reading: str) -> dict[str, float]:
    """path_id -> Jaccard for every candidate at or above ``MATCH_THRESHOLD`` under one reading. The node reading
    also requires the candidate to hold one of the key path's target logon uids (ATK-SC-16); ``nodes`` and the key
    sets must already be canonical (``copy_alias_map``)."""
    out: dict[str, float] = {}
    for c in candidates:
        if reading == READING_HOP:
            j = jaccard(c.hop_ids, key_path.mapped_hop_ids)
        elif reading == READING_NODE:
            held = nodes.get(c.path_id, frozenset())
            if not held & key_path.target_logon_uids:              # ATK-SC-16: no key target logon, no match
                continue
            j = jaccard(held, key_path.node_uids)
        else:
            raise ValueError(f"unknown match reading {reading!r}")
        if j >= MATCH_THRESHOLD:
            out[c.path_id] = j
    return dict(sorted(out.items()))


def placement(candidates: Sequence[Candidate], matched: Iterable[str]) -> Placement:
    """The 065 tie readings of the first match among ``candidates`` (see the module docstring)."""
    hit = set(matched)
    found = sorted((c for c in candidates if c.path_id in hit), key=lambda c: (c.rank, c.path_id))
    if not found:
        return Placement(tuple(sorted(hit)), (), None, None, None, None, None, 0.0, 0.0, 0.0, None)
    r, t = found[0].rank, found[0].tie_size
    group = tuple(sorted(c.path_id for c in found if c.rank == r))
    m = len(group)
    expected = r - 1 + (t + 1) / (m + 1)
    pess = r + t - m
    return Placement(matched=tuple(sorted(hit)), first_group=group, first_rank=r, tie_size=t,
                     rank_expected=expected, rank_optimistic=r, rank_pessimistic=pess,
                     top1_expected=m / t if r == 1 else 0.0, top1_optimistic=1.0 if r == 1 else 0.0,
                     top1_pessimistic=1.0 if pess == 1 else 0.0, first_score=found[0].score)


def chance_line(n: int, m: int) -> dict[str, float | None]:
    """A uniformly random order of n candidates with m matches: top-1 m/n, expected rank (n+1)/(m+1), its inverse,
    and E[1 / rank of the first match] (exact, via P(first match at i) = C(n-i, m-1) / C(n, m))."""
    if n <= 0 or m <= 0:
        return {"top1": 0.0, "rank": None, "rr": 0.0, "rr_mean": 0.0}
    total = math.comb(n, m)
    rr_mean = sum(Fraction(math.comb(n - i, m - 1), total) / i for i in range(1, n - m + 2))
    rank = (n + 1) / (m + 1)
    return {"top1": m / n, "rank": rank, "rr": 1.0 / rank, "rr_mean": float(rr_mean)}


def score_gap(first_scores: Sequence[float | None], candidates: Sequence[Candidate],
              attack_ids: Iterable[str]) -> tuple[float | None, float | None, tuple[str, ...], float | None]:
    """(lowest key attack score, highest other score, the other paths at that score, gap). The lowest key attack
    score is None when a key attack path has no match (the gap is then undefined); the other side is None when every
    candidate matches a key attack path."""
    attack = set(attack_ids)
    low = None if (not first_scores or any(s is None for s in first_scores)) else min(first_scores)  # type: ignore
    others = [c for c in candidates if c.path_id not in attack]
    high = max((c.score for c in others), default=None)
    at_high = tuple(sorted(c.path_id for c in others if high is not None and c.score == high))
    gap = None if low is None or high is None else low - high
    return low, high, at_high, gap


# ---------------------------------------------------------------- node recall at an equal budget (H4)

def inclusion_probabilities(candidates: Sequence[Candidate], k: int) -> tuple[dict[str, float], list[str], int]:
    """(path_id -> P(in the top k) for the paths above the cut (1.0), the cut group's paths, slots of the cut group).
    The cut group is the tie group that straddles position k; each of its t paths is in the top k with probability
    slots / t under a random order inside the group."""
    sure: dict[str, float] = {}
    pos = 0
    for rank in sorted({c.rank for c in candidates}):
        group = [c.path_id for c in candidates if c.rank == rank]
        if pos + len(group) <= k:
            sure.update({p: 1.0 for p in group})
            pos += len(group)
            if pos == k:
                return sure, [], 0
            continue
        return sure, sorted(group), k - pos
    return sure, [], 0


def expected_coverage(nodes: Mapping[str, frozenset[str]], sure: Iterable[str], cut: Sequence[str],
                      slots: int) -> dict[str, float]:
    """uid -> P(the uid is a node of the top k): 1 when a sure path holds it; else 1 - C(t-c, s)/C(t, s) with c = cut
    paths holding it, t = cut size, s = slots (exact under a random order inside the cut group)."""
    out: dict[str, float] = {}
    for p in sure:
        for u in nodes.get(p, frozenset()):
            out[u] = 1.0
    t = len(cut)
    if t and slots:
        holders: dict[str, int] = {}
        for p in cut:
            for u in nodes.get(p, frozenset()):
                holders[u] = holders.get(u, 0) + 1
        for u, c in holders.items():
            if u not in out:
                out[u] = 1.0 - math.comb(t - c, slots) / math.comb(t, slots)
    return dict(sorted(out.items()))


def b0_recall(b0_rows: Sequence[Mapping[str, str]], budget: float,
              key_nodes: frozenset[str]) -> tuple[float, float]:
    """(expected recall of ``key_nodes``, expected nodes held) of ``b0`` taking units in rank order until it holds
    ``budget`` event nodes; the tie group at the cut is read by expectation at node level (module docstring)."""
    items = [(r["unit_id"], _int(r["rank"], "b0 rank"), _int(r["tie_size"], "b0 tie_size"),
              frozenset(split_list(r["event_uids"]))) for r in b0_rows]
    check_groups([(u, rk, ts) for u, rk, ts, _ in items], "b0_ranked.csv")
    held: set[str] = set()
    hit = 0.0
    total = 0.0
    for rank in sorted({rk for _, rk, _, _ in items}):
        if total >= budget:
            break
        new = set().union(*(n for _, rk, _, n in items if rk == rank)) - held
        if not new:
            continue
        if total + len(new) <= budget:
            held |= new
            total += len(new)
            hit += len(new & key_nodes)
            continue
        share = (budget - total) / len(new)
        hit += share * len(new & key_nodes)
        total = budget
    recall = hit / len(key_nodes) if key_nodes else 0.0
    return recall, total


# ---------------------------------------------------------------- unkeyed trials

def distribution(candidates: Sequence[Candidate]) -> dict[str, float | int | None]:
    """n and the score distribution of one variant (no right / wrong): max, min, mean, zero scores, distinct scores
    and the size of the top tie group."""
    scores = [c.score for c in candidates]
    if not scores:
        return {"n": 0, "max": None, "min": None, "mean": None, "n_zero": 0, "n_distinct": 0, "top_tie": 0}
    top = [c for c in candidates if c.rank == 1]
    return {"n": len(scores), "max": max(scores), "min": min(scores), "mean": math.fsum(scores) / len(scores),
            "n_zero": sum(1 for s in scores if s == 0.0), "n_distinct": len(set(scores)),
            "top_tie": top[0].tie_size if top else 0}
