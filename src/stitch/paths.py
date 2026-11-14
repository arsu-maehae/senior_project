"""T7.5 paths: chain edges between seed hops, candidate paths, merged chains and per-hop path facts (spec
03_stitch ST-23, ST-70, ST-72, ST-73, ST-74; owner answers Q6, Q7, Q13, Q15 (b), Q16 (a); decision 050 items 1-4
and 6; limitation L-ST2).

WHY pure and built on the ``LinkIndex``: hops, links, verdicts and the corrected times are already decided by
T7.2-T7.4; a path is only a reading of them. Nothing here opens a file or a DB, and nothing is recomputed, so the
T7.4 files cannot change because paths were added (decision 050 consequences).

Rules in one place:
- A seed (ST-23, Q13) starts a path (ST-70); a hop with no trigger is in no path and never chains.
- A seed whose members are all machine accounts takes no part in chaining (Q15 (b)) but is still its own path.
- H1 -> H2 when H2 leaves the host H1 entered and starts no more than ``order_tol_s`` before H1 (ST-72, Q6).
- A path is a weakly connected component of the edge graph (decision 050 item 1). WHY components: ST-73 merges
  maximal chains that share a hop, and doing that until nothing changes gives exactly the components; computing
  components directly means path membership never depends on how chains are enumerated.
- ``merged_from`` (the maximal simple chains) is for display only (ST-73 lists them; membership ignores it).

Every time comparison is on corrected microseconds (ST-02): the two hops' first members are on different hosts,
so this is a cross-host comparison with the ``order_tol_s`` tolerance (decision 014).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from gate.timeutil import delta_ms, seconds_to_us

from .hops import Hop
from .links import LinkIndex
from .params import StitchParams
from .sessions import SessionKey
from .source import SubjectLinks
from .tiers import HopVerdicts

__all__ = ["LINK_SESSION", "LINK_HOST_TIME", "LINK_TYPES", "STRONG_TIERS", "ChainEdge", "Path", "HopPathFacts",
           "PathSet", "chainable", "hop_clock_unreliable", "first_ranked_sessions", "first_ranked_ab_sessions",
           "hop_order", "source_label", "hop_hosts", "chain_edges", "components", "maximal_chains",
           "chain_text", "edge_types_text", "path_id", "build_paths"]

# ST-72 link types; ``session`` is the stronger one. The tuple order is the ``edge_types`` order (050 item 6).
LINK_HOST_TIME, LINK_SESSION = "host_time", "session"
LINK_TYPES: tuple[str, ...] = (LINK_HOST_TIME, LINK_SESSION)
# ST-71 / ST-72: only a first-ranked session of tier A or B is trusted enough for a session edge or session events.
STRONG_TIERS: frozenset[str] = frozenset({"A", "B"})


# ---------------------------------------------------------------- records

@dataclass(frozen=True)
class ChainEdge:
    """One ST-72 edge H1 -> H2 (a ``path_edges.csv`` row without its path id).

    ``time_delta_us`` / ``time_delta_ms`` = H2 first member - H1 first member, corrected (negative down to
    ``-order_tol_s``). ``order_within_tolerance`` = 1 when |delta| <= ``order_tol_s`` (050 item 2: so every edge
    with a negative delta is flagged). ``clock_unreliable`` = the larger ``hop_clock_unreliable`` of the two hops.
    ``supporting_sessions``: for a ``session`` edge, the H2 first-ranked tier A / B session keys that are member
    sessions of H1 (empty for ``host_time``), so the type is traceable.
    """
    from_hop_id: str
    to_hop_id: str
    link_type: str
    time_delta_us: int
    time_delta_ms: int
    order_within_tolerance: int
    clock_unreliable: int
    supporting_sessions: tuple[SessionKey, ...] = ()


@dataclass
class Path:
    """One candidate path (a ``paths.csv`` row before spelling).

    ``hop_ids`` in time order (corrected first member, then hop id). ``hosts`` one ``source>target`` per hop in
    the same order (050 item 6; the writer joins them with ``;``). ``merged_from`` the maximal chains spelled
    ``h…>h…`` (display only, ST-73). ``isolated`` = 1 hop and no edge (ST-74). ``edge_types`` = edge count per
    ``LINK_TYPES`` type. ``edges`` the ChainEdges inside the path, in edge order. The two note lists are filled
    by the T7.5 notes step (ST-73: notes, never a merge) and stay empty until then.
    """
    path_id: str
    hop_ids: list[str]
    hosts: list[str]
    n_hops: int
    seed_trigger_ids: list[str]
    merged_from: list[str]
    isolated: int
    edge_types: dict[str, int]
    edges: list[ChainEdge]
    shared_source_session_with: list[str] = field(default_factory=list)
    shared_event_with: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HopPathFacts:
    """The ``hops.csv`` path columns of one hop (spec 3; ST-72, L-ST2, ST-23).

    ``chain_parent_hop_ids`` sorted by hop order; ``multi_chain_parent`` = 1 when there is more than one parent
    (owner Q16 (a): the locked merge still applies, the flag tells the reader two movements met here).
    ``in_path`` = 1 when the hop is in a path; ``path_id`` None otherwise (non-seed hops, ST-23).
    """
    hop_id: str
    chain_parent_count: int
    chain_parent_hop_ids: list[str]
    multi_chain_parent: int
    in_path: int
    path_id: str | None


@dataclass
class PathSet:
    """All T7.5 path results of one trial: paths in path-id order, every edge in edge order, the path facts of
    every hop (seed or not, ST-04), and the counts block for ``stats.json``."""
    trial_id: str
    paths: list[Path]
    edges: list[ChainEdge]
    hop_facts: dict[str, HopPathFacts]
    counts: dict[str, Any]


# ---------------------------------------------------------------- per-hop helpers

def chainable(hop: Hop) -> bool:
    """A hop takes part in chaining when it is a seed (ST-23, ST-72 chains seeds only, Q13) and not
    machine-account-only (Q15 (b), decision 050 item 4: the DB flag on every member, as identity uses)."""
    return bool(hop.is_seed) and not hop.machine_account_only


def hop_clock_unreliable(hop: Hop, sl: SubjectLinks) -> int:
    """The hop's ``clock_unreliable`` (``hops.csv``, and the input of an edge's flag): the larger of the
    members' event flag and the source / target host flag (ST-02 both parts). WHY one definition: the hop file
    and the edge file must agree on which hops have an unreliable clock."""
    return max(int(hop.clock_unreliable), int(sl.host_clock_unreliable))


def first_ranked_sessions(hv: HopVerdicts) -> set[SessionKey]:
    """Session keys with ``link_rank`` 1, any tier (ties share rank 1). Used by the notes (decision 050 item 5):
    rank-2 candidates are the ones the ranking set aside."""
    return {k for k, v in hv.sessions.items() if v.link_rank == 1}


def first_ranked_ab_sessions(hv: HopVerdicts) -> set[SessionKey]:
    """Session keys with ``link_rank`` 1 and tier A or B: the only sessions that make a ``session`` edge (ST-72)
    or give source-session nodes (ST-71). WHY: a tier C / D link is too weak to say which session moved."""
    return {k for k, v in hv.sessions.items() if v.link_rank == 1 and v.confidence_tier in STRONG_TIERS}


def hop_order(hop: Hop) -> tuple[int, str]:
    """(corrected first-member time, hop id): the time order of hops inside a path, of edges and of path ids.
    WHY corrected: hops on different hosts are compared (ST-02); the hop id makes the order total."""
    return (hop.first_us, hop.hop_id)


def source_label(hop: Hop, sl: SubjectLinks | None) -> str:
    """The source side of the ``hosts`` spelling (050 item 6): the source host, else the source IP, else ""."""
    if sl is not None and sl.source_host:
        return sl.source_host
    return hop.source_ip or ""


def hop_hosts(hop: Hop, sl: SubjectLinks | None) -> str:
    """``source>target`` of one hop (050 item 6). WHY per hop: a merged path need not be a line (s05: two hops
    enter ep-02), so a single host sequence would mislead."""
    return f"{source_label(hop, sl)}>{hop.target_host}"


# ---------------------------------------------------------------- edges (ST-72)

def _member_sessions(hop: Hop) -> set[SessionKey]:
    """The members' session keys on the target (a NULL logon ID forms no session, decision 005)."""
    return {m.session_key for m in hop.members if m.session_key is not None}


def _edge(h1: Hop, h2: Hop, links: Mapping[str, SubjectLinks], verdicts: Mapping[str, HopVerdicts],
          tol_us: int) -> ChainEdge | None:
    """The edge H1 -> H2, or None. Conditions (ST-72, 050 item 2): H2's source host is known and is H1's target
    host, and H2.first >= H1.first - tol (inclusive, µs exact). Type ``session`` when a first-ranked tier A / B
    session of H2 is one of H1's member sessions, compared on the full key (050 item 3: a logon ID can repeat
    after a boot); otherwise ``host_time``."""
    src = links[h2.hop_id].source_host
    if src is None or src != h1.target_host:
        return None
    d_us = h2.first_us - h1.first_us
    if d_us < -tol_us:
        return None
    shared = tuple(sorted(first_ranked_ab_sessions(verdicts[h2.hop_id]) & _member_sessions(h1)))
    flag = max(hop_clock_unreliable(h1, links[h1.hop_id]), hop_clock_unreliable(h2, links[h2.hop_id]))
    return ChainEdge(from_hop_id=h1.hop_id, to_hop_id=h2.hop_id,
                     link_type=LINK_SESSION if shared else LINK_HOST_TIME, time_delta_us=d_us,
                     time_delta_ms=delta_ms(h2.first_us, h1.first_us),
                     order_within_tolerance=int(abs(d_us) <= tol_us), clock_unreliable=flag,
                     supporting_sessions=shared)


def chain_edges(hops: Iterable[Hop], links: Mapping[str, SubjectLinks], verdicts: Mapping[str, HopVerdicts],
                params: StitchParams = StitchParams()) -> list[ChainEdge]:
    """Every ST-72 edge over ordered pairs of distinct chainable hops, sorted by (from-hop order, to-hop order).

    WHY every ordered pair: with the ±``order_tol_s`` tolerance both A -> B and B -> A can hold (a 2-cycle), and
    the rule is symmetric in neither host nor time, so no pair may be skipped. Non-chainable hops (non-seeds,
    machine-account-only seeds) never appear (Q13, Q15 (b)).
    """
    tol_us = seconds_to_us(params.order_tol_s)
    cands = sorted((h for h in hops if chainable(h)), key=hop_order)
    out: list[ChainEdge] = []
    for h1 in cands:
        for h2 in cands:
            if h1.hop_id == h2.hop_id:
                continue
            e = _edge(h1, h2, links, verdicts, tol_us)
            if e is not None:
                out.append(e)
    return out


# ---------------------------------------------------------------- components and chains (ST-73)

def components(hop_ids: Sequence[str], edges: Iterable[ChainEdge]) -> list[list[str]]:
    """Weakly connected components of the graph (``hop_ids``, ``edges``), each in the order of ``hop_ids``,
    listed in the order of their first member. Edges touching an id outside ``hop_ids`` are ignored.

    WHY weakly: ST-73 merges maximal chains that share a hop, transitively; two chains meeting at a hop from
    different parents (s05) or leaving one hop to different children are one path either way (050 item 1).
    """
    pos = {h: i for i, h in enumerate(hop_ids)}
    parent = list(range(len(hop_ids)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for e in edges:
        if e.from_hop_id in pos and e.to_hop_id in pos:
            a, b = find(pos[e.from_hop_id]), find(pos[e.to_hop_id])
            if a != b:
                parent[max(a, b)] = min(a, b)
    groups: dict[int, list[str]] = {}
    for h in hop_ids:
        groups.setdefault(find(pos[h]), []).append(h)
    return sorted(groups.values(), key=lambda g: pos[g[0]])


def maximal_chains(component_hop_ids: Sequence[str], edges: Iterable[ChainEdge]) -> list[tuple[str, ...]]:
    """The maximal simple chains of one component: hop sequences along edges with no repeated hop that cannot be
    extended at the start by a parent, nor at the end by a child, that is not already in the chain.

    ``component_hop_ids`` must be in hop order; chains are sorted by the hop-order positions of their hops, so
    the result is deterministic. A hop with no edge gives one chain of length 1. WHY simple paths and not
    "chains from parentless hops": ±``order_tol_s`` allows a 2-cycle, which has no parentless hop (050 item 1);
    the visited check makes the search stop on any cycle. Display only: path membership never uses this.
    """
    pos = {h: i for i, h in enumerate(component_hop_ids)}
    children: dict[str, list[str]] = {h: [] for h in component_hop_ids}
    parents: dict[str, set[str]] = {h: set() for h in component_hop_ids}
    for e in edges:
        if e.from_hop_id in pos and e.to_hop_id in pos:
            children[e.from_hop_id].append(e.to_hop_id)
            parents[e.to_hop_id].add(e.from_hop_id)
    for h in children:
        children[h] = sorted(set(children[h]), key=pos.__getitem__)

    out: list[tuple[str, ...]] = []

    def walk(chain: list[str], seen: set[str]) -> None:
        nxt = [c for c in children[chain[-1]] if c not in seen]
        if not nxt:
            if parents[chain[0]] <= seen:
                out.append(tuple(chain))
            return
        for c in nxt:
            chain.append(c)
            seen.add(c)
            walk(chain, seen)
            seen.discard(c)
            chain.pop()

    for start in component_hop_ids:
        walk([start], {start})
    return sorted(out, key=lambda ch: [pos[h] for h in ch])


def chain_text(chain: Sequence[str]) -> str:
    """One ``merged_from`` item: hop ids joined by ``>`` (050 item 1)."""
    return ">".join(chain)


def edge_types_text(counts: Mapping[str, int]) -> str:
    """``host_time:N;session:M`` (050 item 6), in ``LINK_TYPES`` order. WHY here: ``paths.csv`` and
    ``report.md`` must spell it the same way, from one definition next to the link types."""
    return ";".join(f"{t}:{counts.get(t, 0)}" for t in LINK_TYPES)


def path_id(trial_id: str, n: int) -> str:
    """``<trial>-p<NNNN>``, 1-based (050 item 6)."""
    return f"{trial_id}-p{n:04d}"


# ---------------------------------------------------------------- assembly

def _path_groups(hops: Sequence[Hop], edges: Sequence[ChainEdge]) -> list[list[str]]:
    """Hop-id groups of the paths, each in hop order, groups in order of their first hop: the components over
    the chainable seeds, plus one singleton per other seed (Q15 (b): still a seed, its own path; ST-74). Non-seed
    hops are in no group (ST-23, ST-70)."""
    ordered = sorted(hops, key=hop_order)
    order_pos = {h.hop_id: i for i, h in enumerate(ordered)}
    groups = components([h.hop_id for h in ordered if chainable(h)], edges)
    groups += [[h.hop_id] for h in ordered if h.is_seed and not chainable(h)]
    return sorted(groups, key=lambda g: order_pos[g[0]])


def _build_path(pid: str, hop_ids: list[str], by_id: Mapping[str, Hop], links: Mapping[str, SubjectLinks],
                edges: Sequence[ChainEdge]) -> Path:
    """One ``Path`` from its hop ids (already in hop order) and all trial edges (only its own are kept)."""
    members = set(hop_ids)
    own = [e for e in edges if e.from_hop_id in members and e.to_hop_id in members]
    triggers = sorted({t for h in hop_ids for t in by_id[h].trigger_ids})
    return Path(path_id=pid, hop_ids=list(hop_ids),
                hosts=[hop_hosts(by_id[h], links.get(h)) for h in hop_ids], n_hops=len(hop_ids),
                seed_trigger_ids=triggers,
                merged_from=[chain_text(c) for c in maximal_chains(hop_ids, own)],
                isolated=int(len(hop_ids) == 1 and not own),
                edge_types={t: sum(1 for e in own if e.link_type == t) for t in LINK_TYPES}, edges=own)


def _hop_facts(hops: Sequence[Hop], edges: Sequence[ChainEdge], path_of: Mapping[str, str]
               ) -> dict[str, HopPathFacts]:
    """``HopPathFacts`` for every hop (seed or not), keyed and sorted by hop id."""
    order = {h.hop_id: hop_order(h) for h in hops}
    parents: dict[str, set[str]] = {}
    for e in edges:
        parents.setdefault(e.to_hop_id, set()).add(e.from_hop_id)
    out: dict[str, HopPathFacts] = {}
    for h in sorted(hops, key=lambda x: x.hop_id):
        ps = sorted(parents.get(h.hop_id, set()), key=order.__getitem__)
        pid = path_of.get(h.hop_id)
        out[h.hop_id] = HopPathFacts(hop_id=h.hop_id, chain_parent_count=len(ps), chain_parent_hop_ids=ps,
                                     multi_chain_parent=int(len(ps) > 1), in_path=int(pid is not None),
                                     path_id=pid)
    return out


def _path_counts(hops: Sequence[Hop], paths: Sequence[Path], edges: Sequence[ChainEdge],
                 facts: Mapping[str, HopPathFacts]) -> dict[str, Any]:
    """The path part of ``stats.json`` (spec 3; ST-04, ST-23, L-ST2). Ids sorted."""
    return {
        "chain_edges_by_type": {t: sum(1 for e in edges if e.link_type == t) for t in LINK_TYPES},
        "paths": len(paths),
        "multi_hop_paths": sum(1 for p in paths if p.n_hops > 1),
        "isolated_paths": sum(1 for p in paths if p.isolated),
        "seeds": sum(1 for h in hops if h.is_seed),
        "chainable_seeds": sum(1 for h in hops if chainable(h)),
        "multi_chain_parent_hops": {k: list(f.chain_parent_hop_ids) for k, f in sorted(facts.items())
                                    if f.multi_chain_parent},
        "hops_in_no_path": sorted(k for k, f in facts.items() if not f.in_path),
        "non_seed_hops": sorted(h.hop_id for h in hops if not h.is_seed),
    }


def build_paths(li: LinkIndex, params: StitchParams = StitchParams()) -> PathSet:
    """Edges (ST-72), paths (ST-70, ST-73, ST-74), per-hop path facts and counts of one trial. Pure.

    Path ids are numbered by each path's earliest hop (corrected first member, then hop id; 050 item 1).
    Every seed is in exactly one path; no seed is dropped, an isolated ``target_only`` seed included (ST-74).
    """
    hops = list(li.hopset.hops)
    by_id = {h.hop_id: h for h in hops}
    edges = chain_edges(hops, li.links, li.verdicts, params)
    paths = [_build_path(path_id(li.trial_id, i), g, by_id, li.links, edges)
             for i, g in enumerate(_path_groups(hops, edges), start=1)]
    path_of = {h: p.path_id for p in paths for h in p.hop_ids}
    facts = _hop_facts(hops, edges, path_of)
    return PathSet(trial_id=li.trial_id, paths=paths, edges=edges, hop_facts=facts,
                   counts=_path_counts(hops, paths, edges, facts))
