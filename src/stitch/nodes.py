"""T7.5 path nodes and path notes (spec 03_stitch ST-71, ST-73, ST-01; decision 050 items 5 and 7).

WHY pure and separate from ``paths``: which hops form a path (ST-72, ST-73) never depends on nodes; nodes are the
path's content for T8 / T9 (Sigma labels, scores). Keeping them apart makes that visible in the code: nothing in
this module can change a path's membership. The notes (``shared_source_session_with``, ``shared_event_with``) are
written next to the paths and never merge them (ST-73, owner Q7).

Nodes of one hop of a path (ST-71, 050 item 7), one row per (path, hop, role, event uid, link id):
- ``target_logon`` (context 0): every uid of every member 4624, ST-05 copies kept.
- ``artefact`` (context 0; ``followup_logon`` rows context 1): every uid of the hop's artefact rows.
- ``source_evidence`` (context 0): the evidence uids of the link rows of the hop's first-ranked sessions, any
  tier (the spec text; 050 item 7).
- ``source_session_event`` (context 1): events of a first-ranked source session of tier A or B only, at or
  before the hop's last member on corrected time (no tolerance, 050 item 7).
- ``target_session_event`` (context 1): events of the members' sessions on the target, whole window.

Every node event must be an in-window scan event (ST-01): its corrected time is read from ``LinkIndex.event_us``,
which holds exactly the in-window rows, and a uid missing there raises ValueError instead of being written.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Mapping, Sequence

from .artefacts import ArtefactRow
from .hops import FOLLOWUP_KIND, Hop
from .linkids import numbered_link_rows
from .links import LinkIndex
from .params import StitchParams
from .paths import PathSet, build_paths, first_ranked_ab_sessions, first_ranked_sessions, hop_order
from .sessions import SessionKey
from .source import LinkRow

__all__ = ["ROLE_TARGET_LOGON", "ROLE_ARTEFACT", "ROLE_SOURCE_EVIDENCE", "ROLE_SOURCE_SESSION_EVENT",
           "ROLE_TARGET_SESSION_EVENT", "ROLES", "PathNode", "event_time", "target_logon_nodes", "artefact_nodes",
           "source_evidence_nodes", "source_session_nodes", "target_session_nodes", "hop_nodes", "dedupe_nodes",
           "build_nodes", "path_notes", "apply_notes", "build_path_outputs"]

ROLE_TARGET_LOGON = "target_logon"
ROLE_ARTEFACT = "artefact"
ROLE_SOURCE_EVIDENCE = "source_evidence"
ROLE_SOURCE_SESSION_EVENT = "source_session_event"
ROLE_TARGET_SESSION_EVENT = "target_session_event"
# Spec 3 ``role`` values, in the row order used when two nodes have the same time.
ROLES: tuple[str, ...] = (ROLE_TARGET_LOGON, ROLE_ARTEFACT, ROLE_SOURCE_EVIDENCE, ROLE_SOURCE_SESSION_EVENT,
                          ROLE_TARGET_SESSION_EVENT)
_ROLE_POS: dict[str, int] = {r: i for i, r in enumerate(ROLES)}


@dataclass(frozen=True)
class PathNode:
    """One ``path_nodes.csv`` row (spec 3) plus ``us``, the event's corrected time, used only to order rows.

    ``session_id``: the decimal logon ID of the session the node belongs to (D1: an integer; the spec has no hex
    column here), None when the node has none (an install with no member, an unknown follow-up logon ID).
    ``link_id``: the ``links.csv`` id of the link row the node comes from (source roles), "" otherwise.
    ``context`` = 1 for session events and follow-up logons (ST-71): content around the hop, not the hop itself.
    """
    path_id: str
    hop_id: str
    role: str
    context: int
    host: str
    session_id: int | None
    event_uid: str
    link_id: str
    us: int


# ---------------------------------------------------------------- helpers

def event_time(uid: str, event_us: Mapping[str, int]) -> int:
    """Corrected time of a node event. ValueError when the uid is not an in-window scan event: a node must never
    name an event outside the window (ST-01), so a missing uid means a broken input, not a value to guess."""
    try:
        return event_us[uid]
    except KeyError:
        raise ValueError(f"node event {uid!r} is not an in-window scan event (ST-01)") from None


def _node(pid: str, hop: Hop, role: str, context: int, host: str, session_id: int | None, uid: str, link_id: str,
          event_us: Mapping[str, int]) -> PathNode:
    """A ``PathNode`` with its corrected time looked up (and checked) through ``event_time``."""
    return PathNode(path_id=pid, hop_id=hop.hop_id, role=role, context=context, host=host,
                    session_id=session_id, event_uid=uid, link_id=link_id, us=event_time(uid, event_us))


def _member_logon_ids(hop: Hop) -> dict[str, int | None]:
    """Every uid of every member (representative and ST-05 copies) -> that member's logon ID."""
    return {u: m.logon_id for m in hop.members for u in [m.uid, *m.event_uids]}


def _followup_logon_ids(hop: Hop, li: LinkIndex) -> dict[str, int | None]:
    """Every uid of the hop's follow-up logons -> that logon's own logon ID (ST-26). WHY per uid: one
    ``followup_logon`` artefact row can hold several logons with different logon IDs."""
    logons = list(hop.followups) + [lg for f in li.hopset.followups if f.hop_id == hop.hop_id for lg in f.logons]
    return {u: lg.logon_id for lg in logons for u in [lg.uid, *lg.event_uids]}


# ---------------------------------------------------------------- roles (ST-71)

def target_logon_nodes(pid: str, hop: Hop, event_us: Mapping[str, int]) -> list[PathNode]:
    """``target_logon``: every uid of every member 4624 (ST-05 copies kept, so each copy can be traced), context 0,
    on the target with the member's logon ID."""
    return [_node(pid, hop, ROLE_TARGET_LOGON, 0, hop.target_host, m.logon_id, u, "", event_us)
            for m in hop.members for u in m.event_uids]


def artefact_nodes(pid: str, hop: Hop, rows: Iterable[ArtefactRow], li: LinkIndex) -> list[PathNode]:
    """``artefact``: every uid of the hop's artefact rows, on the target. Context 1 for ``followup_logon`` rows
    (ST-71: a follow-up logon is context, not the move itself), else 0. ``session_id`` = the logon ID of the
    row's member (``member_logon_uid``); for a follow-up row, the follow-up logon's own logon ID; None when the
    row names no member (an install tied by file name and time)."""
    members = _member_logon_ids(hop)
    followups = _followup_logon_ids(hop, li)
    out: list[PathNode] = []
    for r in rows:
        if r.hop_id != hop.hop_id:
            continue
        followup = r.kind == FOLLOWUP_KIND
        for u in r.event_uids:
            sid = followups.get(u) if followup else members.get(r.member_logon_uid)
            out.append(_node(pid, hop, ROLE_ARTEFACT, int(followup), hop.target_host, sid, u, "", li.event_us))
    return out


def _rank1_rows(hop: Hop, li: LinkIndex) -> list[tuple[str, LinkRow]]:
    """(link id, row) of the hop's link rows whose session has ``link_rank`` 1 (any tier), in link-id order.
    Rows with no session (unresolved, ``target_only``) have no rank and give no source node."""
    rank1 = first_ranked_sessions(li.verdicts[hop.hop_id])
    return [(lid, r) for lid, r in numbered_link_rows(hop, li) if r.session_key is not None and r.session_key in rank1]


def _source_host(r: LinkRow) -> str:
    """The source host of a session row: the row's ``source_host``, else the session key's host (the session,
    and so its evidence, lives on that host)."""
    assert r.session_key is not None
    return r.source_host or r.session_key[0]


def source_evidence_nodes(pid: str, hop: Hop, li: LinkIndex) -> list[PathNode]:
    """``source_evidence``: the ``evidence_uids`` (source events only, never the matched member uids) of every
    link row of a first-ranked session, any tier (ST-71 text, 050 item 7), context 0. One node per (event, link
    id): the same event found by two methods stays traceable to both rows."""
    return [_node(pid, hop, ROLE_SOURCE_EVIDENCE, 0, _source_host(r), r.source_session_id, u, lid, li.event_us)
            for lid, r in _rank1_rows(hop, li) for u in r.evidence_uids]


def source_session_nodes(pid: str, hop: Hop, li: LinkIndex) -> list[PathNode]:
    """``source_session_event`` (context 1): events of each first-ranked tier A / B source session whose
    corrected time is at or before the hop's last member's corrected time.

    WHY A / B only (ST-71): a tier C / D link does not establish which session moved, so its processes are not
    the hop's content. WHY corrected time and no tolerance: the source events and the target 4624 are on
    different hosts, so they are compared on the corrected basis (decision 014, ST-02); 050 item 7 fixes the
    cutoff at "≤ last member" with no tolerance. ``link_id`` = the session's first row in link-id order.
    """
    if li.index is None:
        raise ValueError("LinkIndex.index is missing: source-session nodes need the process index (T7.5)")
    strong = first_ranked_ab_sessions(li.verdicts[hop.hop_id])
    first_lid: dict[SessionKey, str] = {}
    for lid, r in numbered_link_rows(hop, li):
        if r.session_key in strong and r.session_key not in first_lid:
            first_lid[r.session_key] = lid
    out: list[PathNode] = []
    for key in sorted(first_lid):
        for u in li.index.processes.events_of_session(key):
            n = _node(pid, hop, ROLE_SOURCE_SESSION_EVENT, 1, key[0], key[1], u, first_lid[key], li.event_us)
            if n.us <= hop.last_us:
                out.append(n)
    return out


def target_session_nodes(pid: str, hop: Hop, li: LinkIndex) -> list[PathNode]:
    """``target_session_event`` (context 1): events of every distinct member session on the target, whole window
    (050 item 7). Follow-up logons' sessions add nothing (050 item 7): they are context artefacts already."""
    if li.index is None:
        raise ValueError("LinkIndex.index is missing: target-session nodes need the process index (T7.5)")
    keys = sorted({m.session_key for m in hop.members if m.session_key is not None})
    return [_node(pid, hop, ROLE_TARGET_SESSION_EVENT, 1, hop.target_host, key[1], u, "", li.event_us)
            for key in keys for u in li.index.processes.events_of_session(key)]


def hop_nodes(pid: str, hop: Hop, li: LinkIndex) -> list[PathNode]:
    """All ST-71 nodes of one hop of path ``pid``, undeduplicated and unsorted (``build_nodes`` does both)."""
    return (target_logon_nodes(pid, hop, li.event_us) + artefact_nodes(pid, hop, li.artefacts.rows, li)
            + source_evidence_nodes(pid, hop, li) + source_session_nodes(pid, hop, li)
            + target_session_nodes(pid, hop, li))


# ---------------------------------------------------------------- order and assembly

def _full_key(n: PathNode, hop_pos: Mapping[str, tuple[int, str]]) -> tuple:
    """Row order (path, hop order, time, role order, uid, link id), then context and session id so that the
    order is total even for two rows that differ only there."""
    return (n.path_id, hop_pos[n.hop_id], n.us, _ROLE_POS[n.role], n.event_uid, n.link_id, n.context,
            -1 if n.session_id is None else n.session_id, n.host)


def dedupe_nodes(nodes: Iterable[PathNode], hop_pos: Mapping[str, tuple[int, str]]) -> list[PathNode]:
    """Sort by ``_full_key`` and keep the first row per (path, hop, role, uid, link id), the ST-71 row identity.
    WHY first after sorting: when two artefact rows of a hop hold the same uid, the context-0 reading wins,
    deterministically."""
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[PathNode] = []
    for n in sorted(nodes, key=lambda x: _full_key(x, hop_pos)):
        k = (n.path_id, n.hop_id, n.role, n.event_uid, n.link_id)
        if k not in seen:
            seen.add(k)
            out.append(n)
    return out


def build_nodes(li: LinkIndex, pathset: PathSet) -> list[PathNode]:
    """Every ``path_nodes.csv`` row of the trial (ST-71): the nodes of every hop of every path, deduplicated and
    in row order. Pure. Nodes never change a path (ST-73)."""
    by_id = {h.hop_id: h for h in li.hopset.hops}
    hop_pos = {h: hop_order(by_id[h]) for p in pathset.paths for h in p.hop_ids}
    raw = [n for p in pathset.paths for h in p.hop_ids for n in hop_nodes(p.path_id, by_id[h], li)]
    return dedupe_nodes(raw, hop_pos)


# ---------------------------------------------------------------- notes (ST-73)

def _overlaps(sets: Mapping[str, set]) -> dict[str, list[str]]:
    """Path id -> the other path ids (sorted) whose set shares at least one item with its own."""
    return {p: sorted(q for q, other in sets.items() if q != p and mine & other) for p, mine in sets.items()}


def path_notes(li: LinkIndex, pathset: PathSet, nodes: Sequence[PathNode]
               ) -> dict[str, tuple[list[str], list[str]]]:
    """Path id -> (``shared_source_session_with``, ``shared_event_with``) (ST-73, 050 item 5).

    Source sessions: the first-ranked session keys (any tier) of the path's hops, compared on the full key; rank-2
    candidates are left out because the ranking set them aside. Events: every node uid of the path, context rows
    included. WHY notes and never a merge (ST-73, owner Q7): two hops of one agent session are separate moves; a
    reader sees the link through the note, while the paths stay as chaining built them.
    """
    sessions = {p.path_id: {k for h in p.hop_ids for k in first_ranked_sessions(li.verdicts[h])}
                for p in pathset.paths}
    events: dict[str, set[str]] = {p.path_id: set() for p in pathset.paths}
    for n in nodes:
        events[n.path_id].add(n.event_uid)
    shared_s, shared_e = _overlaps(sessions), _overlaps(events)
    return {p.path_id: (shared_s[p.path_id], shared_e[p.path_id]) for p in pathset.paths}


def apply_notes(pathset: PathSet, notes: Mapping[str, tuple[list[str], list[str]]]) -> PathSet:
    """A new ``PathSet`` whose paths carry the notes; the input is not changed. Membership, edges, hop facts
    and counts are the same objects: notes never alter a path (ST-73)."""
    paths = [replace(p, shared_source_session_with=list(notes[p.path_id][0]),
                     shared_event_with=list(notes[p.path_id][1])) for p in pathset.paths]
    return replace(pathset, paths=paths)


def build_path_outputs(li: LinkIndex, params: StitchParams = StitchParams()) -> tuple[PathSet, list[PathNode]]:
    """The one T7.5 entry point: paths (``paths.build_paths``), their nodes, then the notes applied.

    WHY in this order and in one place: the nodes are built from the PathSet whose notes are then filled, and the
    notes are computed from those nodes (``shared_event_with``), so the three can never come from different
    path sets. Notes never change membership (ST-73), so the returned paths have the same hops and ids as the
    nodes refer to. Pure.
    """
    pathset = build_paths(li, params)
    nodes = build_nodes(li, pathset)
    return apply_notes(pathset, path_notes(li, pathset, nodes)), nodes
