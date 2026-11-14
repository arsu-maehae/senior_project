"""Link ids of a hop: the one numbering of its link rows (spec 03_stitch section 3 ``links.csv`` ``link_id``;
T7.4 task 3; T7.5 ST-71, decision 050 item 7).

WHY a module of its own (moved out of ``outputs`` in T7.5): ``links.csv`` and ``path_nodes.csv`` must name the
same link row with the same id. Path nodes are built in ``nodes`` / ``paths``, which ``outputs`` will import to
write their files; if the numbering stayed in ``outputs`` those modules would have to import ``outputs`` back
(an import cycle) or copy the rule (two definitions that could drift). Here it is defined once and both sides
import it.

Pure: no file, no DB, no global state. ``LinkIndex`` is imported for type hints only, so this module can be
imported by anything ``links`` imports without a cycle.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Mapping

from .hops import Hop
from .params import METHODS
from .sessions import SessionKey
from .source import METHOD_TARGET_ONLY, LinkRow
from .tiers import HopVerdicts, SessionVerdict

if TYPE_CHECKING:  # WHY only for hints: ``links`` builds the LinkIndex; a runtime import is not needed here
    from .links import LinkIndex

__all__ = ["link_id", "link_sort_key", "ordered_link_rows", "numbered_link_rows"]

_METHOD_ORDER: dict[str, int] = {m: i for i, m in enumerate(METHODS)}
# Row groups of a hop, in link-id order: candidate sessions, unresolved process rows, the target_only row.
_GROUP_SESSION, _GROUP_UNRESOLVED, _GROUP_TARGET_ONLY = 0, 1, 2


def link_id(hop_id: str, n: int) -> str:
    """``<hop_id>-l<NN>``: 1-based, at least 2 digits, more when a hop has 100 rows or more (spec 3)."""
    return f"{hop_id}-l{n:02d}"


def link_sort_key(r: LinkRow, sv: Mapping[SessionKey, SessionVerdict]) -> tuple:
    """Link-id order inside one hop (T7.4 task 3): session rows by (``link_rank``, method order, session key);
    then unresolved rows by (method order, reason); then the ``target_only`` row.

    WHY rank first: link ids then read best-first, like the ranking itself; method and session key only make the
    order total. Time is not a key (Q14), as for the rank.
    """
    method = _METHOD_ORDER.get(r.method, len(_METHOD_ORDER))
    if r.method == METHOD_TARGET_ONLY:
        return (_GROUP_TARGET_ONLY, 0, 0, ())
    if r.session_key is None:
        return (_GROUP_UNRESOLVED, method, r.session_unresolved_reason, ())
    verdict = sv.get(r.session_key)
    if verdict is None:
        raise ValueError(f"link row of session {r.session_key!r} has no T7.4 verdict")
    return (_GROUP_SESSION, verdict.link_rank, method, r.session_key)


def ordered_link_rows(rows: Iterable[LinkRow], verdicts: HopVerdicts) -> list[LinkRow]:
    """The hop's link rows in link-id order (``link_sort_key``). ValueError for a session row with no verdict
    (T7.4 builds one for every candidate session, so a gap means a broken run)."""
    return sorted(rows, key=lambda r: link_sort_key(r, verdicts.sessions))


def numbered_link_rows(hop: Hop, li: LinkIndex) -> list[tuple[str, LinkRow]]:
    """(link id, ``LinkRow``) of every link row of ``hop``, in link-id order, numbered from 1.

    WHY one function for both files: ``links.csv`` rows and ``path_nodes.csv`` ``link_id`` values must come from
    the same numbering (decision 050 item 7). A hop with no links or no verdicts is a broken run (T7.3 / T7.4
    build both for every hop) and raises ValueError instead of numbering a partial set.
    """
    sl = li.links.get(hop.hop_id)
    hv = li.verdicts.get(hop.hop_id)
    if sl is None or hv is None:
        raise ValueError(f"{hop.hop_id}: no link rows or no T7.4 verdicts")
    return [(link_id(hop.hop_id, i), r) for i, r in enumerate(ordered_link_rows(sl.rows, hv), start=1)]
