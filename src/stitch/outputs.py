"""Writer side of the stitch CSVs: rows and CSV text of ``links.csv``, ``hop_artefacts.csv``, ``hop_identity.csv``
(T7.4) and ``hops.csv``, ``paths.csv``, ``path_edges.csv``, ``path_nodes.csv`` (T7.5) (spec 03_stitch section 3;
ST-01, ST-02, ST-04, ST-23, ST-45..ST-50, ST-49, ST-60..ST-64, ST-70..ST-74; decisions 038, 049 items 3, 4, 6, 7,
050 items 6, 8; D1).

WHY a separate pure module: every value of the files is already decided in the ``LinkIndex`` (T7.3 link rows,
T7.4 verdicts and identity rows, the artefact set), the ``PathSet`` and the path nodes. This module only spells
those values as text, in the spec's column order and a fixed row order, so the bytes are the same on every run
on the same inputs (spec 3). It opens no file and no DB; ``stitch.__main__`` writes the text.

WHY built field by field from named columns and never by dumping dataclasses: a field added to ``LinkRow`` or
``IdentityRow`` later (a credential account, a command fragment) can then never reach a file by accident. The
only text columns are: hosts, uids, method / reason / verdict vocabularies, target-side names (artefact names
and the matched ``name_check_names``, both taken from target-side events, spec 2), and the four account / image
columns that are DB fields of referenced events (``source_session_account`` and ``account``: a 4624
``account_name``; ``dump_source_image`` / ``dump_account``: the Sysmon 10 ``source_image`` / ``account_name``;
049 item 7), plus ``hops.csv`` ``member_accounts`` (each member 4624's ``account_name``, 050 item 8). No value
comes from a command line.

Cell spelling: None -> empty; lists / tuples -> ``;``-joined in their stored order (None items empty); logon IDs
as a decimal integer plus a separate hex column (D1); times as ``fmt_us`` text.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Iterable, Mapping, Sequence

from gate.timeutil import fmt_us

from .artefacts import ArtefactRow, row_order
from .hops import Hop
from .identity import IdentityRow
from .linkids import link_id, link_sort_key, numbered_link_rows, ordered_link_rows
from .links import LinkIndex
from .nodes import PathNode
from .paths import ChainEdge, HopPathFacts, Path, PathSet, edge_types_text, hop_clock_unreliable, hop_order
from .source import METHOD_TARGET_ONLY, LinkRow
from .tiers import ACCOUNT_NONE, HopVerdicts, SessionVerdict

__all__ = ["LINKS_COLUMNS", "ARTEFACT_COLUMNS", "IDENTITY_COLUMNS", "LINKS_FILE", "ARTEFACT_FILE", "IDENTITY_FILE",
           "TIER_NO_SESSION", "BASIS_NO_SESSION", "BASIS_TARGET_ONLY", "cell", "link_id", "ordered_link_rows",
           "link_sort_key", "numbered_link_rows", "link_row", "link_rows", "artefact_row", "artefact_rows",
           "identity_row", "identity_rows", "csv_text", "HOPS_FILE", "PATHS_FILE", "EDGES_FILE", "NODES_FILE",
           "HOPS_COLUMNS", "PATHS_COLUMNS", "EDGES_COLUMNS", "NODES_COLUMNS", "CHAIN_SEPARATOR", "hop_row",
           "hop_rows", "path_row", "path_rows", "edge_row", "edge_rows", "node_row", "node_rows"]

LINKS_FILE, ARTEFACT_FILE, IDENTITY_FILE = "links.csv", "hop_artefacts.csv", "hop_identity.csv"
HOPS_FILE, PATHS_FILE, EDGES_FILE, NODES_FILE = "hops.csv", "paths.csv", "path_edges.csv", "path_nodes.csv"

# Spec 03_stitch section 3, in spec order. WHY tuples here and nowhere else: a test can compare them with the spec,
# and ``csv_text`` refuses a row whose keys differ, so a column cannot be added or dropped silently.
LINKS_COLUMNS: tuple[str, ...] = (
    "link_id", "hop_id", "method", "session_methods", "source_host", "source_session_id", "source_session_id_hex",
    "session_unresolved_reason", "source_session_account", "source_session_logon_type", "source_session_logon_uid",
    "account_match", "account_match_members", "account_match_member_count", "name_check", "name_check_names",
    "name_check_event_uids", "candidate_count", "candidate_count_all", "candidate_count_account",
    "matched_member_count", "time_delta_ms", "time_delta_raw_ms", "supporting_event_uids", "confidence_tier",
    "link_rank", "tie", "rank_basis", "target_only_reason", "clock_unreliable",
)
ARTEFACT_COLUMNS: tuple[str, ...] = (
    "hop_id", "kind", "member_logon_uid", "logged_under_hop_id", "method", "candidate_count", "time_delta_ms",
    "supporting_span_ms", "confidence_tier", "event_uids", "names", "untied_same_name_bursts",
)
IDENTITY_COLUMNS: tuple[str, ...] = (
    "hop_id", "account", "source_host", "move_utc_corrected", "dump_event_uid", "dump_utc_corrected",
    "dump_source_image", "dump_account", "gap_ms", "order_margin_ms", "order_ok", "order_within_tolerance",
    "order_within_uncertainty", "offset_unc_source_ms", "offset_unc_target_ms", "open_session_uids",
    "open_session_types", "session_open_before_window", "end_unknown_session_uids", "not_applicable",
    "clock_unreliable",
)
HOPS_COLUMNS: tuple[str, ...] = (
    "hop_id", "target_host", "source_ip", "ip_kind", "source_host", "first_utc", "first_utc_corrected",
    "last_utc_corrected", "member_count", "member_logon_uids", "member_logon_ids", "member_logon_ids_hex",
    "member_accounts", "member_ports", "mixed_account", "protocol", "rules", "chain_parent_count",
    "chain_parent_hop_ids", "multi_chain_parent", "trigger_ids", "is_seed", "in_path", "authentication_packages",
    "confirm", "confirm_event_uids", "inside_gap_max_ms", "prev_gap_ms", "next_gap_ms", "gap_near_threshold",
    "splits_at_1s", "merges_at_3s", "service_install_count", "shares_port_with_hops", "followup_logon_uids",
    "followup_logon_count", "candidate_count", "best_tier", "evidence_before_range", "evidence_after_range",
    "supporting_span_ms", "clock_unreliable", "gate_clock_unreliable",
)
PATHS_COLUMNS: tuple[str, ...] = (
    "path_id", "hop_ids", "hosts", "n_hops", "seed_trigger_ids", "merged_from", "isolated", "edge_types",
    "shared_source_session_with", "shared_event_with",
)
EDGES_COLUMNS: tuple[str, ...] = (
    "path_id", "from_hop_id", "to_hop_id", "link_type", "time_delta_ms", "order_within_tolerance", "clock_unreliable",
)
NODES_COLUMNS: tuple[str, ...] = (
    "path_id", "hop_id", "role", "context", "host", "session_id", "event_uid", "link_id",
)
# 050 item 1: ``merged_from`` chains are ``|``-joined (each chain is ``h>h``), because ``;`` already separates
# list items in every other column.
CHAIN_SEPARATOR = "|"

# 049 item 4: what a row with no session carries (an unresolved process row or the ``target_only`` row).
TIER_NO_SESSION = "D"
BASIS_NO_SESSION, BASIS_TARGET_ONLY = "no_session", "target_only"


# ---------------------------------------------------------------- cells

def cell(value: Any) -> str:
    """One CSV cell: None -> "", bool -> 0 / 1, list / tuple -> ``;``-joined cells, everything else ``str``.

    WHY one function: every file must spell an empty value, a flag and a list the same way, or two runs (or two
    files) could disagree on text while agreeing on facts.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return str(int(value))
    if isinstance(value, (list, tuple)):
        return ";".join(cell(v) for v in value)
    return str(value)


def _fmt_time(us: int | None) -> str:
    """Corrected instant as ``fmt_us`` text; empty for None (an identity row with no read)."""
    return "" if us is None else fmt_us(us)


# ---------------------------------------------------------------- links.csv

# ``link_id``, ``link_sort_key``, ``ordered_link_rows`` and ``numbered_link_rows`` live in ``linkids`` (T7.5): the
# same numbering names link rows in ``path_nodes.csv``. They are imported above and re-exported in ``__all__``.


def _session_fields(sv: SessionVerdict) -> dict[str, Any]:
    """The verdict columns of a row with a session: the (hop, session) values repeated on each of its rows."""
    return {
        "account_match": sv.account_match,
        "account_match_members": sv.account_match_members,
        "account_match_member_count": sv.account_match_member_count,
        "name_check": sv.name_check,
        "name_check_names": sv.name_check_names,
        "name_check_event_uids": sv.name_check_event_uids,
        "confidence_tier": sv.confidence_tier,
        "link_rank": sv.link_rank,
        "tie": sv.tie,
        "rank_basis": sv.rank_basis,
    }


def _no_session_fields(r: LinkRow, hv: HopVerdicts, member_count: int) -> dict[str, Any]:
    """049 item 4 for an unresolved or ``target_only`` row: tier D, account ``none`` for every member (count 0),
    the hop's ``no_session_name_check`` with no names or uids, no rank, ``tie`` 0, and ``rank_basis``
    ``target_only`` / ``no_session``. WHY no rank: there is no session to order (ST-50 orders sessions)."""
    return {
        "account_match": ACCOUNT_NONE,
        "account_match_members": (ACCOUNT_NONE,) * member_count,
        "account_match_member_count": 0,
        "name_check": hv.no_session_name_check,
        "name_check_names": (),
        "name_check_event_uids": (),
        "confidence_tier": TIER_NO_SESSION,
        "link_rank": None,
        "tie": 0,
        "rank_basis": BASIS_TARGET_ONLY if r.method == METHOD_TARGET_ONLY else BASIS_NO_SESSION,
    }


def link_row(lid: str, hop_id: str, r: LinkRow, hv: HopVerdicts, member_count: int) -> dict[str, str]:
    """One ``links.csv`` row. Link facts from the T7.3 ``LinkRow``; verdict columns from the session's
    ``SessionVerdict`` or, with no session, from 049 item 4; ``candidate_count_account`` is the hop's value
    (``HopVerdicts``) on every row, as ``candidate_count_all`` is.

    ``source_session_id`` is the decimal integer and ``source_session_id_hex`` the hex display form (D1).
    ``source_session_account`` / ``_logon_type`` / ``_logon_uid`` are the session's own in-window 4624 (DB
    fields; empty when it lies before the window). Never a 4648 credential account and never command text.
    """
    sv = hv.sessions.get(r.session_key) if r.session_key is not None else None
    if r.session_key is not None and sv is None:
        raise ValueError(f"{hop_id}: link row of session {r.session_key!r} has no T7.4 verdict")
    verdict = _session_fields(sv) if sv is not None else _no_session_fields(r, hv, member_count)
    values: dict[str, Any] = {
        "link_id": lid,
        "hop_id": hop_id,
        "method": r.method,
        "session_methods": r.session_methods,
        "source_host": r.source_host,
        "source_session_id": r.source_session_id,
        "source_session_id_hex": r.source_session_id_hex,
        "session_unresolved_reason": r.session_unresolved_reason,
        "source_session_account": r.source_session_account,
        "source_session_logon_type": r.source_session_logon_type,
        "source_session_logon_uid": r.source_session_logon_uids,
        "candidate_count": r.candidate_count,
        "candidate_count_all": r.candidate_count_all,
        "candidate_count_account": hv.candidate_count_account,
        "matched_member_count": r.matched_member_count,
        "time_delta_ms": r.time_delta_ms,
        "time_delta_raw_ms": r.time_delta_raw_ms,
        "supporting_event_uids": r.supporting_event_uids,
        "target_only_reason": r.target_only_reason,
        "clock_unreliable": r.clock_unreliable,
    }
    values.update(verdict)
    return {c: cell(values[c]) for c in LINKS_COLUMNS}


def _hop_link_rows(hop: Hop, li: LinkIndex) -> list[dict[str, str]]:
    """All ``links.csv`` rows of one hop, numbered in link-id order (``linkids.numbered_link_rows``). A hop with
    no links or no verdicts is a broken run (T7.3 / T7.4 build both for every hop) and raises ValueError there,
    before any row is built, instead of writing a partial file."""
    numbered = numbered_link_rows(hop, li)
    hv = li.verdicts[hop.hop_id]
    return [link_row(lid, hop.hop_id, r, hv, len(hop.members)) for lid, r in numbered]


def link_rows(li: LinkIndex) -> list[dict[str, str]]:
    """Every ``links.csv`` row of the trial: by hop (hop ids are numbered in time order, spec 3), then link number.

    WHY numeric link order and not text order: ``-l100`` would sort before ``-l99`` as text. Follow-up groups
    are not hops and have no link rows (ST-26). Every hop has at least one row (a ``target_only`` row when it
    has no candidate, ST-49), so no hop is dropped (ST-04).
    """
    out: list[dict[str, str]] = []
    for hop in sorted(li.hopset.hops, key=lambda h: h.hop_id):
        out.extend(_hop_link_rows(hop, li))
    return out


# ---------------------------------------------------------------- hop_artefacts.csv

def artefact_row(r: ArtefactRow) -> dict[str, str]:
    """One ``hop_artefacts.csv`` row; ``names`` are target-side file / service names (spec 2)."""
    values: dict[str, Any] = {
        "hop_id": r.hop_id,
        "kind": r.kind,
        "member_logon_uid": r.member_logon_uid,
        "logged_under_hop_id": r.logged_under_hop_id,
        "method": r.method,
        "candidate_count": r.candidate_count,
        "time_delta_ms": r.time_delta_ms,
        "supporting_span_ms": r.supporting_span_ms,
        "confidence_tier": r.confidence_tier,
        "event_uids": r.event_uids,
        "names": r.names,
        "untied_same_name_bursts": r.untied_same_name_bursts,
    }
    return {c: cell(values[c]) for c in ARTEFACT_COLUMNS}


def artefact_rows(li: LinkIndex) -> list[dict[str, str]]:
    """Every artefact row in ``artefacts.row_order`` (hop id, first event, kind, first uid): the same order
    ``build_artefacts`` uses, from its one definition."""
    return [artefact_row(r) for r in sorted(li.artefacts.rows, key=row_order)]


# ---------------------------------------------------------------- hop_identity.csv

def identity_row(r: IdentityRow) -> dict[str, str]:
    """One ``hop_identity.csv`` row. Times on the corrected basis (ST-02); the parallel ``open_session_*`` lists
    stay parallel (a None logon type is an empty item). ``open_session_ids_hex`` and ``move_uid`` are not spec
    columns and are not written. No value is computed here (ST-64, Q9 open)."""
    values: dict[str, Any] = {
        "hop_id": r.hop_id,
        "account": r.account,
        "source_host": r.source_host,
        "move_utc_corrected": _fmt_time(r.move_us),
        "dump_event_uid": r.dump_event_uid,
        "dump_utc_corrected": _fmt_time(r.dump_us),
        "dump_source_image": r.dump_source_image,
        "dump_account": r.dump_account,
        "gap_ms": r.gap_ms,
        "order_margin_ms": r.order_margin_ms,
        "order_ok": r.order_ok,
        "order_within_tolerance": r.order_within_tolerance,
        "order_within_uncertainty": r.order_within_uncertainty,
        "offset_unc_source_ms": r.offset_unc_source_ms,
        "offset_unc_target_ms": r.offset_unc_target_ms,
        "open_session_uids": r.open_session_uids,
        "open_session_types": r.open_session_types,
        "session_open_before_window": r.session_open_before_window,
        "end_unknown_session_uids": r.end_unknown_session_uids,
        "not_applicable": r.not_applicable,
        "clock_unreliable": r.clock_unreliable,
    }
    return {c: cell(values[c]) for c in IDENTITY_COLUMNS}


def identity_rows(li: LinkIndex) -> list[dict[str, str]]:
    """Every identity row in ``li.identity`` order (``identity.build_identity`` already sorts them: hop id,
    account, dump time, dump uid)."""
    return [identity_row(r) for r in li.identity]


# ---------------------------------------------------------------- hops.csv (T7.5)

def hop_row(hop: Hop, li: LinkIndex, facts: HopPathFacts) -> dict[str, str]:
    """One ``hops.csv`` row (spec 3), field by field.

    Member columns are parallel, one item per member in member order: the member's representative uid (its ST-05
    copies are in ``path_nodes.csv``), the logon ID as a decimal integer and as hex (D1), the 4624
    ``account_name`` (a DB field, 050 item 8) and the source port. ``candidate_count`` = distinct candidate
    sessions over all methods (``candidate_count_all``); ``best_tier`` from the T7.4 verdicts (D with no session,
    ST-49); ``clock_unreliable`` = ``paths.hop_clock_unreliable`` (ST-02 both parts, the edge flag's input).
    Path columns from ``HopPathFacts`` (ST-72, ST-23). Follow-up logons: their representative uids (ST-26).
    """
    sl = li.links.get(hop.hop_id)
    hv = li.verdicts.get(hop.hop_id)
    if sl is None or hv is None:
        raise ValueError(f"{hop.hop_id}: no link rows or no T7.4 verdicts")
    confirm, confirm_uids = li.confirm[hop.hop_id]
    values: dict[str, Any] = {
        "hop_id": hop.hop_id,
        "target_host": hop.target_host,
        "source_ip": hop.source_ip,
        "ip_kind": hop.ip_kind,
        "source_host": sl.source_host,
        "first_utc": hop.first_utc,
        "first_utc_corrected": hop.first_utc_corrected,
        "last_utc_corrected": hop.last_utc_corrected,
        "member_count": hop.member_count,
        "member_logon_uids": [m.uid for m in hop.members],
        "member_logon_ids": [m.logon_id for m in hop.members],
        "member_logon_ids_hex": [m.logon_id_hex for m in hop.members],
        "member_accounts": [m.account for m in hop.members],
        "member_ports": [m.source_port for m in hop.members],
        "mixed_account": hop.mixed_account,
        "protocol": hop.protocol,
        "rules": hop.rules,
        "chain_parent_count": facts.chain_parent_count,
        "chain_parent_hop_ids": facts.chain_parent_hop_ids,
        "multi_chain_parent": facts.multi_chain_parent,
        "trigger_ids": hop.trigger_ids,
        "is_seed": hop.is_seed,
        "in_path": facts.in_path,
        "authentication_packages": hop.authentication_packages,
        "confirm": confirm,
        "confirm_event_uids": list(confirm_uids),
        "inside_gap_max_ms": hop.inside_gap_max_ms,
        "prev_gap_ms": hop.prev_gap_ms,
        "next_gap_ms": hop.next_gap_ms,
        "gap_near_threshold": hop.gap_near_threshold,
        "splits_at_1s": hop.splits_at_1s,
        "merges_at_3s": hop.merges_at_3s,
        "service_install_count": li.artefacts.service_install_count.get(hop.hop_id, 0),
        "shares_port_with_hops": hop.shares_port_with_hops,
        "followup_logon_uids": [m.uid for m in hop.followups],
        "followup_logon_count": len(hop.followups),
        "candidate_count": sl.candidate_count_all,
        "best_tier": hv.best_tier,
        "evidence_before_range": sl.evidence_before_range,
        "evidence_after_range": sl.evidence_after_range,
        "supporting_span_ms": li.artefacts.supporting_span_ms.get(hop.hop_id),
        "clock_unreliable": hop_clock_unreliable(hop, sl),
        "gate_clock_unreliable": hop.gate_clock_unreliable,
    }
    return {c: cell(values[c]) for c in HOPS_COLUMNS}


def hop_rows(li: LinkIndex, pathset: PathSet) -> list[dict[str, str]]:
    """Every hop, seed or not, by hop id (= time order, spec 3): no hop is dropped (ST-04). ValueError when a hop
    has no path facts (``build_paths`` makes them for every hop)."""
    out: list[dict[str, str]] = []
    for hop in sorted(li.hopset.hops, key=lambda h: h.hop_id):
        facts = pathset.hop_facts.get(hop.hop_id)
        if facts is None:
            raise ValueError(f"{hop.hop_id}: no path facts")
        out.append(hop_row(hop, li, facts))
    return out


# ---------------------------------------------------------------- paths.csv, path_edges.csv, path_nodes.csv (T7.5)

def path_row(p: Path) -> dict[str, str]:
    """One ``paths.csv`` row: lists ``;``-joined (``hosts`` one ``source>target`` per hop, 050 item 6),
    ``merged_from`` chains ``|``-joined, ``edge_types`` as ``host_time:N;session:M``."""
    values: dict[str, Any] = {
        "path_id": p.path_id,
        "hop_ids": p.hop_ids,
        "hosts": p.hosts,
        "n_hops": p.n_hops,
        "seed_trigger_ids": p.seed_trigger_ids,
        "merged_from": CHAIN_SEPARATOR.join(p.merged_from),
        "isolated": p.isolated,
        "edge_types": edge_types_text(p.edge_types),
        "shared_source_session_with": p.shared_source_session_with,
        "shared_event_with": p.shared_event_with,
    }
    return {c: cell(values[c]) for c in PATHS_COLUMNS}


def path_rows(pathset: PathSet) -> list[dict[str, str]]:
    """Every path in path-id order (= order of each path's first hop, 050 item 1)."""
    return [path_row(p) for p in sorted(pathset.paths, key=lambda p: p.path_id)]


def edge_row(pid: str, e: ChainEdge) -> dict[str, str]:
    """One ``path_edges.csv`` row (ST-72). ``supporting_sessions`` is not a spec column and is not written."""
    values: dict[str, Any] = {
        "path_id": pid,
        "from_hop_id": e.from_hop_id,
        "to_hop_id": e.to_hop_id,
        "link_type": e.link_type,
        "time_delta_ms": e.time_delta_ms,
        "order_within_tolerance": e.order_within_tolerance,
        "clock_unreliable": e.clock_unreliable,
    }
    return {c: cell(values[c]) for c in EDGES_COLUMNS}


def edge_rows(li: LinkIndex, pathset: PathSet) -> list[dict[str, str]]:
    """Every edge with its path id, by (path id, from-hop order, to-hop order). Every edge joins two hops of
    one path (both ends are chainable seeds of one component), so the row count equals ``pathset.edges``."""
    order = {h.hop_id: hop_order(h) for h in li.hopset.hops}
    rows = [(p.path_id, order[e.from_hop_id], order[e.to_hop_id], e) for p in pathset.paths for e in p.edges]
    return [edge_row(pid, e) for pid, _f, _t, e in sorted(rows, key=lambda r: r[:3])]


def node_row(n: PathNode) -> dict[str, str]:
    """One ``path_nodes.csv`` row (ST-71). ``session_id`` is the decimal logon ID (D1); ``us`` only orders rows
    and is not a spec column."""
    values: dict[str, Any] = {
        "path_id": n.path_id,
        "hop_id": n.hop_id,
        "role": n.role,
        "context": n.context,
        "host": n.host,
        "session_id": n.session_id,
        "event_uid": n.event_uid,
        "link_id": n.link_id,
    }
    return {c: cell(values[c]) for c in NODES_COLUMNS}


def node_rows(nodes: Iterable[PathNode]) -> list[dict[str, str]]:
    """Every node in ``nodes.build_nodes`` order (path, hop order, time, role, uid, link id)."""
    return [node_row(n) for n in nodes]


# ---------------------------------------------------------------- CSV text

def csv_text(columns: Sequence[str], rows: Iterable[Mapping[str, str]]) -> str:
    """CSV text: header row, then one line per row, ``\\n`` line ends, values as given (str).

    ValueError when a row's keys are not exactly ``columns`` or a value is not a str. WHY strict: the column
    lists are the spec contract, and a non-str value would leave its spelling to the csv module instead of
    ``cell``. Deterministic: the same rows give the same text.
    """
    cols = list(columns)
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for row in rows:
        if set(row) != set(cols):
            raise ValueError(f"row keys differ from the columns: {sorted(set(row) ^ set(cols))}")
        values = [row[c] for c in cols]
        if not all(isinstance(v, str) for v in values):
            raise ValueError("every CSV value must be a str (use outputs.cell)")
        w.writerow(values)
    return buf.getvalue()
