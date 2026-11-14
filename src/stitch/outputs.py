"""T7.4 writer side: rows and CSV text of ``links.csv``, ``hop_artefacts.csv`` and ``hop_identity.csv`` (spec
03_stitch section 3; ST-01, ST-02, ST-45..ST-50, ST-49, ST-60..ST-64; decisions 038, 049 items 3, 4, 6, 7; D1).

WHY a separate pure module: every value of the three files is already decided in the ``LinkIndex`` (T7.3 link
rows, T7.4 verdicts and identity rows, the artefact set). This module only spells those values as text, in the
spec's column order and a fixed row order, so the bytes are the same on every run on the same inputs (spec 3).
It opens no file and no DB; ``stitch.__main__`` writes the text.

WHY built field by field from named columns and never by dumping dataclasses: a field added to ``LinkRow`` or
``IdentityRow`` later (a credential account, a command fragment) can then never reach a file by accident. The
only text columns are: hosts, uids, method / reason / verdict vocabularies, target-side names (artefact names
and the matched ``name_check_names``, both taken from target-side events, spec 2), and the four account / image
columns that are DB fields of referenced events (``source_session_account`` and ``account``: a 4624
``account_name``; ``dump_source_image`` / ``dump_account``: the Sysmon 10 ``source_image`` / ``account_name``;
049 item 7). No value comes from a command line.

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
from .links import LinkIndex
from .params import METHODS
from .sessions import SessionKey
from .source import METHOD_TARGET_ONLY, LinkRow
from .tiers import ACCOUNT_NONE, HopVerdicts, SessionVerdict

__all__ = ["LINKS_COLUMNS", "ARTEFACT_COLUMNS", "IDENTITY_COLUMNS", "LINKS_FILE", "ARTEFACT_FILE", "IDENTITY_FILE",
           "TIER_NO_SESSION", "BASIS_NO_SESSION", "BASIS_TARGET_ONLY", "cell", "link_id", "ordered_link_rows",
           "link_row", "link_rows", "artefact_row", "artefact_rows", "identity_row", "identity_rows", "csv_text"]

LINKS_FILE, ARTEFACT_FILE, IDENTITY_FILE = "links.csv", "hop_artefacts.csv", "hop_identity.csv"

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

# 049 item 4: what a row with no session carries (an unresolved process row or the ``target_only`` row).
TIER_NO_SESSION = "D"
BASIS_NO_SESSION, BASIS_TARGET_ONLY = "no_session", "target_only"

_METHOD_ORDER: dict[str, int] = {m: i for i, m in enumerate(METHODS)}
# Row groups of a hop, in link-id order: candidate sessions, unresolved process rows, the target_only row.
_GROUP_SESSION, _GROUP_UNRESOLVED, _GROUP_TARGET_ONLY = 0, 1, 2


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

def link_id(hop_id: str, n: int) -> str:
    """``<hop_id>-l<NN>``: 1-based, at least 2 digits, more when a hop has 100 rows or more (spec 3)."""
    return f"{hop_id}-l{n:02d}"


def _link_sort_key(r: LinkRow, sv: Mapping[SessionKey, SessionVerdict]) -> tuple:
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
    """The hop's link rows in link-id order (``_link_sort_key``). ValueError for a session row with no verdict
    (T7.4 builds one for every candidate session, so a gap means a broken run)."""
    return sorted(rows, key=lambda r: _link_sort_key(r, verdicts.sessions))


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
    """All ``links.csv`` rows of one hop, numbered in link-id order. A hop with no links or no verdicts is a
    broken run (T7.3 / T7.4 build both for every hop) and raises ValueError instead of writing a partial file."""
    sl = li.links.get(hop.hop_id)
    hv = li.verdicts.get(hop.hop_id)
    if sl is None or hv is None:
        raise ValueError(f"{hop.hop_id}: no link rows or no T7.4 verdicts")
    rows = ordered_link_rows(sl.rows, hv)
    return [link_row(link_id(hop.hop_id, i), hop.hop_id, r, hv, len(hop.members))
            for i, r in enumerate(rows, start=1)]


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
