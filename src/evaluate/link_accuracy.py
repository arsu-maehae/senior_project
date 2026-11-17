"""Link accuracy verdicts, hop facts and totals from the stitch rows and the read key (decision 051 items 5-8).

Pure: every function takes parsed rows (dicts of the text the stitcher wrote) and returns rows of text. WHY pure:
the same code must run unchanged on development now and on test at T10 (051 consequences), and a test can feed
it synthetic rows. Nothing here reads a file, and nothing here is ever read by the stitcher (051 item 1).

Vocabulary of a keyed row (one per key hop):
- ``session_compare``: ``logon_uid`` / ``host_logon_id`` / ``ambiguous_boot`` (051 item 5);
- ``among_candidates`` / ``only_candidate``: 1 / 0; ``rank1``: correct / tied_correct / wrong / no_candidate
  (051 item 6); all three empty under ``ambiguous_boot``, for an unmatched key hop and for a key hop without a key
  source session (that one gets ``expected_target_only`` = 1 and ``target_only_ok``);
- identity: ``identity_value`` 0 / 1 / ``q9_dependent`` / ``missing`` (empty when not applicable) and
  ``identity_match`` 1 / 0 / ``q9_dependent`` (051 item 7; for comparison only, T9 owns IdentityCoherence).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .keys import KeySession, MatchResult, hex_id, key_account, key_logons_in_hop, split_list
from .params import (DEFAULT_VARIANT, ENDPOINTS, METHOD_4648, METHOD_CMD, METHOD_PORT, METHOD_TARGET_ONLY, METHODS,
                     PROTOCOL_GROUP_ORDER, PROTOCOL_GROUPS, Q9_VARIANTS, SYSTEM_ACCOUNTS, TIER_ORDER)

__all__ = ["KEYED_COLUMNS", "FACT_COLUMNS", "TOTAL_COLUMNS", "KEYED_COUNTS", "HOP_COUNTS", "SCOPES",
           "IdentityReading", "protocol_group", "rows_by_hop", "session_rows", "session_key", "method_counts",
           "port_cmd_agree", "rank1_rows", "union_methods", "join_distinct", "hop_tie", "target_only_reason",
           "has_only_target_only", "key_uid_source", "compare_mode", "session_verdicts", "is_system_read",
           "selected_reads", "deciding_rows", "identity_reading", "identity_match", "user_e2e", "keyed_row",
           "fact_row", "total_rows", "headline"]

KEYED_COLUMNS: tuple[str, ...] = (
    "split", "trial_id", "key_hop_id", "key_role", "key_protocol", "key_source_host", "key_target_host",
    "key_account", "match", "hop_id", "key_logons_in_hop", "protocol", "protocol_group", "best_tier",
    "candidate_count", "candidate_count_port", "candidate_count_4648", "candidate_count_cmd", "key_sessions_hex",
    "key_session_uid_source", "session_compare", "among_candidates", "rank1", "only_candidate", "rank1_sessions_hex",
    "rank1_tier", "rank1_methods", "key_session_tier", "key_session_methods", "key_session_rank", "tie",
    "target_only_reason", "expected_target_only", "target_only_ok", "evidence_before_range", "evidence_after_range",
    "port_cmd_agree", "clock_unreliable", "identity_expected", "identity_value", "identity_match",
    "identity_not_applicable", "identity_order_within_tolerance", "identity_order_within_uncertainty",
    "identity_deciding_dump_uids")

FACT_COLUMNS: tuple[str, ...] = (
    "split", "trial_id", "hop_id", "target_host", "source_host", "protocol", "protocol_group", "is_seed", "in_path",
    "user_e2e", "member_count", "best_tier", "candidate_count", "candidate_count_port", "candidate_count_4648",
    "candidate_count_cmd", "rank1_sessions_hex", "rank1_tier", "rank1_methods", "tie", "target_only_reason",
    "evidence_before_range", "evidence_after_range", "port_cmd_agree", "identity_values", "clock_unreliable",
    "key_hop_id")

KEYED_COUNTS: tuple[str, ...] = (
    "key_hops", "matched", "with_key_session", "among", "rank1_correct", "rank1_tied_correct", "rank1_wrong",
    "rank1_no_candidate", "only_candidate", "compare_logon_uid", "compare_host_logon_id", "compare_ambiguous_boot",
    "background", "background_target_only_ok", "identity_match", "identity_q9_dependent")
HOP_COUNTS: tuple[str, ...] = ("hops", "seeds", "target_only", "port_cmd_both", "port_cmd_agree")
TOTAL_COLUMNS: tuple[str, ...] = ("split", "trial_id", "scope", "protocol_group", "tier") + KEYED_COUNTS + HOP_COUNTS
SCOPES: tuple[str, ...] = ("keyed", "all_hops", "user_e2e_hops")
ALL = "all"

_SESSION_ID = "source_session_id"
_SESSION_UID = "source_session_logon_uid"


# ---------------------------------------------------------------- small helpers

def protocol_group(protocol: str) -> str:
    """ST-22 protocol -> 051 item 8 group (smb = smb + smb_service). ValueError for a value outside the spec
    vocabulary, so a changed stitch vocabulary is noticed instead of counted as ``none``."""
    try:
        return PROTOCOL_GROUPS[protocol]
    except KeyError:
        raise ValueError(f"unknown stitch protocol {protocol!r}") from None


def _key_protocol_group(key_protocol: str) -> str:
    """Group of an unmatched key hop, from the key's own protocol text (``SMB`` / ``WinRM`` / ``RDP``)."""
    return PROTOCOL_GROUPS.get(str(key_protocol or "").lower(), "none")


def rows_by_hop(links: Iterable[Mapping[str, str]]) -> dict[str, list[Mapping[str, str]]]:
    """hop_id -> its links.csv rows, in file order."""
    out: dict[str, list[Mapping[str, str]]] = {}
    for r in links:
        out.setdefault(r["hop_id"], []).append(r)
    return out


def session_rows(rows: Iterable[Mapping[str, str]]) -> list[Mapping[str, str]]:
    """Rows that name a candidate source session (non-empty ``source_session_id``). WHY: ``target_only`` rows and
    unresolved-process rows name no session, so they are never a candidate session (051 item 5)."""
    return [r for r in rows if r.get(_SESSION_ID, "") != ""]


def session_key(row: Mapping[str, str]) -> tuple[str, int, str]:
    """The stitcher's identity of a candidate session on a row: (source host, logon ID, its 4624 uid). WHY all
    three: rows of one session repeat all of them, and counting distinct sessions must not merge two sessions
    that reuse a logon ID across a boot."""
    return (row.get("source_host", ""), int(row[_SESSION_ID]), row.get(_SESSION_UID, ""))


def method_counts(rows: Sequence[Mapping[str, str]]) -> dict[str, int]:
    """Distinct candidate sessions per method (``sysmon3_port``, ``source_4648``, ``cmdline_target``)."""
    sess = session_rows(rows)
    return {m: len({session_key(r) for r in sess if r.get("method") == m}) for m in METHODS}


def port_cmd_agree(rows: Sequence[Mapping[str, str]]) -> str:
    """``yes`` when the port join and the command-line rule both found sessions and found the same set; ``no``
    when both found sessions and the sets differ; ``n_a`` otherwise. WHY: the only check that does not use the key
    (STA-05)."""
    sess = session_rows(rows)
    port = {session_key(r) for r in sess if r.get("method") == METHOD_PORT}
    cmd = {session_key(r) for r in sess if r.get("method") == METHOD_CMD}
    if not port or not cmd:
        return "n_a"
    return "yes" if port == cmd else "no"


def rank1_rows(rows: Sequence[Mapping[str, str]]) -> list[Mapping[str, str]]:
    """Session rows with ``link_rank`` = 1 (all sessions of a shared first rank, ST-50)."""
    return [r for r in session_rows(rows) if r.get("link_rank") == "1"]


def union_methods(rows: Iterable[Mapping[str, str]]) -> str:
    """The distinct methods of the rows' ``session_methods``, ``;``-joined in the canonical method order."""
    found = {m for r in rows for m in split_list(r.get("session_methods"))}
    known = [m for m in METHODS if m in found]
    return ";".join(known + sorted(found - set(METHODS)))


def join_distinct(values: Iterable[str]) -> str:
    """Distinct non-empty values, sorted, ``;``-joined."""
    return ";".join(sorted({v for v in values if v != ""}))


def _sessions_hex(rows: Iterable[Mapping[str, str]]) -> str:
    """Distinct session logon IDs of the rows in hex, sorted numerically, ``;``-joined."""
    return ";".join(hex_id(i) for i in sorted({int(r[_SESSION_ID]) for r in session_rows(rows)}))


def hop_tie(rows: Sequence[Mapping[str, str]]) -> str:
    """``1`` if any row of the hop says the first rank is shared, else ``0`` (``0`` also for a target_only hop)."""
    return "1" if any(r.get("tie") == "1" for r in rows) else "0"


def target_only_reason(rows: Sequence[Mapping[str, str]]) -> str:
    """The ``target_only_reason`` of the hop's target_only row; empty when the hop has candidates."""
    return join_distinct(r.get("target_only_reason", "") for r in rows if r.get("method") == METHOD_TARGET_ONLY)


def has_only_target_only(rows: Sequence[Mapping[str, str]]) -> bool:
    """True when the hop has a ``target_only`` row and no candidate session (051 item 6 as amended by decision 055,
    owner ruling OQ-2): unresolved-process rows (ST-41, empty session) may sit beside it, because they name no
    session and so are not candidates (ST-49)."""
    return any(r.get("method") == METHOD_TARGET_ONLY for r in rows) and not session_rows(rows)


def _flag(value: bool) -> str:
    """1 / 0 as text."""
    return "1" if value else "0"


# ---------------------------------------------------------------- session comparison (051 items 5, 6)

def key_uid_source(sessions: Sequence[KeySession]) -> str:
    """Hop-level origin of the key uid: ``direct`` if every key session's uid is in the key, ``lookup`` if every
    session has a uid and at least one came from the DB lookup, ``none`` if any session has no uid; empty when the
    key hop has no source session."""
    if not sessions:
        return ""
    if any(s.uid is None for s in sessions):
        return "none"
    return "direct" if all(s.uid_source == "direct" for s in sessions) else "lookup"


def compare_mode(sessions: Sequence[KeySession], cand_rows: Sequence[Mapping[str, str]]) -> str:
    """051 item 5: ``logon_uid`` when every key session has a 4624 uid and every candidate session row has a
    ``source_session_logon_uid`` (vacuously true for a hop with no candidate rows); else ``host_logon_id`` when
    each key logon ID opens in at most one boot epoch on its host; else ``ambiguous_boot``."""
    if all(s.uid for s in sessions) and all(r.get(_SESSION_UID, "") != "" for r in cand_rows):
        return "logon_uid"
    if all(len(s.epochs) <= 1 for s in sessions):
        return "host_logon_id"
    return "ambiguous_boot"


def _cand_id(row: Mapping[str, str], mode: str, key_uids: frozenset[str] = frozenset()) -> Any:
    """A candidate row's session identity under the compare mode.

    Under ``logon_uid`` the stitcher's ``source_session_logon_uid`` may hold several ``;``-joined uids of ONE session
    (ST-05 copies, or a second 4624 while the session was open). WHY the key uid when it is one of them: the key names
    one 4624 of the session, and comparing it with the whole cell would score a correct session as wrong (review
    ATK-23). A cell holding no key uid keeps its whole text as the identity."""
    if mode != "logon_uid":
        return (row.get("source_host", ""), int(row[_SESSION_ID]))
    cell = row[_SESSION_UID]
    hits = sorted(u for u in cell.split(";") if u in key_uids)
    return hits[0] if hits else cell


def _key_id(s: KeySession, mode: str) -> Any:
    """A key session's identity under the compare mode."""
    return s.uid if mode == "logon_uid" else (s.host, s.logon_id)


def session_verdicts(sessions: Sequence[KeySession], hop_rows: Sequence[Mapping[str, str]]) -> dict[str, str]:
    """The session columns of a keyed row whose key hop has a key source session and matched a hop (051 items 5, 6).

    ``among_candidates``: key set inside the candidate set; ``rank1``: ``correct`` (rank-1 set = key set),
    ``tied_correct`` (key set strictly inside the rank-1 set), ``wrong``, ``no_candidate`` (no candidate
    session); ``only_candidate``: candidate set = key set. Under ``ambiguous_boot`` no verdict is given.
    """
    cand = session_rows(hop_rows)
    mode = compare_mode(sessions, cand)
    out = {"session_compare": mode, "among_candidates": "", "rank1": "", "only_candidate": "",
           "key_session_tier": "", "key_session_methods": "", "key_session_rank": ""}
    if mode == "ambiguous_boot":
        return out
    key_set = {_key_id(s, mode) for s in sessions}
    key_uids = frozenset(k for k in key_set if isinstance(k, str))
    cand_set = {_cand_id(r, mode, key_uids) for r in cand}
    first = {_cand_id(r, mode, key_uids) for r in rank1_rows(hop_rows)}
    if not cand_set:
        rank1 = "no_candidate"
    elif first == key_set:
        rank1 = "correct"
    elif key_set < first:
        rank1 = "tied_correct"
    else:
        rank1 = "wrong"
    mine = [r for r in cand if _cand_id(r, mode, key_uids) in key_set]
    out.update(among_candidates=_flag(bool(cand_set) and key_set <= cand_set), rank1=rank1,
               only_candidate=_flag(cand_set == key_set),
               key_session_tier=join_distinct(r.get("confidence_tier", "") for r in mine),
               key_session_methods=union_methods(mine),
               key_session_rank=join_distinct(r.get("link_rank", "") for r in mine))
    return out


# ---------------------------------------------------------------- identity (051 item 7)

def _int(cell: str | None) -> int | None:
    """Integer cell or None when empty."""
    return None if cell is None or cell == "" else int(cell)


def is_system_read(row: Mapping[str, str]) -> bool:
    """An LSASS read by SYSTEM / NETWORK SERVICE / LOCAL SERVICE or a machine account (the test helper's rule)."""
    a = (row.get("dump_account") or "").lower()
    return a in SYSTEM_ACCOUNTS or a.endswith("$")


def selected_reads(rows: Sequence[Mapping[str, str]], reads: str) -> list[Mapping[str, str]]:
    """The LSASS-read rows a Q9 variant looks at: ``all`` rows with a dump; ``nonsystem`` drops system reads;
    ``key_rule`` = among non-system rows with ``order_ok`` = 1, the single one nearest before the move (smallest
    non-negative gap first; a small negative gap inside the tolerance ranks after)."""
    with_dump = [r for r in rows if r.get("dump_event_uid", "") != ""]
    if reads == "all":
        return with_dump
    nonsys = [r for r in with_dump if not is_system_read(r)]
    if reads == "nonsystem":
        return nonsys
    if reads != "key_rule":
        raise ValueError(f"unknown Q9 reads variant {reads!r}")
    ok = [r for r in nonsys if r.get("order_ok") == "1"]
    if not ok:
        return []
    return [min(ok, key=lambda r: (int(r["gap_ms"]) < 0, abs(int(r["gap_ms"])), r.get("dump_event_uid", "")))]


def deciding_rows(rows: Sequence[Mapping[str, str]], reads: str, counted: bool) -> list[Mapping[str, str]]:
    """Selected rows that decide value 1: ``order_ok`` = 1 and an open session (plus ``end_unknown`` sessions when
    the variant counts them) (051 item 7)."""
    out: list[Mapping[str, str]] = []
    for r in selected_reads(rows, reads):
        uids = split_list(r.get("open_session_uids")) + (split_list(r.get("end_unknown_session_uids")) if counted
                                                          else [])
        if r.get("order_ok") == "1" and uids:
            out.append(r)
    return out


@dataclass(frozen=True)
class IdentityReading:
    """The identity facts of one (hop, account) under the six Q9 variants."""
    value: str                  # "0" / "1" / "q9_dependent" / "missing" / "" (not applicable)
    not_applicable: str
    within_tolerance: str       # max over the default variant's deciding rows; empty when none decides
    within_uncertainty: str
    deciding_dump_uids: str


def identity_reading(rows: Sequence[Mapping[str, str]]) -> IdentityReading:
    """Read hop_identity.csv rows of one (hop, account) (051 item 7). No rows -> ``missing``; a row with
    ``not_applicable`` -> empty value and that reason; else the value shared by the six variants or
    ``q9_dependent``. The order flags and deciding dump uids come from the default variant (all reads,
    end_unknown not counted)."""
    if not rows:
        return IdentityReading("missing", "", "", "", "")
    na = join_distinct(r.get("not_applicable", "") for r in rows)
    if na:
        return IdentityReading("", na, "", "", "")
    values = {int(bool(deciding_rows(rows, reads, counted))) for reads, counted in Q9_VARIANTS}
    value = str(values.pop()) if len(values) == 1 else "q9_dependent"
    dec = deciding_rows(rows, *DEFAULT_VARIANT)
    tol = str(max(_int(r.get("order_within_tolerance")) or 0 for r in dec)) if dec else ""
    unc = str(max(_int(r.get("order_within_uncertainty")) or 0 for r in dec)) if dec else ""
    return IdentityReading(value, "", tol, unc, join_distinct(r.get("dump_event_uid", "") for r in dec))


def identity_match(reading: IdentityReading, expected: Any) -> str:
    """``1`` / ``0`` against the key's ``identity_expected``; ``q9_dependent`` passes through; a missing or
    not-applicable value is ``0`` (the key expects a value)."""
    if reading.value == "q9_dependent":
        return "q9_dependent"
    if reading.value in ("0", "1") and expected is not None:
        return _flag(int(reading.value) == int(expected))
    return "0"


def _identity_rows(identity: Iterable[Mapping[str, str]], hop_id: str, account: str) -> list[Mapping[str, str]]:
    """hop_identity.csv rows of (hop, account), account compared lower-cased."""
    return [r for r in identity if r.get("hop_id") == hop_id and (r.get("account") or "").lower() == account]


# ---------------------------------------------------------------- rows

def user_e2e(hop: Mapping[str, str]) -> bool:
    """Endpoint -> endpoint hop with a user (non-machine) member account. WHY: the scope where identity and links
    matter for the lab's attacks; machine and DC traffic dominates the raw hop count."""
    return (hop.get("source_host") in ENDPOINTS and hop.get("target_host") in ENDPOINTS
            and any(not a.endswith("$") for a in split_list(hop.get("member_accounts"))))


def _hop_link_columns(hop: Mapping[str, str], rows: Sequence[Mapping[str, str]]) -> dict[str, str]:
    """Columns shared by keyed and fact rows that describe a stitch hop and its links (no key involved)."""
    counts = method_counts(rows)
    first = rank1_rows(rows)
    return {"protocol": hop.get("protocol", ""), "protocol_group": protocol_group(hop.get("protocol", "")),
            "best_tier": hop.get("best_tier", ""), "candidate_count": hop.get("candidate_count", ""),
            "candidate_count_port": str(counts[METHOD_PORT]), "candidate_count_4648": str(counts[METHOD_4648]),
            "candidate_count_cmd": str(counts[METHOD_CMD]), "rank1_sessions_hex": _sessions_hex(first),
            "rank1_tier": join_distinct(r.get("confidence_tier", "") for r in first),
            "rank1_methods": union_methods(first), "tie": hop_tie(rows), "target_only_reason": target_only_reason(rows),
            "evidence_before_range": hop.get("evidence_before_range", ""),
            "evidence_after_range": hop.get("evidence_after_range", ""), "port_cmd_agree": port_cmd_agree(rows),
            "clock_unreliable": hop.get("clock_unreliable", "")}


def keyed_row(split: str, trial: str, key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
              match: MatchResult, hop: Mapping[str, str] | None, hop_rows: Sequence[Mapping[str, str]],
              sessions: Sequence[KeySession], identity: Sequence[Mapping[str, str]]) -> dict[str, str]:
    """One keyed row (051 items 3-7). ``hop`` is the matched hops.csv row (None unless ``match`` is ``matched``);
    ``hop_rows`` its links.csv rows; ``sessions`` the key source sessions (empty for a background hop)."""
    row = {c: "" for c in KEYED_COLUMNS}
    account = key_account(key_hop)
    row.update(split=split, trial_id=trial, key_hop_id=str(key_hop.get("hop_id", "")),
               key_role=str(key_hop.get("role", "")), key_protocol=str(key_hop.get("protocol", "")),
               key_source_host=str(key_hop.get("source_host", "")), key_target_host=str(key_hop.get("target_host", "")),
               key_account=account, match=match.outcome, hop_id=";".join(match.hop_ids),
               key_sessions_hex=";".join(hex_id(i) for i in sorted({s.logon_id for s in sessions})),
               key_session_uid_source=key_uid_source(sessions),
               expected_target_only=_flag(not sessions),
               identity_expected="" if key_hop.get("identity_expected") is None
               else str(int(key_hop["identity_expected"])))
    if hop is None:
        row.update(identity_value="missing", identity_match="0")
        return row
    row.update(_hop_link_columns(hop, hop_rows))
    row["key_logons_in_hop"] = key_logons_in_hop(key_hop, event_keys, hop)
    if sessions:
        row.update(session_verdicts(sessions, hop_rows))
    else:
        row["target_only_ok"] = _flag(has_only_target_only(hop_rows))
    reading = identity_reading(_identity_rows(identity, hop["hop_id"], account))
    row.update(identity_value=reading.value, identity_match=identity_match(reading, key_hop.get("identity_expected")),
               identity_not_applicable=reading.not_applicable,
               identity_order_within_tolerance=reading.within_tolerance,
               identity_order_within_uncertainty=reading.within_uncertainty,
               identity_deciding_dump_uids=reading.deciding_dump_uids)
    return row


def _identity_values(identity: Sequence[Mapping[str, str]], hop_id: str) -> str:
    """``account=value`` per account of the hop's identity rows, sorted, ``;``-joined; a not-applicable account is
    ``account=not_applicable:<reason>``. Account text is the stitch ``account`` column (STT-13 covered)."""
    accounts = sorted({r.get("account", "") for r in identity if r.get("hop_id") == hop_id})
    parts = []
    for a in accounts:
        reading = identity_reading([r for r in identity if r.get("hop_id") == hop_id and r.get("account", "") == a])
        parts.append(f"{a}=" + (reading.value if not reading.not_applicable
                                else f"not_applicable:{reading.not_applicable}"))
    return ";".join(parts)


def fact_row(split: str, trial: str, hop: Mapping[str, str], hop_rows: Sequence[Mapping[str, str]],
             identity: Sequence[Mapping[str, str]], key_hop_ids: Sequence[str]) -> dict[str, str]:
    """One fact row per stitch hop, every trial, no right / wrong (051 item 8)."""
    row = {c: "" for c in FACT_COLUMNS}
    row.update(_hop_link_columns(hop, hop_rows))
    row.update(split=split, trial_id=trial, hop_id=hop["hop_id"], target_host=hop.get("target_host", ""),
               source_host=hop.get("source_host", ""), is_seed=hop.get("is_seed", ""), in_path=hop.get("in_path", ""),
               user_e2e=_flag(user_e2e(hop)), member_count=hop.get("member_count", ""),
               identity_values=_identity_values(identity, hop["hop_id"]), key_hop_id=";".join(key_hop_ids))
    return row


# ---------------------------------------------------------------- totals (051 item 8)

def _order_index(value: str, order: Sequence[str]) -> tuple[int, str]:
    """Sort key: position in a fixed order, unknown values after it, alphabetically."""
    return (order.index(value), "") if value in order else (len(order), value)


def _keyed_counts(r: Mapping[str, str]) -> dict[str, int]:
    """The keyed-scope counts one keyed row contributes."""
    has_session = r["expected_target_only"] == "0"
    return {"key_hops": 1, "matched": int(r["match"] == "matched"),
            "with_key_session": int(has_session),
            "among": int(r["among_candidates"] == "1"), "rank1_correct": int(r["rank1"] == "correct"),
            "rank1_tied_correct": int(r["rank1"] == "tied_correct"), "rank1_wrong": int(r["rank1"] == "wrong"),
            "rank1_no_candidate": int(r["rank1"] == "no_candidate"), "only_candidate": int(r["only_candidate"] == "1"),
            "compare_logon_uid": int(r["session_compare"] == "logon_uid"),
            "compare_host_logon_id": int(r["session_compare"] == "host_logon_id"),
            "compare_ambiguous_boot": int(r["session_compare"] == "ambiguous_boot"),
            "background": int(not has_session), "background_target_only_ok": int(r["target_only_ok"] == "1"),
            "identity_match": int(r["identity_match"] == "1"),
            "identity_q9_dependent": int(r["identity_match"] == "q9_dependent")}


def _hop_counts(r: Mapping[str, str]) -> dict[str, int]:
    """The hop-scope counts one fact row contributes."""
    return {"hops": 1, "seeds": int(r["is_seed"] == "1"), "target_only": int(r["target_only_reason"] != ""),
            "port_cmd_both": int(r["port_cmd_agree"] in ("yes", "no")),
            "port_cmd_agree": int(r["port_cmd_agree"] == "yes")}


def _add(acc: dict[tuple[str, str, str], dict[str, int]], key: tuple[str, str, str], counts: Mapping[str, int]) -> None:
    """Add counts into the group ``key`` and into its scope's ``all`` / ``all`` group."""
    for k in (key, (key[0], ALL, ALL)):
        slot = acc.setdefault(k, {})
        for name, n in counts.items():
            slot[name] = slot.get(name, 0) + n


def total_rows(split: str, trial: str, keyed: Sequence[Mapping[str, str]] | None,
               facts: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    """Totals per (scope, protocol_group, tier), plus an ``all`` / ``all`` row per scope (051 item 8).

    ``keyed`` scope (only when the trial has a key): tier = matched hop ``best_tier`` or ``unmatched``.
    ``all_hops`` and ``user_e2e_hops``: tier = the hop's ``best_tier``. Counts that do not belong to a scope are
    empty. Order: scope, protocol group (smb, winrm, rdp, none), tier (A-D, unmatched), ``all`` last per scope.
    """
    acc: dict[tuple[str, str, str], dict[str, int]] = {}
    for r in keyed or ():
        matched = r["match"] == "matched"
        grp = r["protocol_group"] if matched else _key_protocol_group(r["key_protocol"])
        _add(acc, ("keyed", grp, r["best_tier"] if matched else "unmatched"), _keyed_counts(r))
    if keyed is not None and not keyed:
        acc[("keyed", ALL, ALL)] = {k: 0 for k in KEYED_COUNTS}
    for r in facts:
        key = (r["protocol_group"], r["best_tier"])
        _add(acc, ("all_hops", *key), _hop_counts(r))
        if r["user_e2e"] == "1":
            _add(acc, ("user_e2e_hops", *key), _hop_counts(r))
    for scope in ("all_hops", "user_e2e_hops"):
        acc.setdefault((scope, ALL, ALL), {k: 0 for k in HOP_COUNTS})

    def order(k: tuple[str, str, str]) -> tuple:
        s, g, t = k
        return (SCOPES.index(s), g == ALL, _order_index(g, PROTOCOL_GROUP_ORDER), _order_index(t, TIER_ORDER))

    out: list[dict[str, str]] = []
    for k in sorted(acc, key=order):
        names = KEYED_COUNTS if k[0] == "keyed" else HOP_COUNTS
        row = {c: "" for c in TOTAL_COLUMNS}
        row.update(split=split, trial_id=trial, scope=k[0], protocol_group=k[1], tier=k[2])
        row.update({n: str(acc[k].get(n, 0)) for n in names})
        out.append(row)
    return out


def headline(keyed: Sequence[Mapping[str, str]] | None, facts: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """Headline numbers of one trial (JSON-ready): keyed counts (if keyed), key-uid origins, key-session tiers per
    protocol group, the key hops with evidence before the range, and the hop counts of both hop scopes."""
    out: dict[str, Any] = {"keyed": keyed is not None}
    if keyed is not None:
        sums = {k: 0 for k in KEYED_COUNTS}
        tiers: dict[str, dict[str, int]] = {}
        for r in keyed:
            for k, n in _keyed_counts(r).items():
                sums[k] += n
            if r["key_session_tier"]:
                g = tiers.setdefault(r["protocol_group"], {})
                g[r["key_session_tier"]] = g.get(r["key_session_tier"], 0) + 1
        out.update(sums)
        out["match_multiple"] = sum(1 for r in keyed if r["match"] == "multiple")
        out["match_unmatched"] = sum(1 for r in keyed if r["match"] == "unmatched")
        out["key_uid_source"] = {v: sum(1 for r in keyed if r["key_session_uid_source"] == v)
                                 for v in ("direct", "lookup", "none")}
        out["key_session_tiers"] = {g: dict(sorted(t.items())) for g, t in sorted(tiers.items())}
        out["evidence_before_range_keyed"] = {r["key_hop_id"]: int(r["evidence_before_range"]) for r in keyed
                                              if r["evidence_before_range"] not in ("", "0")}
    for scope, rows in (("all_hops", facts), ("user_e2e_hops", [r for r in facts if r["user_e2e"] == "1"])):
        sums = {k: 0 for k in HOP_COUNTS}
        for r in rows:
            for k, n in _hop_counts(r).items():
                sums[k] += n
        out[scope] = sums
    return out
