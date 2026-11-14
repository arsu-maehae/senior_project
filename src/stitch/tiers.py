"""T7.4 verdicts per (hop, candidate source session): ``account_match``, ``name_check``, ``confidence_tier`` and
the order of a hop's sessions (spec 03_stitch ST-45, ST-46, ST-48, ST-50; decisions 013, 044 (a), 049 items 1-5).

WHY a separate module on top of the T7.3 ``SubjectLinks``: T7.3 finds candidate sessions and collects the data
side (the session's own in-window 4624 account, its 4648 credential accounts, the target-side names per command
event). Judging that data is a different question with its own locked rules, so it lives here and changes no
T7.3 result. Everything is pure: hops, links and artefact rows in, frozen verdict records out. No file access,
no command text (only names taken from target-side events, spec 2).

WHY the account is used here and nowhere earlier: Correction I as amended by 013 says the account is a
supporting check, never a join condition. Every candidate is already written by T7.3; the account only decides
the tier (ST-48: ``none`` -> D, checked first, 049 item 1) and the order (ST-50). ``direct`` and ``4648`` count
the same for both (owner Q14); the best value direct > 4648 > none is only for display.

WHY the name check can never change the tier (044 (a), ST-46): it reads the same command lines as the
``cmdline_target`` method, so letting it lift a tier would count one event twice. It is a recorded field and the
last tie-break of the order. Blanking the names therefore moves only ``link_rank``, ``tie``, ``rank_basis`` and
the ``name_check*`` fields (STT-07); ``tier_of`` does not even take it as an argument.

WHY time is never a rank key (Q14): cross-host clock residuals of 1.5 s and more (spec 10.8) would make a time
tie-break order sessions by noise. Sessions still equal stay equal (``tie`` = 1) and all are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .artefacts import KIND_BURST, KIND_INSTALL, ArtefactRow
from .hops import Hop, HopSet, RemoteLogon
from .sessions import SessionKey
from .source import METHOD_CMD, METHOD_PORT, SubjectLinks

__all__ = ["ACCOUNT_DIRECT", "ACCOUNT_4648", "ACCOUNT_NONE", "ACCOUNT_MATCHES", "NAME_MATCH", "NAME_NO_MATCH",
           "NAME_NO_NAMES", "TIERS", "RANK_BASES", "NAMED_KINDS", "account_match_member", "best_account_match",
           "is_consistent", "hop_names", "name_check_of", "tier_of", "SessionVerdict", "HopVerdicts",
           "rank_sessions", "hop_verdicts", "all_verdicts"]

ACCOUNT_DIRECT, ACCOUNT_4648, ACCOUNT_NONE = "direct", "4648", "none"
# Best first: the display order of ``best_account_match`` (049 item 2).
ACCOUNT_MATCHES: tuple[str, ...] = (ACCOUNT_DIRECT, ACCOUNT_4648, ACCOUNT_NONE)
NAME_MATCH, NAME_NO_MATCH, NAME_NO_NAMES = "match", "no_match", "no_names"
# Best first: the tier is the first rank key (ST-50).
TIERS: tuple[str, ...] = ("A", "B", "C", "D")
RANK_BASES: tuple[str, ...] = ("only", "tier", "account_match", "name_check", "equal", "no_session", "target_only")
# Artefact kinds whose ``names`` are target-side file / service names (ST-46): the same kinds as
# ``links.NAMED_ARTEFACT_KINDS``, taken from the artefacts constants so there is one spelling.
NAMED_KINDS: tuple[str, ...] = (KIND_BURST, KIND_INSTALL)

_RANK_KEY_NAMES: tuple[str, ...] = ("tier", "account_match", "name_check")
_BASIS_ONLY, _BASIS_EQUAL = "only", "equal"


# ---------------------------------------------------------------- account match (ST-45, 049 item 2)

def _lower(value: str | None) -> str | None:
    """Lower-cased account, None for NULL or empty: a missing account never matches anything (049 item 2)."""
    if value is None:
        return None
    text = str(value)
    return text.lower() if text else None


def account_match_member(member_account: str | None, session_account: str | None,
                         credential_accounts: Iterable[str]) -> str:
    """ST-45 for one member: ``direct`` when the member's 4624 account equals the session's own in-window 4624
    account, else ``4648`` when it equals one of the session's 4648 credential accounts (TargetUserName of its
    in-range 4648s naming the target), else ``none``. Case-insensitive; NULL / empty never matches.

    WHY the in-window 4624 only: ``SessionData.account`` comes from ``window_open`` (ST-01, decision 039); a
    session opened before the window has no account here, so it can only reach ``4648`` or ``none``.
    """
    member = _lower(member_account)
    if member is None:
        return ACCOUNT_NONE
    if member == _lower(session_account):
        return ACCOUNT_DIRECT
    if any(member == _lower(a) for a in credential_accounts):
        return ACCOUNT_4648
    return ACCOUNT_NONE


def best_account_match(values: Iterable[str]) -> str:
    """The best of the member values, direct > 4648 > none; ``none`` for no values. ValueError for an unknown
    value. WHY a best value at all: it is the display column; the tier and rank use ``is_consistent`` only."""
    best = len(ACCOUNT_MATCHES) - 1
    for v in values:
        if v not in ACCOUNT_MATCHES:
            raise ValueError(f"unknown account_match value: {v!r}")
        best = min(best, ACCOUNT_MATCHES.index(v))
    return ACCOUNT_MATCHES[best]


def is_consistent(value: str) -> bool:
    """True for ``direct`` or ``4648``: both rank equal and both allow tiers A-C (owner Q14, ST-50)."""
    return value in (ACCOUNT_DIRECT, ACCOUNT_4648)


# ---------------------------------------------------------------- name check (ST-46, 049 item 5)

def _sorted_names(names: Iterable[str]) -> list[str]:
    """Unique non-empty names, sorted case-insensitively then exactly (the order of ``Evidence.names_found``)."""
    return sorted({str(n) for n in names if n}, key=lambda n: (n.lower(), n))


def hop_names(hop_id: str, artefact_rows: Iterable[ArtefactRow]) -> list[str]:
    """The target-side names of the hop's own ``share_burst`` / ``service_install`` rows (049 item 5).

    WHY ``r.hop_id`` and not ``logged_under_hop_id``: a burst moved to this hop by ST-32 is this hop's artefact
    and its names count; a burst moved away is not this hop's.
    """
    return _sorted_names(n for r in artefact_rows if r.hop_id == hop_id and r.kind in NAMED_KINDS for n in r.names)


def name_check_of(session_key: SessionKey, sl: SubjectLinks,
                  names: Sequence[str]) -> tuple[str, list[str], list[str]]:
    """(``name_check``, matched names, event uids) of one candidate session (ST-46, 049 item 5).

    A hop name matches when it equals, case-insensitively, a name in ``Evidence.names_by_uid[u]`` of THIS
    session's own ``cmdline_target`` evidence for this hop. WHY equality on found names: the boundary-aware
    search in the command text was already done by ``cmdtext`` (048 item 1) and reduced to names; this step only
    asks which of the hop's own names were among them. Evidence of another session, another method or another
    hop never counts. Names keep the hop's spelling, sorted case-insensitively then exactly; uids sorted.
    ``no_names`` when the hop has no names; else ``match`` / ``no_match``.
    """
    hop = _sorted_names(names)
    if not hop:
        return NAME_NO_NAMES, [], []
    matched: set[str] = set()
    uids: set[str] = set()
    result = sl.methods.get(METHOD_CMD)
    for e in (result.evidence if result is not None else []):
        if e.session_key != session_key:
            continue
        for uid, found in e.names_by_uid.items():
            lowered = {str(f).lower() for f in found}
            hits = {n for n in hop if n.lower() in lowered}
            if hits:
                matched.update(hits)
                uids.add(uid)
    if not matched:
        return NAME_NO_MATCH, [], []
    return NAME_MATCH, _sorted_names(matched), sorted(uids)


# ---------------------------------------------------------------- tier (ST-48, 049 item 1)

def tier_of(account_best: str, in_port: bool, port_session_count: int, consistent_count: int) -> str:
    """ST-48 in the 049 item 1 order: ``account_match`` none -> D (checked first, no exception); else found by
    ``sysmon3_port`` alone -> A; else found by ``sysmon3_port`` among several -> C; else (4648 / command line)
    the hop's only account-consistent session over all methods -> B, otherwise C.

    WHY D first: 013 says the tier uses the account, and ST-48's D clause has no exception (limitation L-ST4: a
    port-joined session whose account matches nothing gets D). A hop whose members all have port 0 never has a
    port session, so it is at most B. The name check is deliberately not an argument (044 (a)).
    """
    if account_best not in ACCOUNT_MATCHES:
        raise ValueError(f"unknown account_match value: {account_best!r}")
    if not is_consistent(account_best):
        return "D"
    if in_port:
        return "A" if port_session_count == 1 else "C"
    return "B" if consistent_count == 1 else "C"


# ---------------------------------------------------------------- rank (ST-50, 049 item 3)

def _rank_key(signature: tuple[str, bool, bool]) -> tuple[int, int, int]:
    """(tier index, 0 if account-consistent else 1, 0 if name_check match else 1): smaller ranks first."""
    tier, consistent, name_match = signature
    if tier not in TIERS:
        raise ValueError(f"unknown tier: {tier!r}")
    return TIERS.index(tier), 0 if consistent else 1, 0 if name_match else 1


def _basis(own: tuple[int, int, int], other: tuple[int, int, int]) -> str:
    """The first rank key on which two rank groups differ (tier, account_match, name_check)."""
    for name, a, b in zip(_RANK_KEY_NAMES, own, other):
        if a != b:
            return name
    raise ValueError("two rank groups with equal keys")


def rank_sessions(signatures: Mapping[SessionKey, tuple[str, bool, bool]]) -> dict[SessionKey, tuple[int, int, str]]:
    """Session -> (``link_rank``, ``tie``, ``rank_basis``) from (tier, account_consistent, name_match) (ST-50,
    049 item 3).

    ``link_rank`` = dense rank by tier, then consistent first, then name match first; time is never a key (Q14).
    ``tie`` = 1 for every session that shares rank 1 with another session. ``rank_basis``: ``only`` for a single
    session; ``equal`` when there are several and all are on rank 1; otherwise the first key separating the
    session's rank group from the next group up (rank 1: from rank 2). Output sorted by session key.
    """
    keys = {k: _rank_key(s) for k, s in sorted(signatures.items())}
    groups = sorted(set(keys.values()))
    rank_of = {g: i + 1 for i, g in enumerate(groups)}
    first_count = sum(1 for g in keys.values() if rank_of[g] == 1)
    out: dict[SessionKey, tuple[int, int, str]] = {}
    for k, g in keys.items():
        rank = rank_of[g]
        tie = int(rank == 1 and first_count > 1)
        if len(keys) == 1:
            basis = _BASIS_ONLY
        elif len(groups) == 1:
            basis = _BASIS_EQUAL
        else:
            basis = _basis(g, groups[rank - 2] if rank > 1 else groups[1])
        out[k] = (rank, tie, basis)
    return out


# ---------------------------------------------------------------- verdict records

@dataclass(frozen=True)
class SessionVerdict:
    """The T7.4 columns of one (hop, candidate session), repeated on every link row of that session (spec 3).

    ``account_match_members`` has one value per member in member order (us_raw, uid);
    ``account_match_member_count`` = members ``direct`` or ``4648``. ``name_check_event_uids`` are the command
    events that held the matched names (traceability, CLAUDE.md code rules).
    """
    session_key: SessionKey
    account_match: str
    account_match_members: tuple[str, ...]
    account_match_member_count: int
    name_check: str
    name_check_names: tuple[str, ...]
    name_check_event_uids: tuple[str, ...]
    confidence_tier: str
    link_rank: int
    tie: int
    rank_basis: str


@dataclass(frozen=True)
class HopVerdicts:
    """All session verdicts of one hop plus the hop-level values the writer needs.

    ``candidate_count_account`` = sessions whose ``account_match`` is not ``none`` (049 item 2).
    ``no_session_name_check`` is what an unresolved or ``target_only`` row carries (049 item 4: ``no_names`` when
    the hop has no names, else ``no_match``; such rows are tier D, account ``none``, no rank). ``best_tier`` is the
    best tier over the sessions, ``D`` when the hop has none (a ``target_only`` hop is D, ST-49).
    """
    hop_id: str
    sessions: dict[SessionKey, SessionVerdict]
    candidate_count_account: int
    names: tuple[str, ...]
    no_session_name_check: str
    best_tier: str


def _member_order(members: Iterable[RemoteLogon]) -> list[RemoteLogon]:
    """Members in member order (us_raw, uid), the order of every per-member column (spec 3)."""
    return sorted(members, key=lambda m: (m.us_raw, m.uid))


def hop_verdicts(hop: Hop, sl: SubjectLinks, names: Sequence[str]) -> HopVerdicts:
    """Account match, name check, tier and rank for every candidate session of one hop.

    Account data per session: ``SessionData.account`` (the session's in-window 4624, ``window_open``) and
    ``SessionData.credential_accounts``. Port sessions = the ``sysmon3_port`` method's candidate sessions. The
    tier is computed before and independently of the name check, so ``names`` can only move the rank fields.
    """
    members = _member_order(hop.members)
    port = sl.methods.get(METHOD_PORT)
    port_sessions = set(port.sessions) if port is not None else set()
    keys = sorted(sl.sessions)
    per_member: dict[SessionKey, tuple[str, ...]] = {}
    for k in keys:
        data = sl.sessions[k]
        per_member[k] = tuple(account_match_member(m.account, data.account, data.credential_accounts)
                              for m in members)
    best = {k: best_account_match(v) for k, v in per_member.items()}
    consistent_count = sum(1 for v in best.values() if is_consistent(v))
    tiers = {k: tier_of(best[k], k in port_sessions, len(port_sessions), consistent_count) for k in keys}
    checks = {k: name_check_of(k, sl, names) for k in keys}
    ranks = rank_sessions({k: (tiers[k], is_consistent(best[k]), checks[k][0] == NAME_MATCH) for k in keys})
    sessions = {k: SessionVerdict(session_key=k, account_match=best[k], account_match_members=per_member[k],
                                  account_match_member_count=sum(1 for v in per_member[k] if is_consistent(v)),
                                  name_check=checks[k][0], name_check_names=tuple(checks[k][1]),
                                  name_check_event_uids=tuple(checks[k][2]), confidence_tier=tiers[k],
                                  link_rank=ranks[k][0], tie=ranks[k][1], rank_basis=ranks[k][2])
                for k in keys}
    hop_name_list = _sorted_names(names)
    return HopVerdicts(hop_id=hop.hop_id, sessions=sessions,
                       candidate_count_account=sum(1 for v in best.values() if v != ACCOUNT_NONE),
                       names=tuple(hop_name_list),
                       no_session_name_check=NAME_NO_MATCH if hop_name_list else NAME_NO_NAMES,
                       best_tier=min(tiers.values(), key=TIERS.index, default="D"))


def all_verdicts(hopset: HopSet, links: Mapping[str, SubjectLinks],
                 artefact_rows: Iterable[ArtefactRow]) -> dict[str, HopVerdicts]:
    """``hop_verdicts`` for every hop of the set, by hop id, with the hop's own names (``hop_names``).
    Follow-up groups have no links and so no verdicts (ST-26)."""
    rows = list(artefact_rows)
    return {h.hop_id: hop_verdicts(h, links[h.hop_id], hop_names(h.hop_id, rows)) for h in hopset.hops}
