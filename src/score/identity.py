"""IdentityCoherence (spec 05_score SC-50..SC-55; decision 064; Correction K; decisions 013, 014, 044 (c)).

The stitcher writes identity facts per (hop, account, LSASS read) and computes no value (ST-64). Here:

- SC-51 counted reads = the ``R1_lsass`` rows minus reads by wmiprvse / csrss / wininit / MsMpEng **at their system
  folder AND under a system account** (b'); a same-named binary elsewhere or under a user account still counts.
- SC-50 a (hop, account) is 1 iff some counted read has ``order_ok`` = 1 (move >= dump - 5 s, decision 014; the
  stitcher's flag, not re-computed) and a non-empty ``open_session_uids`` (``end_unknown`` sessions are already
  left out of that column by the stitcher, ST-63); else 0. Only the moving account and the source host are used (013),
  so ``target_only`` hops get a value too.
- SC-52 a (hop, account) with ``not_applicable`` set is no crossing; a hop's value = max over its applicable accounts;
  a hop with at least one applicable account is a crossing.
- SC-53 IdentityCoherence = coherent crossings / crossings, 0 when there are none; every (hop, account) carries
  ``identity_status`` so "no evidence" is never shown as "not exposed" (ATK-SC-06).
- SC-54 ``identity_low`` / ``identity_high``, per account (ATK-SC-19, decision 069 item 2): an applicable account is
  *robust* when its value is 1 and it is not clock-flagged, *possible* when its value is 1 or it is flagged; a hop's
  low value is 1 iff some account is robust, its high value 1 iff some account is possible; the path values are the
  fractions over the crossings. WHY per account: a flagged, unexposed second account must not pull down a hop that
  an unflagged exposed account already makes coherent.

"Exposed" means the account had a session open on the source host when LSASS was read there; it is not evidence
that the credentials were taken or used (SC-55). All functions are pure.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .params import EXCLUDED_READ_IMAGE_PATTERNS, EXCLUDED_READ_IMAGES, SYSTEM_ACCOUNTS
from .sequence import split_list

__all__ = ["STATUS_EXPOSED", "STATUS_NOT_EXPOSED", "STATUS_END_UNKNOWN", "AccountIdentity", "HopIdentity",
           "PathIdentity", "is_excluded_read", "counted_reads", "account_identity", "account_identities",
           "hop_identities", "path_identity"]

STATUS_EXPOSED, STATUS_NOT_EXPOSED = "exposed", "not_exposed"
# SC-53 "no logoff seen for a counted session": a counted, order-ok read whose only candidate sessions are
# ``end_unknown`` (a log clear between logon and dump, ST-63). Scores 0 like "not exposed", but is shown as unknown.
STATUS_END_UNKNOWN = "unknown:end_unknown_session"

_PATTERNS = tuple(re.compile(p) for p in EXCLUDED_READ_IMAGE_PATTERNS)
Row = Mapping[str, str]


@dataclass(frozen=True)
class AccountIdentity:
    """The value of one (hop, account) (one ``hop_identity_values.csv`` row)."""
    hop_id: str
    account: str
    applicable: bool
    not_applicable: str
    value: int | None                       # 1 / 0, None when not applicable
    status: str
    candidate_count: int                    # counted reads (distinct dump events) after SC-51
    deciding_dump_event_uids: tuple[str, ...]
    open_session_uids: tuple[str, ...]
    time_delta_ms: str                      # gap_ms of the earliest deciding read, "" if none
    order_within_uncertainty: int           # on a deciding or a rejecting read (SC-54)
    session_open_before_window: int         # on a deciding read
    clock_unreliable: int                   # on any row of this (hop, account)


@dataclass(frozen=True)
class HopIdentity:
    """The crossing value of one hop (SC-52)."""
    hop_id: str
    crossing: bool                          # at least one applicable account
    value: int                              # max over applicable accounts; 0 when no crossing
    flagged: bool                           # an applicable account has order_within_uncertainty = 1
    robust: bool                            # ATK-SC-19: an applicable account has value 1 and no flag
    possible: bool                          # ATK-SC-19: an applicable account has value 1 or a flag


@dataclass(frozen=True)
class PathIdentity:
    """SC-53 / SC-54 values of one path."""
    coherence: float
    low: float
    high: float
    n_crossings: int
    n_coherent: int
    n_flagged: int
    n_unknown: int                          # ATK-SC-06: path hops with no applicable account (not a crossing)


def is_excluded_read(image: str, account: str) -> bool:
    """SC-51 (b'): True for a routine OS / AV read: image at one of the stated system paths (case-insensitive) AND a
    system account. WHY both conditions: the four images read LSASS routinely (wmiprvse 12, MsMpEng 12, wininit 9,
    csrss 9 distinct in-path reads), but a renamed dumper or one run by a user must still count (ATK-SC-04)."""
    img, acct = (image or "").strip().lower(), (account or "").strip().lower()
    if acct not in SYSTEM_ACCOUNTS:
        return False
    return img in EXCLUDED_READ_IMAGES or any(p.match(img) for p in _PATTERNS)


def counted_reads(rows: Iterable[Row]) -> list[Row]:
    """The rows of one (hop, account) that are counted R1 reads (SC-51): a dump event is present and not excluded."""
    return [r for r in rows if r["dump_event_uid"] and not is_excluded_read(r["dump_source_image"], r["dump_account"])]


def _flag(rows: Iterable[Row], column: str) -> int:
    """1 when any row has ``column`` = 1."""
    return int(any(r[column] == "1" for r in rows))


def _dump_order(r: Row) -> tuple[str, str]:
    """Earliest read first: corrected dump time (ISO text with fixed width sorts as time), then uid."""
    return (r["dump_utc_corrected"], r["dump_event_uid"])


def account_identity(hop_id: str, account: str, rows: Sequence[Row]) -> AccountIdentity:
    """SC-50, SC-51, SC-53, SC-54 for one (hop, account) from its ``hop_identity.csv`` rows.

    Deciding read = counted, ``order_ok`` = 1, open session. Rejecting read = counted, open session, ``order_ok`` = 0:
    with a clock flag on it, the true order might make it deciding, so it flags the crossing like a deciding read does
    (SC-54 "a deciding or a rejecting read"). A read with no open session is neither: its order cannot change the
    value. ``not_applicable`` (machine account, unknown source host, source host without logs) gives no value."""
    na = next((r["not_applicable"] for r in rows if r["not_applicable"]), "")
    clock = _flag(rows, "clock_unreliable")
    if na:
        return AccountIdentity(hop_id, account, False, na, None, f"unknown:{na}", 0, (), (), "", 0, 0, clock)
    counted = counted_reads(rows)
    deciding = sorted((r for r in counted if r["order_ok"] == "1" and split_list(r["open_session_uids"])),
                      key=_dump_order)
    rejecting = [r for r in counted if r["order_ok"] != "1" and split_list(r["open_session_uids"])]
    end_unknown = any(r["order_ok"] == "1" and split_list(r["end_unknown_session_uids"]) for r in counted)
    value = 1 if deciding else 0
    status = STATUS_EXPOSED if value else (STATUS_END_UNKNOWN if end_unknown else STATUS_NOT_EXPOSED)
    return AccountIdentity(
        hop_id=hop_id, account=account, applicable=True, not_applicable="", value=value, status=status,
        candidate_count=len({r["dump_event_uid"] for r in counted}),
        deciding_dump_event_uids=tuple(sorted({r["dump_event_uid"] for r in deciding})),
        open_session_uids=tuple(sorted({u for r in deciding for u in split_list(r["open_session_uids"])})),
        time_delta_ms=deciding[0]["gap_ms"] if deciding else "",
        order_within_uncertainty=_flag(deciding + rejecting, "order_within_uncertainty"),
        session_open_before_window=_flag(deciding, "session_open_before_window"),
        clock_unreliable=clock)


def account_identities(rows: Iterable[Row]) -> list[AccountIdentity]:
    """Every (hop, account) of ``hop_identity.csv``, sorted by hop then account."""
    groups: dict[tuple[str, str], list[Row]] = {}
    for r in rows:
        groups.setdefault((r["hop_id"], r["account"]), []).append(r)
    return [account_identity(h, a, g) for (h, a), g in sorted(groups.items())]


def _robust(a: AccountIdentity) -> bool:
    """ATK-SC-19: value 1 whatever the true clock order, i.e. exposed and not flagged."""
    return a.value == 1 and not a.order_within_uncertainty


def _possible(a: AccountIdentity) -> bool:
    """ATK-SC-19: value 1 under some clock order inside the uncertainty: exposed, or flagged (the true order might
    make a rejecting read deciding)."""
    return a.value == 1 or bool(a.order_within_uncertainty)


def hop_identities(accounts: Iterable[AccountIdentity]) -> dict[str, HopIdentity]:
    """hop_id -> crossing value (SC-52): max over applicable accounts (Q8 (a): the hop is the unit of "fraction of
    hops", CLAUDE.md); a hop with no applicable account is no crossing. ``robust`` / ``possible`` are decided per
    account, then "any account" per hop (ATK-SC-19)."""
    by_hop: dict[str, list[AccountIdentity]] = {}
    for a in accounts:
        by_hop.setdefault(a.hop_id, []).append(a)
    out: dict[str, HopIdentity] = {}
    for hop, accs in sorted(by_hop.items()):
        app = [a for a in accs if a.applicable]
        out[hop] = HopIdentity(hop_id=hop, crossing=bool(app), value=max((a.value or 0 for a in app), default=0),
                               flagged=any(a.order_within_uncertainty for a in app),
                               robust=any(_robust(a) for a in app), possible=any(_possible(a) for a in app))
    return out


def path_identity(hop_ids: Iterable[str], hops: Mapping[str, HopIdentity]) -> PathIdentity:
    """SC-53 / SC-54 for one path: coherent crossings / crossings (0 when none, handoff §12.4, Q9 (a)); low / high =
    crossings with a robust / a possible account, over the crossings (ATK-SC-19; 044 (c): the flag never changes
    ``order_ok``). ``n_unknown`` = the path's hops that are no crossing (ATK-SC-06), so "no evidence" stays visible at
    path level."""
    distinct = sorted(set(hop_ids))
    cross = [hops[h] for h in distinct if h in hops and hops[h].crossing]
    n = len(cross)
    unknown = len(distinct) - n
    coherent = sum(1 for c in cross if c.value == 1)
    flagged = sum(1 for c in cross if c.flagged)
    robust = sum(1 for c in cross if c.robust)
    possible = sum(1 for c in cross if c.possible)
    if n == 0:
        return PathIdentity(0.0, 0.0, 0.0, 0, 0, 0, unknown)
    return PathIdentity(coherence=coherent / n, low=robust / n, high=possible / n, n_crossings=n,
                        n_coherent=coherent, n_flagged=flagged, n_unknown=unknown)
