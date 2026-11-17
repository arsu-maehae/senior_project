"""Reading an approved key against the stitch hops: the ST-25 match and the key source session (decision 051
items 3 and 4). Pure: the DB facts are passed in, already queried.

WHY a module apart from the verdicts: how the key is read is fixed by the owner (051 item 4) and must be the same
for development and test; keeping it apart lets a test check it on synthetic keys without any stitch row.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence

from .inputs import BootRow, EvalError, EventRow, LogonRow
from .params import BOOT_SHUTDOWN_IDS, BOOT_STARTUP_IDS

__all__ = ["KeySession", "MatchResult", "iso_to_us", "parse_hex", "hex_id", "split_list", "key_account",
           "match_key_hop", "key_logons_in_hop", "sysmon1_agent_uids", "explicit_session_id", "boot_groups",
           "group_boundaries", "boundaries_of", "epoch_of", "lookup_session_uid", "epochs_of_logon_id",
           "key_sessions", "session_lookup_requests"]

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_STARTUP, _SHUTDOWN = "startup", "shutdown"


# ---------------------------------------------------------------- small parsers

def iso_to_us(text: str) -> int:
    """ISO-8601 UTC text (``...Z`` or ``+00:00``) to integer microseconds since the epoch.

    WHY integers: same-instant comparisons ("at or before", "at a boundary") must be exact, with no float error.
    Zone-less text is refused (ValueError): guessing UTC could shift a whole trial.
    """
    dt = datetime.fromisoformat(str(text).strip())
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError(f"timestamp without a time zone: {text!r}")
    delta = dt.astimezone(timezone.utc) - _EPOCH
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def parse_hex(text: str | int) -> int:
    """Key logon id text (``0x1a9231``) to the integer used for joins (D1: integers join, hex displays)."""
    if isinstance(text, int):
        return text
    return int(str(text).strip(), 16)


def hex_id(logon_id: int) -> str:
    """Display form ``0x...`` in lower case (D1)."""
    return f"0x{int(logon_id):x}"


def split_list(cell: str | None) -> list[str]:
    """A ``;``-joined stitch cell to its parts; empty cell -> []."""
    return [p for p in (cell or "").split(";") if p != ""]


def key_account(key_hop: Mapping[str, Any]) -> str:
    """The moving account of a key hop, lower-cased: ``logon_account``, else ``account`` (decision 027)."""
    return str(key_hop.get("logon_account") or key_hop.get("account") or "").lower()


# ---------------------------------------------------------------- ST-25 match (051 item 3)

@dataclass(frozen=True)
class MatchResult:
    """Outcome of matching one key hop to the stitch hops."""
    outcome: str                      # matched / unmatched / multiple
    hop_ids: tuple[str, ...]          # every hop with the key's target 4624 as a member
    member_uids: tuple[str, ...]      # that 4624's uid per hop, same order


def match_key_hop(key_hop: Mapping[str, Any], hops: Sequence[Mapping[str, str]]) -> MatchResult:
    """The hops that have the key's target 4624 as a member: a member whose uid is in ``target_event_uids`` and
    whose logon ID equals ``target_logon_id`` (ST-25; 051 item 3).

    WHY both conditions: ``target_event_uids`` also lists artefacts and other 4624s of the move; the logon ID picks
    the one 4624 the key calls the target logon. ``member_logon_uids`` and ``member_logon_ids`` are parallel lists.
    """
    uids = set(key_hop.get("target_event_uids") or [])
    want = parse_hex(key_hop["target_logon_id"])
    found: list[tuple[str, str]] = []
    for hop in hops:
        for uid, lid in zip(split_list(hop.get("member_logon_uids")), split_list(hop.get("member_logon_ids"))):
            if uid in uids and int(lid) == want:
                found.append((hop["hop_id"], uid))
                break
    outcome = "matched" if len(found) == 1 else ("unmatched" if not found else "multiple")
    return MatchResult(outcome, tuple(h for h, _ in found), tuple(u for _, u in found))


def key_logons_in_hop(key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
                      hop: Mapping[str, str] | None) -> str:
    """``n/m``: m = the key's ``target_event_uids`` that ``event_keys`` says are target-host Security 4624s; n = how
    many of them are members of the matched hop (051 item 3). WHY: shows whether the stitcher put the key's
    logons of one move into one group or split them. Empty when no hop matched."""
    if hop is None:
        return ""
    target = key_hop.get("target_host")
    logons = [u for u in key_hop.get("target_event_uids") or []
              if (event_keys.get(u) or {}).get("host") == target
              and (event_keys.get(u) or {}).get("channel") == "Security"
              and (event_keys.get(u) or {}).get("event_id") == 4624]
    members = set(split_list(hop.get("member_logon_uids")))
    return f"{sum(1 for u in logons if u in members)}/{len(logons)}"


# ---------------------------------------------------------------- boot epochs (047 item 3; 051 item 4)

def _boot_kind(event_id: int) -> str:
    """``startup`` (41, 6005, 6008) or ``shutdown`` (1074, 6006)."""
    if event_id in BOOT_STARTUP_IDS:
        return _STARTUP
    if event_id in BOOT_SHUTDOWN_IDS:
        return _SHUTDOWN
    raise ValueError(f"not a boot event id: {event_id}")


def boot_groups(rows: Iterable[BootRow], boot_group_s: float) -> list[tuple[str, list[tuple[int, str]]]]:
    """One host's boot events cut into groups, in logged-time order: (kind, [(us, uid)]).

    Consecutive events of one kind at most ``boot_group_s`` apart form one group; a change of kind or a larger gap
    starts a new one. WHY groups: one restart logs 41 / 6005 / 6008 up to 40.9 s apart, and each event as its own
    boundary would split a boot in two (047 item 3).
    """
    gap_us = int(round(boot_group_s * 1_000_000))
    events = sorted((iso_to_us(r.event_utc), r.event_uid, _boot_kind(r.event_id)) for r in rows)
    groups: list[tuple[str, list[tuple[int, str]]]] = []
    prev: tuple[int, str, str] | None = None
    for us, uid, kind in events:
        if prev is None or kind != prev[2] or us - prev[0] > gap_us:
            groups.append((kind, []))
        groups[-1][1].append((us, uid))
        prev = (us, uid, kind)
    return groups


def group_boundaries(groups: Sequence[tuple[str, Sequence[tuple[int, str]]]]) -> list[int]:
    """Boundary instants: a shutdown group's LAST event; a startup group's FIRST event unless a shutdown group comes
    right before it (047 item 3 as amended 2026-11-14: a clean restart has one boundary, at its 6006)."""
    out: list[int] = []
    for i, (kind, events) in enumerate(groups):
        if kind == _SHUTDOWN:
            out.append(events[-1][0])
        elif i == 0 or groups[i - 1][0] != _SHUTDOWN:
            out.append(events[0][0])
    return sorted(out)


def boundaries_of(rows: Iterable[BootRow], boot_group_s: float) -> list[int]:
    """One host's sorted boundary instants (``boot_groups`` then ``group_boundaries``)."""
    return group_boundaries(boot_groups(rows, boot_group_s))


def epoch_of(us: int, boundaries: Sequence[int]) -> int:
    """Number of boundaries at or before ``us``: an event at a boundary instant belongs to the new boot (047)."""
    return bisect_right(list(boundaries), us)


def epochs_of_logon_id(logons: Iterable[LogonRow], boundaries: Sequence[int]) -> frozenset[int]:
    """Epochs in which the logon ID has an opening 4624 on its host. WHY: more than one means the same ID was
    reused after a reboot, so (host, logon ID) alone does not name one session (051 item 5, ``ambiguous_boot``)."""
    return frozenset(epoch_of(iso_to_us(r.event_utc), boundaries) for r in logons)


def lookup_session_uid(logons: Iterable[LogonRow], boundaries: Sequence[int], command_us: int) -> str | None:
    """The session's opening 4624: at or before the earliest key command, in the same boot epoch as it, the latest
    if several (051 item 4). None when no 4624 qualifies. WHY "latest in the same epoch": a logon ID reused after
    a boot (or reopened) must not be confused with the session that actually ran the command."""
    epoch = epoch_of(command_us, boundaries)
    ok = sorted((iso_to_us(r.event_utc), r.event_uid) for r in logons
                if iso_to_us(r.event_utc) <= command_us and epoch_of(iso_to_us(r.event_utc), boundaries) == epoch)
    return ok[-1][1] if ok else None


# ---------------------------------------------------------------- key source session (051 item 4)

@dataclass(frozen=True)
class KeySession:
    """One key source session: host, logon ID, its 4624 uid (or None) and where the uid came from."""
    host: str
    logon_id: int
    uid: str | None
    uid_source: str                   # direct / lookup / none
    command_uids: tuple[str, ...]     # the key command events used for the lookup
    epochs: frozenset[int]            # epochs of the logon ID's opening 4624s on the host


def sysmon1_agent_uids(key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """``agent_event_uids`` whose ``event_keys`` entry is Sysmon event 1, in key order (051 item 4)."""
    return [u for u in key_hop.get("agent_event_uids") or []
            if (event_keys.get(u) or {}).get("channel") == "Sysmon" and (event_keys.get(u) or {}).get("event_id") == 1]


def explicit_session_id(key_hop: Mapping[str, Any]) -> int | None:
    """``source_session_logon_id``, else ``session_evidence.session_id``, as an integer; None when neither."""
    if key_hop.get("source_session_logon_id"):
        return parse_hex(key_hop["source_session_logon_id"])
    se = key_hop.get("session_evidence") or {}
    if se.get("session_id"):
        return parse_hex(se["session_id"])
    return None


def _explicit_commands(key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
                       host: str) -> tuple[str, ...]:
    """Command events of an explicit key session: ``session_evidence.command_event_uids`` when given, else the
    ``agent_event_uids``; only those that ``event_keys`` places on the source host."""
    se = key_hop.get("session_evidence") or {}
    uids = se.get("command_event_uids") or key_hop.get("agent_event_uids") or []
    return tuple(u for u in uids if (event_keys.get(u) or {}).get("host") == host)


def _direct_uid(key_hop: Mapping[str, Any], logon_id: int) -> str | None:
    """``session_evidence.session_logon_uid`` when the key gives it for this same session id, else None."""
    se = key_hop.get("session_evidence") or {}
    uid = se.get("session_logon_uid")
    if not uid:
        return None
    if se.get("session_id") and parse_hex(se["session_id"]) != logon_id:
        return None
    return str(uid)


def session_lookup_requests(key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
                            events: Mapping[str, EventRow]) -> list[tuple[str, int, tuple[str, ...]]]:
    """The key's source sessions before the uid lookup: [(host, logon ID, command uids)], sorted (051 item 4).

    - explicit id (``source_session_logon_id`` / ``session_evidence.session_id``) on the key ``source_host``;
    - else the (host, session_id) of the key's Sysmon 1 agent events, session_id from the DB (NULL skipped).
    An empty list means the key hop has no source session (background, ``time_account_only``).
    A Sysmon 1 agent uid of the key that is absent from ``events_dedup`` is refused (EvalError): the key and the DB
    (whose hashes match) disagree, and skipping the uid would silently turn a keyed hop into a background hop
    (review ATK-24). The message names the key hop id and a count, never a uid or other key value.
    """
    sid = explicit_session_id(key_hop)
    if sid is not None:
        host = str(key_hop.get("source_host"))
        return [(host, sid, _explicit_commands(key_hop, event_keys, host))]
    by_session: dict[tuple[str, int], list[str]] = {}
    agent = sysmon1_agent_uids(key_hop, event_keys)
    missing = sum(1 for uid in agent if uid not in events)
    if missing:
        raise EvalError(f"refused: key hop {key_hop.get('hop_id', '?')}: {missing} Sysmon 1 agent event(s) of the key "
                        "are not in the DB view events_dedup")
    for uid in agent:
        ev = events[uid]
        if ev.session_id is None:
            continue
        by_session.setdefault((ev.host, ev.session_id), []).append(uid)
    return [(h, s, tuple(u)) for (h, s), u in sorted(by_session.items())]


def key_sessions(key_hop: Mapping[str, Any], event_keys: Mapping[str, Mapping[str, Any]],
                 events: Mapping[str, EventRow], logons: Mapping[tuple[str, int], Sequence[LogonRow]],
                 boots: Mapping[str, Sequence[BootRow]], boot_group_s: float) -> list[KeySession]:
    """The key's source sessions with their 4624 uid and epochs (051 item 4).

    The uid is ``session_evidence.session_logon_uid`` where present (``direct``), else the DB lookup of
    ``lookup_session_uid`` at the earliest key command of that session (time from ``event_keys``) (``lookup``),
    else None (``none``). ``logons`` holds every 4624 per (host, logon ID); ``boots`` every boot event per host.
    """
    out: list[KeySession] = []
    for host, lid, commands in session_lookup_requests(key_hop, event_keys, events):
        bounds = boundaries_of(boots.get(host, ()), boot_group_s)
        rows = list(logons.get((host, lid), ()))
        epochs = epochs_of_logon_id(rows, bounds)
        uid, source = _direct_uid(key_hop, lid), "direct"
        if uid is None:
            times = [iso_to_us(event_keys[u]["time_utc"]) for u in commands
                     if (event_keys.get(u) or {}).get("time_utc")]
            uid = lookup_session_uid(rows, bounds, min(times)) if times else None
            source = "lookup" if uid is not None else "none"
        out.append(KeySession(host, lid, uid, source, tuple(commands), epochs))
    return out
