"""Correction K identity value per hop, computed from the DB (AK-07..AK-10).

identity_expected = 1 iff the moving account had a logon session open on the SOURCE
host when LSASS was read there (Sysmon 10, rundll32 -> lsass) and the move (target
4624 time) is not before the dump (cross-host tolerance 5 s, decision 014). Exposed,
not stolen: nothing here claims the credential was used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .targets import is_user_account, normalise_account

CROSS_HOST_TOL_S = 5.0
DUMP_PAIR_S = 1.0
STRONG_TYPES = {2, 4, 5, 7, 10, 11}
WEAK_TYPES = {3}
SYSTEM_LOGON_IDS = {0x3E4, 0x3E5, 0x3E7}
BOOT_OR_CLEAR_IDS = {1102, 104, 6005, 6006, 6008, 41, 1074}


@dataclass(frozen=True)
class Dump:
    """One LSASS dump: Sysmon 10 records of one rundll32 within DUMP_PAIR_S of each other."""
    host: str
    ts: float
    time_utc: str
    account: str
    process_guid: str
    event_uids: tuple[str, ...]


def _endswith(path: str | None, tail: str) -> bool:
    return bool(path) and path.lower().replace("/", "\\").endswith(tail)


def _lsass_records(rows: Sequence[Mapping], user_tokens: bool) -> list[Mapping]:
    """Sysmon 10 rundll32 -> lsass.exe records whose token is (or is not) a domain user."""
    return [r for r in rows
            if r["channel"] == "Sysmon" and r["event_id"] == 10
            and _endswith(r.get("source_image"), "\\rundll32.exe") and _endswith(r.get("target_image"), "\\lsass.exe")
            and is_user_account(r.get("account_name")) == user_tokens]


def _pair_records(recs: Sequence[Mapping]) -> list[Dump]:
    """Collapse records of one rundll32 within DUMP_PAIR_S into one Dump (E3 pairing)."""
    recs = sorted(recs, key=lambda r: (r["host"], r["process_guid"] or "", r["ts"]))
    dumps: list[Dump] = []
    group: list[Mapping] = []

    def flush() -> None:
        if group:
            dumps.append(Dump(group[0]["host"], group[0]["ts"], group[0]["t_utc"],
                              normalise_account(group[0]["account_name"]), group[0]["process_guid"] or "",
                              tuple(g["event_uid"] for g in group)))
            group.clear()

    for r in recs:
        if group and (r["host"], r["process_guid"]) == (group[-1]["host"], group[-1]["process_guid"])                 and r["ts"] - group[-1]["ts"] <= DUMP_PAIR_S:
            group.append(r)
        else:
            flush()
            group.append(r)
    flush()
    dumps.sort(key=lambda d: (d.ts, d.host))
    return dumps


def find_dumps(rows: Sequence[Mapping]) -> list[Dump]:
    """Sysmon 10 rundll32 -> lsass.exe by a domain user; E3 pairs collapse to one dump.

    VBoxService / svchost accesses are SYSTEM and never match (E1, E2); a single
    surviving record still counts as a dump (AK-10).
    """
    return _pair_records(_lsass_records(rows, True))


def system_dumps_ignored(rows: Sequence[Mapping]) -> list[dict]:
    """Per host, the rundll32 -> lsass accesses skipped because the token was not a user.

    WHY: the 'domain SourceUser' rule (AK-10) deliberately ignores SYSTEM-owned dumps; listing
    them (count, uids, times) means nothing the rule skipped is invisible to the reviewer.
    """
    by_host: dict[str, list[Dump]] = {}
    for d in _pair_records(_lsass_records(rows, False)):
        by_host.setdefault(d.host, []).append(d)
    return [{"host": h, "count": len(ds), "times_utc": [d.time_utc for d in ds],
             "accounts": sorted({d.account for d in ds}),
             "event_uids": [u for d in ds for u in d.event_uids]} for h, ds in sorted(by_host.items())]


@dataclass(frozen=True)
class HostState:
    """Logons, logoffs and boot/clear markers of every host, indexed once."""
    logons: dict[str, list[Mapping]]
    logoff_ts: dict[tuple[str, int], list[float]]
    boot_ts: dict[str, list[float]]


def build_host_state(rows: Sequence[Mapping]) -> HostState:
    """Index 4624 (logons), 4634/4647 (logoffs) and boot/clear events (decision 004)."""
    logons: dict[str, list[Mapping]] = {}
    logoff: dict[tuple[str, int], list[float]] = {}
    boots: dict[str, list[float]] = {}
    for r in rows:
        eid, ch = r["event_id"], r["channel"]
        if ch == "Security" and eid == 4624 and r.get("target_logon_id") is not None:
            logons.setdefault(r["host"], []).append(r)
        elif ch == "Security" and eid in (4634, 4647):
            lid = r.get("target_logon_id") if eid == 4634 else r.get("subject_logon_id")
            if lid is not None:
                logoff.setdefault((r["host"], lid), []).append(r["ts"])
        elif eid in BOOT_OR_CLEAR_IDS and ch in ("System", "Security"):
            boots.setdefault(r["host"], []).append(r["ts"])
    for v in logoff.values():
        v.sort()
    return HostState(logons, logoff, boots)


def exposure_strength(logon_type: int | None) -> str:
    """Annotation only: strong = types 2,4,5,7,10,11; weak = type 3 (never changes the value)."""
    if logon_type in STRONG_TYPES:
        return "strong"
    if logon_type in WEAK_TYPES:
        return "weak"
    return "other"


def sessions_at(state: HostState, host: str, account: str, at_ts: float) -> tuple[list[dict], list[dict]]:
    """Sessions of ``account`` on ``host`` open at ``at_ts`` and those with unknown end.

    Open = logon at or before the dump, no logoff of THIS session (logon < logoff <= dump; an
    older 4634 reusing the same logon id must not close a newer session), and no
    boot/log-clear marker between logon and dump. A session that would be open but for
    a boot/clear marker is ``end_unknown``: listed, never dropped, not counted.
    """
    acct = normalise_account(account)
    open_s: list[dict] = []
    unknown: list[dict] = []
    for r in state.logons.get(host, []):
        if normalise_account(r.get("account_name")) != acct or r["target_logon_id"] in SYSTEM_LOGON_IDS:
            continue
        if r["ts"] > at_ts or r.get("logon_type") in (None, 0):
            continue
        closed = any(r["ts"] < off <= at_ts for off in state.logoff_ts.get((host, r["target_logon_id"]), ()))
        if closed:
            continue
        item = {"logon_id": r["target_logon_id"], "logon_id_hex": hex(r["target_logon_id"]),
                "logon_type": r.get("logon_type"), "exposure_strength": exposure_strength(r.get("logon_type")),
                "logon_time_utc": r["t_utc"], "event_uid": r["event_uid"]}
        has_later_off = any(off > r["ts"] for off in state.logoff_ts.get((host, r["target_logon_id"]), ()))
        if not has_later_off and any(r["ts"] < b <= at_ts for b in state.boot_ts.get(host, [])):
            unknown.append(item)
        else:
            open_s.append(item)
    open_s.sort(key=lambda s: s["logon_time_utc"])
    return open_s, unknown


def pick_dump(dumps: Sequence[Dump], host: str, move_ts: float, tol_s: float) -> Dump | None:
    """Latest dump on ``host`` that is not after the move (dump <= move + tol)."""
    cands = [d for d in dumps if d.host == host and d.ts <= move_ts + tol_s]
    return max(cands, key=lambda d: d.ts) if cands else None


def evaluate_identity(dumps: Sequence[Dump], state: HostState, account: str, source_host: str | None,
                      move_ts: float, tol_s: float = CROSS_HOST_TOL_S) -> dict:
    """Correction K for one hop, with the evidence and flags (AK-07).

    Returns ``{identity_expected, identity_basis, flags}``. ``identity_at_tol0`` repeats
    the value with no tolerance, as the spec's sensitivity check.
    """
    flags: list[str] = []
    basis: dict = {"dump_event_uid": None, "dump_event_uids": [], "dump_time_utc": None, "dump_host": source_host,
                   "open_session_ids": [], "open_sessions": [], "end_unknown_ids": [],
                   "move_after_dump": False, "tolerance_s": tol_s, "dump_candidates_on_host": 0,
                   "identity_at_tol0": 0, "identity_if_unknown_counted": 0}
    if source_host is None:
        return {"identity_expected": 0, "identity_basis": {**basis, "note": "source host unknown"}, "flags": flags}
    basis["dump_candidates_on_host"] = sum(1 for d in dumps if d.host == source_host)
    dump = pick_dump(dumps, source_host, move_ts, tol_s)
    dump0 = pick_dump(dumps, source_host, move_ts, 0.0)
    open0 = sessions_at(state, source_host, account, dump0.ts)[0] if dump0 else []
    basis["identity_at_tol0"] = 1 if (dump0 and open0) else 0
    basis["identity_if_unknown_counted"] = basis["identity_at_tol0"]
    if dump is None:
        return {"identity_expected": 0, "identity_basis": basis, "flags": flags}
    open_s, unknown = sessions_at(state, source_host, account, dump.ts)
    basis.update({"dump_event_uid": dump.event_uids[0], "dump_event_uids": list(dump.event_uids),
                  "dump_time_utc": dump.time_utc, "dump_account": dump.account,
                  "move_after_dump": move_ts >= dump.ts - tol_s,
                  "open_session_ids": [s["logon_id_hex"] for s in open_s], "open_sessions": open_s,
                  "end_unknown_ids": [s["logon_id_hex"] for s in unknown], "end_unknown": unknown})
    if abs(move_ts - dump.ts) <= tol_s:
        flags.append("order_within_tolerance")
    if unknown:
        flags.append("end_unknown")
    if open_s and all(s["exposure_strength"] == "weak" for s in open_s):
        flags.append("weak_exposure_only")
    value = 1 if (open_s and basis["move_after_dump"]) else 0
    # decision 004 lists unknown-end sessions without guessing; this records what counting them as open would give
    basis["identity_if_unknown_counted"] = 1 if ((open_s or unknown) and basis["move_after_dump"]) else 0
    return {"identity_expected": value, "identity_basis": basis, "flags": flags}
