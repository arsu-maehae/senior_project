"""LC-08 and LC-08b: credential dumps and the sessions open on the dump host.

Correction K scores a hop 1 only if the moving account had a session open on the SOURCE
host when LSASS was read there. These checks measure whether the logs can show that
(exposed ≠ stolen); they list sessions by host, never by the dumper's process owner.
"""

from __future__ import annotations

import bisect
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .common import (INFO, NOT_MEASURABLE, OK, PREDEFINED_LOGON_IDS, PROBLEM, CheckResult,
                     Context, account_from_subject, gated_status, hex_id, load_all_4624,
                     load_commands, with_time)
from .matching import mask_command_line
from .params import Params
from .timeutil import parse_utc, seconds, to_db, to_display

DUMPS_SQL = """
    SELECT event_uid, host, event_utc, source_image, target_image, account_name,
           granted_access, process_guid
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 10
      AND lower(source_image) LIKE '%rundll32.exe' AND lower(target_image) LIKE '%lsass.exe'
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY host, event_utc, event_uid
"""
LOGOFF_SQL = """
    SELECT event_uid, host, event_id, event_utc, session_id
    FROM events_dedup
    WHERE channel = 'Security' AND event_id IN (4634, 4647) AND session_id IS NOT NULL
"""
LOGSTATE_SQL = """
    SELECT event_uid, host, channel, event_id, event_utc
    FROM events_dedup
    WHERE (channel = 'Security' AND event_id = 1102)
       OR (channel = 'System' AND event_id IN (104, 6005, 6006, 6008, 41, 1074))
"""
FIRST_RECORD_SQL = """
    SELECT host, min(event_utc) AS first_utc
    FROM events_dedup
    GROUP BY host
"""
PROCESS_SESSIONS_SQL = """
    SELECT host, session_id, min(event_utc) AS first_utc, max(event_utc) AS last_utc,
           count(*) AS n,
           max(CASE WHEN channel = 'Sysmon' THEN account_name END) AS sysmon_account,
           max(CASE WHEN channel = 'Security' THEN subject_account END) AS subject_account
    FROM events_dedup
    WHERE ((channel = 'Sysmon' AND event_id = 1) OR (channel = 'Security' AND event_id = 4688))
      AND host = ? AND event_utc >= ? AND event_utc <= ? AND session_id IS NOT NULL
    GROUP BY host, session_id
"""

BOOT_IDS = frozenset({6005, 6006, 6008, 41, 1074})
CLEAR_IDS = frozenset({1102, 104})
OPEN, CLOSED, END_UNKNOWN = "open", "closed", "end_unknown"


def logon_category(logon_type: int | None) -> str:
    """LC-08 split: interactive (2, 7, 10, 11), batch/service (4, 5), network (3)."""
    if logon_type in (2, 7, 10, 11):
        return "interactive"
    if logon_type in (4, 5):
        return "batch_service"
    if logon_type == 3:
        return "network"
    return "other" if logon_type is not None else "unknown"


@dataclass
class Dump:
    """One credential dump: a 0x1410 + 0x1fffff pair within DUMP_PAIR_S counts once (LCT-09)."""

    host: str
    t: datetime
    rows: list[dict[str, Any]]


def group_dumps(rows: list[dict[str, Any]], pair_s: float) -> list[Dump]:
    """Merge rundll32→lsass rows on one host that start within pair_s of the dump's first row."""
    dumps: list[Dump] = []
    for r in sorted(rows, key=lambda r: (r["host"], r["t"], r["event_uid"])):
        last = dumps[-1] if dumps else None
        if last and last.host == r["host"] and (r["t"] - last.t).total_seconds() <= pair_s:
            last.rows.append(r)
        else:
            dumps.append(Dump(r["host"], r["t"], [r]))
    return sorted(dumps, key=lambda d: (d.t, d.host))


@dataclass
class HostHistory:
    """Per-host session-end evidence: logoffs by id, boot and log-clear times, 4624s by id."""

    logoffs: dict[int, list[dict[str, Any]]]
    boots: list[datetime]
    clears: list[datetime]
    logons_by_id: dict[int, list[datetime]]
    first_record: datetime | None


def build_history(host: str, logons: list[dict], logoffs: list[dict], states: list[dict],
                  first_record: datetime | None) -> HostHistory:
    """Index one host's rows so session_state() is a pure lookup."""
    by_id: dict[int, list[dict]] = defaultdict(list)
    for lo in logoffs:
        if lo["host"] == host:
            by_id[int(lo["session_id"])].append(lo)
    reuse: dict[int, list[datetime]] = defaultdict(list)
    for lg in logons:
        if lg["host"] == host and lg.get("target_logon_id") is not None:
            reuse[int(lg["target_logon_id"])].append(lg["t"])
    boots = sorted(s["t"] for s in states if s["host"] == host and s["event_id"] in BOOT_IDS)
    clears = sorted(s["t"] for s in states if s["host"] == host and s["event_id"] in CLEAR_IDS)
    return HostHistory(dict(by_id), boots, clears, {k: sorted(v) for k, v in reuse.items()}, first_record)


def _any_between(times: list[datetime], lo: datetime, hi: datetime) -> bool:
    """Is there an event strictly between lo and hi? (times sorted)."""
    i = bisect.bisect_right(times, lo)
    return i < len(times) and times[i] < hi


def session_state(logon: dict[str, Any], hist: HostHistory, at: datetime) -> tuple[str, str, str | None]:
    """State of one 4624 session at time `at`: (state, reason, closing logoff uid).

    Closed: a 4634/4647 on the logon id or its linked id, after this 4624, before `at`,
    before the id is reused by a later 4624, with no boot in between. Otherwise
    end_unknown if the id was reused, a boot or log clear lies between start and `at`, or
    the session starts before the host's first record; else open.
    """
    start = logon["t"]
    lid = int(logon["target_logon_id"])
    ids = {lid} | ({int(logon["target_linked_logon_id"])} if logon.get("target_linked_logon_id") else set())
    later = [t for t in hist.logons_by_id.get(lid, []) if start < t < at]
    reuse_at = later[0] if later else None
    for sid in sorted(ids):
        for lo in sorted(hist.logoffs.get(sid, []), key=lambda r: r["t"]):
            if not (start < lo["t"] < at):
                continue
            if reuse_at is not None and lo["t"] > reuse_at:
                continue
            if _any_between(hist.boots, start, lo["t"]):
                continue
            return CLOSED, f"logoff {lo['event_id']} on {hex_id(sid)}", lo["event_uid"]
    if reuse_at is not None:
        return END_UNKNOWN, "logon id reused by a later 4624", None
    if _any_between(hist.boots, start, at):
        return END_UNKNOWN, "boot/shutdown event between start and dump", None
    if _any_between(hist.clears, start, at):
        return END_UNKNOWN, "log cleared between start and dump", None
    if hist.first_record is not None and start < hist.first_record:
        return END_UNKNOWN, "starts before the host's first record", None
    return OPEN, "no logoff before dump", None


def sessions_at(dump: Dump, logons: list[dict], hist: HostHistory, params: Params) -> tuple[list[dict], Counter]:
    """4624 sessions on the dump host started within SESSION_LOOKBACK_S, with their state."""
    lookback = dump.t - seconds(params.session_lookback_s)
    listed, counts = [], Counter()
    predefined: dict[int, dict] = {}
    for lg in logons:
        if lg["host"] != dump.host or lg.get("target_logon_id") is None or not (lookback <= lg["t"] < dump.t):
            continue
        if int(lg["target_logon_id"]) in PREDEFINED_LOGON_IDS:
            # Every service logon reuses 0x3e7/0x3e5/0x3e4; these sessions live from boot to
            # shutdown, so list each once (latest 4624) instead of as dozens of "reused" ids.
            predefined[int(lg["target_logon_id"])] = lg
            continue
        state, reason, logoff_uid = session_state(lg, hist, dump.t)
        counts[state] += 1
        if state == CLOSED:
            continue
        listed.append({"session_id": int(lg["target_logon_id"]), "session_hex": hex_id(lg["target_logon_id"]),
                       "linked_id": hex_id(lg.get("target_linked_logon_id")),
                       "linked_id_int": lg.get("target_linked_logon_id"),
                       "account_name": lg.get("account_name"), "logon_type": lg.get("logon_type"),
                       "category": logon_category(lg.get("logon_type")), "start": to_display(lg["t"]),
                       "state": state, "reason": reason, "source_ip": lg.get("source_ip"),
                       "event_uid": lg["event_uid"]})
    for lid, lg in sorted(predefined.items()):
        counts["predefined"] += 1
        listed.append({"session_id": lid, "session_hex": hex_id(lid), "linked_id": None, "linked_id_int": None,
                       "account_name": lg.get("account_name"), "logon_type": lg.get("logon_type"),
                       "category": "predefined", "start": to_display(lg["t"]), "state": OPEN,
                       "reason": "predefined system session (boot to shutdown)",
                       "source_ip": lg.get("source_ip"), "event_uid": lg["event_uid"]})
    return listed, counts


def process_only_sessions(rows: list[dict], hist: HostHistory, dump: Dump) -> list[dict]:
    """Sessions that ran processes before the dump but have no 4624 on the host before it:
    they started before the host's first record (or the logon was lost) → end_unknown."""
    out = []
    for r in rows:
        sid = int(r["session_id"])
        if any(t < dump.t for t in hist.logons_by_id.get(sid, [])):
            continue
        account = r.get("sysmon_account") or account_from_subject(r.get("subject_account"))
        out.append({"session_id": sid, "session_hex": hex_id(sid), "linked_id": None,
                    "account_name": account, "logon_type": None,
                    "category": "predefined" if sid in PREDEFINED_LOGON_IDS else "unknown",
                    "start": None, "first_process": r["first_utc"], "processes": r["n"],
                    "state": END_UNKNOWN, "reason": "no 4624 in DB (process activity only)",
                    "event_uid": None})
    return out


def commands_after(session_ids: set[int], host: str, commands: list[dict], start: datetime,
                   end: datetime) -> list[dict]:
    """Commands of the given sessions on host in (start, end] (LC-08b 'ran a command')."""
    return [c for c in commands if c["host"] == host and c.get("session_id") is not None
            and int(c["session_id"]) in session_ids and start < c["t"] <= end]


@dataclass
class DumpData:
    dumps: list[Dump]
    logons: list[dict]
    histories: dict[str, HostHistory]
    process_rows: dict[int, list[dict]]


def load_dump_data(ctx: Context) -> DumpData:
    db, p = ctx.db, ctx.params
    rows = with_time(db.query("LC-08", DUMPS_SQL, (ctx.window.start_db, ctx.window.end_db)))
    dumps = group_dumps(rows, p.dump_pair_s)
    logons = load_all_4624(ctx, "LC-08")
    logoffs = with_time(db.query("LC-08", LOGOFF_SQL))
    states = with_time(db.query("LC-08", LOGSTATE_SQL))
    firsts = {r["host"]: r["first_utc"] for r in db.query("LC-08", FIRST_RECORD_SQL)}
    hosts = sorted({d.host for d in dumps})
    hist = {h: build_history(h, logons, logoffs, states, parse_utc(firsts[h]) if firsts.get(h) else None)
            for h in hosts}
    proc_rows = {}
    for i, d in enumerate(dumps):
        rng = (d.host, to_db(d.t - seconds(p.session_lookback_s)), to_db(d.t))
        proc_rows[i] = db.query("LC-08", PROCESS_SESSIONS_SQL, rng)
    return DumpData(dumps, logons, hist, proc_rows)


def run_lc08(ctx: Context, data: DumpData) -> tuple[CheckResult, list[list[dict]]]:
    """LC-08: every dump with the sessions open on its host at dump time."""
    p = ctx.params
    out, all_sessions = [], []
    for i, d in enumerate(data.dumps):
        hist = data.histories[d.host]
        listed, counts = sessions_at(d, data.logons, hist, p)
        listed += process_only_sessions(data.process_rows[i], hist, d)
        all_sessions.append(listed)
        by_cat = Counter(f"{s['state']}:{s['category']}" for s in listed)
        out.append({"dump_index": i, "host": d.host, "time": to_display(d.t),
                    "source_image": d.rows[0].get("source_image"),
                    "account_name": d.rows[0].get("account_name"),
                    "granted_access": [r.get("granted_access") for r in d.rows],
                    "event_uids": [r["event_uid"] for r in d.rows],
                    "sessions_4624_by_state": dict(counts), "listed_by_state_category": dict(by_cat),
                    "sessions": listed})
    expected = p.expectation_for(ctx.scenario).dumps
    status = (OK if data.dumps else PROBLEM) if expected else INFO
    summary = "; ".join(f"{d.host} {to_display(d.t)} ({d.rows[0].get('account_name')}, "
                        f"open {sum(s['state'] == OPEN for s in ss)}, end_unknown "
                        f"{sum(s['state'] == END_UNKNOWN for s in ss)})"
                        for d, ss in zip(data.dumps, all_sessions)) or "no rundll32→lsass dump in window"
    status, summary = gated_status(ctx, status, summary)
    return CheckResult("LC-08", "Credential dumps and open sessions on the dump host", status, summary,
                       "Correction K: the sessions open at dump time are the accounts exposed on that host.",
                       {"dumps": out, "expected_dumps": expected,
                        "params": {"SESSION_LOOKBACK_S": p.session_lookback_s, "DUMP_PAIR_S": p.dump_pair_s}}), all_sessions


def run_lc08b(ctx: Context, data: DumpData, sessions: list[list[dict]]) -> CheckResult:
    """LC-08b: scenario accounts exposed at each dump, and whether they acted afterwards."""
    p = ctx.params
    commands = load_commands(ctx, "LC-08b")
    ctx.db.share("LC-08b", "LC-08")
    per_dump, all_have = [], bool(data.dumps)
    for i, (d, listed) in enumerate(zip(data.dumps, sessions)):
        entries = []
        for s in listed:
            if s["account_name"] not in p.scenario_accounts:
                continue
            ids = {s["session_id"]} | ({s["linked_id_int"]} if s.get("linked_id_int") else set())
            after = commands_after(ids, d.host, commands, d.t, d.t + seconds(p.post_dump_cmd_s))
            entries.append({"account_name": s["account_name"], "session_id": s["session_hex"],
                            "start": s["start"], "logon_type": s["logon_type"], "state": s["state"],
                            "ran_command_within_10min": bool(after),
                            "first_command_after": to_display(after[0]["t"]) if after else None,
                            "first_command": mask_command_line(after[0].get("command_line"), ctx.secrets)
                            if after else None})
        all_have = all_have and any(e["state"] == OPEN for e in entries)
        per_dump.append({"dump_index": i, "host": d.host, "time": to_display(d.t),
                         "scenario_accounts": sorted({e["account_name"] for e in entries}),
                         "sessions": entries})
    result: dict[str, Any] = {"dumps": per_dump}
    if ctx.scenario == "s04":
        result["s04_a"] = s04a_answer(per_dump)
    if not data.dumps:
        status, summary = NOT_MEASURABLE, "no dump in window"
    else:
        status = OK if all_have else PROBLEM
        summary = "; ".join(f"{x['host']} {x['time']}: " + (", ".join(
            f"{e['account_name']} {e['session_id']} {e['state']}" for e in x["sessions"]) or "none")
            for x in per_dump)
    if "s04_a" in result:
        summary += f" | S04-A: {result['s04_a']['answer']}"
    status, summary = gated_status(ctx, status, summary)
    return CheckResult("LC-08b", "Scenario accounts exposed at each dump", status, summary,
                       "Sessions here are the 'exposed' accounts IdentityCoherence can use; exposed ≠ stolen.",
                       result)


def s04a_answer(per_dump: list[dict]) -> dict[str, Any]:
    """Handoff Correction H.2: did admin_it have a session on ep-01 at the S04 dump?"""
    ep01 = [x for x in per_dump if x["host"] == "ep-01"]
    if not ep01:
        return {"answer": "not measurable: no dump on ep-01 in window", "sessions": []}
    hits = [dict(e, dump_time=x["time"]) for x in ep01 for e in x["sessions"] if e["account_name"] == "admin_it"]
    open_hits = [e for e in hits if e["state"] == OPEN]
    if open_hits:
        ans = "yes: " + ", ".join(f"{e['session_id']} type {e['logon_type']} since {e['start']}" for e in open_hits)
    elif hits:
        ans = "end unknown: " + ", ".join(f"{e['session_id']} ({e['state']})" for e in hits)
    else:
        ans = "no admin_it session open on ep-01 at the dump"
    return {"answer": ans, "sessions": hits}
