"""LC-05 (RDP) and LC-06 (WinRM): protocols where Sysmon 3 does exist, so the Correction I
port join can be measured directly and compared with the command-line join of LC-04."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .bridge import bridges
from .checks_smb import confidence_tier
from .common import (INFO, NOT_MEASURABLE, OK, PROBLEM, CheckResult, Context, gated_status, hex_id,
                     load_remote_4624, session_logon, with_time)
from .matching import target_name_forms
from .params import Params
from .db import in_list
from .hops import HopInstance, hop_by_logon_uid, port_join
from .timeutil import delta_ms, seconds, to_db, to_display

METHOD_PORT = "sysmon3_port"
ZERO_NO_JOIN = "no_sysmon3_port_join"

MSTSC_SQL = """
    SELECT event_uid, host, event_utc, image, source_ip, source_port, destination_ip,
           destination_port, initiated, process_guid
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 3 AND destination_port = 3389
      AND lower(image) LIKE '%\\mstsc.exe'
      AND event_utc >= ? AND event_utc <= ?
"""
INBOUND_RDP_SQL = """
    SELECT event_uid, host, event_utc, image, source_ip, source_port, destination_ip,
           destination_port, initiated
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 3 AND destination_port = 3389 AND initiated = 0
      AND event_utc >= ? AND event_utc <= ?
"""
WINRM_CONN_SQL = """
    SELECT event_uid, host, event_utc, image, source_ip, source_port, destination_ip,
           destination_port, initiated, process_guid
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 3 AND destination_port IN (5985, 5986)
      AND lower(image) LIKE '%\\powershell.exe'
      AND event_utc >= ? AND event_utc <= ?
"""
WINRM91_SQL = """
    SELECT event_uid, host, event_utc, account_name, source_ip
    FROM events_dedup
    WHERE channel = 'WinRM' AND event_id = 91
      AND event_utc >= ? AND event_utc <= ?
"""
WSMPROVHOST_SQL = """
    SELECT event_uid, host, event_utc, session_id, account_name, process_guid
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 1 AND lower(image) LIKE '%\\wsmprovhost.exe'
      AND event_utc >= ? AND event_utc <= ?
"""
CREATOR_SQL = """
    SELECT event_uid, host, event_utc, session_id, account_name, process_guid, image
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 1 AND process_guid IN {guids}
"""


def _padded_range(ctx: Context) -> tuple[str, str]:
    """Window ± PORT_JOIN_S, so a join at the window edge is not lost."""
    pad = seconds(ctx.params.port_join_s)
    return to_db(ctx.window.start - pad), to_db(ctx.window.end + pad)


# --- RDP ----------------------------------------------------------------------------------

def inbound_rdp_matches(inbound: list[dict], logons: list[dict], tol_s: float) -> list[dict]:
    """Target inbound 3389 ↔ remote 4624 type 10/3 from the same IP on the same host within tol."""
    out = []
    for conn in inbound:
        for lg in logons:
            if lg["host"] == conn["host"] and lg.get("source_ip") == conn.get("source_ip") \
                    and lg.get("logon_type") in (3, 10) \
                    and abs((lg["t"] - conn["t"]).total_seconds()) <= tol_s:
                out.append({"conn": conn, "logon": lg, "time_delta_ms": delta_ms(lg["t"], conn["t"])})
    return out


@dataclass
class RdpEvidence:
    """Inputs of LC-05 plus the hop ids that look like RDP (for the protocol label)."""

    mstsc: list[dict]
    inbound: list[dict]
    source_pairs: list[dict]
    inbound_pairs: list[dict]
    hop_ids: set[str] = field(default_factory=set)


def rdp_evidence(ctx: Context, hops: list[HopInstance]) -> RdpEvidence:
    rng = _padded_range(ctx)
    mstsc = with_time(ctx.db.query("LC-05", MSTSC_SQL, rng))
    inbound = with_time(ctx.db.query("LC-05", INBOUND_RDP_SQL, rng))
    logons = load_remote_4624(ctx, "LC-05")
    p = ctx.params
    src = port_join(mstsc, logons, p, p.port_join_s)
    inb = inbound_rdp_matches(inbound, logons, p.rdp_inbound_s)
    by_uid = hop_by_logon_uid(hops)
    ids = {h.hop_id for h in hops if any(r.get("logon_type") == 10 for r in h.logons)}
    ids |= {by_uid[x["logon"]["event_uid"]].hop_id for x in src + inb if x["logon"]["event_uid"] in by_uid}
    return RdpEvidence(mstsc, inbound, src, inb, ids)


def run_lc05(ctx: Context, ev: RdpEvidence) -> CheckResult:
    """LC-05: NOT_MEASURABLE until RDP source data exists (S01 t01)."""
    result = {
        "mstsc_3389_rows": len(ev.mstsc), "source_joined": len(ev.source_pairs),
        "inbound_3389_rows": len(ev.inbound), "inbound_with_4624": len(ev.inbound_pairs),
        "inbound_pairs": [{"host": x["conn"]["host"], "source_ip": x["conn"].get("source_ip"),
                           "conn_time": to_display(x["conn"]["t"]), "logon_type": x["logon"].get("logon_type"),
                           "account_name": x["logon"].get("account_name"),
                           "time_delta_ms": x["time_delta_ms"],
                           "event_uids": [x["conn"]["event_uid"], x["logon"]["event_uid"]]}
                          for x in ev.inbound_pairs],
        "rdp_hop_ids": sorted(ev.hop_ids),
    }
    if not ev.mstsc:
        status, summary = NOT_MEASURABLE, (f"no mstsc→3389 source rows (until S01 t01); inbound 3389 "
                                           f"{len(ev.inbound)}, with 4624 {len(ev.inbound_pairs)}")
    else:
        expected = ctx.params.expectation_for(ctx.scenario).rdp_hops
        status = (OK if ev.source_pairs else PROBLEM) if expected else INFO
        summary = f"{len(ev.mstsc)} mstsc rows, {len(ev.source_pairs)} joined to a target 4624"
    status, summary = gated_status(ctx, status, summary)
    return CheckResult("LC-05", "RDP port join (mstsc → 3389)", status, summary,
                       "RDP hops can use the Correction I port join once source data exists.", result)


# --- WinRM --------------------------------------------------------------------------------

@dataclass
class WinrmEvidence:
    """Inputs of LC-06 per hop plus the hop ids that look like WinRM (for the protocol label)."""

    conns: list[dict]
    pairs: list[dict]
    winrm91: list[dict]
    wsmprov: list[dict]
    creators: dict[str, dict]
    pairs_by_hop: dict[str, list[dict]] = field(default_factory=dict)
    w91_by_hop: dict[str, list[dict]] = field(default_factory=dict)
    wsm_by_hop: dict[str, list[dict]] = field(default_factory=dict)
    hop_ids: set[str] = field(default_factory=set)


def match_winrm91(hop: HopInstance, events: list[dict], tol_s: float) -> list[dict]:
    """WinRM 91 on the target with the hop's account and source IP within tol of any 4624."""
    return [e for e in events
            if e["host"] == hop.target_host and e.get("account_name") == hop.account_name
            and e.get("source_ip") == hop.source_ip
            and any(abs((e["t"] - lg["t"]).total_seconds()) <= tol_s for lg in hop.logons)]


def match_wsmprovhost(hop: HopInstance, rows: list[dict]) -> list[dict]:
    """wsmprovhost.exe Sysmon 1 on the target whose session is one of the hop's logon ids."""
    ids = hop.target_logon_ids
    return [r for r in rows if r["host"] == hop.target_host and r.get("session_id") is not None
            and int(r["session_id"]) in ids]


def winrm_evidence(ctx: Context, hops: list[HopInstance]) -> WinrmEvidence:
    rng = _padded_range(ctx)
    p = ctx.params
    conns = with_time(ctx.db.query("LC-06", WINRM_CONN_SQL, rng))
    w91 = with_time(ctx.db.query("LC-06", WINRM91_SQL, rng))
    wsm = with_time(ctx.db.query("LC-06", WSMPROVHOST_SQL, rng))
    logons = load_remote_4624(ctx, "LC-06")
    guids = sorted({c["process_guid"] for c in conns if c.get("process_guid")})
    creators: dict[str, dict] = {}
    if guids:
        rows = ctx.db.query("LC-06", CREATOR_SQL.format(guids=in_list(guids)), guids)
        creators = {(r["host"], r["process_guid"]): r for r in with_time(rows)}
    ev = WinrmEvidence(conns, port_join(conns, logons, p, p.port_join_s), w91, wsm, creators)
    by_uid = hop_by_logon_uid(hops)
    for pair in ev.pairs:
        hop = by_uid.get(pair["logon"]["event_uid"])
        if hop:
            ev.pairs_by_hop.setdefault(hop.hop_id, []).append(pair)
    for hop in hops:
        hits91, hitsw = match_winrm91(hop, w91, p.port_join_s), match_wsmprovhost(hop, wsm)
        if hits91:
            ev.w91_by_hop[hop.hop_id] = hits91
        if hitsw:
            ev.wsm_by_hop[hop.hop_id] = hitsw
    ev.hop_ids = set(ev.pairs_by_hop) | set(ev.w91_by_hop) | set(ev.wsm_by_hop)
    return ev


def source_sessions(pairs: list[dict], creators: dict, logon_index: dict) -> list[dict]:
    """Distinct source sessions behind the joined connections (via ProcessGuid → Sysmon 1)."""
    sessions: dict[Any, dict] = {}
    for pair in sorted(pairs, key=lambda x: x["conn"]["t"]):
        conn = pair["conn"]
        creator = creators.get((conn["host"], conn.get("process_guid")))
        sid = int(creator["session_id"]) if creator and creator.get("session_id") is not None else None
        key = (conn["host"], sid)
        if key not in sessions:
            logon = session_logon(logon_index, conn["host"], sid, conn["t"]) if sid is not None else None
            account = (logon or {}).get("account_name") or (creator or {}).get("account_name")
            sessions[key] = {"host": conn["host"], "session_id": sid, "account": account,
                             "account_source": "source_4624" if logon else ("sysmon1_user" if creator else "unknown"),
                             "logon": logon, "creator": creator, "pairs": [], "first_t": conn["t"]}
        sessions[key]["pairs"].append(pair)
    return list(sessions.values())


def hop_bridges(hop: HopInstance, explicit_by_host: dict | None, params: Params) -> dict[int, list[str]]:
    """LC-04e bridge for a WinRM hop (same window and name forms as LC-04)."""
    if hop.source_host is None:
        return {}
    forms = target_name_forms(hop.target_host, params.host_ip.get(hop.target_host))
    return bridges((explicit_by_host or {}).get(hop.source_host, []), forms, hop.account_name,
                   hop.t, params.cmd_before_s, params.cmd_after_s)


def passes(s: dict, hop: HopInstance, bridged: dict[int, list[str]]) -> bool:
    """Account filter with the LC-04e bridge: same account, or a bridging 4648 in that session."""
    return s["account"] == hop.account_name or (s["session_id"] is not None and s["session_id"] in bridged)


def winrm_csv_rows(trial_id: str, hop: HopInstance, sessions: list[dict],
                   bridged: dict[int, list[str]] | None = None) -> list[dict]:
    """hop_candidates.csv rows for LC-06 (method sysmon3_port)."""
    bridged = bridged or {}
    after = [s for s in sessions if s["account"] == hop.account_name]
    after_bridge = [s for s in sessions if passes(s, hop, bridged)]
    base = {"trial_id": trial_id, "protocol": hop.protocol, "hop_id": hop.hop_id,
            "target_host": hop.target_host, "target_event_uids": ";".join(hop.event_uids),
            "target_time_utc": to_display(hop.t), "account_name": hop.account_name,
            "source_ip": hop.source_ip, "source_port": hop.source_port,
            "source_host": hop.source_host or "", "method": METHOD_PORT,
            "candidate_count_sessions_before_account": len(sessions),
            "candidate_count_sessions_after_account": len(after),
            "candidate_count_sessions_after_4648_bridge": len(after_bridge)}
    if not sessions:
        return [{**base, "candidate_count_rows": 0, "time_delta_ms": "", "confidence_tier": "",
                 "candidate_session_id": "", "candidate_account": "", "candidate_logon_type": "",
                 "zero_reason": ZERO_NO_JOIN, "supporting_event_uids": ";".join(hop.event_uids)}]
    rows = []
    for s in sessions:
        uids = hop.event_uids + [x["conn"]["event_uid"] for x in s["pairs"]]
        if s["creator"]:
            uids.append(s["creator"]["event_uid"])
        uids += bridged.get(s["session_id"], []) if s["session_id"] is not None else []
        rows.append({**base, "candidate_count_rows": len(s["pairs"]),
                     "time_delta_ms": delta_ms(s["first_t"], hop.t),
                     "confidence_tier": confidence_tier(METHOD_PORT, passes(s, hop, bridged), len(after_bridge)),
                     "candidate_session_id": hex_id(s["session_id"]) or "",
                     "candidate_account": s["account"] or "",
                     "candidate_logon_type": (s["logon"] or {}).get("logon_type") or "",
                     "zero_reason": "", "supporting_event_uids": ";".join(dict.fromkeys(uids))})
    return rows


def run_lc06(ctx: Context, hops: list[HopInstance], ev: WinrmEvidence, logon_index: dict,
             explicit_by_host: dict | None = None) -> tuple[CheckResult, list[dict]]:
    """LC-06: WinRM port join, WinRM 91, wsmprovhost session, source session per hop."""
    p = ctx.params
    details, csv_rows, linked = [], [], 0
    winrm_hops = [h for h in hops if h.protocol == "WinRM"]
    for hop in winrm_hops:
        sessions = source_sessions(ev.pairs_by_hop.get(hop.hop_id, []), ev.creators, logon_index)
        bridged = hop_bridges(hop, explicit_by_host, p)
        after = [s for s in sessions if s["account"] == hop.account_name]
        after_bridge = [s for s in sessions if passes(s, hop, bridged)]
        linked += int(bool(after_bridge) and hop.is_scenario_account(p))
        csv_rows += winrm_csv_rows(ctx.trial_id, hop, sessions, bridged)
        details.append({
            **hop.summary(), "scenario_account": hop.is_scenario_account(p),
            "port_joins": [{"sysmon3_event_uid": x["conn"]["event_uid"], "source_host": x["conn"]["host"],
                            "source_port": x["conn"].get("source_port"),
                            "target_event_uid": x["logon"]["event_uid"], "time_delta_ms": x["time_delta_ms"]}
                           for x in ev.pairs_by_hop.get(hop.hop_id, [])],
            "winrm91": [{"event_uid": e["event_uid"], "time": to_display(e["t"])}
                        for e in ev.w91_by_hop.get(hop.hop_id, [])],
            "wsmprovhost": [{"event_uid": r["event_uid"], "session_id": hex_id(r.get("session_id")),
                             "time": to_display(r["t"])} for r in ev.wsm_by_hop.get(hop.hop_id, [])],
            "source_sessions": [{"host": s["host"], "session_id": hex_id(s["session_id"]),
                                 "account": s["account"], "account_source": s["account_source"],
                                 "logon_type": (s["logon"] or {}).get("logon_type"),
                                 "connections": len(s["pairs"])} for s in sessions],
            "candidate_count_sessions_before_account": len(sessions),
            "candidate_count_sessions_after_account": len(after),
            "candidate_count_sessions_after_4648_bridge": len(after_bridge),
            "bridging_4648": {hex_id(k): v for k, v in bridged.items()}})
    hop_91 = {e["event_uid"] for v in ev.w91_by_hop.values() for e in v}
    unmatched91 = [{"event_uid": e["event_uid"], "host": e["host"], "time": to_display(e["t"]),
                    "account_name": e.get("account_name"), "source_ip": e.get("source_ip")}
                   for e in ev.winrm91 if e["event_uid"] not in hop_91]
    expected = p.expectation_for(ctx.scenario).winrm_hops
    status = (OK if linked >= expected else PROBLEM) if expected else INFO
    summary = (f"{len(ev.conns)} powershell→5985/5986 rows, {len(ev.pairs)} joined to 4624; "
               f"{len(winrm_hops)} WinRM hop instances, {linked} scenario hops with a source session "
               f"incl. 4648 bridge (expected {expected}); WinRM 91 in window {len(ev.winrm91)} "
               f"({len(unmatched91)} not on a hop)")
    status, summary = gated_status(ctx, status, summary)
    return CheckResult("LC-06", "WinRM port join + WinRM 91 + wsmprovhost", status, summary,
                       "WinRM hops can be linked by the Correction I port join to a source session.",
                       {"sysmon3_rows": len(ev.conns), "joined_pairs": len(ev.pairs),
                        "winrm_hops": details, "winrm91_not_on_hop": unmatched91,
                        "scenario_hops_linked": linked, "expected_winrm_hops": expected}), csv_rows
