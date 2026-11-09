"""LC-01, LC-02, LC-03, LC-07: descriptive counts that frame the linking checks."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .common import (INFO, OK, PROBLEM, CheckResult, Context, ip_category, is_lab_ipv4,
                     load_process_sessions, load_remote_4624)
from .timeutil import seconds, to_db

ZERO_GUID = "00000000-0000-0000-0000-000000000000"

COUNTS_ALL_SQL = """
    SELECT channel, event_id, count(*) AS n
    FROM events_dedup
    GROUP BY channel, event_id
    ORDER BY channel, event_id
"""
COUNTS_WINDOW_SQL = """
    SELECT channel, event_id, count(*) AS n
    FROM events_dedup
    WHERE event_utc >= ? AND event_utc <= ?
    GROUP BY channel, event_id
    ORDER BY channel, event_id
"""
HOST_CHANNEL_WINDOW_SQL = """
    SELECT host, channel, count(*) AS n
    FROM events_dedup
    WHERE event_utc >= ? AND event_utc <= ?
    GROUP BY host, channel
    ORDER BY host, channel
"""
TOTAL_WINDOW_SQL = """
    SELECT count(*) AS n
    FROM events_dedup
    WHERE event_utc >= ? AND event_utc <= ?
"""
ROWS_SQL = """
    SELECT (SELECT count(*) FROM events) AS events_rows,
           (SELECT count(*) FROM events_dedup) AS events_dedup_rows
"""
HOST_IP_SQL = """
    SELECT host, source_ip, count(*) AS n
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 3 AND initiated = 1 AND source_ip IS NOT NULL
    GROUP BY host, source_ip
    ORDER BY host, n DESC
"""
DC_4769_GUID_SQL = """
    SELECT DISTINCT logon_guid
    FROM events_dedup
    WHERE host = 'dc01' AND channel = 'Security' AND event_id = 4769
      AND logon_guid IS NOT NULL AND logon_guid <> '00000000-0000-0000-0000-000000000000'
"""


def valid_guid(value: str | None) -> bool:
    """A LogonGuid is usable for the Kerberos confirmation only if present and not all zeros."""
    return bool(value) and value.strip("{}").lower() != ZERO_GUID


def _counts_table(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"channel": r["channel"], "event_id": r["event_id"], "n": r["n"]} for r in rows]


def host_ip_check(rows: list[dict[str, Any]], host_ip: dict[str, str]) -> dict[str, Any]:
    """HOST_IP is observed, not configured: each host's most frequent outbound Sysmon 3
    source IP should equal its HOST_IP entry (hosts without Sysmon 3 cannot be verified)."""
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        by_host[r["host"]].append({"source_ip": r["source_ip"], "n": r["n"]})
    out = {}
    for host, ip in sorted(host_ip.items()):
        seen = by_host.get(host, [])
        ipv4 = [s for s in seen if "." in (s["source_ip"] or "")]
        top = ipv4[0]["source_ip"] if ipv4 else None
        out[host] = {"expected": ip, "observed_top_ipv4": top,
                     "verified": None if top is None else top == ip, "observed": seen[:5]}
    return out


def run_lc01(ctx: Context) -> CheckResult:
    """LC-01: counts by channel/event_id, whole DB and in window; events vs events_dedup."""
    db, w = ctx.db, ctx.window
    rows = db.query("LC-01", ROWS_SQL)[0]
    whole = _counts_table(db.query("LC-01", COUNTS_ALL_SQL))
    inwin = _counts_table(db.query("LC-01", COUNTS_WINDOW_SQL, (w.start_db, w.end_db)))
    per_host = db.query("LC-01", HOST_CHANNEL_WINDOW_SQL, (w.start_db, w.end_db))
    result: dict[str, Any] = {
        "events_rows": rows["events_rows"], "events_dedup_rows": rows["events_dedup_rows"],
        "duplicates_removed": rows["events_rows"] - rows["events_dedup_rows"],
        "whole_db_total": sum(r["n"] for r in whole), "in_window_total": sum(r["n"] for r in inwin),
        "whole_db": whole, "in_window": inwin,
        "in_window_by_host_channel": [dict(r) for r in per_host],
        "host_ip": host_ip_check(db.query("LC-01", HOST_IP_SQL), dict(ctx.params.host_ip)),
    }
    if w.source == "anchors" and w.anchors:
        alt = ctx.params.margin_alt_s
        start, end = to_db(w.anchors[0].time - seconds(alt)), to_db(w.anchors[-1].time + seconds(alt))
        result["in_window_total_margin_300s"] = db.query("LC-01", TOTAL_WINDOW_SQL, (start, end))[0]["n"]
    summary = (f"{result['events_dedup_rows']} dedup rows ({result['events_rows']} raw); "
               f"{result['in_window_total']} in window")
    return CheckResult("LC-01", "Counts by channel / event_id", INFO, summary,
                       "Scopes every other count; whole-DB total must equal the DB row count.", result)


def lc02_table(rows: list[dict[str, Any]], params) -> dict[str, Any]:
    """Per IP category and package: count, port > 0, port = 0, valid logon_guid."""
    table: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for r in rows:
        cat = ip_category(r.get("source_ip"), params)
        pkg = r.get("authentication_package") or "(none)"
        cell = table[cat][pkg]
        cell["count"] += 1
        port = r.get("source_port")
        cell["port_gt_0" if port and int(port) > 0 else "port_0"] += 1
        cell["valid_logon_guid"] += int(valid_guid(r.get("logon_guid")))
        cell[f"type_{r.get('logon_type')}"] += 1
    return {cat: {pkg: dict(c) for pkg, c in pkgs.items()} for cat, pkgs in sorted(table.items())}


def run_lc02(ctx: Context) -> CheckResult:
    """LC-02: remote 4624 in window split by source category and package."""
    remote = load_remote_4624(ctx, "LC-02")
    table = lc02_table(remote, ctx.params)
    totals = {cat: sum(c["count"] for c in pkgs.values()) for cat, pkgs in table.items()}
    exp = ctx.params.expectation_for(ctx.scenario)
    lab = totals.get("lab_ipv4", 0)
    expects_hops = exp.smb_hops + exp.winrm_hops + exp.rdp_hops > 0
    status = (OK if lab else PROBLEM) if expects_hops else INFO
    summary = ", ".join(f"{k} {v}" for k, v in totals.items()) or "no remote 4624"
    return CheckResult("LC-02", "Remote 4624 in window", status, summary,
                       "Lab-IPv4 rows are the hop candidates; loopback/link-local are gate suppression.",
                       {"totals": totals, "by_category_package": table, "n": len(remote)})


def run_lc03(ctx: Context) -> CheckResult:
    """LC-03: lab-IPv4 remote 4624 whose logon_guid equals a dc01 4769 logon_guid."""
    remote = [r for r in load_remote_4624(ctx, "LC-03") if is_lab_ipv4(r.get("source_ip"), ctx.params)]
    guids = {r["logon_guid"].lower() for r in ctx.db.query("LC-03", DC_4769_GUID_SQL)}
    per: dict[str, Counter] = defaultdict(Counter)
    for r in remote:
        key = f"{r['host']}|{r.get('authentication_package') or '(none)'}"
        per[key]["total"] += 1
        has = valid_guid(r.get("logon_guid"))
        per[key]["valid_guid"] += int(has)
        per[key]["confirmed_by_dc01_4769"] += int(has and r["logon_guid"].lower() in guids)
    confirmed = sum(c["confirmed_by_dc01_4769"] for c in per.values())
    with_guid = sum(c["valid_guid"] for c in per.values())
    status = INFO if guids else "NOT_MEASURABLE"
    return CheckResult("LC-03", "Kerberos confirmation (4624 ↔ dc01 4769 LogonGuid)", status,
                       f"{confirmed}/{with_guid} lab-IPv4 4624 with a valid LogonGuid confirmed "
                       f"({len(remote)} lab-IPv4 total)",
                       "Confirms Kerberos hops only; NTLM SMB hops carry no LogonGuid.",
                       {"dc01_4769_guids": len(guids), "lab_ipv4_4624": len(remote),
                        "with_valid_guid": with_guid, "confirmed": confirmed,
                        "by_host_package": {k: dict(v) for k, v in sorted(per.items())}})


def run_lc07(ctx: Context) -> CheckResult:
    """LC-07: share of lab-IPv4 remote 4624 whose logon id ran a process on the same host."""
    remote = [r for r in load_remote_4624(ctx, "LC-07") if is_lab_ipv4(r.get("source_ip"), ctx.params)]
    sessions = load_process_sessions(ctx, "LC-07")
    per: dict[str, Counter] = defaultdict(Counter)
    for r in remote:
        per[r["host"]]["total"] += 1
        lid = r.get("target_logon_id")
        per[r["host"]]["with_process"] += int(lid is not None and (r["host"], int(lid)) in sessions)
    total = sum(c["total"] for c in per.values())
    hit = sum(c["with_process"] for c in per.values())
    share = round(hit / total, 3) if total else None
    return CheckResult("LC-07", "Remote logon sessions that ran a process", INFO,
                       f"{hit}/{total} ({share})",
                       "SMB/WinRM network sessions rarely run processes themselves; the session "
                       "link uses source-side command processes instead.",
                       {"total": total, "with_process": hit, "share": share,
                        "by_host": {h: dict(c) for h, c in sorted(per.items())}})
