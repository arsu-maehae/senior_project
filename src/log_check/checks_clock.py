"""LC-09: clock offsets per host (vs dc01, Security vs Sysmon, Sysmon record gap).

The stitcher compares times across hosts and channels (LC-04 measured commands 0.9–1.7 s
after the target 4624). These numbers tell T7 how large its tolerances must be.
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from .common import INFO, CheckResult, Context, base_name, with_time
from .params import Params
from .timeutil import delta_ms, parse_utc, summarise

GUID_4624_SQL = """
    SELECT event_uid, host, event_utc, logon_guid
    FROM events_dedup
    WHERE channel = 'Security' AND event_id = 4624
      AND logon_guid IS NOT NULL AND logon_guid <> '00000000-0000-0000-0000-000000000000'
"""
DC_4769_SQL = """
    SELECT event_uid, event_utc, logon_guid, service_name
    FROM events_dedup
    WHERE host = 'dc01' AND channel = 'Security' AND event_id = 4769
      AND logon_guid IS NOT NULL AND logon_guid <> '00000000-0000-0000-0000-000000000000'
"""
SYSMON1_SQL = """
    SELECT event_uid, host, event_utc, process_id, image
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 1 AND process_id IS NOT NULL
"""
SEC4688_SQL = """
    SELECT event_uid, host, event_utc, process_id, image
    FROM events_dedup
    WHERE channel = 'Security' AND event_id = 4688 AND process_id IS NOT NULL
"""
SYSMON_GAP_SQL = """
    SELECT host, timestamp_utc, event_utc
    FROM events_dedup
    WHERE channel = 'Sysmon' AND timestamp_utc IS NOT NULL AND event_utc IS NOT NULL
"""


def machine_account(host: str) -> str:
    """Kerberos service account of a host as it appears in 4769 ServiceName (`ENDPOINT-02$`)."""
    match = re.fullmatch(r"ep-(\d+)", host)
    if match:
        return f"endpoint-{match.group(1)}$"
    return "dc-01$" if host == "dc01" else f"{host}$"


def _nearest(t: datetime, pool: list[dict]) -> dict:
    return min(pool, key=lambda x: (abs((t - x["t"]).total_seconds()), x["event_uid"]))


def kerberos_deltas(logons: list[dict], tickets: list[dict]) -> tuple[list[dict], int]:
    """Per 4624, delta = 4624 time − dc01 4769 time with the same LogonGuid.

    One TGT LogonGuid appears in many 4769s and a cached service ticket serves many later
    4624s, so "the" 4769 of a 4624 is not unique. A pair is kept only when the 4624's
    nearest ticket (preferring ServiceName = the host's machine account) and that ticket's
    nearest same-host 4624 are each other (mutual nearest). Without this, cached-ticket
    reuse showed up as offsets of minutes to hours (dc01 vs itself: median 177 s).
    Returns the kept pairs and the number of 4624s dropped as ticket reuse.
    """
    by_guid: dict[str, list[dict]] = defaultdict(list)
    for t in tickets:
        by_guid[t["logon_guid"].lower()].append(t)
    logons_by_key: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for lg in logons:
        logons_by_key[(lg["host"], (lg.get("logon_guid") or "").lower())].append(lg)
    out, dropped = [], 0
    for lg in logons:
        guid = (lg.get("logon_guid") or "").lower()
        cands = by_guid.get(guid, [])
        if not cands:
            continue
        own = [t for t in cands if (t.get("service_name") or "").lower() == machine_account(lg["host"])]
        best = _nearest(lg["t"], own or cands)
        if _nearest(best["t"], logons_by_key[(lg["host"], guid)])["event_uid"] != lg["event_uid"]:
            dropped += 1
            continue
        out.append({"host": lg["host"], "t": lg["t"], "delta_ms": delta_ms(lg["t"], best["t"]),
                    "service_match": bool(own)})
    return out, dropped


def cross_channel_deltas(sec: list[dict], sysmon: list[dict], tol_s: float) -> list[dict]:
    """4688 time − Sysmon 1 time for the same process (host, PID, image file name, |Δt| ≤ tol)."""
    index: dict[tuple, list[dict]] = defaultdict(list)
    for s in sysmon:
        index[(s["host"], int(s["process_id"]), base_name(s.get("image")))].append(s)
    out = []
    for r in sec:
        cands = index.get((r["host"], int(r["process_id"]), base_name(r.get("image"))), [])
        near = [s for s in cands if abs((r["t"] - s["t"]).total_seconds()) <= tol_s]
        if near:
            best = min(near, key=lambda s: abs((r["t"] - s["t"]).total_seconds()))
            out.append({"host": r["host"], "t": r["t"], "delta_ms": delta_ms(r["t"], best["t"])})
    return out


def gap_stats(rows: list[dict], flag_s: float) -> dict[str, dict[str, Any]]:
    """Sysmon record time − UtcTime per host, in seconds (NF-23)."""
    per: dict[str, list[float]] = defaultdict(list)
    for r in rows:
        gap = (parse_utc(r["timestamp_utc"]) - parse_utc(r["event_utc"])).total_seconds()
        per[r["host"]].append(gap)
    out = {}
    for host, gaps in sorted(per.items()):
        s = summarise(gaps, (50, 99), digits=3)
        s.update({"rows_over_flag": sum(g > flag_s for g in gaps), "rows_negative": sum(g < 0 for g in gaps)})
        out[host] = s
    return out


def per_host_stats(deltas: list[dict], start: datetime | None = None, end: datetime | None = None) -> dict:
    """n, p5, p50, p95, min, max of delta_ms per host (optionally restricted to [start, end])."""
    per: dict[str, list[float]] = defaultdict(list)
    for d in deltas:
        if start is None or start <= d["t"] <= end:
            per[d["host"]].append(d["delta_ms"])
    return {h: summarise(v) for h, v in sorted(per.items())}


def skew_flag(stats: dict[str, dict], params: Params) -> bool:
    """dc01_skew_possible: endpoint medians agree within 1 s but all differ from 0 by > 1 s."""
    medians = [s["p50"] for h, s in stats.items() if h in params.endpoint_hosts and s["n"]]
    if len(medians) < 2:
        return False
    agree = max(medians) - min(medians) <= params.skew_agree_ms
    return agree and all(abs(m) > params.skew_agree_ms for m in medians)


def run_lc09(ctx: Context) -> CheckResult:
    db, p, w = ctx.db, ctx.params, ctx.window
    krb, krb_dropped = kerberos_deltas(with_time(db.query("LC-09", GUID_4624_SQL)),
                                       with_time(db.query("LC-09", DC_4769_SQL)))
    krb_all, krb_win = per_host_stats(krb), per_host_stats(krb, w.start, w.end)
    xch = cross_channel_deltas(with_time(db.query("LC-09", SEC4688_SQL)),
                               with_time(db.query("LC-09", SYSMON1_SQL)), p.cross_channel_s)
    gaps = gap_stats(db.query("LC-09", SYSMON_GAP_SQL), p.sysmon_gap_flag_s)
    flags = ["dc01_skew_possible"] if skew_flag(krb_all, p) else []
    summary = "kerberos p50 ms: " + ", ".join(f"{h} {s['p50']} (n={s['n']})" for h, s in krb_all.items())
    summary += "; 4688−Sysmon1 p50 ms: " + ", ".join(f"{h} {s['p50']}" for h, s in per_host_stats(xch).items())
    if flags:
        summary += "; FLAG dc01_skew_possible"
    return CheckResult("LC-09", "Clock offsets (vs dc01, Security vs Sysmon, Sysmon record gap)", INFO,
                       summary, "Sets the time tolerance of cross-host joins (LC-04 deltas, Kerberos confirmation).",
                       {"kerberos_vs_dc01_ms": krb_all, "kerberos_vs_dc01_ms_in_window": krb_win,
                        "kerberos_pairing": "mutual nearest 4624<->4769 per LogonGuid",
                        "kerberos_4624_dropped_as_ticket_reuse": krb_dropped,
                        "kerberos_service_matched_share": round(sum(d["service_match"] for d in krb) / len(krb), 3)
                        if krb else None,
                        "security4688_minus_sysmon1_ms": per_host_stats(xch),
                        "security4688_minus_sysmon1_ms_in_window": per_host_stats(xch, w.start, w.end),
                        "sysmon_record_gap_s": gaps, "flags": flags})
