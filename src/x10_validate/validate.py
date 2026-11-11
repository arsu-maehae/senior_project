"""Validate one trial DB against its scenario design (pure: rows in, result dict out).

WHY pure: the CLI does all file I/O; this function takes already loaded rows and metadata, so a
tester can feed synthetic rows and check each criterion without a DB or the file system.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from . import criteria as C
from .agent import Execution, agent_executions, attach_4688, manual_executions, manual_procs, sysmon_tree, tree_4688
from .db import iso, parse_ts
from .design import ScenarioDesign
from .events import (admin_binary_access, agent_beacons, agent_starts, find_dumps, in_range, kerberos_pairs_input,
                     rdp_source_connections, remote_logons, services, winrm91, wsmprovhost)
from .hops import TrialEvents, evaluate_hops
from .params import CLOCK_PAD_S, ENDPOINTS, IMPLEMENTATION_NOTES
from .window import anchors_of, clusters_of, design_window, run_start, window_of


def _hosts_without_sysmon(counts: Mapping[str, Mapping[str, int]]) -> set[str]:
    return {h for h in ENDPOINTS if counts.get(h, {}).get("sysmon", 0) == 0}


def build_executions(rows: Sequence[Mapping], counts: Mapping[str, Mapping[str, int]]) -> tuple[list[Execution], set[str]]:
    """Agent executions over the whole DB (Sysmon tree, 4688 fallback on hosts without Sysmon) and tree uids."""
    tree = sysmon_tree(rows)
    attach_4688(tree, rows)
    fallback = _hosts_without_sysmon(counts)
    if fallback:
        tree += tree_4688(rows, fallback)
    return agent_executions(tree), {p.event_uid for p in tree}


def shape_of(counts: Mapping[str, Mapping[str, int]], ingest: Mapping | None, hops: Sequence[Mapping],
             dsteps: Sequence[Mapping]) -> dict:
    """Shape signature for criterion i (029): hosts, steps found, service names, accounts, protocols."""
    if ingest is not None:
        hosts = sorted({f["host"] for f in ingest.get("files_copied", [])})
    else:
        hosts = sorted(h for h, ch in counts.items() if sum(ch.values()) > 0)
    found = [d["step_id"] for d in dsteps if d["present"]]
    found += [f"{h['hop_id']}:{s}" for h in hops for s, v in h["steps"].items() if v["present"]]
    svc = sorted({n for h in hops for n in h["steps"].get("service", {}).get("names", [])})
    return {"hosts_present": hosts, "steps_found": sorted(found), "service_names": svc,
            "target_accounts": {h["hop_id"]: h["hop_accounts"] for h in hops},
            "protocols": {h["hop_id"]: (h["execution"] or {}).get("protocols", [h["protocol"]] if h["protocol"] == "RDP" else [])
                          for h in hops}}


def design_rdp_connections(design: ScenarioDesign, rows: Sequence[Mapping]) -> list[Mapping]:
    """mstsc -> 3389 Sysmon 3 of every RDP hop of the design, any time in the DB (anchors of the run, N16)."""
    out: list[Mapping] = []
    for hop in design.hops:
        if hop.protocol == "RDP":
            out += rdp_source_connections(rows, hop.source, hop.target)
    return sorted(out, key=lambda r: r["ts"])


def attach_rundll32_listing(hops: Sequence[dict], dumps_w: Sequence) -> None:
    """List rundll32 -> lsass reads of the window in the RDP hops' evidence; no status depends on it (N20)."""
    listing = [{"host": d.host, "utc": iso(d.ts), "account": d.account, "user_token": d.user_token,
                "event_uids": d.event_uids[:4]} for d in dumps_w]
    for h in hops:
        if h.get("rdp") is not None:
            h["rdp"]["rundll32_lsass_in_window"] = listing


def _public_hops(hops: Sequence[Mapping]) -> list[dict]:
    return [{k: v for k, v in h.items() if not k.startswith("_")} for h in hops]


def validate_trial(trial_id: str, scenario: str, quarantine: bool, design: ScenarioDesign, rows: Sequence[Mapping],
                   counts: Mapping[str, Mapping[str, int]], span: tuple[str | None, str | None],
                   ingest: Mapping | None) -> dict:
    """All criteria a-h for one trial plus its shape (i is completed across trials in ``cross``)."""
    executions, tree_uids = build_executions(rows, counts)
    dumps = find_dumps(rows)
    logons = remote_logons(rows)
    rdp_conns = design_rdp_connections(design, rows)
    anchors = anchors_of(executions, dumps, logons, rdp_conns)
    clusters = clusters_of(anchors)
    base = {"trial_id": trial_id, "scenario": scenario, "quarantine": quarantine, "design_source": design.source,
            "db_span_utc": list(span), "anchor_clusters": len(clusters),
            "implementation_notes": list(IMPLEMENTATION_NOTES)}
    if not clusters:
        empty = C.result("FAIL", reason="no design anchor in the DB")
        na = C.result("n/a", reason="no trial window")
        crit = {"a": C.crit_a(design, ingest, counts), "b": empty, "c": na, "d": na, "e": na, "f": na, "g": na,
                "h": na, "i": na}
        return {**base, "window": None, "hops": [], "dump_steps": [], "criteria": crit, "shape": None}
    run, older = clusters[-1], clusters[:-1]
    lo, hi = window_of(run)
    db_end = parse_ts(span[1]) or hi
    hi = min(hi, db_end)          # no event of this trial can be logged after its own export
    floor = window_of(older[-1])[1] if older else None
    beacons = agent_beacons(rows)
    r_lo = run_start(run.first, floor, [r["ts"] for r in beacons] + [r["ts"] for r in agent_starts(rows)])

    rows_w = [r for r in rows if in_range(r["ts"], lo, hi)]
    manual = manual_executions(manual_procs(rows, tree_uids, lo, hi))
    execs_w = [e for e in executions + manual if in_range(e.ts_first, lo, hi)]
    dumps_w = [d for d in dumps if in_range(d.ts, lo, hi)]
    ev = TrialEvents(logons=[r for r in logons if in_range(r["ts"], lo, hi)],
                     smb_binaries=admin_binary_access(rows_w), services=services(rows_w),
                     winrm91=winrm91(rows_w), wsmprov=wsmprovhost(rows_w),
                     session_src={(r["host"], r["target_logon_id"]): r["source_ip"] for r in rows_w
                                  if r["channel"] == "Security" and r["event_id"] == 4624 and r["target_logon_id"]},
                     rdp_rows=[r for r in rows_w if (r["channel"], r["event_id"]) in (("Sysmon", 3), ("Security", 4624))]
                     if any(h.protocol == "RDP" for h in design.hops) else [])
    hops, groups, _ = evaluate_hops(design, execs_w, ev, (lo, hi))
    attach_rundll32_listing(hops, dumps_w)
    dsteps = C.dump_steps(design, dumps_w)
    dwin = design_window([e.ts_first for cands in groups.values() for e in cands]
                         + [d.ts for d in dumps_w if d.user_token]
                         + [h["_first_logon_ts"] for h in hops] + [h["_last_logon_ts"] for h in hops]
                         + [t for h in hops for t in h.get("_rdp_source_ts", [])])
    guid_session = {(r["process_guid"] or "").lower(): r["session_id"] for r in rows_w
                    if r["channel"] == "Sysmon" and r["event_id"] == 1}
    e4624, d4769 = kerberos_pairs_input([r for r in rows if in_range(r["ts"], lo - CLOCK_PAD_S, hi + CLOCK_PAD_S)])
    dc_security = counts.get("dc01", {}).get("security", 0) > 0 and not (
        ingest is not None and any(m["host"] == "dc01" and m["channel"] == "security" for m in ingest.get("files_missing", [])))
    crit = {
        "a": C.crit_a(design, ingest, counts),
        "b": C.crit_b(hops, dsteps, True),
        "c": C.crit_c(design, hops, rows_w),
        "d": C.crit_d(design, hops, rows_w, dumps_w, guid_session),
        "e": C.crit_e(design, beacons, r_lo, hi),
        "f": C.crit_f_local(older, (lo, hi)),
        "g": C.crit_g(e4624, d4769, hops, dc_security),
        "h": C.crit_h(design, groups, execs_w, dumps_w, hops),
        "i": C.result("n/a", reason="computed across trials"),
    }
    return {**base,
            "window": {"start_utc": iso(lo), "end_utc": iso(hi), "first_anchor_utc": iso(run.first),
                       "last_anchor_utc": iso(run.last), "anchors": run.summary()["counts"],
                       "agent_run_start_utc": iso(r_lo),
                       "design_start_utc": iso(dwin[0]) if dwin else None,
                       "design_end_utc": iso(min(dwin[1], db_end)) if dwin else None,
                       "design_end_unclipped_utc": iso(dwin[1]) if dwin else None,
                       "end_clip": "DB last event (export end; decision 026 amendment outer clip)"},
            "hops": _public_hops(hops), "dump_steps": dsteps, "criteria": crit,
            "shape": shape_of(counts, ingest, hops, dsteps)}
