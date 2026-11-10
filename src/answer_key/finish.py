"""Second half of the draft assembly: roles, decision checks, paths, window, evidence keys.

Split from build.py only to keep functions small. Pure: takes the pieces built there.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping, Sequence

from .timeutil import fmt_utc, parse_utc

HOP_DEFAULTS = {"move_time_utc": None, "identity_expected": None, "identity_basis": None, "time_delta_ms": None,
                "confidence_tier": "D", "target_binding": None, "target_event_uids": [], "account": None,
                "logon_account": None, "account_mismatch": False, "method": None, "candidate_count": None,
                "reviewed": False, "excluded": False, "excluded_reason": None, "reviewed_note": None,
                "credential_logon_uids": [], "related_logon_uids": [], "port_join_event_uids": []}
ROLES = ("attack", "benign", "background")
PRIVATE = ("_names", "_anchor_ts", "_burst_uids", "_absorbed_uids")
KEY_MARGIN_BEFORE_S, KEY_MARGIN_AFTER_S = 60.0, 300.0


def _iso(ts: float) -> str:
    return fmt_utc(datetime.fromtimestamp(ts, tz=timezone.utc))


def track_a_evidence(hop: Mapping, manual: Sequence, rows: Sequence[Mapping], by_guid: Mapping, rows4688: Sequence[Mapping],
                     tgt_rows: Mapping[str, Mapping]) -> dict:
    """Which session ran the command naming the target, which target artefacts tie to it (AK-08)."""
    from .build import splunkd_ancestor
    from .targets import artifact_names
    act = next((a for a in manual if hop["agent_event_uids"] and hop["agent_event_uids"][0] in {p.event_uid for p in a.procs}), None)
    if act is None:
        return {"note": "no manual command found"}
    sid = act.session_id
    logon = next((r for r in rows if r["channel"] == "Security" and r["event_id"] == 4624 and r["host"] == act.host
                  and r.get("target_logon_id") == sid), None)
    anc, chain = splunkd_ancestor(by_guid, act.root.process_guid, rows4688, act.host, act.root.process_id)
    names = artifact_names(act.texts)
    tie = [u for u in hop["target_event_uids"] if tgt_rows.get(u) and (
        (tgt_rows[u].get("service_name") or "").lower() in names["services"]
        or (tgt_rows[u].get("relative_target_name") or "").lower() in names["binaries"])]
    return {"session_id": hex(sid) if sid is not None else None, "session_logon_type": logon.get("logon_type") if logon else None,
            "session_logon_time_utc": logon["t_utc"] if logon else None, "session_logon_uid": logon["event_uid"] if logon else None,
            "command_event_uids": [p.event_uid for p in act.procs], "command_account": act.root.account,
            "splunkd_ancestor": anc, "ancestor_chain": chain, "names_in_command": names,
            "target_events_tied_by_name": tie,
            "other_open_sessions_at_dump": [(s["logon_id_hex"], s["logon_type"]) for s in
                                            (hop.get("identity_basis") or {}).get("open_sessions", [])]}


def finish(scenario: str, trial_id: str, sc: Mapping, isteps: Sequence[Mapping], rows: Sequence[Mapping],
           steps: list[dict], hops: list[dict], unconfirmed: list[dict], open_points: list[str], dumps: Sequence,
           net: Mapping, tree: Sequence, stray_acts: Sequence, db_sha256: str, provisional: Mapping | None,
           days: Sequence[str], by_guid: Mapping[str, Mapping], rows4688: Sequence[Mapping], manual: Sequence,
           sys_dumps: Sequence[Mapping] = (), flags: Sequence[str] = (),
           run_interval: Mapping | None = None, manifest_span: Mapping | None = None) -> dict:
    """Assemble the final draft dict (roles, decision checks, paths, window, evidence keys)."""
    by_uid = {r["event_uid"]: r for r in rows}
    s06_dump = scenario == "s06" and bool(dumps)
    for h in hops:
        for k, v in HOP_DEFAULTS.items():
            h.setdefault(k, v)
        h.setdefault("handoff_step", None)
        h.setdefault("path_role", None)
        if scenario == "s04" and h.get("handoff_step") == "s04-A-h1":
            h["needs_owner_approval"] = False
            h["owner_note"] = "decision 021, owner approved the source session 2026-11-10 on this evidence"
            h["session_evidence"] = track_a_evidence(h, manual, rows, by_guid, rows4688, by_uid)
            if h["identity_expected"] != 1:
                h["flags"].append("decision_conflict")
            open_points.append("S04 Track A source session: owner approved on the evidence in hops[].session_evidence (decision 021, 2026-11-10).")
        if scenario == "s06":
            if h["identity_expected"] or s06_dump:
                h["flags"].append("decision_conflict")
        h["flags"] = list(dict.fromkeys(h["flags"]))
    if s06_dump:
        open_points.append("S06: a dump was found; decision 017 kill criterion raised.")
    # steps from hops
    for h in hops:
        benign = h.get("role") != "attack"
        if h["basis"] in ("command_names_target", "manual_command_names_target") or h["agent_event_uids"]:
            steps.append({"step_id": f"{h['hop_id']}-move", "kind": "benign" if benign else "move", "host": h["source_host"],
                          "time_utc": h.get("agent_command_time_utc"), "account": h.get("agent_account"),
                          "status": h["status"], "source": {"command_names_target": "agent_tree",
                                      "manual_command_names_target": "manual_session"}.get(h["basis"], "target_side"),
                          "event_uids": h["agent_event_uids"], "note": f"command naming {h['target_host']}"})
        svc = [u for u in h["target_event_uids"] if by_uid[u]["event_id"] in (7045, 4697)]
        if svc:
            steps.append({"step_id": f"{h['hop_id']}-svc", "kind": "service_exec", "host": h["target_host"],
                          "time_utc": by_uid[svc[0]]["t_utc"], "account": None, "status": h["status"],
                          "source": "target_side", "event_uids": svc, "note": "service install evidence on the target"})
        if h["status"] == "unconfirmed":
            unconfirmed.append({"kind": "hop", "id": h["hop_id"], "role": h.get("role"),
                                "reason": h.get("reason"), "flags": h["flags"], "event_uids": h["agent_event_uids"] + h["target_event_uids"]})
    used = {h["handoff_step"] for h in hops if h.get("handoff_step")}
    for st in isteps:
        if st["kind"] == "move" and st["id"] not in used:
            steps.append({"step_id": st["id"], "kind": "move", "host": st["source_host"], "time_utc": None,
                          "account": st["account"], "status": "unconfirmed", "source": "agent_tree", "event_uids": [],
                          "note": "intended step not found in the agent tree"})
            unconfirmed.append({"kind": "step", "id": st["id"], "reason": "not_found_in_agent_tree", "flags": [], "event_uids": []})
    # paths
    paths, benign_paths = [], []
    chain = [h for h in hops if h.get("handoff_step") and h.get("path_role") == "attack"]
    if chain:
        paths.append({"path_id": f"{scenario}-p1", "role": "attack", "hop_ids": [h["hop_id"] for h in sorted(chain, key=lambda x: x["move_time_utc"] or "")],
                      "status": "confirmed" if all(h["status"] == "confirmed" for h in chain) else "unconfirmed"})
    for h in hops:
        if h.get("handoff_step") and h.get("path_role") == "attack_pair":
            paths.append({"path_id": f"{h['hop_id']}-path", "role": "attack_pair", "hop_ids": [h["hop_id"]], "status": h["status"]})
        elif h.get("role") == "benign" or scenario == "s06":
            benign_paths.append({"path_id": f"{h['hop_id']}-path", "role": "benign", "hop_ids": [h["hop_id"]], "status": h["status"],
                                 "note": "S06 has no attack path (AK-09)" if scenario == "s06" else None})
    for st in isteps:
        if st["kind"] == "move" and st["id"] not in used and st["role"] in ("attack", "attack_pair"):
            paths.append({"path_id": f"{st['id']}-path", "role": st["role"], "hop_ids": [], "missing_steps": [st["id"]], "status": "unconfirmed"})
    # window
    times = [parse_utc(s["time_utc"]).timestamp() for s in steps if s["kind"] != "agent_start" and s["time_utc"]]
    win: dict = {"source": "key", "start_utc": None, "end_utc": None, "provisional": None, "shrink_flag": None,
                 "outside_counts": {"target_side_events": 0, "per_hop": {}}}
    if times:
        lo, hi = min(times) - KEY_MARGIN_BEFORE_S, max(times) + KEY_MARGIN_AFTER_S
        win["start_utc"], win["end_utc"] = _iso(lo), _iso(hi)
        for h in hops:
            n = sum(1 for u in h["target_event_uids"] if not lo <= by_uid[u]["ts"] <= hi)
            if n:
                win["outside_counts"]["per_hop"][h["hop_id"]] = n
                win["outside_counts"]["target_side_events"] += n
        if provisional:
            win["provisional"] = {"start_utc": provisional["start_utc"], "end_utc": provisional["end_utc"]}
            win["shrink_flag"] = (lo > parse_utc(provisional["start_utc"]).timestamp()
                                  or hi < parse_utc(provisional["end_utc"]).timestamp())
    missing = [h["hop_id"] for h in hops if h.get("role") not in ROLES]
    if missing:
        raise ValueError(f"hops without a valid role {ROLES}: {missing}")
    accounts = sorted({p.account for p in tree if p.depth == 1})
    agent = {"image": "C:\\Users\\Public\\splunkd.exe", "server_ip": (net["connections"][0]["ip"] if net["connections"] else None),
             "server_port": (net["connections"][0]["port"] if net["connections"] else None),
             "server_confirmed": net["server_confirmed"], "sysmon3_event_uids": net["event_uids"], "accounts": accounts,
             "run_days": list(days), "run_day": days[-1] if days else None,
             "run_interval": dict(run_interval) if run_interval else None,
             "manifest_span": dict(manifest_span) if manifest_span else None,
             "run_day_rule": "run = the latest splunkd root plus every earlier root reached by walking back while "
                             "consecutive roots are <= 6 h apart (roots = Sysmon 1 children of "
                             "the agent splunkd.exe in Users/Public plus pid_match_4688 roots); run days = UTC days from the "
                             "earliest to the latest of those roots; run_interval start = earliest root of a walk-back with a 30 min gap "
                             "(trials of one day share a DB) - 60 s, end = last step + 300 s; "
                             "older roots belong to other runs"}
    for h in hops:
        for k in PRIVATE:
            h.pop(k, None)
    if any(h.get("agent_root_link") == "pid_match_4688" for h in hops):
        open_points.append("Some agent roots are tied by 4688 parent=splunkd.exe because Sysmon 1 shows ParentImage '-' (root_link=pid_match_4688).")
    draft = {"trial_id": trial_id, "scenario": scenario, "status": "draft", "provenance": "log-based, agent process tree (decision 020)",
             "db_sha256": db_sha256, "window": win, "agent": agent, "steps": steps, "hops": hops, "paths": paths,
             "benign_paths": benign_paths, "unconfirmed": unconfirmed, "system_dumps_ignored": list(sys_dumps),
             "flags": list(flags), "open_points": open_points}
    draft["event_keys"] = event_keys(draft, by_uid)
    return draft


def collect_uids(node) -> set[str]:
    """Every event uid referenced under keys ending in ``uid``/``uids`` (recursive)."""
    out: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "event_keys":
                continue
            if k.endswith("uids") or k.endswith("_uid") or k == "event_uid":
                out.update([v] if isinstance(v, str) else [x for x in (v or []) if isinstance(x, str)])
            else:
                out |= collect_uids(v)
    elif isinstance(node, list):
        for v in node:
            out |= collect_uids(v)
    return out


def event_keys(draft: Mapping, by_uid: Mapping[str, Mapping]) -> dict:
    """Content key per uid (host, channel, event_id, record_id, time) so verify can detect a wrong uid."""
    keys = {}
    for u in sorted(collect_uids(draft)):
        r = by_uid.get(u)
        if r:
            keys[u] = {"host": r["host"], "channel": r["channel"], "event_id": r["event_id"],
                       "record_id": r["record_id"], "time_utc": r["t_utc"]}
    return keys
