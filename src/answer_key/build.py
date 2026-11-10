"""Assemble a draft answer key for one trial (spec 07, section 3).

Everything here is a pure function of (event rows, intended steps, db hash). Reading the DB
and writing the file happen in ``__main__``. The key is built only from the agent process
tree, the handoff's intended steps and target-side events (decision 020); it never reads
linker output (AK-06).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from . import collect, identity, targets
from .agent_tree import AgentProc, agent_network, attach_4688, build_tree, is_splunkd, run_day
from .timeutil import add_s, delta_ms, fmt_utc, parse_utc

IMAGE = "C:\\Users\\Public\\splunkd.exe"
KEY_MARGIN_BEFORE_S = 60.0
KEY_MARGIN_AFTER_S = 300.0
SEARCH_MARGIN_S = 300.0     # only to look for time/account-only logons (AK-04), never to confirm
STRAY_SERVICE_WINDOW_S = 60.0
PROVENANCE = "log-based, agent process tree (decision 020)"


@dataclass
class Action:
    """One agent (or manual) command: a depth-1 process and the processes below it."""
    host: str
    root: AgentProc
    procs: list[AgentProc]
    in_agent_tree: bool = True
    session_id: int | None = None
    targets: set[str] = field(default_factory=set)
    decode_failed: bool = False

    @property
    def texts(self) -> list[str]:
        return [p.command_line for p in self.procs]


# ----------------------------------------------------------------------------- actions

def group_actions(tree: Sequence[AgentProc]) -> list[Action]:
    """One Action per splunkd child (root_guid); children are its descendants."""
    by_root: dict[tuple[str, str], list[AgentProc]] = {}
    for p in tree:
        by_root.setdefault((p.host, p.root_guid), []).append(p)
    acts = []
    for (host, _), procs in by_root.items():
        procs.sort(key=lambda p: (p.depth, p.time_utc))
        acts.append(Action(host, procs[0], procs))
    acts.sort(key=lambda a: a.root.time_utc)
    return acts


def manual_actions(rows: Sequence[Mapping], tree_uids: set[str], day: str | None,
                   ip_to_host: Mapping[str, str]) -> list[Action]:
    """Sysmon 1 commands on the run day, not in the agent tree, that name another host.

    WHY: S04 Track A was run by hand (handoff l.1416); the key lists such commands as
    time/account-only evidence, never as confirmed (AK-04, AK-08).
    """
    cands = []
    for r in rows:
        if (r["channel"] == "Sysmon" and r["event_id"] == 1 and r["event_uid"] not in tree_uids
                and (r["t_utc"] or "")[:10] == day and r.get("command_line")
                and targets.is_user_account(r.get("account_name"))):
            named, failed = targets.find_targets([r["command_line"]], ip_to_host)
            named.discard(r["host"])
            if named:
                cands.append((r, named, failed))
    cands.sort(key=lambda c: (c[0]["host"], c[0].get("session_id") or 0, c[0]["ts"]))
    acts: list[Action] = []
    last: tuple | None = None
    for r, named, failed in cands:
        p = AgentProc(r["event_uid"], r["host"], r["t_utc"], (r["account_name"] or "").lower(), r["process_guid"],
                      r["parent_process_guid"] or "", r["process_id"], r["image"] or "", r["command_line"], 1,
                      r["process_guid"], "manual")
        key = (r["host"], r.get("session_id"))
        if last and last[0] == key and r["ts"] - last[1] <= 30.0:
            acts[-1].procs.append(p)
            acts[-1].targets |= named
            acts[-1].decode_failed |= failed
        else:
            acts.append(Action(r["host"], p, [p], False, r.get("session_id"), set(named), failed))
        last = (key, r["ts"])
    return acts


def annotate_targets(acts: Sequence[Action], ip_to_host: Mapping[str, str]) -> None:
    """Fill ``targets``/``decode_failed`` for agent actions (full command lines, decoded -enc)."""
    for a in acts:
        if a.in_agent_tree:
            named, failed = targets.find_targets(a.texts, ip_to_host)
            a.targets = named
            a.decode_failed = failed


def is_stray(a: Action) -> bool:
    """Agent action run under a non-user token (SYSTEM / machine account) is a stray run."""
    return a.in_agent_tree and not targets.is_user_account(a.root.account)


def splunkd_ancestor(rows_by_guid: Mapping[str, Mapping], proc_guid: str, rows4688: Sequence[Mapping],
                     host: str, pid: int | None) -> tuple[bool, list[str]]:
    """Walk Sysmon 1 parents upward; True if splunkd.exe is an ancestor (or 4688 names it as parent)."""
    chain: list[str] = []
    cur = rows_by_guid.get((proc_guid or "").lower())
    seen: set[str] = set()
    while cur is not None and cur["event_uid"] not in seen:
        seen.add(cur["event_uid"])
        chain.append(f"{(cur['image'] or '?').rsplit(chr(92), 1)[-1]}({cur['event_uid'][:8]})")
        if is_splunkd(cur.get("parent_image")):
            return True, chain
        cur = rows_by_guid.get((cur["parent_process_guid"] or "").lower())
    via_4688 = any(r["host"] == host and r["process_id"] == pid and is_splunkd(r.get("parent_image")) for r in rows4688)
    return via_4688, chain


# ----------------------------------------------------------------------------- hop assembly

def match_step(steps: Sequence[Mapping], consumed: set[str], protocol: str | None, source_host: str,
               target_host: str, account: str, names: Mapping[str, Sequence[str]], manual: bool) -> Mapping | None:
    """Best unconsumed intended move step with the same protocol (and target, if the handoff names one).

    Source host and account only rank the candidates and raise ``handoff_mismatch`` later; they
    do not reject a step (handoff l.1720/1723 conflict with the agent placement in the data).
    """
    best, best_score = None, -1
    for st in steps:
        if st["kind"] != "move" or st["protocol"] != protocol or bool(st.get("manual")) != manual:
            continue
        if st["id"] in consumed and not st.get("repeatable"):
            continue
        if st.get("target_host") and st["target_host"] != target_host:
            continue
        score = (2 if st.get("source_host") == source_host else 0) + (2 if st.get("account") == account else 0) \
            + (3 if st.get("service") and st["service"].lower() in names.get("services", ()) else 0)
        if score > best_score:
            best, best_score = st, score
    return best


def service_exec_uids(idx: collect.Index, host: str, anchor_ts: float, names: Mapping[str, Sequence[str]],
                      stray_ranges: Sequence[tuple[float, float]]) -> list[Mapping]:
    """7045 rows by service/binary name near the anchor, minus events inside stray runs."""
    return collect.service_events(idx, host, anchor_ts, names, stray_ranges)


def tier(basis: str, port_join: bool, candidate_count: int, binding: str) -> str:
    """Annotation only (not a T7 rule): A port join, B named + logon-id artefact, C weaker/several, D time/account."""
    if basis == "time_account_only":
        return "D"
    if port_join:
        return "A"
    if candidate_count <= 1 and binding == "logon_id_artifact":
        return "B"
    return "C"


def port_join_present(rows_idx: collect.Index, source_host: str, target_ip: str | None, src_port: int | None) -> bool:
    """Sysmon 3 on the source host whose source port equals the target 4624 IpPort (where logged: WinRM)."""
    if not target_ip or not src_port:
        return False
    return any(e.get("source_port") == src_port and e.get("destination_ip") == target_ip
               for e in rows_idx.by_key.get((source_host, "Sysmon", 3), []))


def build_hop(a: Action, target: str, ctx: "Ctx") -> dict:
    """One hop record for action ``a`` naming ``target`` (confirmed only per AK-02)."""
    agent_account = targets.normalise_account(a.root.account)
    cred = targets.credential_account(a.texts)
    protocol = targets.classify_protocol(" ".join(a.texts + targets.decode_encoded(" ".join(a.texts))[0]))
    names = targets.artifact_names(a.texts + targets.decode_encoded(" ".join(a.texts))[0])
    src_ip = ctx.host_ip.get(a.host)
    t0 = a.root.time_utc
    ts0 = parse_utc(t0).timestamp()
    logons = collect.remote_logons(ctx.idx, target, src_ip, ts0 - collect.CMD_BEFORE_LOGON_S, ts0 + collect.CMD_AFTER_LOGON_S)
    bursts = collect.cluster_bursts(logons)
    arts = [collect.burst_artifacts(ctx.idx, target, b, names) for b in bursts]
    sel, how = collect.select_burst(bursts, arts, [cred or "", agent_account])
    hop: dict = {"protocol": protocol, "source_host": a.host, "target_host": target,
                 "basis": "command_names_target" if a.in_agent_tree else "time_account_only",
                 "agent_account": agent_account, "cmd_credential_account": cred,
                 "agent_command": targets.mask_command(a.root.command_line)[:600],
                 "agent_command_time_utc": t0, "agent_root_link": a.root.root_link,
                 "agent_event_uids": [p.event_uid for p in a.procs if _names(p.command_line, target, ctx)],
                 "agent_corroboration_4688_uids": sorted({u for p in a.procs for u in p.corroborating_4688}),
                 "candidate_count": len(bursts), "flags": [], "needs_owner_approval": False,
                 "candidates": [collect.describe_burst(b, ar) for b, ar in zip(bursts, arts)],
                 "target_binding": None, "reason": None, "handoff_step": None, "handoff_account": None,
                 "role": None, "proposed_role": None, "stray": False, "_names": names, "_anchor_ts": None}
    if a.decode_failed:
        hop["flags"].append("decode_failed")
    if sel is None:
        hop["status"] = "unconfirmed"
        hop["reason"] = "attempt_no_target_evidence" if how == "none" else "ambiguous_target_logon"
        if how == "none":
            hop["flags"].append("attempt_no_target_evidence")
        return hop
    burst, art = bursts[sel], arts[sel]
    anchor = burst[0]
    anchor_ts = anchor["ts"]
    svc = service_exec_uids(ctx.idx, target, anchor_ts, names, ctx.stray_ranges.get(target, []))
    wrm = collect.winrm_events(ctx.idx, target, anchor["account_name"], src_ip or "", anchor_ts) if protocol == "WinRM" else []
    binding = ("logon_id_artifact" if art["bound"] else "name_only" if svc else "time_account")
    logon_account = targets.normalise_account(anchor["account_name"])
    tgt_uids = ([b["event_uid"] for b in burst] + art["share_uids"] + art["file_uids"] + art["install_uids"]
                + art["wsmprovhost_uids"] + [e["event_uid"] for e in svc] + [e["event_uid"] for e in wrm])
    source_by_ip = ctx.ip_host.get(anchor.get("source_ip") or "")
    ident = identity.evaluate_identity(ctx.dumps, ctx.state, logon_account, source_by_ip, anchor_ts)
    hop.update({
        "account": logon_account, "logon_account": logon_account, "target_binding": binding,
        "move_time_utc": anchor["t_utc"], "target_logon_id": hex(anchor["target_logon_id"]),
        "authentication_package": anchor.get("authentication_package"),
        "target_event_uids": list(dict.fromkeys(tgt_uids)), "service_candidates_by_name": len(svc),
        "time_delta_ms": delta_ms(t0, anchor["t_utc"]), "select_how": how,
        "source_host_by_ip": source_by_ip, "identity_expected": ident["identity_expected"],
        "identity_basis": ident["identity_basis"], "_anchor_ts": anchor_ts, "_burst_uids": [b["event_uid"] for b in burst]})
    hop["flags"] += ident["flags"]
    port = port_join_present(ctx.idx, a.host, ctx.host_ip.get(target), anchor.get("source_port"))
    hop["port_join_sysmon3"] = port
    hop["confidence_tier"] = tier(hop["basis"], port, len(bursts), binding)
    if source_by_ip and source_by_ip != a.host:
        hop["flags"].append("source_host_conflict")
    if len({x for x in (agent_account, cred, logon_account) if x}) > 1:
        hop["flags"].append("account_mismatch")
    hop["account_mismatch"] = "account_mismatch" in hop["flags"]
    # source-clock order check (dump vs the agent command on that host)
    dump = identity.pick_dump(ctx.dumps, source_by_ip, anchor_ts, identity.CROSS_HOST_TOL_S) if source_by_ip else None
    if dump is not None and a.in_agent_tree:
        before = dump.ts <= ts0
        hop["identity_basis"]["dump_before_agent_command_source_clock"] = before
        if before != hop["identity_basis"]["move_after_dump"]:
            hop["flags"].append("clock_order_disagree")
    hop["status"] = "confirmed" if a.in_agent_tree else "unconfirmed"
    if not a.in_agent_tree:
        hop["reason"] = "command_not_under_agent_tree"
    return hop


def _names(text: str, host: str, ctx: "Ctx") -> bool:
    return host in targets.find_targets([text], ctx.ip_host)[0]


@dataclass
class Ctx:
    """Per-trial lookups shared by hop builders."""
    idx: collect.Index
    ip_host: dict[str, str]
    host_ip: dict[str, str]
    dumps: list[identity.Dump]
    state: identity.HostState
    stray_ranges: dict[str, list[tuple[float, float]]]


# ----------------------------------------------------------------------------- draft

def _step(step_id: str, kind: str, host: str | None, time_utc: str | None, account: str | None, status: str,
          source: str, uids: Sequence[str], note: str) -> dict:
    return {"step_id": step_id, "kind": kind, "host": host, "time_utc": time_utc, "account": account,
            "status": status, "source": source, "event_uids": list(dict.fromkeys(uids)), "note": note}


def leftover_bursts(ctx: Ctx, used: set[str], t_lo: float, t_hi: float) -> list[tuple[str, str, list[Mapping]]]:
    """Remote ep->ep user logons in the search interval that no command explained (AK-04)."""
    out = []
    ep_hosts = [h for h in ctx.host_ip if h.startswith("ep-")]
    for tgt in ep_hosts:
        for ip, src in ctx.ip_host.items():
            if src == tgt or not src.startswith("ep-"):
                continue
            for b in collect.cluster_bursts(collect.remote_logons(ctx.idx, tgt, ip, t_lo, t_hi)):
                if not any(x["event_uid"] in used for x in b):
                    out.append((src, tgt, b))
    out.sort(key=lambda x: x[2][0]["ts"])
    return out


def window_from_steps(steps: Sequence[Mapping]) -> tuple[str, str] | None:
    """[first - 60 s, last + 300 s] over every step except agent_start (AK-12)."""
    times = [parse_utc(s["time_utc"]).timestamp() for s in steps if s["kind"] != "agent_start" and s["time_utc"]]
    if not times:
        return None
    from datetime import datetime, timezone
    f = lambda t: fmt_utc(datetime.fromtimestamp(t, tz=timezone.utc))  # noqa: E731
    return f(min(times) - KEY_MARGIN_BEFORE_S), f(max(times) + KEY_MARGIN_AFTER_S)


def build_draft(rows: list[dict], trial_id: str, intended: Mapping, db_sha256: str,
                provisional: Mapping | None = None) -> dict:
    """Return the draft key (a plain dict) for one trial. See spec 07 section 3."""
    scenario = trial_id.split("_")[0]
    sc = intended["scenarios"][scenario]
    isteps = sc["steps"]
    day = run_day(rows)
    tree = attach_4688(build_tree(rows, day), rows)
    net = agent_network(rows, day)
    ip_host = targets.lab_ip_to_host(rows)
    host_ip = {h: ip for ip, h in ip_host.items()}
    idx = collect.build_index(rows)
    state = identity.build_host_state(rows)
    all_dumps = identity.find_dumps([r for r in rows if (r["t_utc"] or "")[:10] == day])
    acts = group_actions(tree)
    annotate_targets(acts, ip_host)
    stray_acts = [a for a in acts if is_stray(a)]
    stray_guids = {p.process_guid for a in stray_acts for p in a.procs}
    dumps = [d for d in all_dumps if d.process_guid.lower() not in {g.lower() for g in stray_guids}]
    stray_dumps = [d for d in all_dumps if d not in dumps]
    stray_ranges: dict[str, list[tuple[float, float]]] = {}
    for a in stray_acts:
        t = parse_utc(a.root.time_utc).timestamp()
        stray_ranges.setdefault(a.host, []).append((t - 5.0, t + STRAY_SERVICE_WINDOW_S))
    ctx = Ctx(idx, ip_host, host_ip, dumps, state, stray_ranges)
    tree_uids = {p.event_uid for p in tree}
    manual = manual_actions(rows, tree_uids, day, ip_host)
    by_guid = {(r["process_guid"] or "").lower(): r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1}
    rows4688 = [r for r in rows if r["event_id"] == 4688 and r["channel"] == "Security"]

    steps: list[dict] = []
    hops: list[dict] = []
    unconfirmed: list[dict] = []
    open_points: list[str] = []
    consumed: set[str] = set()
    counters = {"x": 0, "t": 0}
    used_logons: set[str] = set()

    # agent_start steps (not used for the window)
    starts = [r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1 and is_splunkd(r.get("image"))
              and (r["t_utc"] or "")[:10] == day]
    for i, r in enumerate(sorted(starts, key=lambda r: r["ts"]), 1):
        corr = [x["event_uid"] for x in rows4688 if x["host"] == r["host"] and is_splunkd(x.get("image"))
                and abs(x["ts"] - r["ts"]) <= 3.0]
        steps.append(_step(f"{scenario}-agent-{r['host']}-{i}", "agent_start", r["host"], r["t_utc"],
                           targets.normalise_account(r["account_name"]), "confirmed", "agent_tree",
                           [r["event_uid"]] + corr, "splunkd.exe launch (Sysmon 1; 4688 corroborates)"))

    # strays: agent run under a non-user token
    for n, a in enumerate(stray_acts, 1):
        if not a.targets and not any(targets.classify_protocol(t) for t in a.texts) and "lsass" not in " ".join(a.texts).lower():
            continue
        flag = ["stray_agent_ep02"] if a.host == "ep-02" else []
        self_target = a.host in {h for h in targets.find_targets(a.texts, ip_host)[0]} or \
            any(ip_pat for ip_pat in [targets.ip_pattern(host_ip.get(a.host, "-")).search(t) for t in a.texts])
        svc_names = targets.artifact_names(a.texts)
        t0 = parse_utc(a.root.time_utc).timestamp()
        stray_events = [e["event_uid"] for e in collect.service_events(idx, a.host, t0 + 30.0, svc_names)
                        if t0 - 5 <= e["ts"] <= t0 + STRAY_SERVICE_WINDOW_S] if svc_names["services"] else []
        sid = f"{scenario}-stray-{a.host}-{n}"
        unconfirmed.append({"kind": "stray", "id": sid, "role": "stray", "host": a.host, "time_utc": a.root.time_utc,
                            "agent_account": targets.normalise_account(a.root.account), "flags": flag,
                            "reason": "agent run under a non-user token" + ("; target is the host's own IP" if self_target else ""),
                            "agent_command": targets.mask_command(a.root.command_line)[:300],
                            "event_uids": [p.event_uid for p in a.procs], "stray_target_side_event_uids": stray_events})
        steps.append(_step(sid, "benign", a.host, a.root.time_utc, targets.normalise_account(a.root.account),
                           "unconfirmed", "agent_tree", [p.event_uid for p in a.procs],
                           "stray agent run (excluded from hops and identity)"))
    for d in stray_dumps:
        unconfirmed.append({"kind": "lsass_dump", "id": f"{scenario}-stray-dump-{d.host}", "role": "stray", "host": d.host,
                            "time_utc": d.time_utc, "flags": ["stray_agent_ep02"] if d.host == "ep-02" else [],
                            "reason": "dump by a stray agent run; not used for identity", "event_uids": list(d.event_uids)})
        steps.append(_step(f"{scenario}-stray-dump-{d.host}", "lsass_dump", d.host, d.time_utc, d.account, "unconfirmed",
                           "agent_tree", d.event_uids, "stray dump, not used for identity"))

    # dumps -> intended dump steps (host, order); agent-tree membership decides confirmed
    tree_guids = {p.process_guid.lower() for p in tree}
    dump_steps = [s for s in isteps if s["kind"] == "lsass_dump"]
    dstep_used: set[str] = set()
    dump_step_id: dict[tuple, str] = {}
    for d in dumps:
        st = next((s for s in dump_steps if s["host"] == d.host and s["id"] not in dstep_used), None)
        in_tree = d.process_guid.lower() in tree_guids
        if st:
            dstep_used.add(st["id"])
        sid = st["id"] if st else f"{scenario}-dump-x{d.host}-{int(d.ts)}"
        dump_step_id[(d.host, d.ts)] = sid
        status = "confirmed" if (in_tree and st) else "unconfirmed"
        note = ("rundll32 -> lsass in agent tree" if in_tree else "rundll32 -> lsass not under splunkd tree") \
            + ("" if st else "; no intended dump step on this host (handoff)")
        steps.append(_step(sid, "lsass_dump", d.host, d.time_utc, d.account, status, "agent_tree" if in_tree else "target_side",
                           d.event_uids, note))
        if status == "unconfirmed":
            unconfirmed.append({"kind": "lsass_dump", "id": sid, "role": None, "host": d.host, "time_utc": d.time_utc,
                                "reason": "no_intended_step" if not st else "not_in_agent_tree", "flags": [],
                                "event_uids": list(d.event_uids)})
    for st in dump_steps:
        if st["id"] not in dstep_used:
            steps.append(_step(st["id"], "lsass_dump", st["host"], None, st["account"], "unconfirmed", "agent_tree", [],
                               "intended step not found in the agent tree"))
            unconfirmed.append({"kind": "step", "id": st["id"], "reason": "not_found_in_agent_tree", "flags": [],
                                "event_uids": []})

    # moves: agent actions first (confirmed path), then manual commands (time/account only)
    cand_actions: list[tuple[Action, str]] = []
    for a in acts + manual:
        if is_stray(a):
            continue
        tg = sorted(t for t in a.targets if t != a.host)
        if not targets.is_user_account(a.root.account):
            continue
        if not a.in_agent_tree and not targets.classify_protocol(" ".join(a.texts)):
            continue   # e.g. a pre-flight ping by hand: no protocol, not a move
        if len(tg) > 1:
            cand_actions += [(a, t) for t in tg]
        else:
            cand_actions += [(a, t) for t in tg]
    cand_actions.sort(key=lambda at: at[0].root.time_utc)
    for a, tgt in cand_actions:
        multi = len([t for t in a.targets if t != a.host]) > 1
        hop = build_hop(a, tgt, ctx)
        if hop["status"] == "unconfirmed" and hop["reason"] == "attempt_no_target_evidence":
            unconfirmed.append({"kind": "attempt", "id": f"{scenario}-attempt-{a.host}-{tgt}", "role": None,
                                "reason": "attempt_no_target_evidence", "flags": hop["flags"],
                                "agent_event_uids": hop["agent_event_uids"], "agent_command": hop["agent_command"],
                                "time_utc": a.root.time_utc, "host": a.host, "target_host": tgt})
            continue
        if multi:
            hop["status"] = "unconfirmed"
            hop["reason"] = "multiple_targets_in_command"
        if hop.get("account") is None:                       # ambiguous burst: keep as unconfirmed hop without anchor
            hop["account"] = hop["logon_account"] = None
        st = match_step(isteps, consumed, hop["protocol"], a.host, tgt, hop.get("logon_account") or hop["agent_account"],
                        hop["_names"], manual=not a.in_agent_tree)
        _attach_step(hop, st, isteps, consumed, counters, scenario, a)
        hops.append(hop)
        used_logons.update(hop.get("_burst_uids", []))
        if hop["status"] == "confirmed" and not st:
            hop["status"] = "unconfirmed"
            hop["reason"] = "no_intended_step"

    # leftover bursts: time/account only
    kinds = [parse_utc(s["time_utc"]).timestamp() for s in steps if s["kind"] != "agent_start" and s["time_utc"]]
    kinds += [parse_utc(h["agent_command_time_utc"]).timestamp() for h in hops if h.get("agent_command_time_utc")]
    if kinds:
        for src, tgt, b in leftover_bursts(ctx, used_logons, min(kinds) - SEARCH_MARGIN_S, max(kinds) + SEARCH_MARGIN_S):
            hops.append(_leftover_hop(b, src, tgt, ctx, counters, scenario, idx))
    return _finish(scenario, trial_id, sc, isteps, rows, steps, hops, unconfirmed, open_points, dumps, net, tree,
                   stray_acts, db_sha256, provisional, day, by_guid, rows4688, manual)


def _attach_step(hop: dict, st: Mapping | None, isteps: Sequence[Mapping], consumed: set[str], counters: dict,
                 scenario: str, a: Action) -> None:
    """Give the hop its stable id and handoff fields from the matched intended step (never overwritten)."""
    if st is None:
        counters["x"] += 1
        hop["hop_id"] = f"{scenario}-x{counters['x']}"
        hop["flags"].append("no_intended_step")
        if hop["status"] != "unconfirmed" or not hop["reason"]:
            hop["status"], hop["reason"] = "unconfirmed", "no_intended_step"
        return
    consumed.add(st["id"])
    n = sum(1 for k in consumed if k == st["id"])
    hop["hop_id"] = st["id"]
    if st.get("repeatable"):
        counters[st["id"]] = counters.get(st["id"], 0) + 1
        hop["hop_id"] = f"{st['id']}-{counters[st['id']]}"
    hop["handoff_step"] = st["id"]
    hop["handoff_account"] = st.get("account")
    hop["role"] = st.get("role")
    acct = hop.get("logon_account") or hop["agent_account"]
    if (st.get("source_host") and st["source_host"] != hop["source_host"]) \
            or (st.get("account") and st["account"] != acct) \
            or (st.get("service") and st["service"].lower() not in hop["_names"].get("services", ())):
        hop["flags"].append("handoff_mismatch")
    del n


def _leftover_hop(b: Sequence[Mapping], src: str, tgt: str, ctx: Ctx, counters: dict, scenario: str,
                  idx: collect.Index) -> dict:
    """A remote logon burst no command explains: time_account_only, unconfirmed (AK-04)."""
    anchor = b[0]
    acct = targets.normalise_account(anchor["account_name"])
    art = collect.burst_artifacts(idx, tgt, b, {})
    protocol = ("WinRM" if art["wsmprovhost_uids"] else "RDP" if anchor.get("logon_type") == 10
                else "SMB" if (art["share_uids"] or art["file_uids"]) else None)
    counters["t"] += 1
    ident = identity.evaluate_identity(ctx.dumps, ctx.state, acct, src, anchor["ts"])
    uids = [x["event_uid"] for x in b] + art["share_uids"] + art["file_uids"] + art["install_uids"] + art["wsmprovhost_uids"]
    return {"hop_id": f"{scenario}-t{counters['t']}", "protocol": protocol, "source_host": src, "target_host": tgt,
            "account": acct, "logon_account": acct, "agent_account": None, "cmd_credential_account": None,
            "handoff_account": None, "handoff_step": None, "account_mismatch": False,
            "move_time_utc": anchor["t_utc"], "basis": "time_account_only", "status": "unconfirmed",
            "reason": "no_agent_command_names_target", "agent_event_uids": [], "target_event_uids": list(dict.fromkeys(uids)),
            "identity_expected": ident["identity_expected"], "identity_basis": ident["identity_basis"],
            "time_delta_ms": None, "confidence_tier": "D", "target_binding": "time_account", "candidate_count": 1,
            "needs_owner_approval": False, "flags": list(ident["flags"]), "role": None, "proposed_role": None,
            "target_logon_id": hex(anchor["target_logon_id"]), "authentication_package": anchor.get("authentication_package"),
            "source_host_by_ip": src, "_anchor_ts": anchor["ts"], "_burst_uids": [x["event_uid"] for x in b], "_names": {}}


def _finish(scenario, trial_id, sc, isteps, rows, steps, hops, unconfirmed, open_points, dumps, net, tree, stray_acts,
            db_sha256, provisional, day, by_guid, rows4688, manual) -> dict:
    """Roles, S04-A evidence, decision checks, paths, window and the final dict (see build_draft)."""
    from . import finish
    return finish.finish(scenario, trial_id, sc, isteps, rows, steps, hops, unconfirmed, open_points, dumps, net, tree,
                         stray_acts, db_sha256, provisional, day, by_guid, rows4688, manual)
