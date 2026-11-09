"""LC-04, LC-04b, LC-04c, LC-04d: SMB hop evidence per decision 011.

SMB connections are owned by the kernel (`System`), so the source session can only come
from a command process in that session whose command line names the target. These checks
measure how many sessions that join leaves per hop; they do not choose one.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .bridge import bridges
from .common import (INFO, OK, PREDEFINED_LOGON_IDS, PROBLEM, CheckResult, Context,
                     account_from_subject, base_name, gated_status, hex_id, load_remote_4624,
                     session_logon, with_time)
from .hops import HopInstance, port_join
from .matching import CommandMatch, mask_command_line, match_command, target_name_forms
from .params import Params
from .timeutil import delta_ms, seconds, to_db, to_display
from .window import normalise_image_path

METHOD_CMDLINE = "cmdline_target"
ZERO_A = "a_no_command_in_range"
ZERO_B = "b_no_command_names_target"
ZERO_C = "c_encoded_undecodable"
ZERO_UNKNOWN_SOURCE = "source_host_unknown"


# --- pure evaluation ---------------------------------------------------------------------

@dataclass
class Process:
    """One command process: a Sysmon 1 row and/or its 4688 twin (LC-04 collapse)."""

    host: str
    session_id: int | None
    t: datetime
    command_line: str
    rows: list[dict[str, Any]]
    via: str | None = None

    @property
    def event_uids(self) -> list[str]:
        return [r["event_uid"] for r in self.rows]

    @property
    def channels(self) -> list[str]:
        return sorted({r["channel"] for r in self.rows})


def _norm_cmd(text: str | None) -> str:
    return " ".join((text or "").split()).lower()


def collapse_processes(rows: list[dict[str, Any]], tol_s: float) -> list[Process]:
    """Pair each Sysmon 1 with at most one 4688 for the same process.

    Same host, same session_id and same command line within tol_s. The spec's
    "session_id or command_line" is read as *both* keys: session alone would merge
    `net use` and `sc create` launched 0.2 s apart in one session (S04), and that would
    undercount processes. Rows of the same channel are never merged.
    """
    sysmon = sorted((r for r in rows if r["channel"] == "Sysmon"), key=lambda r: (r["t"], r["event_uid"]))
    security = sorted((r for r in rows if r["channel"] != "Sysmon"), key=lambda r: (r["t"], r["event_uid"]))
    used: set[str] = set()
    processes: list[Process] = []
    for s in sysmon:
        twin = _nearest_twin(s, security, used, tol_s)
        group = [s] + ([twin] if twin else [])
        if twin:
            used.add(twin["event_uid"])
        processes.append(Process(s["host"], s.get("session_id"), min(r["t"] for r in group),
                                 s["command_line"], group))
    for r in security:
        if r["event_uid"] not in used:
            processes.append(Process(r["host"], r.get("session_id"), r["t"], r["command_line"], [r]))
    return sorted(processes, key=lambda p: (p.t, p.event_uids[0]))


def _nearest_twin(s: dict[str, Any], security: list[dict[str, Any]], used: set[str],
                  tol_s: float) -> dict[str, Any] | None:
    best, best_gap = None, None
    for r in security:
        if r["event_uid"] in used or r["host"] != s["host"] or r.get("session_id") != s.get("session_id"):
            continue
        if _norm_cmd(r["command_line"]) != _norm_cmd(s["command_line"]):
            continue
        gap = abs((r["t"] - s["t"]).total_seconds())
        if gap <= tol_s and (best_gap is None or gap < best_gap):
            best, best_gap = r, gap
    return best


@dataclass
class SessionCandidate:
    """A source logon session that ran at least one command naming the target."""

    session_id: int | None
    processes: list[Process]
    account: str | None
    account_source: str
    logon: dict[str, Any] | None

    @property
    def first_t(self) -> datetime:
        return self.processes[0].t

    @property
    def predefined(self) -> bool:
        return self.session_id in PREDEFINED_LOGON_IDS

    @property
    def raw_rows(self) -> int:
        return sum(len(p.rows) for p in self.processes)

    @property
    def event_uids(self) -> list[str]:
        return [u for p in self.processes for u in p.event_uids]

    def closest_t(self, t: datetime) -> datetime:
        """Matching command nearest to the hop's first 4624.

        Used for time_delta_ms because one source session can serve several hops (S07: the
        same agent session drives two hops 95 s apart); its first command would give the
        later hop a misleading −95 s delta.
        """
        return min((p.t for p in self.processes), key=lambda x: abs((x - t).total_seconds()))


@dataclass
class HopEval:
    """LC-04 numbers for one hop instance at one (CMD_BEFORE_S, CMD_AFTER_S)."""

    rows_in_range: int = 0
    rows_with_cmdline: int = 0
    rows_matched: int = 0
    processes: int = 0
    sessions: list[SessionCandidate] = field(default_factory=list)
    after: list[SessionCandidate] = field(default_factory=list)
    zero_reason: str | None = None
    via: Counter = field(default_factory=Counter)
    after_bridge: list[SessionCandidate] = field(default_factory=list)
    bridge: dict[int, list[str]] = field(default_factory=dict)  # session → bridging 4648 uids

    @property
    def filtered_out(self) -> list[SessionCandidate]:
        """Sessions removed by the account filter (e.g. the other S04 track)."""
        keep = {id(s) for s in self.after}
        return [s for s in self.sessions if id(s) not in keep]

    @property
    def mismatched(self) -> list[SessionCandidate]:
        """Mismatch table: candidates exist but none has the 4624 account.

        Read from LCT-02 ("mismatch table empty" for S04, where the filter removes only the
        other track): a mismatch is a hop whose account filter leaves nothing, which is where
        a true source session using explicit other credentials would be lost.
        """
        return list(self.sessions) if self.sessions and not self.after else []

    @property
    def mismatched_after_bridge(self) -> list[SessionCandidate]:
        """Mismatch table once the LC-04e 4648 bridge is applied."""
        return list(self.sessions) if self.sessions and not self.after_bridge else []


def apply_bridge(ev: HopEval, account: str, bridged: dict[int, list[str]]) -> None:
    """LC-04e: a session passes if its account is the 4624 account OR it has a bridging 4648."""
    ev.bridge = {s.session_id: bridged[s.session_id] for s in ev.sessions
                 if s.session_id is not None and s.session_id in bridged}
    ev.after_bridge = [s for s in ev.sessions if s.account == account or s.session_id in ev.bridge]


def resolve_session_account(host: str, session_id: int | None, rows: list[dict[str, Any]],
                            logon_index: dict, before: datetime) -> tuple[str | None, str, dict | None]:
    """Account of a source session, best evidence first.

    1. the 4624 that created the session on the source host (shows a shared agent session,
       LCT-14); 2. Sysmon 1 `User` of its processes; 3. the 4688 creator (SubjectUserName,
    whose logon id IS the session id; 4688 `account_name` is the new process's user).
    """
    logon = session_logon(logon_index, host, session_id, before) if session_id is not None else None
    if logon is not None and logon.get("account_name"):
        return logon["account_name"], "source_4624", logon
    sysmon = Counter(r.get("account_name") for r in rows if r["channel"] == "Sysmon" and r.get("account_name"))
    if sysmon:
        return sysmon.most_common(1)[0][0], "sysmon1_user", logon
    subj = Counter(account_from_subject(r.get("subject_account")) for r in rows
                   if r["channel"] != "Sysmon" and r.get("subject_account"))
    if subj:
        return subj.most_common(1)[0][0], "4688_subject", logon
    return None, "unknown", logon


def zero_reason(rows_with_cmd: list[dict], matches: list[CommandMatch]) -> str:
    """(a) nothing ran, (c) something encoded could not be read, else (b) nothing names it."""
    if not rows_with_cmd:
        return ZERO_A
    if any(m.undecodable for m in matches):
        return ZERO_C
    return ZERO_B


def evaluate_hop(hop: HopInstance, commands_by_host: dict[str, list[dict[str, Any]]],
                 logon_index: dict, params: Params, before_s: float, after_s: float,
                 explicit_by_host: dict[str, list[dict[str, Any]]] | None = None) -> HopEval:
    """Source candidates for one hop: commands on the source host in [t − before, t + after]
    that name the target, collapsed to processes, grouped to sessions, then account-filtered
    (plain, and with the LC-04e 4648 bridge when 4648 rows are given)."""
    if hop.source_host is None:
        return HopEval(zero_reason=ZERO_UNKNOWN_SOURCE)
    lo, hi = hop.t - seconds(before_s), hop.t + seconds(after_s)
    in_range = [r for r in commands_by_host.get(hop.source_host, []) if lo <= r["t"] <= hi]
    with_cmd = [r for r in in_range if r.get("command_line")]  # 4688 without cmdline = no evidence
    forms = target_name_forms(hop.target_host, params.host_ip.get(hop.target_host))
    tested = [(r, match_command(r["command_line"], forms)) for r in with_cmd]
    matched = [r for r, m in tested if m.matched]
    ev = HopEval(len(in_range), len(with_cmd), len(matched))
    ev.via = Counter(m.via for _, m in tested if m.matched)
    via_by_uid = {r["event_uid"]: m.via for r, m in tested if m.matched}
    processes = collapse_processes(matched, params.process_collapse_s)
    for p in processes:
        p.via = via_by_uid.get(p.rows[0]["event_uid"])
    ev.processes = len(processes)
    by_session: dict[Any, list[Process]] = defaultdict(list)
    for p in processes:
        by_session[p.session_id].append(p)
    for sid, procs in sorted(by_session.items(), key=lambda kv: kv[1][0].t):
        rows = [r for p in procs for r in p.rows]
        account, source, logon = resolve_session_account(hop.source_host, sid, rows, logon_index, procs[0].t)
        ev.sessions.append(SessionCandidate(sid, procs, account, source, logon))
    ev.after = [s for s in ev.sessions if s.account == hop.account_name]
    bridged = bridges((explicit_by_host or {}).get(hop.source_host, []), forms, hop.account_name,
                      hop.t, before_s, after_s)
    apply_bridge(ev, hop.account_name, bridged)
    if not ev.sessions:
        ev.zero_reason = zero_reason(with_cmd, [m for _, m in tested])
    return ev


def confidence_tier(method: str, account_ok: bool, n_after: int) -> str:
    """Provisional tiers (not defined in the spec; see report open questions).

    A port-level join with a unique, account-consistent session; B command-line join with a
    unique account-consistent session; C account-consistent but ambiguous (> 1 session);
    D candidate whose session account differs from the 4624 account.
    """
    if not account_ok:
        return "D"
    if n_after == 1:
        return "A" if method != METHOD_CMDLINE else "B"
    return "C"


# --- report shaping ----------------------------------------------------------------------

def _session_json(s: SessionCandidate, hop: HopInstance, secrets: frozenset[str]) -> dict[str, Any]:
    first = s.processes[0]
    return {
        "session_id": hex_id(s.session_id), "account": s.account, "account_source": s.account_source,
        "logon_type": s.logon.get("logon_type") if s.logon else None,
        "logon_start": to_display(s.logon["t"]) if s.logon else None,
        "logon_event_uid": s.logon["event_uid"] if s.logon else None,
        "first_command_time": to_display(s.first_t),
        "closest_command_time": to_display(s.closest_t(hop.t)),
        "time_delta_ms": delta_ms(s.closest_t(hop.t), hop.t),
        "predefined_system": s.predefined, "processes": len(s.processes), "rows": s.raw_rows,
        "matched_via": sorted({p.via or "" for p in s.processes}),
        "first_command": mask_command_line(first.command_line, secrets),
        "event_uids": s.event_uids,
    }


def hop_csv_rows(trial_id: str, hop: HopInstance, ev: HopEval) -> list[dict[str, Any]]:
    """hop_candidates.csv rows for LC-04: one per candidate session, or one empty row."""
    base = {
        "trial_id": trial_id, "protocol": hop.protocol, "hop_id": hop.hop_id,
        "target_host": hop.target_host, "target_event_uids": ";".join(hop.event_uids),
        "target_time_utc": to_display(hop.t), "account_name": hop.account_name,
        "source_ip": hop.source_ip, "source_port": hop.source_port,
        "source_host": hop.source_host or "", "method": METHOD_CMDLINE,
        "candidate_count_sessions_before_account": len(ev.sessions),
        "candidate_count_sessions_after_account": len(ev.after),
        "candidate_count_sessions_after_4648_bridge": len(ev.after_bridge),
    }
    if not ev.sessions:
        return [{**base, "candidate_count_rows": 0, "time_delta_ms": "", "confidence_tier": "",
                 "candidate_session_id": "", "candidate_account": "", "candidate_logon_type": "",
                 "zero_reason": ev.zero_reason or "", "supporting_event_uids": ";".join(hop.event_uids)}]
    rows = []
    for s in ev.sessions:
        # LC-04e defines passing the account filter as "same account OR bridging 4648", so the
        # LC-04g tier uses the bridged filter; the plain count stays in its own column.
        bridge_uids = ev.bridge.get(s.session_id, [])
        ok = s.account == hop.account_name or bool(bridge_uids)
        rows.append({**base, "candidate_count_rows": len(s.processes),
                     "time_delta_ms": delta_ms(s.closest_t(hop.t), hop.t),
                     "confidence_tier": confidence_tier(METHOD_CMDLINE, ok, len(ev.after_bridge)),
                     "candidate_session_id": hex_id(s.session_id) or "",
                     "candidate_account": s.account or "",
                     "candidate_logon_type": (s.logon or {}).get("logon_type") or "",
                     "zero_reason": "",
                     "supporting_event_uids": ";".join(hop.event_uids + s.event_uids + bridge_uids)})
    return rows


def hop_result(hop: HopInstance, ev: HopEval, secrets: frozenset[str], params: Params) -> dict[str, Any]:
    """Per-hop LC-04 detail for report.json."""
    return {
        **hop.summary(), "scenario_account": hop.is_scenario_account(params),
        "rows_in_range": ev.rows_in_range, "rows_with_cmdline": ev.rows_with_cmdline,
        "candidate_count_rows_raw": ev.rows_matched,
        "candidate_count_rows": ev.processes,
        "candidate_count_rows_after_account": sum(len(s.processes) for s in ev.after),
        "candidate_count_sessions_before_account": len(ev.sessions),
        "candidate_count_sessions_after_account": len(ev.after),
        "candidate_count_sessions_after_4648_bridge": len(ev.after_bridge),
        "bridging_4648": {hex_id(sid): uids for sid, uids in ev.bridge.items()},
        "mismatch_after_bridge": [{"session_id": hex_id(s.session_id), "account": s.account}
                                  for s in ev.mismatched_after_bridge],
        "zero_reason": ev.zero_reason,
        "zero_after_account_filter": bool(ev.sessions) and not ev.after,
        "matched_via": dict(ev.via),
        "candidates": [_session_json(s, hop, secrets) for s in ev.sessions],
        "mismatch_table": [{"session_id": hex_id(s.session_id), "account": s.account,
                            "hop_account": hop.account_name, "first_command_time": to_display(s.first_t),
                            "first_command": mask_command_line(s.processes[0].command_line, secrets)}
                           for s in ev.mismatched],
        "filtered_by_account": [{"session_id": hex_id(s.session_id), "account": s.account}
                                for s in ev.filtered_out],
    }


def commands_by_host(commands: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in commands:
        out[r["host"]].append(r)
    return out


def run_lc04(ctx: Context, hops: list[HopInstance], by_host: dict, logon_index: dict,
             excluded: dict[str, int], explicit_by_host: dict | None = None) -> tuple[CheckResult, dict[str, HopEval]]:
    """LC-04 (+ LC-04e bridge) on every hop instance; status from SMB-labelled hops."""
    p = ctx.params
    evals = {h.hop_id: evaluate_hop(h, by_host, logon_index, p, p.cmd_before_s, p.cmd_after_s,
                                    explicit_by_host) for h in hops}
    details = [hop_result(h, evals[h.hop_id], ctx.secrets, p) for h in hops]
    smb_scen = [h for h in hops if h.protocol == "SMB" and h.is_scenario_account(p)]
    linked = [h for h in smb_scen if evals[h.hop_id].after_bridge]
    linked_plain = [h for h in smb_scen if evals[h.hop_id].after]
    changed = [h.hop_id for h in hops if len(evals[h.hop_id].after) != len(evals[h.hop_id].after_bridge)]
    expected = p.expectation_for(ctx.scenario).smb_hops
    status = (OK if len(linked) >= expected else PROBLEM) if expected else INFO
    summary = (f"{len(hops)} hop instances ({len(smb_scen)} SMB with scenario account); "
               f"{len(linked)} SMB scenario hops with ≥1 account-consistent session incl. 4648 bridge "
               f"({len(linked_plain)} without; expected {expected}); per hop before/after/bridge: "
               + "; ".join(f"{h.hop_id} {h.account_name}@{h.target_host} "
                           f"{len(evals[h.hop_id].sessions)}/{len(evals[h.hop_id].after)}/"
                           f"{len(evals[h.hop_id].after_bridge)}"
                           for h in hops if h.is_scenario_account(p)))
    status, summary = gated_status(ctx, status, summary)
    return CheckResult(
        "LC-04", "SMB source session by command-line target (decision 011)", status, summary,
        "Source session for SMB hops (IdentityCoherence needs it). >1 session after the account "
        "filter means the join is ambiguous for that hop (decision 011 kill criterion).",
        {"hop_instances": len(hops), "excluded_4624": excluded,
         "params": {"CMD_BEFORE_S": p.cmd_before_s, "CMD_AFTER_S": p.cmd_after_s,
                    "HOP_GROUP_S": p.hop_group_s},
         "smb_scenario_hops": len(smb_scen), "smb_scenario_hops_linked": len(linked),
         "smb_scenario_hops_linked_without_bridge": len(linked_plain),
         "hops_changed_by_4648_bridge": changed,
         "expected_smb_hops": expected, "hops": details}), evals


def run_lc04d(ctx: Context, hops: list[HopInstance], by_host: dict, logon_index: dict) -> CheckResult:
    """LC-04d: after-filter session counts over the CMD_BEFORE_S × CMD_AFTER_S grid."""
    p = ctx.params
    grid = []
    changed = 0
    for h in hops:
        cells = {f"before{int(b)}_after{int(a)}":
                 len(evaluate_hop(h, by_host, logon_index, p, b, a).after)
                 for b in p.cmd_before_grid for a in p.cmd_after_grid}
        changed += int(len(set(cells.values())) > 1)
        grid.append({"hop_id": h.hop_id, "protocol": h.protocol, "account_name": h.account_name,
                     "target_host": h.target_host, "sessions_after_account": cells})
    ctx.db.share("LC-04d", "LC-04")
    status, summary = gated_status(ctx, INFO, f"{changed}/{len(hops)} hop instances change their "
                                              f"after-filter count over the grid")
    return CheckResult("LC-04d", "LC-04 sensitivity (CMD_BEFORE_S × CMD_AFTER_S)", status, summary,
                       "Shows whether the ±window choice drives the candidate count.",
                       {"grid_before": list(p.cmd_before_grid), "grid_after": list(p.cmd_after_grid),
                        "hops": grid})


# --- LC-04b ------------------------------------------------------------------------------

SYSMON3_SMB_SQL = """
    SELECT event_uid, host, event_utc, image, source_ip, source_port, destination_ip,
           destination_port, initiated, process_guid
    FROM events_dedup
    WHERE channel = 'Sysmon' AND event_id = 3 AND destination_port = 445
      AND (image = 'System' OR lower(image) LIKE '%\\system')
      AND event_utc >= ? AND event_utc <= ?
"""


def run_lc04b(ctx: Context) -> CheckResult:
    """LC-04b: legacy Correction I join for SMB (expected 0 rows per decision 011)."""
    w, p = ctx.window, ctx.params
    lo, hi = w.start - seconds(p.port_join_s), w.end + seconds(p.port_join_s)
    conns = with_time(ctx.db.query("LC-04b", SYSMON3_SMB_SQL, (to_db(lo), to_db(hi))))
    logons = load_remote_4624(ctx, "LC-04b")
    pairs = port_join(conns, logons, p, p.port_join_s)
    rows = [{"sysmon3_event_uid": x["conn"]["event_uid"], "source_host": x["conn"]["host"],
             "target_host": x["logon"]["host"], "account_name": x["logon"].get("account_name"),
             "source_port": x["conn"].get("source_port"), "time_delta_ms": x["time_delta_ms"],
             "target_event_uid": x["logon"]["event_uid"]} for x in pairs]
    return CheckResult("LC-04b", "Legacy SMB port join (Sysmon 3 System → 445)", INFO,
                       f"{len(conns)} Sysmon 3 System→445 rows, {len(rows)} joined (expected 0)",
                       "Decision 011: the Sysmon config never logged SMB; 0 confirms the port join "
                       "cannot be used for SMB.", {"sysmon3_rows": len(conns), "joined": rows})


# --- LC-04c ------------------------------------------------------------------------------

SHARES_SQL = """
    SELECT event_uid, host, event_id, event_utc, session_id, share_name,
           relative_target_name, account_name, source_ip
    FROM events_dedup
    WHERE channel = 'Security' AND event_id IN (5140, 5145)
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY host, event_utc, event_uid
"""
SERVICES_SQL = """
    SELECT event_uid, host, channel, event_id, event_utc, service_name, service_image_path,
           account_name, subject_logon_id
    FROM events_dedup
    WHERE ((channel = 'System' AND event_id = 7045) OR (channel = 'Security' AND event_id = 4697))
      AND event_utc >= ? AND event_utc <= ?
    ORDER BY host, event_utc, event_uid
"""


def load_shares(ctx: Context) -> list[dict[str, Any]]:
    """5140/5145 in the window on all hosts (filtered to hop sessions by the caller)."""
    return with_time(ctx.db.query("LC-04c", SHARES_SQL, (ctx.window.start_db, ctx.window.end_db)))


def shares_by_hop(hops: list[HopInstance], shares: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Same-host share events whose session_id is one of the hop's 4624 logon ids."""
    index: dict[tuple[str, int], str] = {}
    for h in hops:
        for lid in h.target_logon_ids:
            index[(h.target_host, lid)] = h.hop_id
    out: dict[str, list[dict]] = defaultdict(list)
    for s in shares:
        if s.get("session_id") is None:
            continue
        hop_id = index.get((s["host"], int(s["session_id"])))
        if hop_id:
            out[hop_id].append(s)
    return out


def dedup_services(rows: list[dict[str, Any]], tol_s: float) -> list[dict[str, Any]]:
    """4697 and 7045 for one service count once: same host, service name, |Δt| ≤ tol_s."""
    services: list[dict[str, Any]] = []
    for r in sorted(rows, key=lambda r: (r["t"], r["event_uid"])):
        name = (r.get("service_name") or "").lower()
        match = next((s for s in services if s["host"] == r["host"] and s["name_key"] == name
                      and abs((r["t"] - s["t"]).total_seconds()) <= tol_s), None)
        if match is None:
            match = {"host": r["host"], "name_key": name, "service_name": r.get("service_name"),
                     "t": r["t"], "image_path": None, "event_ids": [], "event_uids": [],
                     "subject_logon_ids": []}
            services.append(match)
        match["event_ids"].append(r["event_id"])
        match["event_uids"].append(r["event_uid"])
        if r.get("service_image_path") and (match["image_path"] is None or r["event_id"] == 7045):
            match["image_path"] = r["service_image_path"]
        if r["event_id"] == 4697 and r.get("subject_logon_id") is not None:
            match["subject_logon_ids"].append(int(r["subject_logon_id"]))
    return services


def is_system_binary(path: str | None) -> bool:
    """Built-in service binaries (system32/SysWOW64/svchost) can never be an ADMIN$ upload."""
    low = normalise_image_path(path).lower()
    return "\\system32\\" in low or "\\syswow64\\" in low or low.endswith("svchost.exe")


def admin_write_sessions(service: dict[str, Any], shares: list[dict[str, Any]]) -> list[int]:
    """Sessions whose ADMIN$ 5145 relative_target_name ends with the service binary file name."""
    file_name = base_name(normalise_image_path(service["image_path"]))
    if not file_name:
        return []
    found: set[int] = set()
    for s in shares:
        if s["event_id"] != 5145 or s["host"] != service["host"] or s.get("session_id") is None:
            continue
        if not (s.get("share_name") or "").upper().endswith("ADMIN$"):
            continue
        rel = (s.get("relative_target_name") or "").lower().replace("/", "\\")
        if rel == file_name or rel.endswith("\\" + file_name):
            found.add(int(s["session_id"]))
    return sorted(found)


def load_services(ctx: Context) -> list[dict[str, Any]]:
    """7045/4697 in the window on endpoint hosts, one entry per service (4697+7045 deduped)."""
    raw = with_time(ctx.db.query("LC-04c", SERVICES_SQL, (ctx.window.start_db, ctx.window.end_db)))
    return dedup_services([r for r in raw if r["host"] in ctx.params.endpoint_hosts],
                          ctx.params.service_dedup_s)


def service_subject_hops(services: list[dict[str, Any]], hops: list[HopInstance]) -> set[str]:
    """Hops whose logon session installed a service (4697 SubjectLogonId = a hop logon id)."""
    session_to_hop = {(h.target_host, lid): h.hop_id for h in hops for lid in h.target_logon_ids}
    return {session_to_hop[(s["host"], lid)] for s in services for lid in s["subject_logon_ids"]
            if (s["host"], lid) in session_to_hop}


def run_lc04c(ctx: Context, hops: list[HopInstance], shares: list[dict[str, Any]],
              by_hop: dict[str, list[dict]], services: list[dict[str, Any]]) -> CheckResult:
    """LC-04c: target-side SMB evidence (shares per hop, service ↔ ADMIN$ session, port 0)."""
    p = ctx.params
    session_to_hop = {(h.target_host, lid): h.hop_id for h in hops for lid in h.target_logon_ids}
    svc_rows, buckets = [], Counter()
    for s in services:
        sessions = admin_write_sessions(s, shares)
        bucket = "one" if len(sessions) == 1 else ("several" if sessions else "none")
        system = is_system_binary(s["image_path"])
        buckets[f"{'system' if system else 'non_system'}_{bucket}"] += 1
        svc_rows.append({"host": s["host"], "service_name": s["service_name"],
                         "time": to_display(s["t"]), "image_path": s["image_path"],
                         "system_binary": system, "event_ids": s["event_ids"],
                         "event_uids": s["event_uids"], "match": bucket,
                         "admin_write_sessions": [hex_id(x) for x in sessions],
                         "hops": sorted({session_to_hop.get((s["host"], x)) or "?" for x in sessions}),
                         "subject_logon_ids_4697": [hex_id(x) for x in s["subject_logon_ids"]],
                         "subject_hops_4697": sorted({session_to_hop.get((s["host"], x)) or "?"
                                                      for x in s["subject_logon_ids"]})})
    per_hop = []
    for h in hops:
        rows = by_hop.get(h.hop_id, [])
        per_hop.append({"hop_id": h.hop_id, "protocol": h.protocol, "account_name": h.account_name,
                        "target_host": h.target_host, "n_5140": sum(r["event_id"] == 5140 for r in rows),
                        "n_5145": sum(r["event_id"] == 5145 for r in rows),
                        "shares": sorted({r.get("share_name") or "" for r in rows}),
                        "services_by_4697_subject": sorted({s["service_name"] or "" for s in services
                                                            if s["host"] == h.target_host and
                                                            set(s["subject_logon_ids"]) & h.target_logon_ids}),
                        "admin_files": sorted({r.get("relative_target_name") or "" for r in rows
                                               if (r.get("share_name") or "").upper().endswith("ADMIN$")
                                               and r["event_id"] == 5145})})
    smb = [h for h in hops if h.protocol == "SMB"]
    port0 = sum(1 for h in smb if not h.source_port)
    scen_with_shares = [h for h in hops if h.is_scenario_account(p) and by_hop.get(h.hop_id)]
    expected = p.expectation_for(ctx.scenario).smb_hops
    status = (OK if len(scen_with_shares) >= expected else PROBLEM) if expected else INFO
    non_sys = [r for r in svc_rows if not r["system_binary"]]
    summary = (f"{len(scen_with_shares)} scenario hops with 5140/5145; non-system services "
               f"{len(non_sys)}: one={buckets['non_system_one']} several={buckets['non_system_several']} "
               f"none={buckets['non_system_none']}; SMB hops with port 0: {port0}/{len(smb)}")
    return CheckResult("LC-04c", "Target-side SMB evidence (5140/5145, service ↔ ADMIN$ session)", status,
                       summary, "Ties services and share writes to the hop's target session; a "
                       "service matching exactly one session gives a target-side anchor for the hop.",
                       {"services": svc_rows, "service_match_counts": dict(buckets),
                        "hops": per_hop, "smb_hops": len(smb), "smb_hops_port0": port0,
                        "smb_hops_port0_share": round(port0 / len(smb), 3) if smb else None,
                        "share_events_in_window": len(shares)})
