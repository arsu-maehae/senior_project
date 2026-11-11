"""Design hops: find each designed move's command, target logon and target-side steps (criterion b).

WHY: decision 029 says a design step is present only if its events are found in the trial window.
Each hop keeps the evidence it used (event_uids, binding method, time delta) so every PASS/FAIL can
be traced to rows (CLAUDE.md code rules).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .agent import Execution
from .db import iso
from .design import HopDesign, ScenarioDesign, hop_groups
from .events import file_name_of, in_range, is_write, logons_to, service_names_of
from .params import CMD_AFTER_S, CMD_BEFORE_S, HOST_IP
from .textmatch import norm_account


@dataclass
class TrialEvents:
    """Window-restricted event extracts the hop search works on."""
    logons: list[Mapping]            # remote endpoint 4624s
    smb_binaries: list[Mapping]      # 5145 ADMIN$ binary access
    services: list[Mapping]          # 7045 / 4697 with C:\Windows\*.exe
    winrm91: list[Mapping]
    wsmprov: list[Mapping]
    session_src: dict[tuple[str, int], str | None] = field(default_factory=dict)   # (host, logon id) -> 4624 source IP


@dataclass
class HopCandidate:
    """Intermediate result for one hop before conflicts with other hops are resolved."""
    design: HopDesign
    execution: Execution | None
    lo: float
    hi: float
    logons: list[Mapping] = field(default_factory=list)
    writes: list[Mapping] = field(default_factory=list)
    services: list[Mapping] = field(default_factory=list)
    winrm: list[Mapping] = field(default_factory=list)
    wsm: list[Mapping] = field(default_factory=list)


def assign_executions(design: ScenarioDesign, executions: Sequence[Execution]) -> tuple[dict[str, Execution | None], dict[tuple, list[Execution]]]:
    """Assign candidate executions to hops in time order; return (hop -> execution, group -> all candidates).

    A candidate is an execution of the hop's lane on its source host naming its target with the
    hop's protocol and a user token (self-targets and SYSTEM runs never qualify; they are counted
    under h instead).
    """
    assigned: dict[str, Execution | None] = {}
    by_group: dict[tuple, list[Execution]] = {}
    for key, hops in hop_groups(design).items():
        src, tgt, proto, lane = key
        cands = [e for e in executions if e.lane == lane and e.host == src and e.target == tgt
                 and proto in e.protocols and e.user_token]
        cands.sort(key=lambda e: e.ts_first)
        by_group[key] = cands
        for i, hop in enumerate(hops):
            assigned[hop.hop_id] = cands[i] if i < len(cands) else None
    return assigned, by_group


def command_window(ex: Execution, group: Sequence[Execution]) -> tuple[float, float]:
    """[first command - 10 s, last command + 120 s], capped at the next execution of the same group."""
    lo, hi = ex.ts_first - CMD_BEFORE_S, ex.ts_last + CMD_AFTER_S
    later = [e.ts_first for e in group if e.ts_first > ex.ts_first]
    if later:
        hi = min(hi, max(ex.ts_last, min(later) - CMD_BEFORE_S))
    return lo, hi


def _candidate(hop: HopDesign, ex: Execution | None, lo: float, hi: float, ev: TrialEvents) -> HopCandidate:
    ip = HOST_IP[hop.source]
    c = HopCandidate(hop, ex, lo, hi)
    c.logons = logons_to(ev.logons, hop.target, hop.source, lo, hi)
    c.writes = [r for r in ev.smb_binaries if r["host"] == hop.target and r["source_ip"] == ip and in_range(r["ts"], lo, hi)]
    c.services = [r for r in ev.services if r["host"] == hop.target and in_range(r["ts"], lo, hi)]
    c.winrm = [r for r in ev.winrm91 if r["host"] == hop.target and in_range(r["ts"], lo, hi) and r["client_ip"] == ip]
    c.wsm = [r for r in ev.wsmprov if r["host"] == hop.target and in_range(r["ts"], lo, hi)
             and ev.session_src.get((hop.target, r["session_id"])) == ip]
    return c


def _names_of_artefact(r: Mapping) -> set[str]:
    return service_names_of(r) if r["event_id"] in (7045, 4697) else {file_name_of(r)}


def _prefer_named(rows: Sequence[Mapping], own: set[str], others: set[str]) -> tuple[list[Mapping], bool]:
    """Artefacts named in the hop's own command if any; else those not named by another hop's command."""
    named = [r for r in rows if _names_of_artefact(r) & own]
    if named:
        return named, True
    return [r for r in rows if not (_names_of_artefact(r) & others)], False


def _step(present: bool, rows: Sequence[Mapping], **extra) -> dict:
    return {"present": present, "count": len(rows), "event_uids": [r["event_uid"] for r in rows][:20],
            "first_utc": iso(min((r["ts"] for r in rows), default=None)), **extra}


def resolve_hop(c: HopCandidate, other_names: set[str], claimed_logon_ids: set[int]) -> dict:
    """Final evidence and step presence for one hop (binding by artefact logon id, else time window)."""
    own = c.execution.names if c.execution else set()
    writes, w_named = _prefer_named(c.writes, own, other_names)
    services_named, s_named = _prefer_named(c.services, own, other_names)
    bind_ids = {r["subject_logon_id"] for r in writes if r["subject_logon_id"]} if w_named else set()
    if s_named:
        bind_ids |= {r["subject_logon_id"] for r in services_named if r["event_id"] == 4697 and r["subject_logon_id"]}
    winrm_hop = c.design.protocol == "WinRM"
    if winrm_hop:
        bind_ids |= {r["session_id"] for r in c.wsm if r["session_id"]}
    content = w_named or s_named or (winrm_hop and bool(c.wsm))
    bound = [r for r in c.logons if r["target_logon_id"] in bind_ids] if content else []
    if c.execution is None:
        binding = "no_command"
        logons = [r for r in c.logons if r["target_logon_id"] not in claimed_logon_ids]
    elif bound:
        binding, logons = "logon_id_artifact", bound
    else:
        logons = [r for r in c.logons if r["target_logon_id"] not in claimed_logon_ids]
        binding = "time_window" if logons else "none"
    first_logon = min((r["ts"] for r in logons), default=None)
    svc = [r for r in services_named if first_logon is not None and r["ts"] >= first_logon]
    real_writes = [r for r in writes if is_write(r) is not False]
    steps = {
        "command": {"present": c.execution is not None, "count": len(c.execution.procs) if c.execution else 0,
                    "event_uids": c.execution.event_uids[:20] if c.execution else [],
                    "first_utc": iso(c.execution.ts_first) if c.execution else None},
        "logon": _step(bool(logons), logons, accounts=sorted({norm_account(r["account_name"]) for r in logons})),
        "binary_write": _step(bool(real_writes), real_writes, name_matched=w_named,
                              files=sorted({file_name_of(r) for r in real_writes}),
                              mask_missing=sum(1 for r in real_writes if is_write(r) is None),
                              logon_tied=sum(1 for r in real_writes if r["subject_logon_id"] in {l["target_logon_id"] for l in logons})),
        "service": _step(bool(svc), svc, name_matched=s_named,
                         names=sorted({(r["service_name"] or "").strip() for r in svc if r["service_name"]}),
                         images=sorted({r["service_image_path"] for r in svc})),
        "winrm": _step(bool(c.winrm or c.wsm), c.winrm + c.wsm, winrm91=len(c.winrm), wsmprovhost=len(c.wsm),
                       winrm91_accounts=sorted({r["client_account"] for r in c.winrm if r["client_account"]})),
    }
    required = {k: steps[k] for k in c.design.steps}
    accounts = {norm_account(r["account_name"]) for r in logons}
    accounts |= {norm_account(r["account_name"]) for r in real_writes}
    accounts |= {norm_account(r["account_name"]) for r in svc if r["event_id"] == 4697}
    ex = c.execution
    return {
        "hop_id": c.design.hop_id, "protocol": c.design.protocol, "source": c.design.source, "target": c.design.target,
        "lane": c.design.lane, "intended_account": c.design.intended_account, "note": c.design.note,
        "binding": binding, "search_window": [iso(c.lo), iso(c.hi)],
        "execution": None if ex is None else {
            "first_utc": iso(ex.ts_first), "last_utc": iso(ex.ts_last), "account": ex.account,
            "protocols": sorted(ex.protocols), "payload_names": sorted(ex.names),
            "credential_accounts": sorted(ex.credential_accounts), "session_ids": sorted(ex.session_ids),
            "root_link": ex.procs[0].root_link, "process_chain": ex.procs[0].chain,
            "decode_failed": any(p.decode_failed for p in ex.procs), "event_uids": ex.event_uids[:20]},
        "steps": required,
        "missing_steps": [k for k, v in required.items() if not v["present"]],
        "hop_accounts": sorted(a for a in accounts if a),
        "time_delta_ms": None if (ex is None or first_logon is None) else round((first_logon - ex.ts_first) * 1000),
        "_first_logon_ts": first_logon, "_exec_ts": ex.ts_first if ex else None,
        "_last_logon_ts": max((r["ts"] for r in logons), default=None),
        "_logon_ids": sorted({r["target_logon_id"] for r in logons if r["target_logon_id"]}),
    }


def evaluate_hops(design: ScenarioDesign, executions: Sequence[Execution], ev: TrialEvents,
                  window: tuple[float, float]) -> tuple[list[dict], dict[tuple, list[Execution]], dict[str, Execution | None]]:
    """All design hops of a scenario: assigned execution, steps found, missing steps."""
    assigned, groups = assign_executions(design, executions)
    cands: list[HopCandidate] = []
    for hop in design.hops:
        ex = assigned[hop.hop_id]
        key = (hop.source, hop.target, hop.protocol, hop.lane)
        lo, hi = command_window(ex, groups[key]) if ex else window
        cands.append(_candidate(hop, ex, lo, hi, ev))
    others = [set().union(*(o.execution.names for j, o in enumerate(cands) if j != i and o.execution))
              for i in range(len(cands))]
    # phase 1: bind by content; phase 2: hops without an artefact binding skip logons bound to another hop
    first = [resolve_hop(c, others[i], set()) for i, c in enumerate(cands)]
    art = {i: set(r["_logon_ids"]) for i, r in enumerate(first) if r["binding"] == "logon_id_artifact"}
    results: list[dict] = []
    for i, c in enumerate(cands):
        if i in art:
            results.append(first[i])
            continue
        claimed = set().union(*(ids for j, ids in art.items() if j != i))
        results.append(resolve_hop(c, others[i], claimed))
    return results, groups, assigned
