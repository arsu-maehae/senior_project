"""Caldera agent process tree from Sysmon 1 (AK-01).

WHY: with the Caldera operation logs lost (decision 020), the record of what the
agent executed is the process tree under ``splunkd.exe``. Only Sysmon 1 has a
ProcessGuid chain, so only Sysmon 1 can *confirm*; Security 4688 corroborates by
command text and PowerShell 4104 never confirms (no parent chain).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

AGENT_IMAGE_SUFFIX = "splunkd.exe"
CALDERA_PORT = 8888


@dataclass(frozen=True)
class AgentProc:
    """One Sysmon 1 process inside the agent tree."""
    event_uid: str
    host: str
    time_utc: str
    account: str
    process_guid: str
    parent_process_guid: str
    process_id: int | None
    image: str
    command_line: str          # FULL command line (never truncated)
    depth: int                 # 1 = direct child of splunkd.exe
    root_guid: str             # guid of the splunkd child this process descends from
    root_link: str = "sysmon_parent_image"   # how the root was tied to splunkd.exe
    corroborating_4688: tuple[str, ...] = field(default=())


def is_splunkd(path: str | None) -> bool:
    """True when an image path ends in splunkd.exe (case-insensitive)."""
    return bool(path) and path.lower().replace("/", "\\").endswith("\\" + AGENT_IMAGE_SUFFIX)


def run_day(rows: Sequence[Mapping]) -> str | None:
    """Trial run day = latest date on which a splunkd child was started (Sysmon 1).

    WHY: the DBs also carry older host logs (ep-03 splunkd from September, ep-02
    pivot start); the trial is the most recent agent activity in the DB.
    """
    days = [r["t_utc"][:10] for r in rows
            if r["event_id"] == 1 and r["channel"] == "Sysmon" and is_splunkd(r["parent_image"]) and r["t_utc"]]
    return max(days) if days else None


def _unresolved(path: str | None) -> bool:
    """Sysmon writes ``-`` / NULL when it could not resolve the parent process."""
    return path in (None, "", "-")


def _splunkd_4688_roots(rows: Sequence[Mapping], tol_s: float = 3.0) -> set[str]:
    """Sysmon 1 uids whose parent Sysmon could not resolve but whose Security 4688
    (same host, new PID and command text, within ``tol_s``) names splunkd.exe as parent.

    WHY: in s02 the attack ``powershell.exe`` on ep-01 has ParentImage ``-`` and a zero
    ParentProcessGuid in Sysmon 1 while 4688 shows parent splunkd.exe (PID 7332). Sysmon
    still supplies the process chain below it, so 4688 is used only to tie the *root*.
    """
    from .timeutil import parse_utc
    idx: dict[tuple[str, int, str], list] = {}
    for r in rows:
        if r["event_id"] == 4688 and r["channel"] == "Security" and is_splunkd(r["parent_image"]) and r["command_line"]:
            idx.setdefault((r["host"], r["process_id"], r["command_line"]), []).append(parse_utc(r["t_utc"]))
    out: set[str] = set()
    for r in rows:
        if (r["event_id"] == 1 and r["channel"] == "Sysmon" and _unresolved(r["parent_image"])
                and r["command_line"]):
            t0 = parse_utc(r["t_utc"])
            for t in idx.get((r["host"], r["process_id"], r["command_line"]), []):
                if abs((t - t0).total_seconds()) <= tol_s:
                    out.add(r["event_uid"])
                    break
    return out


def build_tree(rows: Sequence[Mapping], day: str | None) -> list[AgentProc]:
    """All Sysmon 1 descendants of splunkd.exe at any depth, restricted to ``day``.

    Roots are Sysmon 1 rows whose ParentImage is splunkd.exe, or (``root_link =
    pid_match_4688``) whose parent Sysmon left unresolved and 4688 names splunkd.exe.
    The walk follows ``parent_process_guid`` so ``cmd /c`` wrappers and powershell
    grandchildren are found (attacker case AKT-16). Only rows of the run day are used.
    """
    sysmon1 = [r for r in rows
               if r["event_id"] == 1 and r["channel"] == "Sysmon" and r["process_guid"]
               and day is not None and (r["t_utc"] or "")[:10] == day]
    by_parent: dict[str, list[Mapping]] = {}
    for r in sysmon1:
        by_parent.setdefault((r["parent_process_guid"] or "").lower(), []).append(r)
    via_4688 = _splunkd_4688_roots(rows)
    roots = [(r, "sysmon_parent_image") for r in sysmon1 if is_splunkd(r["parent_image"])]
    roots += [(r, "pid_match_4688") for r in sysmon1 if r["event_uid"] in via_4688]
    out: list[AgentProc] = []
    seen: set[str] = set()
    for root, link in roots:
        stack = [(root, 1, root["process_guid"])]
        while stack:
            r, depth, root_guid = stack.pop()
            if r["event_uid"] in seen:
                continue
            seen.add(r["event_uid"])
            out.append(AgentProc(r["event_uid"], r["host"], r["t_utc"], (r["account_name"] or "").lower(),
                                 r["process_guid"], r["parent_process_guid"] or "", r["process_id"], r["image"] or "",
                                 r["command_line"] or "", depth, root_guid, link))
            for child in by_parent.get((r["process_guid"] or "").lower(), []):
                stack.append((child, depth + 1, root_guid))
    out.sort(key=lambda p: (p.time_utc, p.host))
    return out


def attach_4688(procs: Sequence[AgentProc], rows: Sequence[Mapping], tol_s: float = 3.0) -> list[AgentProc]:
    """Add Security 4688 uids with the same host and command text (corroboration only)."""
    from .timeutil import parse_utc
    s4688 = [r for r in rows if r["event_id"] == 4688 and r["channel"] == "Security" and r["command_line"]]
    out: list[AgentProc] = []
    for p in procs:
        t0 = parse_utc(p.time_utc)
        uids = tuple(r["event_uid"] for r in s4688
                     if r["host"] == p.host and r["command_line"] == p.command_line and r["process_id"] == p.process_id
                     and abs((parse_utc(r["t_utc"]) - t0).total_seconds()) <= tol_s)
        out.append(AgentProc(**{**p.__dict__, "corroborating_4688": uids}))
    return out


def agent_network(rows: Sequence[Mapping], day: str | None) -> dict:
    """Server ip/port evidence: splunkd Sysmon 3 on the run day, excluding mDNS 5353."""
    hits = [r for r in rows
            if r["event_id"] == 3 and r["channel"] == "Sysmon" and is_splunkd(r["image"])
            and (r["t_utc"] or "")[:10] == day and r["destination_port"] != 5353]
    dests = sorted({(r["destination_ip"], r["destination_port"]) for r in hits}, key=str)
    return {"connections": [{"ip": ip, "port": port} for ip, port in dests],
            "server_confirmed": all(p == CALDERA_PORT for _, p in dests) and bool(dests),
            "event_uids": [r["event_uid"] for r in hits][:20],
            "hosts": sorted({r["host"] for r in hits})}
