"""Agent process tree, manual commands, and their grouping into executions.

WHY: decision 029 counts a Caldera command step only when a command with ``splunkd.exe`` ancestry
on the source host names the target, and S04 Track A only when a command WITHOUT that ancestry,
in a logon session on ep-01, names it (decision 021). Criterion h then counts executions, so the
processes of one Caldera link (powershell -> net.exe, sc.exe) must be counted once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .events import is_agent_image, is_user
from .params import MANUAL_GAP_S, PID_TIE_S
from .textmatch import credential_accounts, decode_enc, named_hosts, norm_account, payload_names, protocols


@dataclass
class Proc:
    """One process start (Sysmon 1, or 4688 when the host has no Sysmon 1) with its matching text."""
    event_uid: str
    host: str
    ts: float
    account: str
    image: str
    command_line: str
    text: str                       # command line + decoded -enc (matching only)
    decode_failed: bool
    session_id: int | None
    process_guid: str
    root_key: str                   # guid (or 4688 uid) of the direct splunkd child it descends from; "" if manual
    root_link: str                  # sysmon_parent_image | pid_match_4688 | 4688_pid_chain | manual
    corroborating_4688: list[str] = field(default_factory=list)
    chain: list[str] = field(default_factory=list)   # ancestor images, nearest first (manual evidence)


def _unresolved(path: str | None) -> bool:
    return path in (None, "", "-")


def _proc(r: Mapping, root_key: str, link: str) -> Proc:
    text, failed = decode_enc(r["command_line"])
    sess = r["session_id"] if r["channel"] == "Sysmon" else r["subject_logon_id"]
    return Proc(r["event_uid"], r["host"], r["ts"], norm_account(r["account_name"]), r["image"] or "",
                r["command_line"] or "", text, failed, sess, (r["process_guid"] or "").lower(), root_key, link)


def _pid_tied_roots(sysmon1: Sequence[Mapping], s4688: Sequence[Mapping]) -> set[str]:
    """Sysmon 1 uids with ParentImage '-' whose 4688 (same host, PID, command line, <= 3 s) has parent splunkd."""
    idx: dict[tuple, list[float]] = {}
    for r in s4688:
        if is_agent_image(r["parent_image"]) and r["command_line"]:
            idx.setdefault((r["host"], r["process_id"], r["command_line"]), []).append(r["ts"])
    return {r["event_uid"] for r in sysmon1
            if _unresolved(r["parent_image"]) and r["command_line"]
            and any(abs(t - r["ts"]) <= PID_TIE_S for t in idx.get((r["host"], r["process_id"], r["command_line"]), []))}


def sysmon_tree(rows: Sequence[Mapping]) -> list[Proc]:
    """Every Sysmon 1 descendant of splunkd.exe (any depth, any date) with its root and root link."""
    sysmon1 = [r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1 and r["process_guid"]]
    s4688 = [r for r in rows if r["channel"] == "Security" and r["event_id"] == 4688]
    tied = _pid_tied_roots(sysmon1, s4688)
    by_parent: dict[str, list[Mapping]] = {}
    for r in sysmon1:
        by_parent.setdefault((r["parent_process_guid"] or "").lower(), []).append(r)
    roots = [(r, "sysmon_parent_image") for r in sysmon1 if is_agent_image(r["parent_image"])]
    roots += [(r, "pid_match_4688") for r in sysmon1 if r["event_uid"] in tied]
    out: list[Proc] = []
    seen: set[str] = set()
    for root, link in roots:
        key = root["process_guid"].lower()
        stack = [root]
        while stack:
            r = stack.pop()
            if r["event_uid"] in seen:
                continue
            seen.add(r["event_uid"])
            out.append(_proc(r, key, link))
            stack.extend(by_parent.get((r["process_guid"] or "").lower(), []))
    return sorted(out, key=lambda p: p.ts)


def tree_4688(rows: Sequence[Mapping], hosts: set[str]) -> list[Proc]:
    """Fallback tree from 4688 parent PIDs, only for ``hosts`` that have no Sysmon 1 in the run.

    WHY: a missing Sysmon log is a WARN under a, not a missing design step; 4688 still carries the
    parent image and PID. PID reuse is limited by requiring the child within 600 s of its parent.
    """
    s4688 = sorted((r for r in rows if r["channel"] == "Security" and r["event_id"] == 4688 and r["host"] in hosts),
                   key=lambda r: r["ts"])
    out: list[Proc] = []
    live: dict[tuple[str, int], tuple[str, float]] = {}       # (host, pid) -> (root key, start ts)
    for r in s4688:
        root = None
        if is_agent_image(r["parent_image"]):
            root = r["event_uid"]
        else:
            parent = live.get((r["host"], r["parent_process_id"]))
            if parent and 0 <= r["ts"] - parent[1] <= 600:
                root = parent[0]
        if root is None:
            continue
        live[(r["host"], r["process_id"])] = (root, r["ts"])
        out.append(_proc(r, root, "4688_pid_chain"))
    return out


def attach_4688(procs: Sequence[Proc], rows: Sequence[Mapping]) -> None:
    """Record 4688 uids with the same host, PID and command line within 3 s (corroboration only)."""
    idx: dict[tuple, list[Mapping]] = {}
    for r in rows:
        if r["channel"] == "Security" and r["event_id"] == 4688 and r["command_line"]:
            idx.setdefault((r["host"], r["command_line"]), []).append(r)
    pid_of = {r["event_uid"]: r["process_id"] for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1}
    for p in procs:
        if p.root_link == "4688_pid_chain":
            continue
        pid = pid_of.get(p.event_uid)
        p.corroborating_4688 = [r["event_uid"] for r in idx.get((p.host, p.command_line), [])
                                if r["process_id"] == pid and abs(r["ts"] - p.ts) <= PID_TIE_S]


def _ancestor_chain(r: Mapping, by_guid: Mapping[str, Mapping], depth: int = 6) -> list[str]:
    chain: list[str] = []
    cur = r
    for _ in range(depth):
        parent = by_guid.get((cur["parent_process_guid"] or "").lower())
        if parent is None:
            if cur["parent_image"]:
                chain.append(cur["parent_image"].split("\\")[-1].lower())
            break
        chain.append((parent["image"] or "").split("\\")[-1].lower())
        cur = parent
    return chain


def manual_procs(rows: Sequence[Mapping], tree_uids: set[str], lo: float, hi: float) -> list[Proc]:
    """Sysmon 1 in [lo, hi] that are NOT in the agent tree, by a user token, naming some endpoint.

    WHY: decision 021 basis ``manual_command_names_target`` (S04 Track A). The ancestor images are
    kept so the owner can see the interactive chain (explorer.exe -> powershell.exe -> net.exe).
    """
    sysmon1 = [r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1 and r["process_guid"]]
    by_guid = {r["process_guid"].lower(): r for r in sysmon1}
    out: list[Proc] = []
    for r in sysmon1:
        if r["event_uid"] in tree_uids or not (lo <= r["ts"] <= hi) or not is_user(r["account_name"]):
            continue
        p = _proc(r, "", "manual")
        if not named_hosts(p.text):
            continue
        chain = _ancestor_chain(r, by_guid)
        if any(is_agent_image(c) or c == "splunkd.exe" for c in chain):
            continue
        p.chain = chain
        out.append(p)
    return sorted(out, key=lambda p: p.ts)


# ----------------------------------------------------------------------------- executions

@dataclass
class Execution:
    """One run of a command step: the processes of one Caldera link (or one manual burst) naming a target."""
    lane: str                       # agent | manual
    host: str
    target: str
    ts_first: float
    ts_last: float
    account: str
    protocols: set[str]
    names: set[str]                 # payload binary / service names in its command lines
    credential_accounts: set[str]
    session_ids: set[int]
    procs: list[Proc]

    @property
    def event_uids(self) -> list[str]:
        """Sysmon 1 (or 4688) uids of the processes, then their corroborating 4688 uids."""
        uids = [p.event_uid for p in self.procs]
        return uids + [u for p in self.procs for u in p.corroborating_4688]

    @property
    def self_target(self) -> bool:
        """A command naming its own host (S02 t00 stray ep-02 run) is never a cross-host move."""
        return self.host == self.target

    @property
    def user_token(self) -> bool:
        return is_user(self.account)


def _execution(lane: str, target: str, procs: list[Proc], account: str) -> Execution:
    return Execution(lane, procs[0].host, target, min(p.ts for p in procs), max(p.ts for p in procs), account,
                     set().union(*(protocols(p.text, target) for p in procs)),
                     set().union(*(payload_names(p.text) for p in procs)),
                     set().union(*(credential_accounts(p.text) for p in procs)),
                     {p.session_id for p in procs if p.session_id is not None}, procs)


def agent_executions(tree: Sequence[Proc]) -> list[Execution]:
    """Group agent-tree processes naming an endpoint by (root splunkd child, named endpoint).

    The execution's account is the account of its earliest process (the agent's user token).
    """
    groups: dict[tuple[str, str], list[Proc]] = {}
    for p in tree:
        for target in named_hosts(p.text):
            groups.setdefault((p.root_key, target), []).append(p)
    out = [_execution("agent", target, sorted(ps, key=lambda p: p.ts), sorted(ps, key=lambda p: p.ts)[0].account)
           for (_, target), ps in groups.items()]
    return sorted(out, key=lambda e: e.ts_first)


def manual_executions(procs: Sequence[Proc]) -> list[Execution]:
    """Group manual processes per (host, session, named endpoint) with gaps <= ``MANUAL_GAP_S``."""
    groups: dict[tuple, list[Proc]] = {}
    for p in procs:
        for target in named_hosts(p.text):
            groups.setdefault((p.host, p.session_id, target), []).append(p)
    out: list[Execution] = []
    for (_, _, target), ps in groups.items():
        ps.sort(key=lambda p: p.ts)
        burst = [ps[0]]
        for p in ps[1:]:
            if p.ts - burst[-1].ts > MANUAL_GAP_S:
                out.append(_execution("manual", target, burst, burst[0].account))
                burst = []
            burst.append(p)
        out.append(_execution("manual", target, burst, burst[0].account))
    return sorted(out, key=lambda e: e.ts_first)
