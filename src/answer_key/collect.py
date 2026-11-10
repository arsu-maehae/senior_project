"""Target-side evidence for a command that names a target host (AK-02, AK-03).

For each candidate move the target host's remote logons from the source IP are grouped
into *bursts* (one account, gaps <= BURST_GAP_S). Artefacts tie to a burst by logon id
(5140/5145, 4697, wsmprovhost) or by name (7045 service / binary). Time and account only
choose among bursts that already match by name; every candidate is recorded and the first
candidate is never taken silently.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

from .targets import is_user_account, normalise_account

BURST_GAP_S = 10.0          # consecutive 4624s of one account within this gap are one move
CMD_BEFORE_LOGON_S = 10.0   # command lies in [t - 120, t + 10]  <=>  t in [c - 10, c + 120]
                            # (the upper end is cut at the next command naming the same target, see build.py)
CMD_AFTER_LOGON_S = 120.0
SERVICE_BEFORE_S = 10.0     # 7045 window around the burst anchor
SERVICE_AFTER_S = 120.0
WINRM_TOL_S = 5.0
REMOTE_TYPES = (3, 10)
SYSTEM_LOGON_IDS = {0x3E4, 0x3E5, 0x3E7}


@dataclass
class Index:
    """Rows grouped for the lookups below (built once per trial)."""
    by_key: dict[tuple[str, str, int], list[Mapping]] = field(default_factory=dict)
    by_logon: dict[tuple[str, int], list[Mapping]] = field(default_factory=dict)


def build_index(rows: Sequence[Mapping]) -> Index:
    """Group rows by (host, channel, event_id) and by (host, SubjectLogonId) for share/service events."""
    idx = Index()
    for r in rows:
        idx.by_key.setdefault((r["host"], r["channel"], r["event_id"]), []).append(r)
        if r["event_id"] in (5140, 5145, 4697) and r.get("subject_logon_id") is not None:
            idx.by_logon.setdefault((r["host"], r["subject_logon_id"]), []).append(r)
    return idx


LOOPBACK_OR_EMPTY = {"", "-", "::1", "127.0.0.1", "0.0.0.0"}


def remote_logons(idx: Index, target_host: str, ts_lo: float, ts_hi: float, src_ip: str | None = None,
                  exclude_ips: Sequence[str | None] = ()) -> list[Mapping]:
    """Remote Type 3/10 user logons on ``target_host`` in [ts_lo, ts_hi].

    ``src_ip`` set: only that source. ``src_ip`` None: ANY source IP except loopback/empty and
    ``exclude_ips`` (the target's own address). WHY any: the host that holds the agent command
    is only a cross-check; the source host of a hop is whoever the 4624 IpAddress says
    (decision 013), including an address that maps to no lab host.
    """
    skip = LOOPBACK_OR_EMPTY | {ip for ip in exclude_ips if ip}
    out = []
    for r in idx.by_key.get((target_host, "Security", 4624), []):
        ip = r.get("source_ip")
        if (r.get("logon_type") not in REMOTE_TYPES or not ts_lo <= r["ts"] <= ts_hi
                or not is_user_account(r.get("account_name"))):
            continue
        if (src_ip is not None and ip != src_ip) or (src_ip is None and (ip or "") in skip):
            continue
        out.append(r)
    return out


def cluster_bursts(logons: Sequence[Mapping]) -> list[list[Mapping]]:
    """Group logons by (account, source IP) and split a group at gaps larger than BURST_GAP_S.

    WHY the IP in the key: logons of one account from two different hosts are two moves.
    """
    out: list[list[Mapping]] = []
    groups: dict[tuple[str, str], list[Mapping]] = {}
    for r in sorted(logons, key=lambda x: x["ts"]):
        groups.setdefault((normalise_account(r["account_name"]), r.get("source_ip") or ""), []).append(r)
    for rows in groups.values():
        cur = [rows[0]]
        for r in rows[1:]:
            if r["ts"] - cur[-1]["ts"] > BURST_GAP_S:
                out.append(cur)
                cur = []
            cur.append(r)
        out.append(cur)
    out.sort(key=lambda b: b[0]["ts"])
    return out


def _base(path: str | None) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def burst_artifacts(idx: Index, host: str, burst: Sequence[Mapping], names: Mapping[str, Sequence[str]]) -> dict:
    """Artefacts bound by logon id to the burst's logons, and whether any matches the command's names.

    ``bound`` = a logon-id artefact exists that matches the command (5145 file, 4697 service,
    wsmprovhost session). ``name_match`` is the same condition; kept separate from 7045 (by name only).
    """
    shares: list[str] = []
    files: list[str] = []
    installs: list[str] = []
    wsm: list[str] = []
    matched = False
    for lg in burst:
        lid = lg["target_logon_id"]
        for e in idx.by_logon.get((host, lid), []):
            if e["event_id"] == 5140:
                shares.append(e["event_uid"])
            elif e["event_id"] == 5145:
                files.append(e["event_uid"])
                if _base(e.get("relative_target_name")) in names.get("binaries", ()):
                    matched = True
            elif e["event_id"] == 4697:
                installs.append(e["event_uid"])
                if (e.get("service_name") or "").lower() in names.get("services", ()) \
                        or _base(e.get("service_image_path")) in names.get("binaries", ()):
                    matched = True
        for e in idx.by_key.get((host, "Security", 4688), []):
            if _base(e.get("image")) == "wsmprovhost.exe" and e.get("target_logon_id") == lid:
                wsm.append(e["event_uid"])
        for e in idx.by_key.get((host, "Sysmon", 1), []):
            if _base(e.get("image")) == "wsmprovhost.exe" and e.get("session_id") == lid:
                wsm.append(e["event_uid"])
    if wsm:
        matched = True
    return {"share_uids": shares, "file_uids": files, "install_uids": installs, "wsmprovhost_uids": wsm,
            "name_match": matched, "bound": matched}


def service_events(idx: Index, host: str, anchor_ts: float, names: Mapping[str, Sequence[str]],
                   exclude_ranges: Sequence[tuple[float, float]] = ()) -> list[Mapping]:
    """System 7045 on ``host`` whose service or binary name is in the command, near the anchor.

    ``exclude_ranges`` drops events inside a stray agent run (AK-03, stray_agent_ep02).
    """
    out = []
    for e in idx.by_key.get((host, "System", 7045), []):
        if not (anchor_ts - SERVICE_BEFORE_S <= e["ts"] <= anchor_ts + SERVICE_AFTER_S):
            continue
        if any(lo <= e["ts"] <= hi for lo, hi in exclude_ranges):
            continue
        if (e.get("service_name") or "").lower() in names.get("services", ()) \
                or _base(e.get("service_image_path")) in names.get("binaries", ()):
            out.append(e)
    return out


def stray_events(idx: Index, host: str, ts_lo: float, ts_hi: float, names: Mapping[str, Sequence[str]]) -> list[Mapping]:
    """Target-side events on ``host`` of a stray (SYSTEM-token) agent run in [ts_lo, ts_hi].

    5140/5145 under a system logon id (the stray's own share access, no 4624), and 7045/4697 whose
    service or binary name is in the stray command. Listed only to show they are NOT hop evidence.
    """
    out = []
    for eid, ch in ((5140, "Security"), (5145, "Security"), (4697, "Security"), (7045, "System")):
        for e in idx.by_key.get((host, ch, eid), []):
            if not ts_lo <= e["ts"] <= ts_hi:
                continue
            by_name = ((e.get("service_name") or "").lower() in names.get("services", ())
                       or _base(e.get("service_image_path")) in names.get("binaries", ()))
            system_owned = e.get("subject_logon_id") in SYSTEM_LOGON_IDS
            if (eid in (5140, 5145) and system_owned) or (eid in (4697, 7045) and by_name):
                out.append(e)
    return sorted(out, key=lambda e: e["ts"])


def winrm_events(idx: Index, host: str, account: str, src_ip: str, anchor_ts: float) -> list[Mapping]:
    """WinRM 91 on ``host`` for ``account`` from client ``src_ip`` within WINRM_TOL_S of the anchor."""
    acct = normalise_account(account)
    return [e for e in idx.by_key.get((host, "WinRM", 91), [])
            if normalise_account(e.get("account_name")) == acct and e.get("source_ip") == src_ip
            and abs(e["ts"] - anchor_ts) <= WINRM_TOL_S]


def describe_burst(burst: Sequence[Mapping], art: Mapping) -> dict:
    """Compact, serialisable summary of one candidate burst (kept in the hop for audit)."""
    return {"account": normalise_account(burst[0]["account_name"]),
            "first_logon_time_utc": burst[0]["t_utc"],
            "logon_ids": [hex(b["target_logon_id"]) for b in burst],
            "logon_uids": [b["event_uid"] for b in burst],
            "authentication_package": burst[0].get("authentication_package"),
            "source_ip": burst[0].get("source_ip"),
            "name_match_by_logon_id": art["name_match"]}


def burst_protocol(art: Mapping, burst: Sequence[Mapping]) -> str | None:
    """Protocol a burst shows by its own artefacts (wsmprovhost = WinRM, type 10 = RDP, share = SMB)."""
    if art["wsmprovhost_uids"]:
        return "WinRM"
    if burst[0].get("logon_type") == 10:
        return "RDP"
    if art["share_uids"] or art["file_uids"]:
        return "SMB"
    return None


def port_join_events(idx: Index, source_host: str | None, target_ip: str | None,
                     burst: Sequence[Mapping]) -> list[Mapping]:
    """Sysmon 3 on the source host whose source port equals the IpPort of ANY logon in the burst.

    WHY every logon: a move opens several connections; only some of them are logged by Sysmon 3
    (where logged: WinRM, RDP). Destination address must be the target's.
    """
    if not source_host or not target_ip:
        return []
    ports = {b.get("source_port") for b in burst if b.get("source_port")}
    return [e for e in idx.by_key.get((source_host, "Sysmon", 3), [])
            if e.get("source_port") in ports and e.get("destination_ip") == target_ip]


def select_burst(bursts: Sequence[Sequence[Mapping]], arts: Sequence[Mapping],
                 preferred_accounts: Sequence[str], preferred_ip: str | None = None) -> tuple[int | None, str]:
    """Pick one burst or none. Returns (index|None, how).

    ``how`` is ``artifact`` (a logon-id artefact matches the command), ``account`` (only
    bursts of an account the command or agent used), ``source`` (only bursts from the command
    host's own IP remain) or ``single`` (one burst in the window); ``ambiguous`` (several
    remain: nothing is picked) or ``none`` (no burst). Source and account are soft: they only
    narrow, they never reject a burst that matches by name.
    """
    if not bursts:
        return None, "none"
    pref = {normalise_account(a) for a in preferred_accounts if a}
    acct = [normalise_account(b[0]["account_name"]) for b in bursts]
    matched = [i for i, a in enumerate(arts) if a["name_match"]]
    if len(matched) == 1:
        return matched[0], "artifact"
    pool = matched if matched else list(range(len(bursts)))
    how = "artifact" if matched else None
    if not matched and len(bursts) == 1:
        return 0, "single"
    narrowed = [i for i in pool if acct[i] in pref]
    if len(narrowed) == 1:
        return narrowed[0], how or "account"
    by_ip = [i for i in (narrowed or pool) if preferred_ip and bursts[i][0].get("source_ip") == preferred_ip]
    if len(by_ip) == 1:
        return by_ip[0], how or "source"
    return None, "ambiguous"
