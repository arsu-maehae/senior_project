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
CMD_AFTER_LOGON_S = 120.0
SERVICE_BEFORE_S = 10.0     # 7045 window around the burst anchor
SERVICE_AFTER_S = 120.0
WINRM_TOL_S = 5.0
REMOTE_TYPES = (3, 10)


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


def remote_logons(idx: Index, target_host: str, src_ip: str | None, ts_lo: float, ts_hi: float) -> list[Mapping]:
    """Remote Type 3/10 user logons on ``target_host`` from ``src_ip`` in [ts_lo, ts_hi]."""
    if not src_ip:
        return []
    return [r for r in idx.by_key.get((target_host, "Security", 4624), [])
            if r.get("logon_type") in REMOTE_TYPES and r.get("source_ip") == src_ip
            and ts_lo <= r["ts"] <= ts_hi and is_user_account(r.get("account_name"))]


def cluster_bursts(logons: Sequence[Mapping]) -> list[list[Mapping]]:
    """Group logons by account and split a group at gaps larger than BURST_GAP_S."""
    out: list[list[Mapping]] = []
    by_acct: dict[str, list[Mapping]] = {}
    for r in sorted(logons, key=lambda x: x["ts"]):
        by_acct.setdefault(normalise_account(r["account_name"]), []).append(r)
    for rows in by_acct.values():
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
            "name_match_by_logon_id": art["name_match"]}


def select_burst(bursts: Sequence[Sequence[Mapping]], arts: Sequence[Mapping],
                 preferred_accounts: Sequence[str]) -> tuple[int | None, str]:
    """Pick one burst or none. Returns (index|None, how).

    ``how`` is ``artifact`` (a logon-id artefact matches the command), ``account`` (only
    bursts of an account the command or agent used) or ``single`` (one burst in the window),
    ``ambiguous`` (several remain: nothing is picked) or ``none`` (no burst).
    """
    if not bursts:
        return None, "none"
    pref = {normalise_account(a) for a in preferred_accounts if a}
    acct = [normalise_account(b[0]["account_name"]) for b in bursts]
    matched = [i for i, a in enumerate(arts) if a["name_match"]]
    if len(matched) == 1:
        return matched[0], "artifact"
    if len(matched) > 1:
        narrowed = [i for i in matched if acct[i] in pref]
        return (narrowed[0], "artifact") if len(narrowed) == 1 else (None, "ambiguous")
    if len(bursts) == 1:
        return 0, "single"
    narrowed = [i for i in range(len(bursts)) if acct[i] in pref]
    return (narrowed[0], "account") if len(narrowed) == 1 else (None, "ambiguous")
