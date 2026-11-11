"""Typed event extracts from the loaded rows: dumps, remote logons, SMB writes, services, WinRM.

WHY pure functions over a row list: each criterion needs a few small, independent queries; doing
them in Python over one load keeps the DB read-only, the logic testable with synthetic rows, and
avoids importing any join helper of the parser or stitcher (decision 029, independence).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

from .params import (AGENT_IMAGE, CALDERA_IP, CALDERA_PORT, DUMP_PAIR_S, ENDPOINTS, HOST_IP, IP_HOST,
                     NON_USER_ACCOUNTS, RDP_PORT, WRITE_MASK)
from .textmatch import field as fv_field
from .textmatch import norm_account, winrm91_client


def is_user(account: str | None) -> bool:
    """A domain/local user token: not SYSTEM-like, not a machine account (``name$``)."""
    acc = norm_account(account)
    return bool(acc) and acc not in NON_USER_ACCOUNTS and not acc.endswith("$")


def is_agent_image(path: str | None) -> bool:
    r"""Exact C:\Users\Public\splunkd.exe (case-insensitive); any other splunkd.exe is not the agent."""
    return bool(path) and path.strip().lower().replace("/", "\\") == AGENT_IMAGE


def _endswith(path: str | None, tail: str) -> bool:
    return bool(path) and path.lower().replace("/", "\\").endswith(tail)


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].strip().strip('"').lower()


def in_range(ts: float, lo: float, hi: float) -> bool:
    """Closed interval test used for every window."""
    return lo <= ts <= hi


# ----------------------------------------------------------------------------- dumps

@dataclass
class Dump:
    """One LSASS read: rundll32 -> lsass Sysmon 10 records within 1 s on one host."""
    host: str
    ts: float
    account: str
    user_token: bool
    process_guids: list[str] = field(default_factory=list)
    event_uids: list[str] = field(default_factory=list)


def find_dumps(rows: Sequence[Mapping]) -> list[Dump]:
    """All rundll32 -> lsass reads in the DB, grouped per host within ``DUMP_PAIR_S``."""
    recs = sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 10
                   and _endswith(r["source_image"], "\\rundll32.exe") and _endswith(r["target_image"], "\\lsass.exe")),
                  key=lambda r: (r["host"], r["ts"]))
    out: list[Dump] = []
    for r in recs:
        acc = norm_account(r["account_name"])
        last = out[-1] if out else None
        if last and last.host == r["host"] and r["ts"] - last.ts <= DUMP_PAIR_S and last.account == acc:
            last.event_uids.append(r["event_uid"])
            if r["process_guid"] and r["process_guid"].lower() not in last.process_guids:
                last.process_guids.append(r["process_guid"].lower())
            continue
        out.append(Dump(r["host"], r["ts"], acc, is_user(acc),
                        [r["process_guid"].lower()] if r["process_guid"] else [], [r["event_uid"]]))
    return out


# ----------------------------------------------------------------------------- logons

def remote_logons(rows: Sequence[Mapping]) -> list[Mapping]:
    """4624 type 3/10 on an endpoint from ANOTHER endpoint's IP with a user account (anchor kind 3)."""
    out = []
    for r in rows:
        if r["channel"] != "Security" or r["event_id"] != 4624 or r["logon_type"] not in (3, 10):
            continue
        src = IP_HOST.get((r["source_ip"] or "").strip())
        if r["host"] in ENDPOINTS and src and src != r["host"] and is_user(r["account_name"]):
            out.append(r)
    return sorted(out, key=lambda r: r["ts"])


def logons_to(logons: Iterable[Mapping], target: str, source: str, lo: float, hi: float) -> list[Mapping]:
    """Remote logons on ``target`` from ``source``'s IP inside [lo, hi]."""
    ip = HOST_IP[source]
    return [r for r in logons if r["host"] == target and r["source_ip"] == ip and in_range(r["ts"], lo, hi)]


# ----------------------------------------------------------------------------- SMB writes and services

def is_write(row: Mapping) -> bool | None:
    """True/False from the 5145 AccessMask (WriteData|AppendData); None when the mask is not stored."""
    mask = fv_field(row.get("field_values_json"), "accessmask")
    if not mask:
        return None
    try:
        return bool(int(mask, 16) & WRITE_MASK)
    except ValueError:
        return None


def admin_binary_access(rows: Sequence[Mapping]) -> list[Mapping]:
    """5145 on ``ADMIN$`` whose relative target name is a binary (.exe/.dll), any access."""
    out = []
    for r in rows:
        if r["channel"] == "Security" and r["event_id"] == 5145 and (r["share_name"] or "").upper().endswith("ADMIN$"):
            if re.search(r"\.(exe|dll)$", (r["relative_target_name"] or "").strip(), re.I):
                out.append(r)
    return sorted(out, key=lambda r: r["ts"])


_WIN_EXE = re.compile(r'^"?c:\\windows\\[^\\"]+\.exe"?(\s|$)', re.I)


def windows_exe(path: str | None) -> bool:
    r"""Service image is an .exe directly under C:\Windows\ (decision 029: names are not fixed)."""
    return bool(path) and bool(_WIN_EXE.match(path.strip()))


def services(rows: Sequence[Mapping]) -> list[Mapping]:
    """7045 (System) and 4697 (Security) on endpoints whose image is a C:\\Windows\\*.exe."""
    out = [r for r in rows
           if ((r["channel"] == "System" and r["event_id"] == 7045) or (r["channel"] == "Security" and r["event_id"] == 4697))
           and r["host"] in ENDPOINTS and windows_exe(r["service_image_path"])]
    return sorted(out, key=lambda r: r["ts"])


def service_names_of(row: Mapping) -> set[str]:
    """Lower-case service name and image file name of a 7045/4697 (to match command payload names)."""
    return {n for n in ((row["service_name"] or "").lower(), _basename(row["service_image_path"])) if n}


def file_name_of(row: Mapping) -> str:
    """Lower-case file name of a 5145 relative target name."""
    return _basename(row["relative_target_name"])


# ----------------------------------------------------------------------------- WinRM

def winrm91(rows: Sequence[Mapping]) -> list[dict]:
    """WinRM 91 rows with the account and client IP parsed from the resource URI."""
    out = []
    for r in rows:
        if r["channel"] == "WinRM" and r["event_id"] == 91:
            acc, ip = winrm91_client(r["field_values_json"])
            out.append({**r, "client_account": acc, "client_ip": ip})
    return sorted(out, key=lambda r: r["ts"])


def wsmprovhost(rows: Sequence[Mapping]) -> list[Mapping]:
    """Sysmon 1 of wsmprovhost.exe (the WinRM work process on the target)."""
    return sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1
                   and _endswith(r["image"], "\\wsmprovhost.exe")), key=lambda r: r["ts"])


# ----------------------------------------------------------------------------- RDP (decision 035)

def rdp_source_connections(rows: Sequence[Mapping], source: str, target: str) -> list[Mapping]:
    r"""Sysmon 3 on ``source`` from ``\mstsc.exe`` to the target's IP, port 3389 (the RDP source anchor).

    WHY by IP: the RDP client may be started from the interface, so no command line names the target.
    """
    ip = HOST_IP[target]
    return sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 3 and r["host"] == source
                   and _endswith(r["image"], "\\mstsc.exe") and (r["destination_ip"] or "").strip() == ip
                   and r["destination_port"] == RDP_PORT), key=lambda r: r["ts"])


def rdp_inbound_connections(rows: Sequence[Mapping], source: str, target: str) -> list[Mapping]:
    """Sysmon 3 on ``target`` from ``source``'s IP to port 3389 (any image; the target's svchost logs it)."""
    ip = HOST_IP[source]
    return sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 3 and r["host"] == target
                   and (r["source_ip"] or "").strip() == ip and r["destination_port"] == RDP_PORT),
                  key=lambda r: r["ts"])


def logons_from(rows: Sequence[Mapping], target: str, source: str) -> list[Mapping]:
    """Every 4624 on ``target`` from ``source``'s IP, any logon type (the RDP step reports them all)."""
    ip = HOST_IP[source]
    return sorted((r for r in rows if r["channel"] == "Security" and r["event_id"] == 4624 and r["host"] == target
                   and (r["source_ip"] or "").strip() == ip), key=lambda r: r["ts"])


# ----------------------------------------------------------------------------- agent network and DC

def agent_beacons(rows: Sequence[Mapping]) -> list[Mapping]:
    """splunkd.exe Sysmon 3 to the Caldera server 192.168.50.50:8888 (criterion e)."""
    return sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 3 and is_agent_image(r["image"])
                   and r["destination_ip"] == CALDERA_IP and r["destination_port"] == CALDERA_PORT),
                  key=lambda r: r["ts"])


def agent_starts(rows: Sequence[Mapping]) -> list[Mapping]:
    """Sysmon 1 whose image is splunkd.exe (agent process starts; used to bound the trial run for e)."""
    return sorted((r for r in rows if r["channel"] == "Sysmon" and r["event_id"] == 1 and is_agent_image(r["image"])),
                  key=lambda r: r["ts"])


_ZERO_GUID = "00000000-0000-0000-0000-000000000000"


def guid_of(row: Mapping) -> str | None:
    """Lower-case LogonGuid without braces; the all-zero GUID counts as none."""
    g = (row["logon_guid"] or "").strip("{} ").lower()
    return None if not g or g == _ZERO_GUID else g


def kerberos_pairs_input(rows: Sequence[Mapping]) -> tuple[list[Mapping], list[Mapping]]:
    """(endpoint 4624 with a LogonGuid, dc01 4769 with a LogonGuid) for the clock check g."""
    e4624 = [r for r in rows if r["channel"] == "Security" and r["event_id"] == 4624 and r["host"] in ENDPOINTS and guid_of(r)]
    d4769 = [r for r in rows if r["channel"] == "Security" and r["event_id"] == 4769 and r["host"] == "dc01" and guid_of(r)]
    return e4624, d4769
