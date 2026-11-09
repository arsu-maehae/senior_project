"""Hop instances and the port join shared by LC-04, LC-04b/c, LC-05 and LC-06.

A hop instance is one remote logon burst on a target endpoint: an SMB or WinRM client
opens several 4624 within seconds (S04: several per track), and counting each 4624 as a
separate hop would inflate candidate counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .common import hex_id, is_lab_ipv4
from .params import Params
from .timeutil import delta_ms, to_display


@dataclass
class HopInstance:
    """Target-side hop: 4624s on one host for one (account, source IP) within HOP_GROUP_S."""

    hop_id: str
    target_host: str
    account_name: str
    source_ip: str
    source_host: str | None
    logons: list[dict[str, Any]]
    protocol: str = "unclassified"
    protocol_evidence: list[str] = field(default_factory=list)

    @property
    def first(self) -> dict[str, Any]:
        return self.logons[0]

    @property
    def t(self) -> datetime:
        """t = first 4624 of the hop instance (LC-04)."""
        return self.first["t"]

    @property
    def source_port(self) -> int | None:
        return self.first.get("source_port")

    @property
    def target_logon_ids(self) -> set[int]:
        """Logon ids created by this hop (and their elevated twins) on the target host."""
        ids: set[int] = set()
        for row in self.logons:
            for key in ("target_logon_id", "target_linked_logon_id"):
                if row.get(key) is not None:
                    ids.add(int(row[key]))
        return ids

    @property
    def event_uids(self) -> list[str]:
        return [r["event_uid"] for r in self.logons]

    def is_scenario_account(self, params: Params) -> bool:
        return self.account_name in params.scenario_accounts

    def summary(self) -> dict[str, Any]:
        """Identity of the hop for every report section that mentions it."""
        return {
            "hop_id": self.hop_id, "protocol": self.protocol,
            "protocol_evidence": self.protocol_evidence,
            "target_host": self.target_host, "account_name": self.account_name,
            "source_ip": self.source_ip, "source_port": self.source_port,
            "source_host": self.source_host, "t_first_4624": to_display(self.t),
            "n_4624": len(self.logons),
            "ports": [r.get("source_port") for r in self.logons],
            "packages": sorted({r.get("authentication_package") or "" for r in self.logons}),
            "target_logon_ids": [hex_id(i) for i in sorted(self.target_logon_ids)],
            "target_event_uids": self.event_uids,
        }


def select_hop_logons(remote: list[dict[str, Any]], params: Params) -> tuple[list[dict], dict[str, int]]:
    """LC-04 input: remote 4624 from a lab IPv4 to an endpoint host.

    Logons whose source IP is the target's own address are excluded and counted: they are
    local connections through the host's own IP, not cross-host hops.
    """
    ip_to_host = params.ip_to_host()
    kept, excluded = [], {"not_lab_ipv4": 0, "not_endpoint_target": 0, "self_ip": 0}
    for row in remote:
        if not is_lab_ipv4(row.get("source_ip"), params):
            excluded["not_lab_ipv4"] += 1
        elif row["host"] not in params.endpoint_hosts:
            excluded["not_endpoint_target"] += 1
        elif ip_to_host.get(row["source_ip"]) == row["host"]:
            excluded["self_ip"] += 1
        else:
            kept.append(row)
    return kept, excluded


def group_hop_instances(rows: list[dict[str, Any]], scenario: str, params: Params) -> list[HopInstance]:
    """Group per (host, account, source IP); a 4624 more than HOP_GROUP_S after the FIRST 4624
    of the current instance starts a new one (anchoring on the first keeps instances bounded)."""
    ip_to_host = params.ip_to_host()
    ordered = sorted(rows, key=lambda r: (r["host"], r.get("account_name") or "", r["source_ip"],
                                          r["t"], r["event_uid"]))
    groups: list[list[dict[str, Any]]] = []
    for row in ordered:
        last = groups[-1] if groups else None
        if last is not None and _same_key(last[0], row) and \
                (row["t"] - last[0]["t"]).total_seconds() <= params.hop_group_s:
            last.append(row)
        else:
            groups.append([row])
    groups.sort(key=lambda g: (g[0]["t"], g[0]["host"], g[0]["event_uid"]))
    return [HopInstance(f"{scenario}-h{i}", g[0]["host"], g[0].get("account_name") or "",
                        g[0]["source_ip"], ip_to_host.get(g[0]["source_ip"]), g)
            for i, g in enumerate(groups, start=1)]


def _same_key(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (a["host"], a.get("account_name"), a["source_ip"]) == \
        (b["host"], b.get("account_name"), b["source_ip"])


def hop_by_logon_uid(hops: list[HopInstance]) -> dict[str, HopInstance]:
    """4624 event_uid → its hop instance, to attach port joins and WinRM 91 to hops."""
    return {uid: hop for hop in hops for uid in hop.event_uids}


def port_join(conns: list[dict[str, Any]], logons: list[dict[str, Any]], params: Params,
              tol_s: float) -> list[dict[str, Any]]:
    """Correction I join: source Sysmon 3 ↔ target 4624 on (IP, port > 0, |Δt| ≤ tol).

    The target host must be the HOST_IP owner of the connection's destination IP when known.
    Port 0 is never a key (NF-03). All pairs are returned; candidate counts expose ambiguity.
    """
    ip_to_host = params.ip_to_host()
    by_key: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for logon in logons:
        port = logon.get("source_port")
        if logon.get("source_ip") and port and int(port) > 0:
            by_key.setdefault((logon["source_ip"], int(port)), []).append(logon)
    pairs = []
    for conn in conns:
        port = conn.get("source_port")
        if not conn.get("source_ip") or not port or int(port) <= 0:
            continue
        expected_target = ip_to_host.get(conn.get("destination_ip") or "")
        for logon in by_key.get((conn["source_ip"], int(port)), []):
            if expected_target is not None and logon["host"] != expected_target:
                continue
            gap = delta_ms(conn["t"], logon["t"])
            if abs(gap) <= tol_s * 1000:
                pairs.append({"conn": conn, "logon": logon, "time_delta_ms": gap})
    return pairs


def classify_protocol(hop: HopInstance, winrm: set[str], rdp: set[str], smb_share: set[str],
                      smb_service: set[str] = frozenset()) -> tuple[str, list[str]]:
    """Label a hop for the CSV `protocol` column from the evidence the checks found.

    Order WinRM > RDP > SMB: WinRM and RDP have protocol-specific evidence (WinRM 91 /
    5985 join / wsmprovhost, type 10 / 3389), while SMB evidence is share access
    (5140/5145) or a service installed by the hop's logon session (4697 SubjectLogonId:
    remote SCM calls run over SMB named pipes, and a reused SMB session can write the
    binary in an earlier session, as in S07).
    """
    evidence = []
    if hop.hop_id in winrm:
        evidence.append("winrm")
    if hop.hop_id in rdp:
        evidence.append("rdp")
    if hop.hop_id in smb_share:
        evidence.append("smb_share")
    if hop.hop_id in smb_service:
        evidence.append("service_4697_subject")
    if "winrm" in evidence:
        return "WinRM", evidence
    if "rdp" in evidence:
        return "RDP", evidence
    if "smb_share" in evidence or "service_4697_subject" in evidence:
        return "SMB", evidence
    return "unclassified", evidence
