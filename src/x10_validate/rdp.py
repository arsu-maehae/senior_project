"""RDP design hop (decision 035): source-side mstsc connection and target-side RDP logon.

WHY a module of its own: an RDP hop has no command line that names the target and no service or
share artefact, so the SMB/WinRM binding in ``hops`` does not apply. The source anchor is a Sysmon 3
connection from ``mstsc.exe`` to the target's IP on port 3389, and the target step is a 4624 that is
logon type 10, or type 3 corroborated by an inbound Sysmon 3 to 3389 (Correction E4, decision 035).
Pure functions over already-loaded rows, so a tester can feed synthetic rows.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from .db import iso
from .design import HopDesign
from .events import is_user, logons_from, rdp_inbound_connections, rdp_source_connections
from .params import RDP_CORR_S, RDP_SESSION_GAP_S
from .textmatch import norm_account


def _step(rows: Sequence[Mapping], **extra) -> dict:
    """Same shape as the other hop steps: present, count, event_uids (max 20), first_utc."""
    return {"present": bool(rows), "count": len(rows), "event_uids": [r["event_uid"] for r in rows][:20],
            "first_utc": iso(min((r["ts"] for r in rows), default=None)), **extra}


def classify_logons(logons: Sequence[Mapping], inbound: Sequence[Mapping],
                    tol_s: float = RDP_CORR_S) -> list[dict]:
    """Label every 4624 from the source IP: counted as RDP or not, and why.

    Counted = user account and (logon type 10, or logon type 3 with an inbound 3389 Sysmon 3 within
    ``tol_s`` seconds on the same host). Types 7 (reconnect) and 11 never count (decision 035).
    """
    out = []
    for r in logons:
        corr = [c for c in inbound if abs(c["ts"] - r["ts"]) <= tol_s]
        if not is_user(r["account_name"]):
            basis = "non_user_account"
        elif r["logon_type"] == 10:
            basis = "type10"
        elif r["logon_type"] == 3 and corr:
            basis = "type3_with_inbound_3389"
        else:
            basis = "not_rdp"
        out.append({"row": r, "counted": basis in ("type10", "type3_with_inbound_3389"), "basis": basis,
                    "inbound_uids": [c["event_uid"] for c in corr][:3]})
    return out


def bursts(times: Sequence[float], gap_s: float = RDP_SESSION_GAP_S) -> list[list[float]]:
    """Group sorted times so that consecutive members are at most ``gap_s`` apart."""
    out: list[list[float]] = []
    for t in sorted(times):
        if out and t - out[-1][-1] <= gap_s:
            out[-1].append(t)
        else:
            out.append([t])
    return out


def sessions_of(counted: Sequence[Mapping]) -> list[dict]:
    """RDP sessions: counted logons of one account, bursts with gaps <= 120 s (N19)."""
    by_acc: dict[str, list[Mapping]] = {}
    for r in counted:
        by_acc.setdefault(norm_account(r["account_name"]), []).append(r)
    out = []
    for acc, rows in sorted(by_acc.items()):
        rows = sorted(rows, key=lambda r: r["ts"])
        cur = [rows[0]]
        groups = []
        for r in rows[1:]:
            if r["ts"] - cur[-1]["ts"] <= RDP_SESSION_GAP_S:
                cur.append(r)
            else:
                groups.append(cur)
                cur = [r]
        groups.append(cur)
        out += [{"account": acc, "first_utc": iso(g[0]["ts"]), "last_utc": iso(g[-1]["ts"]), "logons": len(g),
                 "event_uids": [r["event_uid"] for r in g][:10], "_first_ts": g[0]["ts"]} for g in groups]
    return sorted(out, key=lambda s: s["_first_ts"])


def resolve_rdp_hop(hop: HopDesign, rows_w: Sequence[Mapping], window: tuple[float, float]) -> dict:
    """Result dict of one RDP hop with the same keys as ``hops.resolve_hop`` (plus ``rdp`` evidence).

    ``rows_w`` are the window rows (Sysmon 3 and Security 4624 are read). Account is never a join
    condition: every logon from the source IP is listed, and c compares the intended account with
    the counted ones.
    """
    conns = rdp_source_connections(rows_w, hop.source, hop.target)
    inbound = rdp_inbound_connections(rows_w, hop.source, hop.target)
    labelled = classify_logons(logons_from(rows_w, hop.target, hop.source), inbound)
    counted = [x["row"] for x in labelled if x["counted"]]
    counted_acc = sorted({norm_account(r["account_name"]) for r in counted})
    types: dict[str, int] = {}
    for x in labelled:
        key = str(x["row"]["logon_type"])
        types[key] = types.get(key, 0) + 1
    first_logon = min((r["ts"] for r in counted), default=None)
    first_conn = conns[0]["ts"] if conns else None
    steps = {
        "rdp_source": _step(conns, image_suffix="\\mstsc.exe", destination_ip_port=f"{conns[0]['destination_ip']}:{conns[0]['destination_port']}" if conns else None),
        "logon": _step(counted, accounts=counted_acc,
                       logon_types=sorted({r["logon_type"] for r in counted}),
                       basis=sorted({x["basis"] for x in labelled if x["counted"]})),
    }
    required = {k: steps[k] for k in hop.steps}
    return {
        "hop_id": hop.hop_id, "protocol": hop.protocol, "source": hop.source, "target": hop.target,
        "lane": hop.lane, "intended_account": hop.intended_account, "note": hop.note,
        "binding": "rdp_type10_or_type3_3389" if counted else "none",
        "search_window": [iso(window[0]), iso(window[1])],
        "execution": None,
        "steps": required,
        "missing_steps": [k for k, v in required.items() if not v["present"]],
        "hop_accounts": counted_acc,
        "time_delta_ms": None if (first_conn is None or first_logon is None) else round((first_logon - first_conn) * 1000),
        "rdp": {
            "logons_from_source": [{"event_uid": x["row"]["event_uid"], "utc": iso(x["row"]["ts"]),
                                    "account": norm_account(x["row"]["account_name"]),
                                    "logon_type": x["row"]["logon_type"], "counted": x["counted"],
                                    "basis": x["basis"], "inbound_3389_uids": x["inbound_uids"]} for x in labelled][:40],
            "logon_types_observed": dict(sorted(types.items())),
            "accounts_observed": sorted({norm_account(x["row"]["account_name"]) for x in labelled}),
            "counted_accounts": counted_acc,
            "inbound_3389_on_target": len(inbound),
            "source_connection_bursts": len(bursts([c["ts"] for c in conns])),
            "sessions": [{k: v for k, v in s.items() if not k.startswith("_")} for s in sessions_of(counted)],
            "type3_tolerance_s": RDP_CORR_S,
        },
        "_first_logon_ts": first_logon, "_exec_ts": None,
        "_last_logon_ts": max((r["ts"] for r in counted), default=None),
        "_logon_ids": sorted({r["target_logon_id"] for r in counted if r["target_logon_id"]}),
        "_rdp_source_ts": [c["ts"] for c in conns],
    }
