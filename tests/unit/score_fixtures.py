"""Synthetic repo builder for the score tests (spec 05_score section 2 inputs).

Writes `out/stitch/<t>/` and `out/label/<t>/` into a pytest tmp folder with consistent run_info hashes (SC-02), so the
scorer can run on a world whose every number was computed by hand (see `base_world`). The column lists are the spec 05
section 2 "columns used" lists (hop_identity.csv: the spec 03 identity columns). Nothing here touches the real `out/`.

The hand computation of `base_world` (default parameters: lambda = 1/ln 2 so 1 - e^(-n/lambda) = 1 - 2^-n; w = 1/3;
alpha = beta = 0.5; a = b = 1; eps = 0.01):

  p0001  h1 SMB service      seq T1021.002>T1570>T1569.002  steps 1.0, 1.0       L = 0.75 * 1.0           = 0.75
                             units k_smb 1, k_cp 1, k_svc 1 (logged twice)        N = 3/3/4                = 0.25
                             (ctx1 adds the dump, level 3)                        N_ctx1 = 6/4/4           = 0.375
                             h1 exposed                                           I = 1
  p0002  h2 WinRM            seq T1078>T1021.006 (indirect 0.5)                   L = 0.5 * 0.5            = 0.25
                             units 3, 2                                           N = 5/2/4                = 0.625
                             h2 only an excluded OS/AV read                       I = 0
  p0003  h3 machine account  no label, no crossing                                0 / 0 / 0
  p0004  h3;h4 machine + unknown source host                                      0 / 0 / 0
  p0005  h5 target_only, tier D, isolated  no label; exposed                      L = 0, N = 0, I = 1
  p0006  h7;h6 (chain h6 -> h7; h7 is EARLIER in time)  seq T1021.002>T1570>T1569.002>T1078>T1021.006
                             steps 1, 1, hop_chain 1, 0.5                         L = 0.9375 * 0.875 = 0.8203125
                             units 1,1,1,3,2                                      N = 8/5/4                = 0.4
                             h6 exposed, h7 rejecting flagged read                I = 1/2, low 1/2, high 1
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from pathlib import Path

TRIAL = "s02_t00"

PATHS_COLS = ("path_id", "hop_ids", "hosts", "n_hops", "isolated", "merged_from", "edge_types")
EDGES_COLS = ("path_id", "from_hop_id", "to_hop_id", "link_type", "time_delta_ms", "clock_unreliable")
HOPS_COLS = ("hop_id", "first_utc_corrected", "source_host", "target_host", "protocol", "member_accounts",
             "best_tier", "candidate_count", "multi_chain_parent", "clock_unreliable")
IDENT_COLS = ("hop_id", "account", "source_host", "move_utc_corrected", "dump_event_uid", "dump_utc_corrected",
              "dump_source_image", "dump_account", "gap_ms", "order_margin_ms", "order_ok", "order_within_tolerance",
              "order_within_uncertainty", "offset_unc_source_ms", "offset_unc_target_ms", "open_session_uids",
              "open_session_types", "session_open_before_window", "end_unknown_session_uids", "not_applicable",
              "clock_unreliable")
NODES_COLS = ("path_id", "hop_id", "role", "context", "event_uid", "labelled", "rule_ids", "techniques",
              "max_level_value")
EVENTS_COLS = ("event_uid", "count_key", "rule_id", "technique", "tactics", "level_value", "event_utc_corrected",
               "host")

RUNDLL = r"C:\Windows\System32\rundll32.exe"


def csv_bytes(cols, rows) -> bytes:
    buf = io.StringIO(newline="")
    w = csv.DictWriter(buf, fieldnames=list(cols), lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in cols})
    return buf.getvalue().encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------ row makers
def path(pid, hops, *, isolated="0", hosts="ep-01>ep-02", merged_from=None, edge_types="") -> dict:
    hop_list = hops.split(";") if isinstance(hops, str) else list(hops)
    return {"path_id": pid, "hop_ids": ";".join(hop_list), "hosts": hosts, "n_hops": str(len(hop_list)),
            "isolated": isolated, "merged_from": merged_from if merged_from is not None else ";".join(hop_list),
            "edge_types": edge_types}


def edge(pid, frm, to, *, link="session", delta="1000", clock="0") -> dict:
    return {"path_id": pid, "from_hop_id": frm, "to_hop_id": to, "link_type": link, "time_delta_ms": delta,
            "clock_unreliable": clock}


def hop(hid, *, first="2026-09-24T10:00:10.000000Z", proto="smb_service", acct="svc", tier="B", cand="1",
        mcp="0", clock="0") -> dict:
    return {"hop_id": hid, "first_utc_corrected": first, "source_host": "ep-01", "target_host": "ep-02",
            "protocol": proto, "member_accounts": acct, "best_tier": tier, "candidate_count": cand,
            "multi_chain_parent": mcp, "clock_unreliable": clock}


def ident(hid="h1", account="svc", **kw) -> dict:
    row = {"hop_id": hid, "account": account, "source_host": "ep-01",
           "move_utc_corrected": "2026-09-24T10:00:10.000000Z", "dump_event_uid": "d1",
           "dump_utc_corrected": "2026-09-24T10:00:00.000000Z", "dump_source_image": RUNDLL,
           "dump_account": account, "gap_ms": "10000", "order_margin_ms": "10000", "order_ok": "1",
           "order_within_tolerance": "0", "order_within_uncertainty": "0", "offset_unc_source_ms": "",
           "offset_unc_target_ms": "", "open_session_uids": "sess1", "open_session_types": "3",
           "session_open_before_window": "0", "end_unknown_session_uids": "", "not_applicable": "",
           "clock_unreliable": "0"}
    row.update({k: str(v) for k, v in kw.items()})
    return row


def node(pid, hid, uid, *, tech="", level="", ctx="0", labelled="1", role="member") -> dict:
    return {"path_id": pid, "hop_id": hid, "role": role, "context": ctx, "event_uid": uid, "labelled": labelled,
            "rule_ids": "SR-xx" if labelled == "1" else "", "techniques": tech, "max_level_value": str(level)}


def event(uid, key, level, *, tech="", rule="SR-xx", when="2026-09-24T10:00:11.000000Z", host="ep-02",
          tactics="") -> dict:
    return {"event_uid": uid, "count_key": key, "rule_id": rule, "technique": tech, "tactics": tactics,
            "level_value": str(level), "event_utc_corrected": when, "host": host}


@dataclass
class World:
    paths: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    hops: list = field(default_factory=list)
    identity: list = field(default_factory=list)
    nodes: list = field(default_factory=list)
    events: list = field(default_factory=list)


def base_world() -> World:
    """The hand-computed world described in the module docstring."""
    w = World()
    w.hops = [
        hop("h1", tier="B", first="2026-09-24T10:00:10.000000Z"),
        hop("h2", tier="B", proto="winrm", first="2026-09-24T10:05:00.000000Z", acct="admin_it"),
        hop("h3", tier="D", cand="0", first="2026-09-24T10:06:00.000000Z", acct="dc-01$"),
        hop("h4", tier="D", cand="0", first="2026-09-24T10:07:00.000000Z", acct="usr"),
        hop("h5", tier="D", cand="0", first="2026-09-24T10:08:00.000000Z", acct="svc2"),
        hop("h6", tier="A", first="2026-09-24T10:10:00.000000Z", acct="svc6"),
        hop("h7", tier="C", proto="winrm", first="2026-09-24T10:09:00.000000Z", mcp="1", clock="1", acct="u7"),
    ]
    w.paths = [
        path("p0001", "h1"), path("p0002", "h2", hosts="ep-02>ep-03"), path("p0003", "h3"),
        path("p0004", "h3;h4"), path("p0005", "h5", isolated="1"),
        path("p0006", "h7;h6", merged_from="h7;h6", edge_types="session:1"),
    ]
    w.edges = [edge("p0006", "h6", "h7", clock="1")]
    w.identity = [
        ident("h1", "svc", dump_event_uid="d1"),
        # h2: the only read is wininit-like OS/AV activity at its system folder under SYSTEM: not counted (SC-51)
        ident("h2", "admin_it", dump_event_uid="d2", dump_account="system",
              dump_source_image=r"C:\Program Files\Windows Defender\MsMpEng.exe", open_session_uids="sess2"),
        ident("h3", "dc-01$", dump_event_uid="", not_applicable="machine_account", open_session_uids="",
              order_ok="", gap_ms="", dump_utc_corrected="", dump_source_image="", dump_account=""),
        ident("h4", "usr", dump_event_uid="", not_applicable="source_host_unknown", open_session_uids="",
              order_ok="", gap_ms="", dump_utc_corrected="", dump_source_image="", dump_account=""),
        ident("h5", "svc2", dump_event_uid="d5", open_session_uids="sess5"),
        ident("h6", "svc6", dump_event_uid="d6", open_session_uids="sess6"),
        ident("h7", "u7", dump_event_uid="d7", order_ok="0", order_margin_ms="-6000", gap_ms="-6000",
              order_within_uncertainty="1", open_session_uids="sess7", clock_unreliable="1"),
    ]
    smb = [("u_smb", "k_smb", "T1021.002", 1), ("u_cp", "k_cp", "T1570", 1),
           ("u_s4697", "k_svc", "T1569.002", 1), ("u_s7045", "k_svc", "T1569.002", 1)]
    for uid, key, tech, lvl in smb:
        w.nodes.append(node("p0001", "h1", uid, tech=tech, level=lvl))
        w.events.append(event(uid, key, lvl, tech=tech))
    w.nodes += [node("p0001", "h1", "u_dump", tech="T1003.001", level=3, ctx="1", role="session_context"),
                node("p0001", "h1", "u_plain", labelled="0", role="target_logon")]
    w.events += [event("u_dump", "k_dump", 3, tech="T1003.001", rule="SR-01", host="ep-01"),
                 event("u_dump", "k_dump", 2, tech="T1003.001", rule="SR-02", host="ep-01")]
    for uid, key, tech, lvl in (("u_4648", "kw1", "T1078", 3), ("u_wsm", "kw2", "T1021.006", 2)):
        w.nodes.append(node("p0002", "h2", uid, tech=tech, level=lvl))
        w.events.append(event(uid, key, lvl, tech=tech, host="ep-03"))
    # p0006: h6 SMB (later in time), h7 WinRM (earlier in time) chained h6 -> h7
    for uid, key, tech, lvl, when in (
            ("w_smb", "m_smb", "T1021.002", 1, "2026-09-24T10:10:01.000000Z"),
            ("w_cp", "m_cp", "T1570", 1, "2026-09-24T10:10:02.000000Z"),
            ("w_svc", "m_svc", "T1569.002", 1, "2026-09-24T10:10:03.000000Z")):
        w.nodes.append(node("p0006", "h6", uid, tech=tech, level=lvl))
        w.events.append(event(uid, key, lvl, tech=tech, when=when))
    for uid, key, tech, lvl, when in (
            ("w_4648", "m_4648", "T1078", 3, "2026-09-24T10:10:08.250000Z"),
            ("w_4648b", "m_4648", "T1078", 3, "2026-09-24T10:10:09.000000Z"),
            ("w_wsm", "m_wsm", "T1021.006", 2, "2026-09-24T10:10:10.000000Z")):
        w.nodes.append(node("p0006", "h7", uid, tech=tech, level=lvl))
        w.events.append(event(uid, key, lvl, tech=tech, when=when, host="ep-03"))
    w.events.append(event("u_orphan", "k_orphan", 4, tech="T1105", host="ep-09"))   # on no path (b0 only)
    return w


def build_repo(root: Path, w: World, trial: str = TRIAL, *, extra_stitch: dict | None = None) -> Path:
    """Write the eight input files (+ run_info of both stages, + a dummy path_nodes.csv) under `root/out/`."""
    sdir, ldir = Path(root) / "out" / "stitch" / trial, Path(root) / "out" / "label" / trial
    sdir.mkdir(parents=True, exist_ok=True)
    ldir.mkdir(parents=True, exist_ok=True)
    stitch = {"paths.csv": (PATHS_COLS, w.paths), "path_edges.csv": (EDGES_COLS, w.edges),
              "hops.csv": (HOPS_COLS, w.hops), "hop_identity.csv": (IDENT_COLS, w.identity)}
    hashes = {}
    for name, (cols, rows) in stitch.items():
        data = csv_bytes(cols, rows)
        (sdir / name).write_bytes(data)
        hashes[name] = sha(data)
    dummy = b"path_id,hop_id\n"
    (sdir / "path_nodes.csv").write_bytes(dummy)
    s_info = {"files": {n: {"sha256": h, "rows": 0} for n, h in hashes.items()}}
    s_info_bytes = (json.dumps(s_info, indent=1, sort_keys=True) + "\n").encode("utf-8")
    (sdir / "run_info.json").write_bytes(s_info_bytes)
    label = {"node_labels.csv": (NODES_COLS, w.nodes), "event_labels.csv": (EVENTS_COLS, w.events)}
    lhashes = {}
    for name, (cols, rows) in label.items():
        data = csv_bytes(cols, rows)
        (ldir / name).write_bytes(data)
        lhashes[name] = sha(data)
    l_info = {"files": {n: {"sha256": h, "rows": 0} for n, h in lhashes.items()},
              "stitch_files_sha256": {"hop_identity.csv": hashes["hop_identity.csv"], "hops.csv": hashes["hops.csv"],
                                      "path_nodes.csv": sha(dummy), "run_info.json": sha(s_info_bytes)}}
    (ldir / "run_info.json").write_bytes((json.dumps(l_info, indent=1, sort_keys=True) + "\n").encode("utf-8"))
    return Path(root)


def read_rows(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def parse_text(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))
