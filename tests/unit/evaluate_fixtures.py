"""Synthetic fake repo for the T7.6 link accuracy tests (decision 051; spec 03_stitch ST-25, STA-05..08).

Written from decision 051 and spec 03 section 3 (the stitch output column lists), not from the implementation. Everything
lives in a pytest `tmp_path`: a fake repo with `data/processed/<trial>.sqlite3` (a table `events_dedup`, written by
`stitch_fixtures.write_events_db`), `out/stitch/<trial>/` with the ten stitch files (SHA-256s recorded in the
stitch `run_info.json`), and an approved key `ground_truth/approved/<trial>.yaml` (JSON text, as the answer-key writer
produces). The real `data/`, `out/` and `ground_truth/` are never opened. `ground_truth/key_lock.csv` of the real repo
is never created; a manifest only ever exists inside a `tmp_path`.

Event times are seconds after 10:30:00 (`stitch_fixtures.at`). Standard world: source ep-01, target ep-02.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from stitch_fixtures import at, ev, logon  # noqa: E402,F401

SRC, DST = "ep-01", "ep-02"

# spec 03 section 3 column lists (literal, from the spec text / the header of a stitch file)
HOP_COLS = ["hop_id", "target_host", "source_ip", "ip_kind", "source_host", "first_utc", "first_utc_corrected",
            "last_utc_corrected", "member_count", "member_logon_uids", "member_logon_ids", "member_logon_ids_hex",
            "member_accounts", "member_ports", "mixed_account", "protocol", "rules", "chain_parent_count",
            "chain_parent_hop_ids", "multi_chain_parent", "trigger_ids", "is_seed", "in_path",
            "authentication_packages", "confirm", "confirm_event_uids", "inside_gap_max_ms", "prev_gap_ms",
            "next_gap_ms", "gap_near_threshold", "splits_at_1s", "merges_at_3s", "service_install_count",
            "shares_port_with_hops", "followup_logon_uids", "followup_logon_count", "candidate_count", "best_tier",
            "evidence_before_range", "evidence_after_range", "supporting_span_ms", "clock_unreliable",
            "gate_clock_unreliable"]
LINK_COLS = ["link_id", "hop_id", "method", "session_methods", "source_host", "source_session_id",
             "source_session_id_hex", "session_unresolved_reason", "source_session_account",
             "source_session_logon_type", "source_session_logon_uid", "account_match", "account_match_members",
             "account_match_member_count", "name_check", "name_check_names", "name_check_event_uids",
             "candidate_count", "candidate_count_all", "candidate_count_account", "matched_member_count",
             "time_delta_ms", "time_delta_raw_ms", "supporting_event_uids", "confidence_tier", "link_rank", "tie",
             "rank_basis", "target_only_reason", "clock_unreliable"]
IDENT_COLS = ["hop_id", "account", "source_host", "move_utc_corrected", "dump_event_uid", "dump_utc_corrected",
              "dump_source_image", "dump_account", "gap_ms", "order_margin_ms", "order_ok", "order_within_tolerance",
              "order_within_uncertainty", "offset_unc_source_ms", "offset_unc_target_ms", "open_session_uids",
              "open_session_types", "session_open_before_window", "end_unknown_session_uids", "not_applicable",
              "clock_unreliable"]
ART_COLS = ["hop_id", "kind", "member_logon_uid", "logged_under_hop_id", "method", "candidate_count",
            "time_delta_ms", "supporting_span_ms", "confidence_tier", "event_uids", "names",
            "untied_same_name_bursts"]
PATH_COLS = ["path_id", "hop_ids", "hosts", "n_hops", "seed_trigger_ids", "merged_from", "isolated", "edge_types",
             "shared_source_session_with", "shared_event_with"]
EDGE_COLS = ["path_id", "from_hop_id", "to_hop_id", "link_type", "time_delta_ms", "order_within_tolerance",
             "clock_unreliable"]
NODE_COLS = ["path_id", "hop_id", "role", "context", "host", "session_id", "event_uid", "link_id"]
STITCH_FILES = ["hops.csv", "links.csv", "hop_artefacts.csv", "hop_identity.csv", "paths.csv", "path_edges.csv",
                "path_nodes.csv", "stats.json", "report.md", "run_info.json"]
SYSTEM_BOOT = {"startup": (41, 6005, 6008), "shutdown": (1074, 6006)}


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def csv_text(cols: Sequence[str], rows: Sequence[Mapping[str, str]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(list(cols))
    for r in rows:
        w.writerow([str(r.get(c, "")) for c in cols])
    return buf.getvalue()


# ------------------------------------------------------------------------------------------------ row builders
def hop_row(hop_id: str, uids: Sequence[str] = (), lids: Sequence[int] = (), *, accounts: Sequence[str] = (),
            source_host: str = SRC, target_host: str = DST, protocol: str = "smb", tier: str = "B",
            cand: int = 1, is_seed: int = 1, before: int = 0, after: int = 0, **kw: str) -> dict[str, str]:
    row = dict.fromkeys(HOP_COLS, "")
    accts = list(accounts) or ["acct_a"] * len(uids)
    row.update(hop_id=hop_id, target_host=target_host, source_ip="192.168.50.21", ip_kind="lab",
               source_host=source_host, first_utc="2026-09-24T10:31:45.000000Z",
               member_count=str(len(uids)), member_logon_uids=";".join(uids),
               member_logon_ids=";".join(str(i) for i in lids),
               member_logon_ids_hex=";".join(hex(i) for i in lids), member_accounts=";".join(accts),
               mixed_account="0", protocol=protocol, is_seed=str(is_seed), in_path="1",
               candidate_count=str(cand), best_tier=tier, evidence_before_range=str(before),
               evidence_after_range=str(after), clock_unreliable="0", gate_clock_unreliable="0")
    row.update({k: str(v) for k, v in kw.items()})
    return row


def link_row(hop_id: str, n: int, method: str, sid: int | None = None, uid: str = "", *, host: str = SRC,
             rank: int | None = 1, tie: int = 0, tier: str = "B", methods: str | None = None,
             reason: str = "no_evidence_in_range", cand: int = 1) -> dict[str, str]:
    row = dict.fromkeys(LINK_COLS, "")
    row.update(link_id=f"{hop_id}-l{n:02d}", hop_id=hop_id, method=method, confidence_tier=tier, tie=str(tie),
               candidate_count=str(cand), clock_unreliable="0")
    if method == "target_only":
        row.update(session_methods="", confidence_tier="D", target_only_reason=reason, candidate_count="0",
                   rank_basis="target_only", account_match="none")
        return row
    row.update(session_methods=methods if methods is not None else method, source_host=host,
               source_session_id=str(sid), source_session_id_hex=hex(sid), source_session_logon_uid=uid,
               account_match="direct", link_rank="" if rank is None else str(rank), rank_basis="tier")
    return row


def ident_row(hop_id: str, account: str = "acct_a", *, dump: str = "", dump_account: str = "acct_a",
              gap_ms: int = 60000, order_ok: int = 1, open_uids: str = "", end_unknown: str = "",
              na: str = "", tol: int = 0, unc: int = 0) -> dict[str, str]:
    row = dict.fromkeys(IDENT_COLS, "")
    row.update(hop_id=hop_id, account=account, source_host=SRC, move_utc_corrected="2026-09-24T10:31:45.000000Z",
               not_applicable=na, clock_unreliable="0", session_open_before_window="0")
    if dump:
        row.update(dump_event_uid=dump, dump_utc_corrected="2026-09-24T10:30:45.000000Z",
                   dump_source_image="C:\\Windows\\System32\\lsass_reader.exe", dump_account=dump_account,
                   gap_ms=str(gap_ms), order_margin_ms=str(gap_ms + 5000), order_ok=str(order_ok),
                   order_within_tolerance=str(tol), order_within_uncertainty=str(unc),
                   open_session_uids=open_uids, end_unknown_session_uids=end_unknown)
    return row


def ek(uid: str, host: str, channel: str, event_id: int, off: float) -> dict[str, Any]:
    return {"host": host, "channel": channel, "event_id": event_id, "record_id": 1, "time_utc": at(off)}


def key_hop(hop_id: str, *, target_uids: Sequence[str], target_lid: int, protocol: str = "SMB",
            source_host: str = SRC, target_host: str = DST, account: str = "acct_a",
            session_hex: str | None = None, session_evidence: Mapping[str, Any] | None = None,
            agent_uids: Sequence[str] = (), expected: int | None = 1, role: str = "attack",
            **kw: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"hop_id": hop_id, "role": role, "protocol": protocol, "source_host": source_host,
                           "target_host": target_host, "account": account, "logon_account": account,
                           "target_logon_id": hex(target_lid), "target_event_uids": list(target_uids),
                           "agent_event_uids": list(agent_uids), "identity_expected": expected}
    if session_hex is not None:
        out["source_session_logon_id"] = session_hex
    if session_evidence is not None:
        out["session_evidence"] = dict(session_evidence)
    out.update(kw)
    return out


# ------------------------------------------------------------------------------------------------ the world
@dataclass
class World:
    repo: Path
    trial: str
    stitch_dir: Path
    db: Path
    key_path: Path
    key: dict[str, Any]
    run_info: dict[str, Any]
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key_sha(self) -> str:
        return sf.sha256_of(self.key_path)

    def rewrite_run_info(self, **changes: Any) -> None:
        self.run_info.update(changes)
        (self.stitch_dir / "run_info.json").write_text(json.dumps(self.run_info, sort_keys=True, indent=1) + "\n",
                                                       encoding="utf-8")


def build_world(tmp_path: Path, *, trial: str = "s02_t00", name: str = "repo", db_rows: Sequence[Mapping] = (),
                key_hops: Sequence[Mapping] | None = None, event_keys: Mapping[str, Any] | None = None,
                hops: Sequence[Mapping] = (), links: Sequence[Mapping] = (), identity: Sequence[Mapping] = (),
                boot_group_s: float | None = 120.0, write_key: bool = True, key_db_sha: str | None = None,
                key_trial: str | None = None, run_info_db_sha: str | None = None,
                run_info_trial: str | None = None, key_dir: str = "approved") -> World:
    repo = tmp_path / name
    db = repo / "data" / "processed" / f"{trial}.sqlite3"
    sf.write_events_db(db, list(db_rows) or [logon("DUMMY", 1.0, 1)])
    db_sha = sf.sha256_of(db)
    sdir = repo / "out" / "stitch" / trial
    sdir.mkdir(parents=True, exist_ok=True)
    texts = {"hops.csv": csv_text(HOP_COLS, hops), "links.csv": csv_text(LINK_COLS, links),
             "hop_artefacts.csv": csv_text(ART_COLS, []), "hop_identity.csv": csv_text(IDENT_COLS, identity),
             "paths.csv": csv_text(PATH_COLS, []), "path_edges.csv": csv_text(EDGE_COLS, []),
             "path_nodes.csv": csv_text(NODE_COLS, []), "stats.json": json.dumps({"hops": len(hops)}) + "\n",
             "report.md": "# stitch report (synthetic)\n"}
    params: dict[str, Any] = {"group_gap_s": 2.0}
    if boot_group_s is not None:
        params["boot_group_s"] = boot_group_s
    info: dict[str, Any] = {"trial_id": run_info_trial or trial, "parameters": params,
                            "db": {"path": f"data/processed/{trial}.sqlite3", "sha256_before": db_sha,
                                   "sha256_after": run_info_db_sha or db_sha},
                            "files": {n: {"sha256": sha256_text(t), "rows": None} for n, t in texts.items()}}
    for n, t in texts.items():
        (sdir / n).write_text(t, encoding="utf-8", newline="\n")
    (sdir / "run_info.json").write_text(json.dumps(info, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    key: dict[str, Any] = {"trial_id": key_trial or trial, "db_sha256": key_db_sha or db_sha, "status": "draft",
                           "hops": list(key_hops or []), "event_keys": dict(event_keys or {})}
    kpath = repo / "ground_truth" / key_dir / f"{trial}.yaml"
    if write_key:
        kpath.parent.mkdir(parents=True, exist_ok=True)
        kpath.write_text(json.dumps(key, indent=1) + "\n", encoding="utf-8")
    return World(repo, trial, sdir, db, kpath, key, info)


# ------------------------------------------------------------------------------------------------ standard hop
SESSION_KEY, SESSION_KEY_LID = "U500", 0x500          # the key's source session (ep-01)
SESSION_OTHER, SESSION_OTHER_LID = "U600", 0x600
TARGET_LID = 0x100


def std_db(extra: Sequence[Mapping] = (), command: str = sf.PLACEHOLDER_COMMAND) -> list[dict]:
    """ep-01: 4624 of session 0x500 (uid U500) at 10 s and of 0x600 (U600) at 20 s; a Sysmon 1 of session 0x500 at
    100 s (uid C1); then `extra` rows."""
    return [logon(SESSION_KEY, 10.0, SESSION_KEY_LID, host=SRC),
            logon(SESSION_OTHER, 20.0, SESSION_OTHER_LID, host=SRC),
            ev("C1", "Sysmon", 1, host=SRC, off=100.0, session_id=SESSION_KEY_LID, command_line=command),
            *extra]


def std_event_keys(extra: Mapping[str, Any] | None = None) -> dict[str, Any]:
    out = {"C1": ek("C1", SRC, "Sysmon", 1, 100.0), "T1": ek("T1", DST, "Security", 4624, 105.0)}
    out.update(extra or {})
    return out


def std_world(tmp_path: Path, *, links: Sequence[Mapping], key_kw: Mapping[str, Any] | None = None,
              hop_kw: Mapping[str, Any] | None = None, extra_db: Sequence[Mapping] = (), identity: Sequence[Mapping] | None = None,
              event_keys: Mapping[str, Any] | None = None, **build_kw: Any) -> World:
    """One key hop `k1` (target 4624 T1, logon ID 0x100; key source session 0x500 given as `source_session_logon_id`
    with `session_evidence.session_logon_uid` U500 unless `key_kw` overrides) against one stitch hop `H1`."""
    kk: dict[str, Any] = {"session_hex": "0x500", "session_evidence": {"session_logon_uid": SESSION_KEY},
                          "agent_uids": ["C1"]}
    kk.update(key_kw or {})
    ident = [ident_row("H1", dump="D1", open_uids="X1")] if identity is None else identity
    return build_world(tmp_path, db_rows=std_db(extra_db), event_keys=std_event_keys(event_keys),
                       key_hops=[key_hop("k1", target_uids=["T1"], target_lid=TARGET_LID, **kk)],
                       hops=[hop_row("H1", ["T1"], [TARGET_LID], **(hop_kw or {}))], links=list(links),
                       identity=ident, **build_kw)


def only_keyed(res: Any) -> dict[str, str]:
    assert res.keyed_rows is not None and len(res.keyed_rows) == 1, res.keyed_rows
    return dict(res.keyed_rows[0])
