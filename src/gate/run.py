"""Run the gate on one trial: GT-00 refusals, GT-01 clip, GT-02..05 suppression, rules, outputs.

WHY build everything in memory first: on a refusal or any error nothing may be written
(spec 2), so the output folder is only touched after every row, count and text is ready.
"""
from __future__ import annotations

import platform
from dataclasses import fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from answer_key.db import sha256_file
from trial_window.window import ClockFiles, clock_changes_path, offsets_path

from . import classify, inputs, outputs, rules
from .clock import ClockContext, clock_stats, context_from_row
from .inputs import GateError, ScanResult  # GateError re-exported: run_gate raises it
from .params import (DISPOSITION_COLUMNS, RULES, SUPPORTING_COLUMNS, SUPPORTING_RULES, TOOL_VERSION,
                     TRIGGER_COLUMNS, UNMATCHED_COLUMNS, GateParams)
from .timeutil import seconds_to_us

REPO = Path(__file__).resolve().parents[2]


def display_path(path: Path, repo: Path) -> str:
    """Path relative to the repo (POSIX form) when below it, else the absolute POSIX path.

    WHY: stats.json must be byte-identical between two runs on the same inputs, whichever working
    directory they start from.
    """
    p = Path(path).resolve()
    try:
        return p.relative_to(Path(repo).resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def params_dict(params: GateParams) -> dict[str, Any]:
    """Parameters as JSON-ready values (sets sorted, masks as hex, dates ISO) for stats.json."""
    out: dict[str, Any] = {}
    for f in fields(params):
        v = getattr(params, f.name)
        if f.name == "r1_access_masks":
            v = [f"0x{m:x}" for m in sorted(v)]
        elif isinstance(v, (set, frozenset)):
            v = sorted(v)
        elif isinstance(v, Mapping):
            v = dict(sorted(v.items()))
        elif isinstance(v, tuple):
            v = list(v)
        elif hasattr(v, "isoformat"):
            v = v.isoformat()
        out[f.name] = v
    return out


def check_allowed(trial_id: str, db_path: Path, windows_csv: Path, repo: Path | None, params: GateParams,
                  offsets_csv: Path, changes_csv: Path) -> tuple[dict[str, str], int, int, ClockFiles]:
    """GT-00 before any event is read (spec 2, 2.2 as amended in T6b.2, decision 043), in this order: trial
    id; quarantine; decision-019 exclusion and clock-only trial; window row and edges; window time_basis
    (must be the gate's, ``corrected``); offsets and clock-changes files present, for this trial, bound to
    each other and from a complete scan (``clock_files_refusal``, review SF-3/SF-4); the row's
    ``offsets_sha256`` / ``clock_changes_sha256`` equal the files' hashes; CO-17 on the window start.

    The window ``db_sha256`` and the offsets ``db_sha256`` checks run in ``load_events``, once the DB is
    hashed and before any event row is read. Returns (window row, start µs, end µs, clock files); raises
    GateError on refusal.
    """
    inputs.check_trial_id(trial_id)
    inputs.check_not_quarantined(trial_id, db_path, repo)
    inputs.check_clock(trial_id, None, params)
    row = inputs.read_window_row(windows_csv, trial_id)
    start_us, end_us = inputs.window_edges_us(row)
    inputs.check_time_basis(row, params)
    clock = inputs.load_clock(offsets_csv, changes_csv)
    inputs.check_clock(trial_id, None, params, clock)
    inputs.check_clock_hashes(row, clock)
    inputs.check_clock(trial_id, start_us, params, clock)
    return row, start_us, end_us, clock


def apply_rules(events: Sequence[Mapping], logons_all: Sequence[Mapping], params: GateParams,
                own_ll_sysmon3_all: Sequence[Mapping] = ()) -> dict[str, Any]:
    """GT-02..GT-16 on the in-window events: suppression, R4/R5/R6/R8, unmatched, supporting signals.

    Pure: returns every intermediate needed for the outputs and stats so each row stays traceable.
    ``logons_all`` (every 4624) and ``own_ll_sysmon3_all`` (outbound link-local Sysmon 3) come from the
    unclipped DB; they only feed the GT-02(b) map, the own-link-local lookup (decision 042) and stats.
    """
    excl_map = classify.excluded_logon_map(logons_all, params)
    own_ll = classify.own_link_local(logons_all, own_ll_sysmon3_all, params)
    wsm_pairs = classify.pair_wsmprovhost_91(events, seconds_to_us(params.winrm_pair_s))
    e7045 = [e for e in events if classify.is_7045(e)]
    e4697 = [e for e in events if classify.is_4697(e)]
    pairs = classify.pair_services(e7045, e4697, params.service_pair_s)
    suppressed = classify.suppress_all(events, excl_map, pairs, params, own_ll.own, wsm_pairs)
    remote = [e for e in events if classify.is_remote_logon(e, suppressed)]
    r5, r5_reverse = rules.r5_rows(remote, events, suppressed, params)
    drafts = (rules.r4_rows(remote, events, suppressed) + r5
              + rules.r6_rows(remote, events, suppressed, pairs)
              + rules.r8_rows(remote, events, suppressed, params, wsm_pairs))
    unmatched = outputs.unmatched_drafts(remote, drafts)
    signals = rules.supporting_signals(events, excl_map, suppressed, params)
    return {"excl_map": excl_map, "service_pairs": pairs, "suppressed": suppressed, "remote": remote,
            "drafts": drafts, "unmatched": unmatched, "signals": signals, "r5_reverse": r5_reverse,
            "e7045": e7045, "e4697": e4697, "own_ll": own_ll, "wsm_pairs": wsm_pairs}


def sensitivity(events: Sequence[Mapping], res: Mapping[str, Any], params: GateParams) -> dict[str, dict[str, int]]:
    """Pairs found at 2 s, the rule value and 10 s for the RDP, SERVICE and WINRM pairings (spec 5).

    WHY counts only: the rules always run at the spec value; these counts show how much a
    different tolerance would change, without changing any row.
    """
    tols = sorted(set(params.sensitivity_s) | {params.rdp_pair_s, params.service_pair_s, params.winrm_pair_s})
    suppressed, remote = res["suppressed"], res["remote"]
    s3s = [e for e in events if classify.is_inbound_rdp_sysmon3(e) and e["event_uid"] not in suppressed]
    w91 = [e for e in events if classify.is_winrm91(e) and e["event_uid"] not in suppressed]
    starts = [e for e in events if classify.is_wsmprovhost_start(e) and e["event_uid"] not in suppressed]
    anchors = {d.anchor["event_uid"]: d.anchor for d in res["drafts"] if d.rule == "R8_winrm" and d.anchor}
    out: dict[str, dict[str, int]] = {"rdp_pairs": {}, "service_pairs": {}, "winrm_91_anchor_pairs": {},
                                      "winrm_91_to_wsmprovhost_pairs": {}}
    for t in tols:
        key, us = f"{t:g}", seconds_to_us(t)
        out["rdp_pairs"][key] = sum(len(h) for h in rules.rdp_matches(remote, s3s, us).values())
        out["service_pairs"][key] = len(classify.pair_services(res["e7045"], res["e4697"], t))
        out["winrm_91_anchor_pairs"][key] = sum(
            1 for a in anchors.values() for w in w91
            if w["host"] == a["host"] and classify.norm_ip(a.get("source_ip")) is not None
            and classify.norm_ip(w.get("source_ip")) == classify.norm_ip(a.get("source_ip"))
            and classify.within(w["us"], a["us"], us))
        # Decision 042: the 91 is 0..t s AFTER the wsmprovhost Sysmon 1 (the order seen in the data).
        out["winrm_91_to_wsmprovhost_pairs"][key] = sum(
            1 for s in starts for w in w91 if w["host"] == s["host"] and 0 <= w["us"] - s["us"] <= us)
    return out


def build_stats(trial_id: str, db_text: str, sha_before: str, sha_after: str, window_row: Mapping[str, str],
                windows_text: str, windows_sha: str, scan: ScanResult, res: Mapping[str, Any],
                trig_rows: Sequence[Mapping], unm_rows: Sequence[Mapping], disp_rows: Sequence[Mapping],
                sup_rows: Sequence[Mapping], params: GateParams, clock: ClockContext) -> dict[str, Any]:
    """stats.json content, exactly the spec 3.1 keys (``clock`` added in T6b.2, decision 043) plus the spec 5
    sensitivity counts and parameters."""
    events = scan.in_window
    ordered = sorted(res["drafts"], key=outputs.draft_sort_key)
    ids = [r["trigger_id"] for r in trig_rows]
    near_dup = sorted(u for uids in scan.near_dup_groups.values() if len(set(uids)) > 1 for u in uids)
    ip_lookup = classify.logon_ip_lookup(scan.logons_all)
    local = [ids[i] for i, d in enumerate(ordered) if d.rule == "R6_service" and d.anchor is None]
    return {
        "trial_id": trial_id,
        "db": {"path": db_text, "sha256_before": sha_before, "sha256_after": sha_after},
        "window": {"row": dict(window_row), "file": windows_text, "file_sha256": windows_sha},
        "time_basis": params.time_basis,
        "clock": clock_stats(clock, trig_rows, unm_rows, disp_rows, sup_rows),
        "events": {"loaded_total": scan.loaded_total, "in_window_total": scan.in_window_total,
                   "trigger_type_in_window": len(disp_rows),
                   "trigger_type_in_window_per_host": outputs.nested_counts(disp_rows, "host")},
        "removed_by_window": {h: dict(sorted(c.items())) for h, c in sorted(scan.removed_by_window.items())},
        "near_window": {h: {"before": c.get("before", 0), "after": c.get("after", 0)}
                        for h, c in sorted(scan.near_window.items())},
        "dispositions": outputs.disposition_counts(disp_rows),
        "triggers": {"total": len(trig_rows), "per_rule": {r: sum(1 for t in trig_rows if t["rule"] == r) for r in RULES},
                     "per_rule_host_tier": outputs.nested_counts(trig_rows, "rule", "host", "gate_tier")},
        "unmatched_remote": {"total": len(unm_rows), "per_host": outputs.nested_counts(unm_rows, "host")},
        "supporting": {"total": len(sup_rows),
                       "per_rule": {r: sum(1 for s in sup_rows if s["rule"] == r) for r in SUPPORTING_RULES}},
        "remote_logons_per_ip_kind": outputs.nested_counts(
            [{"k": classify.ip_kind(r.get("source_ip"))} for r in res["remote"]], "k"),
        "machine_account_triggers_per_host": outputs.nested_counts(
            [t for t in trig_rows if t["machine_account"] == 1], "host"),
        "local_installs": {"count": len(local), "trigger_ids": local},
        "excluded": {"per_ip": outputs.excluded_per_ip(res["suppressed"]),
                     "excluded_ip_with_artefacts": outputs.excluded_ip_with_artefacts(
                         events, res["excl_map"], res["service_pairs"])},
        "near_duplicate_uids": near_dup,
        "tier_d_ip_lookup": outputs.tier_d_lookup(res["drafts"], ids, ip_lookup),
        "own_link_local": res["own_ll"].report,
        "sensitivity": sensitivity(events, res, params),
        "parameters": params_dict(params),
    }


def run_info(now: datetime | None = None) -> dict[str, str]:
    """Run time and tool version (the only output that is not byte-compared)."""
    now = now or datetime.now(timezone.utc)
    return {"run_utc": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "tool_version": TOOL_VERSION,
            "python_version": platform.python_version()}


def run_gate(trial_id: str, db_path: Path, windows_csv: Path, out_root: Path, repo: Path | None = None,
             params: GateParams = GateParams(), offsets_csv: Path | None = None,
             changes_csv: Path | None = None) -> dict[str, Any]:
    """Gate one trial and write ``out_root/<trial_id>/``; return the in-memory results.

    ``offsets_csv`` / ``changes_csv`` default to ``<repo>/data/processed/<trial>.clock_offsets.csv`` and
    ``.clock_changes.csv`` (spec 08 section 3). Returns {"out_dir", "triggers", "unmatched", "dispositions",
    "supporting", "stats", "run_info", "drafts"}. Raises GateError (and writes nothing) on any refusal or
    input error.
    """
    repo_path = Path(repo) if repo is not None else REPO
    offsets_file = Path(offsets_csv) if offsets_csv is not None else offsets_path(repo_path, trial_id)
    changes_file = Path(changes_csv) if changes_csv is not None else clock_changes_path(repo_path, trial_id)
    window_row, start_us, end_us, clock_files = check_allowed(trial_id, Path(db_path), Path(windows_csv), repo_path,
                                                              params, offsets_file, changes_file)
    windows_sha = sha256_file(Path(windows_csv))
    scan, sha_before, sha_after = inputs.load_events(Path(db_path), start_us, end_us, params,
                                                       expected_sha256=window_row["db_sha256"], clock=clock_files)
    assert clock_files.offsets is not None and clock_files.changes is not None   # check_allowed refused otherwise
    clock = context_from_row(window_row, clock_files.offsets, clock_files.changes,
                             display_path(offsets_file, repo_path), display_path(changes_file, repo_path))
    res = apply_rules(scan.in_window, scan.logons_all, params, scan.own_ll_sysmon3_all)
    near_dup = {u for uids in scan.near_dup_groups.values() if len(set(uids)) > 1 for u in uids}
    ws, tb = window_row["window_source"], params.time_basis
    trig_rows = outputs.numbered_rows(res["drafts"], trial_id, "g", ws, tb, near_dup, TRIGGER_COLUMNS, clock)
    unm_rows = outputs.numbered_rows(res["unmatched"], trial_id, "u", ws, tb, near_dup, UNMATCHED_COLUMNS, clock)
    sup_rows = outputs.supporting_rows(res["signals"], clock)
    disp_rows = outputs.disposition_rows(scan.in_window, res["suppressed"], res["drafts"], res["unmatched"],
                                         res["signals"], res["service_pairs"], res["r5_reverse"], clock)
    stats = build_stats(trial_id, display_path(Path(db_path), repo_path), sha_before, sha_after, window_row,
                        display_path(Path(windows_csv), repo_path), windows_sha, scan, res,
                        trig_rows, unm_rows, disp_rows, sup_rows, params, clock)
    info = run_info()
    files = {
        "triggers.csv": outputs.csv_text(trig_rows, TRIGGER_COLUMNS),
        "unmatched_remote.csv": outputs.csv_text(unm_rows, UNMATCHED_COLUMNS),
        "dispositions.csv": outputs.csv_text(disp_rows, DISPOSITION_COLUMNS),
        "supporting.csv": outputs.csv_text(sup_rows, SUPPORTING_COLUMNS),
        "stats.json": outputs.json_text(stats),
        "report.md": outputs.report_md(stats),
        "run_info.json": outputs.json_text(info),
    }
    out_dir = Path(out_root) / trial_id
    outputs.write_outputs(out_dir, files)
    return {"out_dir": out_dir, "triggers": trig_rows, "unmatched": unm_rows, "dispositions": disp_rows,
            "supporting": sup_rows, "stats": stats, "run_info": info, "drafts": res["drafts"]}
