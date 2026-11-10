"""Orchestrates one log-check run: window → shared evidence → checks → outputs.

The order matters only where one check's evidence labels the hops for another: share
events (LC-04c), WinRM (LC-06) and RDP (LC-05) evidence give each hop its protocol label
before LC-04 rows are written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .bridge import EXPLICIT_SQL, load_explicit
from .checks_4648 import run_lc04h
from .checks_clock import run_lc09
from .checks_counts import run_lc01, run_lc02, run_lc03, run_lc07
from .checks_dumps import load_dump_data, run_lc08, run_lc08b
from .checks_key import load_key_window, run_lc10
from .checks_rdp_winrm import rdp_evidence, run_lc05, run_lc06, winrm_evidence
from .checks_smb import (commands_by_host, hop_csv_rows, load_services, load_shares, run_lc04,
                         run_lc04b, run_lc04c, run_lc04d, service_subject_hops, shares_by_hop)
from .common import OK, CheckResult, Context, load_all_4624, load_commands, load_remote_4624, logons_by_host_id
from .db import Db, connect_ro, normalise_sql, sha256_file
from .hops import HopInstance, classify_protocol, group_hop_instances, select_hop_logons
from .matching import harvest_secrets
from .params import DEFAULT_PARAMS, Params
from .report import build_csv, build_json, build_markdown, write_outputs
from .window import build_window, scenario_of

TRIAL_RE = re.compile(r"^s\d{2}_t\d{2}$")
TRIAL_IDS_SQL = "SELECT DISTINCT scenario_id, trial_id FROM events"


class LogCheckError(RuntimeError):
    """Raised for conditions where no report may be written (bad input, DB changed)."""


@dataclass
class RunOutput:
    report: dict
    markdown: str
    csv_text: str
    files: list[Path]


def check_trial_matches_db(db: Db, trial_id: str) -> None:
    """Refuse to label a DB with the wrong trial id (the DB stores scenario_id + trial_id)."""
    rows = db.query("LC-11", TRIAL_IDS_SQL)
    pairs = {f"{r['scenario_id']}_{r['trial_id']}" for r in rows}
    if pairs != {trial_id}:
        raise LogCheckError(f"--trial {trial_id} does not match the DB contents {sorted(pairs)}")


def label_hops(hops: list[HopInstance], share_ids: set[str], service_ids: set[str],
               winrm_ids: set[str], rdp_ids: set[str]) -> None:
    """Set each hop's protocol label from the evidence sets (see hops.classify_protocol)."""
    for hop in hops:
        hop.protocol, hop.protocol_evidence = classify_protocol(hop, winrm_ids, rdp_ids, share_ids, service_ids)


def run_checks(ctx: Context, keys_dir: Path | None) -> tuple[list[CheckResult], list[dict]]:
    """All LC checks for one trial; returns the results and the hop_candidates rows."""
    commands = load_commands(ctx, "LC-04")
    ctx.secrets = harvest_secrets(r.get("command_line") for r in commands)
    hop_rows, excluded = select_hop_logons(load_remote_4624(ctx, "LC-04"), ctx.params)
    hops = group_hop_instances(hop_rows, ctx.scenario, ctx.params)
    shares = load_shares(ctx)
    by_hop = shares_by_hop(hops, shares)
    services = load_services(ctx)
    winrm_ev, rdp_ev = winrm_evidence(ctx, hops), rdp_evidence(ctx, hops)
    label_hops(hops, set(by_hop), service_subject_hops(services, hops), winrm_ev.hop_ids, rdp_ev.hop_ids)
    logon_index = logons_by_host_id(load_all_4624(ctx, "LC-04"))
    by_host = commands_by_host(commands)
    explicit = load_explicit(ctx, "LC-04")

    lc04, evals = run_lc04(ctx, hops, by_host, logon_index, excluded, explicit)
    ctx.db.record("LC-06", normalise_sql(EXPLICIT_SQL))  # LC-06 reuses the LC-04e 4648 rows
    lc06, winrm_rows = run_lc06(ctx, hops, winrm_ev, logon_index, explicit)
    lc04h, rows_4648 = run_lc04h(ctx, hops, explicit, logon_index, evals)
    dump_data = load_dump_data(ctx)
    lc08, dump_sessions = run_lc08(ctx, dump_data)
    checks = [run_lc01(ctx), run_lc02(ctx), run_lc03(ctx), lc04, run_lc04b(ctx),
              run_lc04c(ctx, hops, shares, by_hop, services), run_lc04d(ctx, hops, by_host, logon_index, explicit), lc04h,
              run_lc05(ctx, rdp_ev), lc06, run_lc07(ctx), lc08, run_lc08b(ctx, dump_data, dump_sessions),
              run_lc09(ctx), run_lc10(ctx, keys_dir)]
    csv_rows = [row for h in hops for row in hop_csv_rows(ctx.trial_id, h, evals[h.hop_id])]
    csv_rows += winrm_rows + rows_4648  # LC-04h rows last: existing row order unchanged
    return checks, csv_rows


def lc11_result(before: str, after: str, out_dir: Path) -> CheckResult:
    """LC-11: SQL is stored per check, the DB hash is unchanged, outputs only in out_dir."""
    return CheckResult("LC-11", "Read-only run, SQL stored, outputs scoped", OK,
                       f"sha256 unchanged ({before[:12]}…); outputs in {out_dir.as_posix()}",
                       "Audit trail: every number in this report can be re-derived from the SQL shown.",
                       {"sha256_before": before, "sha256_after": after, "unchanged": before == after,
                        "open_mode": "file:...?mode=ro", "output_dir": out_dir.as_posix(),
                        "outputs": ["report.json", "report.md", "hop_candidates.csv"]})


def run_log_check(db_path: Path, trial_id: str, out_root: Path, windows_csv: Path | None,
                  keys_dir: Path | None, params: Params = DEFAULT_PARAMS) -> RunOutput:
    """Run every check on one trial DB and write out/log_check/<trial_id>/ (and nothing else)."""
    if not TRIAL_RE.match(trial_id):
        raise LogCheckError(f"trial id must look like s04_t00, got {trial_id!r}")
    if not db_path.is_file():
        raise LogCheckError(f"DB not found: {db_path}")
    scenario = scenario_of(trial_id)
    if scenario not in params.run_day:
        raise LogCheckError(f"no RUN_DAY for scenario {scenario}")
    before = sha256_file(db_path)
    conn = connect_ro(db_path)
    try:
        db = Db(conn)
        check_trial_matches_db(db, trial_id)
        window = build_window(db, trial_id, params, windows_csv, load_key_window(keys_dir, trial_id))
        ctx = Context(db, trial_id, scenario, params, window)
        checks, csv_rows = run_checks(ctx, keys_dir)
    finally:
        conn.close()
    after = sha256_file(db_path)
    if after != before:
        raise LogCheckError(f"DB changed during the run: {before} -> {after}")
    out_dir = out_root / trial_id
    checks.append(lc11_result(before, after, out_dir))
    report = build_json(trial_id, db_path.as_posix(), before, window, checks, db.sql_log, window.source)
    markdown = build_markdown(report, checks)
    csv_text = build_csv(csv_rows)
    files = write_outputs(out_dir, report, markdown, csv_text, ctx.secrets)
    return RunOutput(report, markdown, csv_text, files)
