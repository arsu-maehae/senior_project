"""Core of the labeller: one trial in, every output text out (spec 04_label sections 2-4).

``label_trial`` does every refusal and every read first (allowlist before any file, LB-00; gate, clock, stitch and
rule checks; the DB hash bracket), then builds all texts with the pure modules. Nothing is written here. WHY: on any
refusal nothing may be written (spec 2), and ``--development`` must be able to build all nine trials in memory
before the first folder is touched.
"""
from __future__ import annotations

from dataclasses import dataclass, fields as dc_fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from gate.run import display_path
from stitch.__main__ import file_facts, json_text
from stitch.check_index import window_summary
from stitch.index import jsonable
from stitch.inputs import CheckedInputs, TrialPaths

from .events import count_keys
from .inputs import (DbRead, StitchData, check_allowed, check_allowlist, check_stitch_fresh, load_stitch,
                     read_events, stitch_dir, trial_paths)
from .join import hop_label_rows, label_facts, node_label_rows, stitch_copy_groups
from .labels import Match, apply_rules, wanted
from .outputs import (EVENT_COLUMNS, EVENT_LABELS_FILE, HOP_COLUMNS, HOP_LABELS_FILE, NODE_COLUMNS,
                      NODE_LABELS_FILE, REPORT_FILE, RULES_MANIFEST_FILE, RUN_INFO_FILE, STATS_FILE,
                      event_label_rows, table)
from .params import LABEL_OUT_REL, RULES_DIR, TOOL_VERSION, LabelParams
from .report import hop_counts, label_counts, node_counts, report_md, stats_dict
from .rules import RuleSet, load_rules

__all__ = ["TrialResult", "default_out_dir", "params_dict", "label_trial", "build_files", "run_info", "utc_now"]


@dataclass(frozen=True)
class TrialResult:
    """Everything one labelled trial produced; ``files`` holds every output text, run_info.json included."""
    trial_id: str
    stats: Mapping[str, Any]
    files: Mapping[str, str]


def default_out_dir(repo: Path, trial_id: str) -> Path:
    """``out/label/<trial_id>`` (spec 3.4)."""
    return Path(repo) / LABEL_OUT_REL / trial_id


def utc_now() -> str:
    """Current UTC instant, for run_info.json only (never in another file)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def params_dict(params: LabelParams) -> dict[str, Any]:
    """Parameters as JSON-ready values (sorted mappings)."""
    return {f.name: jsonable(getattr(params, f.name)) for f in dc_fields(params)}


def run_info(trial_id: str, params: LabelParams, db_display: str, db: DbRead, checked: CheckedInputs,
             stitch: StitchData, rules: RuleSet, files: Mapping[str, tuple[str, int | None]],
             generated_utc: str) -> dict[str, Any]:
    """The run_info.json dict. Pure: the timestamp is an argument. It pins every input: DB hash before / after, gate
    stats hash, the SHA-256 of each stitch file read, the rules manifest hash and each rule file hash (LB-10)."""
    return jsonable({
        "tool_version": TOOL_VERSION,
        "trial_id": trial_id,
        "generated_utc": generated_utc,
        "parameters": params_dict(params),
        "db": {"path": db_display, "sha256_before": db.sha_before, "sha256_after": db.sha_after},
        "gate_stats_sha256": checked.gate_stats_sha256,
        "stitch_files_sha256": dict(stitch.file_sha256),
        "rules_manifest_sha256": rules.manifest_sha256,
        "rules_sha256": {r["rule_id"]: r["sha256"] for r in rules.manifest_rows},
        "window": window_summary(checked.window_row),
        "files": file_facts(files),
    })


def build_files(repo: Path, trial_id: str, paths: TrialPaths, checked: CheckedInputs, stitch: StitchData,
                rules: RuleSet, db: DbRead, params: LabelParams, generated_utc: str) -> TrialResult:
    """Every output text of one trial. Pure (no disk access); ``repo`` only shapes the DB display path."""
    events = db.scan.events
    matches: list[Match] = apply_rules(events, rules.rules)
    keys = count_keys(events, params.process_collapse_s, params.service_pair_s)
    facts = label_facts(matches)
    copies = stitch_copy_groups(stitch.hops)
    in_window = frozenset(u for e in events for u in e.uids)
    node_rows = node_label_rows(stitch.path_nodes, facts, copies)
    hop_rows = hop_label_rows(stitch.hops, node_rows, stitch.hop_identity, facts, copies, in_window)
    tables = {EVENT_LABELS_FILE: table(EVENT_COLUMNS, event_label_rows(trial_id, matches, keys)),
              NODE_LABELS_FILE: table(NODE_COLUMNS, node_rows),
              HOP_LABELS_FILE: table(HOP_COLUMNS, hop_rows),
              RULES_MANIFEST_FILE: (rules.manifest_text, len(rules.manifest_rows))}
    db_display = display_path(paths.db, repo)
    stats = stats_dict(trial_id, TOOL_VERSION, db_display, db.sha_before, db.sha_after, rules.manifest_sha256,
                       window_summary(checked.window_row), db.scan, label_counts(matches, rules.rules, keys),
                       node_counts(node_rows), hop_counts(hop_rows), {n: k for n, (_t, k) in tables.items()},
                       params_dict(params))
    files: dict[str, tuple[str, int | None]] = dict(tables)
    files[STATS_FILE] = (json_text(stats), None)
    files[REPORT_FILE] = (report_md(stats, rules.rules), None)
    info = run_info(trial_id, params, db_display, db, checked, stitch, rules, files, generated_utc)
    out = {name: text for name, (text, _n) in files.items()}
    out[RUN_INFO_FILE] = json_text(info)
    return TrialResult(trial_id=trial_id, stats=stats, files=out)


def label_trial(repo: Path, trial_id: str, params: LabelParams = LabelParams(), rules_dir: Path = RULES_DIR,
                generated_utc: str | None = None) -> TrialResult:
    """All refusals and reads, then ``build_files``. Order: allowlist (no file touched before it, LB-00); gate,
    window and clock checks (``stitch.inputs.check_allowed``); stitch outputs present, with the columns the join
    reads and the hashes their run_info records; the stitch run read the current gate stats and clock files (S05);
    rule files and manifest against their pins (LB-10, S01); the DB hash bracket. Raises LabelError on any
    refusal; writes nothing."""
    check_allowlist(trial_id)
    repo = Path(repo)
    paths = trial_paths(repo, trial_id)
    checked = check_allowed(paths)
    stitch = load_stitch(stitch_dir(repo, trial_id))
    check_stitch_fresh(stitch.run_info, checked)
    rules = load_rules(rules_dir)
    db = read_events(checked, paths, stitch.run_info, wanted(rules.rules))
    return build_files(repo, trial_id, paths, checked, stitch, rules, db, params, generated_utc or utc_now())
