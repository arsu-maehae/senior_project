"""Core of the scorer: one trial in, every output text out (spec 05_score sections 2-5).

``run_trial`` does every refusal and every read first (allowlist before any file, SC-01; order table pin, SC-10;
inputs, columns and freshness, SC-02), then ``build_files`` builds all texts with the pure modules. Nothing is
written here. WHY: on any refusal nothing may be written, and ``--development`` must be able to build all nine trials
in memory before the first folder is touched.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from stitch.__main__ import file_facts, json_text

from .assemble import score_trial
from .inputs import ScoreInputs, check_allowlist, load_inputs
from .order import OrderReference, build_reference, load_order_table
from .outputs import (B0_COLUMNS, B0_FILE, IDENTITY_VALUES_COLUMNS, IDENTITY_VALUES_FILE, RANKED_COLUMNS, RANKED_FILE,
                      REPORT_FILE, RUN_INFO_FILE, STATS_FILE, STEPS_COLUMNS, STEPS_FILE, UNITS_COLUMNS, UNITS_FILE,
                      b0_rows, identity_value_rows, ranked_rows, step_rows, table, unit_rows)
from .params import SCORE_OUT_REL, TOOL_VERSION, ScoreParams
from .report import report_md, stats_dict

__all__ = ["TrialResult", "default_out_dir", "utc_now", "params_dict", "run_info", "build_files", "run_trial"]


@dataclass(frozen=True)
class TrialResult:
    """Everything one scored trial produced; ``files`` holds every output text, run_info.json included."""
    trial_id: str
    stats: Mapping[str, Any]
    files: Mapping[str, str]


def default_out_dir(repo: Path, trial_id: str) -> Path:
    """``out/score/<trial_id>`` (spec 3)."""
    return Path(repo) / SCORE_OUT_REL / trial_id


def utc_now() -> str:
    """Current UTC instant, for run_info.json only (the only timestamp anywhere, spec 3)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def params_dict(params: ScoreParams) -> dict[str, float]:
    """Parameters as JSON values, keys sorted (SC-42: written into stats.json and run_info.json)."""
    return dict(sorted(asdict(params).items()))


def run_info(trial_id: str, params: ScoreParams, order_sha: str, inp: ScoreInputs,
             files: Mapping[str, tuple[str, int | None]], generated_utc: str) -> dict[str, Any]:
    """The run_info.json dict: tool version, trial, timestamp (argument, so a test can fix it), parameters, order
    table SHA-256, the SHA-256 of every input file read (stitch and label), and every output file's SHA-256 and rows."""
    return {
        "tool_version": TOOL_VERSION, "trial_id": trial_id, "generated_utc": generated_utc,
        "parameters": params_dict(params), "order_table_sha256": order_sha,
        "inputs": {"stitch": dict(sorted(inp.stitch_sha256.items())),
                   "label": dict(sorted(inp.label_sha256.items()))},
        "files": file_facts(files),
    }


def build_files(inp: ScoreInputs, ref: OrderReference, params: ScoreParams, generated_utc: str) -> TrialResult:
    """Every output text of one trial. Pure (no disk access)."""
    ts = score_trial(inp, ref, params)
    tables: dict[str, tuple[str, int]] = {
        RANKED_FILE: table(RANKED_COLUMNS, ranked_rows(ts)),
        STEPS_FILE: table(STEPS_COLUMNS, step_rows(ts.paths)),
        UNITS_FILE: table(UNITS_COLUMNS, unit_rows(ts.paths)),
        IDENTITY_VALUES_FILE: table(IDENTITY_VALUES_COLUMNS, identity_value_rows(ts)),
        B0_FILE: table(B0_COLUMNS, b0_rows(ts)),
    }
    stats = stats_dict(ts, {n: k for n, (_t, k) in tables.items()}, params_dict(params), ref.table.sha256)
    files: dict[str, tuple[str, int | None]] = dict(tables)
    files[STATS_FILE] = (json_text(stats), None)
    files[REPORT_FILE] = (report_md(ts, stats), None)
    info = run_info(inp.trial_id, params, ref.table.sha256, inp, files, generated_utc)
    out = {name: text for name, (text, _n) in files.items()}
    out[RUN_INFO_FILE] = json_text(info)
    return TrialResult(trial_id=inp.trial_id, stats=stats, files=out)


def run_trial(repo: Path, trial_id: str, params: ScoreParams = ScoreParams(),
              ref: OrderReference | None = None, generated_utc: str | None = None) -> TrialResult:
    """All refusals and reads, then ``build_files``. Order: allowlist (SC-01, before any file); order table and its
    pin (SC-10) unless a reference is given; inputs (SC-02). Raises ScoreError; writes nothing."""
    check_allowlist(trial_id)
    reference = ref if ref is not None else build_reference(load_order_table())
    inp = load_inputs(Path(repo), trial_id)
    return build_files(inp, reference, params, generated_utc or utc_now())
