"""CLI: ``python -m trial_window [--trials T ...] [--repo PATH] [--operator-times PATH] [--out PATH]`` (cwd=src).

Writes ``data/trial_windows.csv`` (spec 02_gate 2.1). Reads only the trial DBs (read-only, hash
before = after), ``data/manifest.csv`` and the optional operator times file.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Sequence

from answer_key import db
from answer_key.__main__ import read_manifest_span

from . import params
from .window import (WindowResult, computed_window, is_quarantined, operator_window, read_operator_times,
                     refusal, window_row, write_csv)

REPO = Path(__file__).resolve().parents[2]


def db_path(repo: Path, trial: str) -> Path:
    """Trial DB location: one DB per trial under data/processed (NF-09)."""
    return Path(repo) / params.PROCESSED_REL / f"{trial}.sqlite3"


def _is_operator_trial(trial: str) -> bool:
    """S01 is manual RDP with no agent (decision 035), so its window comes from the operator."""
    return trial.lower().startswith("s01_")


def window_for_trial(repo: Path, trial: str,
                     operator_times: Mapping[str, tuple[str, str]]) -> tuple[dict | None, WindowResult | None, str | None]:
    """(csv row, edges, skip reason) for one trial; exactly one of row / reason is set.

    WHY refusal twice: the id-only checks run before the DB is opened (no point loading a refused
    trial), and the date check needs the computed start (spec 2.2: date taken from the window start).
    """
    path = db_path(repo, trial)
    if is_quarantined(trial, path):
        return None, None, "quarantined trial (decision 030)"
    early = refusal(trial, None)
    if early:
        return None, None, early
    if not path.exists():
        return None, None, f"trial DB not found: {path}"
    span = read_manifest_span(Path(repo), trial)
    if _is_operator_trial(trial):
        if trial not in operator_times:
            return None, None, "no operator-recorded start/end"
        sha = db.sha256_file(path)
        result = operator_window(*operator_times[trial], span)
        source, rule = params.SOURCE_OPERATOR, params.RULE_OPERATOR
    else:
        with db.guarded(path) as (con, sha):
            rows = db.load_events(con)
        result = computed_window(rows, span)
        if result is None:
            return None, None, "no agent roots in the trial DB"
        source, rule = params.SOURCE_COMPUTED, params.RULE_COMPUTED
    reason = refusal(trial, result.start_utc)
    if reason:
        return None, result, reason
    return window_row(trial, result, source, rule, sha), result, None


def run(repo: Path, trials: Sequence[str], operator_times: Path, out: Path) -> dict:
    """Compute and write the window file; return {"rows", "skipped", "edges"} for callers and tests.

    Only written rows go to the CSV; skipped trials keep their reason so nothing is dropped silently.
    """
    ops = read_operator_times(operator_times)
    rows: list[dict] = []
    skipped: dict[str, str] = {}
    edges: dict[str, WindowResult] = {}
    for trial in dict.fromkeys(trials):          # de-duplicate, keep order
        row, result, reason = window_for_trial(Path(repo), trial, ops)
        if row is not None and result is not None:
            rows.append(row)
            edges[trial] = result
        else:
            skipped[trial] = reason or "unknown"
    rows.sort(key=lambda r: r["trial_id"])
    write_csv(rows, Path(out))
    return {"rows": rows, "skipped": skipped, "edges": edges}


def _report_lines(result: Mapping) -> list[str]:
    """One line per written row (trial, start, end, edge uids) and one per skipped trial."""
    lines = []
    for row in result["rows"]:
        e = result["edges"][row["trial_id"]]
        lines.append(f"{row['trial_id']}  {row['start_utc']} .. {row['end_utc']}  "
                     f"start_event_uid={e.start_event_uid}  end_event_uid={e.end_event_uid}")
    for trial, reason in result["skipped"].items():
        lines.append(f"{trial}  SKIPPED: {reason}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, print the report. Exit 0 when the run finished."""
    ap = argparse.ArgumentParser(prog="trial_window", description=__doc__)
    ap.add_argument("--trials", nargs="+", default=list(params.DEFAULT_TRIALS))
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--operator-times", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    ops = a.operator_times or repo / params.OPERATOR_TIMES_REL
    out = a.out or repo / params.WINDOWS_REL
    result = run(repo, a.trials, ops, out)
    for line in _report_lines(result):
        print(line)
    print(f"wrote {len(result['rows'])} row(s) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
