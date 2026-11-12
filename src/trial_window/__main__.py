"""CLI: ``python -m trial_window [--trials T ...] [--repo PATH] [--operator-times PATH] [--out PATH]`` (cwd=src).

Writes ``data/trial_windows.csv`` (spec 02_gate 2.1) on the corrected time basis (T6b.2, decision 043).
Reads only the trial DBs (read-only, hash before = after), ``data/manifest.csv``, the optional operator
times file and each trial's ``data/processed/<trial>.clock_offsets.csv`` / ``.clock_changes.csv``. A
missing DB for an allowed trial is a hard error (exit 2, no output file); refused trials (including a
missing or mismatching clock file, a clock-only trial, CO-17) are reported as SKIPPED.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Collection, Mapping, Sequence

from answer_key import db
from lab_common.manifest import read_manifest_rows, read_manifest_span

from . import params
from .window import (ClockFiles, TrialWindowError, WindowResult, clock_changes_path, clock_columns, computed_window,
                     corrected_manifest_span, corrected_rows, is_quarantined, load_clock_files,
                     manifest_coverage_reason, offsets_path, operator_window, raw_manifest_span_hosts,
                     read_operator_times, refusal, window_edge_hosts, window_row, write_csv)

REPO = Path(__file__).resolve().parents[2]


def db_path(repo: Path, trial: str) -> Path:
    """Trial DB location: one DB per trial under data/processed (NF-09)."""
    return Path(repo) / params.PROCESSED_REL / f"{trial}.sqlite3"


def _is_operator_trial(trial: str) -> bool:
    """S01 is manual RDP with no agent (decision 035), so its window comes from the operator."""
    return trial.lower().startswith("s01_")


def _refused_early(repo: Path, trial: str, *, excluded_trials: Collection[str],
                   clock_only_trials: Collection[str]) -> str | None:
    """Refusals that need no DB and no file (quarantine, decision 019 exclusion, clock-only trial).

    WHY first: refused trials must never raise for a missing DB and are not worth opening.
    """
    if is_quarantined(trial, db_path(repo, trial), repo):
        return "quarantined trial (decision 030)"
    return refusal(trial, None, excluded_trials=excluded_trials, clock_only_trials=clock_only_trials)


def require_db(repo: Path, trial: str) -> Path:
    """Path of the trial DB, or TrialWindowError if it is missing (an allowed trial must have one)."""
    path = db_path(repo, trial)
    if not path.exists():
        raise TrialWindowError(f"trial DB not found: {path}")
    return path


def _check_basis(time_basis: str) -> None:
    """Only the two documented bases exist; anything else is a programming error, never a guess."""
    if time_basis not in params.TIME_BASES:
        raise ValueError(f"unknown time basis {time_basis!r}; expected one of {params.TIME_BASES}")


def _clock_for(repo: Path, trial: str, time_basis: str) -> ClockFiles | None:
    """The trial's clock files on the corrected basis; None on the raw basis (GTA-06 only: no offsets)."""
    if time_basis == params.TIME_BASIS_RAW:
        return None
    return load_clock_files(offsets_path(repo, trial), clock_changes_path(repo, trial))


def manifest_span(repo: Path, trial: str, clock: ClockFiles | None) -> tuple[dict | None, list[str]]:
    """(export span used for the clip and the coverage check, notes to report) for one trial.

    Raw basis (``clock`` None): exactly ``read_manifest_span`` as before (GTA-06 must reproduce the
    baseline), plus the hosts of the files that set its ends. Corrected basis: every file's span shifted by
    its own host's offset, min/max as instants (owner, T6b.2); a manifest host with no offsets row is
    reported in the notes and stays raw.
    """
    rows = read_manifest_rows(repo, trial)
    if clock is None or clock.offsets is None:
        span = read_manifest_span(repo, trial)
        if span is None:
            return None, []
        start_host, end_host = raw_manifest_span_hosts(rows, span)
        return {**span, "start_host": start_host, "end_host": end_host}, []
    span = corrected_manifest_span(rows, clock.offsets)
    notes = [] if span is None or not span["unmapped_hosts"] else [
        f"manifest host(s) {', '.join(span['unmapped_hosts'])} have no row in {clock.offsets_path.name}; "
        f"their export span is used raw"]
    return span, notes


def window_for_trial(repo: Path, trial: str, operator_times: Mapping[str, tuple[str, str]], *,
                     excluded_trials: Collection[str] = params.EXCLUDED_TRIALS,
                     clock_only_trials: Collection[str] = params.CLOCK_ONLY_TRIALS,
                     time_basis: str = params.TIME_BASIS,
                     ) -> tuple[dict | None, WindowResult | None, str | None, list[str]]:
    """(csv row, edges, skip reason, notes) for one trial; exactly one of row / reason is set. ``notes`` are
    things to report that do not stop the trial (a manifest host without an offsets row).

    Raises TrialWindowError if the trial passes the early refusals but has no DB.
    WHY refusal three times: the id-only checks run before the DB is opened (no point loading a refused
    trial); a missing clock file is known before the DB is read; the offsets-vs-DB hash needs the DB hash
    and CO-17 needs the computed (corrected) start (spec 2, 2.2 as amended in T6b.2).
    On the corrected basis every row's time is corrected (``corrected_rows``) before the agent tree is
    walked, and the manifest export span is corrected per host (``manifest_span``); ``time_basis="raw"``
    skips the offsets, uses the raw span and leaves the clock columns empty (GTA-06 only).
    """
    _check_basis(time_basis)
    repo = Path(repo)
    early = _refused_early(repo, trial, excluded_trials=excluded_trials, clock_only_trials=clock_only_trials)
    if early:
        return None, None, early, []
    path = require_db(repo, trial)
    clock = _clock_for(repo, trial, time_basis)
    flags = {"excluded_trials": excluded_trials, "clock_only_trials": clock_only_trials, "clock": clock}
    pre = refusal(trial, None, **flags)
    if pre:
        return None, None, pre, []
    span, notes = manifest_span(repo, trial, clock)
    start_host = end_host = ""
    if _is_operator_trial(trial):
        if trial not in operator_times:
            return None, None, "no operator-recorded start/end", notes
        sha = db.sha256_file(path)
        result = operator_window(*operator_times[trial], span)
        source, rule = params.SOURCE_OPERATOR, params.RULE_OPERATOR
    else:
        with db.guarded(path) as (con, sha):
            rows = db.load_events(con)
        if clock is not None and clock.offsets is not None:
            rows = corrected_rows(rows, clock.offsets)
        result = computed_window(rows, span)
        if result is None:
            return None, None, "no agent roots in the trial DB", notes
        start_host, end_host = window_edge_hosts(rows, result, span)
        source, rule = params.SOURCE_COMPUTED, params.RULE_COMPUTED
    reason = (refusal(trial, result.start_utc, db_sha256=sha, **flags)
              or manifest_coverage_reason(result, span, trial))
    if reason:
        return None, result, reason, notes
    row = window_row(trial, result, source, rule, sha, time_basis, clock_columns(clock), start_host, end_host)
    return row, result, None, notes


def run(repo: Path, trials: Sequence[str], operator_times: Path, out: Path, *,
        excluded_trials: Collection[str] = params.EXCLUDED_TRIALS,
        clock_only_trials: Collection[str] = params.CLOCK_ONLY_TRIALS,
        time_basis: str = params.TIME_BASIS) -> dict:
    """Compute and write the window file; return {"rows", "skipped", "edges", "notes"} for callers and tests.

    Every needed DB is checked before any trial is processed, so a missing DB raises
    TrialWindowError and no output file (not even a partial one) is written. Only written rows go
    to the CSV; skipped trials keep their reason so nothing is dropped silently. ``time_basis="raw"``
    exists only for the GTA-06 test (spec 02_gate GTA-06; the CLI always writes the corrected basis).
    """
    _check_basis(time_basis)
    repo = Path(repo)
    flags = {"excluded_trials": excluded_trials, "clock_only_trials": clock_only_trials}
    wanted = list(dict.fromkeys(trials))          # de-duplicate, keep order
    for trial in wanted:
        if not _refused_early(repo, trial, **flags):
            require_db(repo, trial)
    ops = read_operator_times(operator_times)
    rows: list[dict] = []
    skipped: dict[str, str] = {}
    edges: dict[str, WindowResult] = {}
    notes: dict[str, list[str]] = {}
    for trial in wanted:
        row, result, reason, trial_notes = window_for_trial(repo, trial, ops, time_basis=time_basis, **flags)
        if trial_notes:
            notes[trial] = trial_notes
        if row is not None and result is not None:
            rows.append(row)
            edges[trial] = result
        else:
            skipped[trial] = reason or "unknown"
    rows.sort(key=lambda r: r["trial_id"])
    write_csv(rows, Path(out))
    return {"rows": rows, "skipped": skipped, "edges": edges, "notes": notes}


def _report_lines(result: Mapping) -> list[str]:
    """One line per written row (trial, start, end, edge uids) and one per skipped trial."""
    lines = []
    for row in result["rows"]:
        e = result["edges"][row["trial_id"]]
        lines.append(f"{row['trial_id']}  {row['start_utc']} .. {row['end_utc']}  ({row['time_basis']})  "
                     f"start_event_uid={e.start_event_uid}  end_event_uid={e.end_event_uid}  "
                     f"start_host={row['start_host'] or '-'}"
                     f"{' (manifest clip)' if e.clipped_by_manifest_start else ''}  "
                     f"end_host={row['end_host'] or '-'}{' (manifest clip)' if e.clipped_by_manifest_end else ''}  "
                     f"clock_flag={row['clock_flag'] or '-'}  "
                     f"clock_change_in_window={row['clock_change_in_window'] or '-'}")
    for trial, reason in result["skipped"].items():
        lines.append(f"{trial}  SKIPPED: {reason}")
    for trial, trial_notes in result.get("notes", {}).items():
        lines.extend(f"{trial}  NOTE: {n}" for n in trial_notes)
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run, print the report. Exit 0 when the run finished, 2 on TrialWindowError."""
    ap = argparse.ArgumentParser(prog="trial_window", description=__doc__)
    ap.add_argument("--trials", nargs="+", default=list(params.DEFAULT_TRIALS))
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--operator-times", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)
    repo = a.repo.resolve()
    ops = a.operator_times or repo / params.OPERATOR_TIMES_REL
    out = a.out or repo / params.WINDOWS_REL
    try:
        result = run(repo, a.trials, ops, out)
    except TrialWindowError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for line in _report_lines(result):
        print(line)
    print(f"wrote {len(result['rows'])} row(s) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
