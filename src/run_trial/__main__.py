"""Runner CLI (spec 06_evaluate section 4 B, RT-01..RT-11), run from the repository root after ``pip install -e .``:

    python -m run_trial --trial <t> [--repo R]
    python -m run_trial --development [--repo R]

``--trial`` rebuilds one development trial: gate -> stitch -> label -> score -> evaluate (link accuracy, label
recall for keyed trials, rank), each as ``python -m <stage> ... --repo <abs R>``, and writes
``<R>/out/run_trial/<t>/run_log.json``. ``--development`` does this for every trial of
``clock_offset.params.DEVELOPMENT_TRIALS`` in order, stops at the first trial that does not succeed, and after all
succeed runs ``evaluate --development`` (link accuracy, ``--label-recall``, ``--rank-sweep``, ``--results``); it writes
``<R>/out/run_trial/development/run_log.json`` and ``run_log.md`` (processing time per stage).

Order of checks: the allowlist (RT-01) before anything else, so a test trial creates nothing and no file of it is
opened; then the repo shape (RT-08); then the presence of the DB, the clock files and the window row (RT-02), which
prints the commands that create anything missing. Every stage keeps its own refusals (RT-04). The runner never runs
``clock_offset``, ``trial_window`` or ingest, never deletes or edits stage outputs (RT-05), and writes only
``<R>/out/run_trial/`` itself (RT-08). Exit 0 = every step ok; 2 = refused (by the runner or a stage); 1 or the
stage's code = failed.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from . import params as p
from .checks import allowlist_refusal, presence_facts, presence_refusal, repo_refusal
from .execute import StepRecord, not_run_record, redact_repo, run_step, runner_exit_code
from .runlog import development_log, development_md, json_text, trial_log, utc_now, write_log
from .steps import Step, summary_steps, trial_steps

__all__ = ["RunFn", "run_steps", "run_trial", "run_development", "main"]

# A function that runs one step (``execute.run_step`` in production; a fake in unit tests).
RunFn = Callable[[Step, Path], StepRecord]


def _parser() -> argparse.ArgumentParser:
    """Exactly one of --trial / --development; --repo defaults to the code location."""
    ap = argparse.ArgumentParser(prog="run_trial", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trial")
    mode.add_argument("--development", action="store_true")
    ap.add_argument("--repo", default=None, help="repository root holding data/ and out/ (default: this checkout)")
    return ap


def _say(rec: StepRecord, trial: str) -> None:
    """One progress line per step on stdout; the stage's own stdout indented below it; the stderr tail of a stopping
    step on stderr (RT-04)."""
    ms = "" if rec.wall_ms is None else f", {rec.wall_ms} ms"
    print(f"[{trial}] {rec.step}: {rec.result} (exit {rec.exit_code}{ms})", flush=True)
    for line in rec.stdout.splitlines():
        print(f"    {line}")
    if rec.result in (p.STATUS_REFUSED, p.STATUS_FAILED):
        print(f"[{trial}] stopped at step {rec.step}, exit {rec.exit_code}: {rec.result}", file=sys.stderr)
        for line in rec.post_check:
            print(f"    {line}", file=sys.stderr)
        if rec.stderr_tail:
            print(rec.stderr_tail, file=sys.stderr)


def run_steps(steps: Sequence[Step], repo_abs: Path, run_fn: RunFn, label: str) -> list[StepRecord]:
    """Run ``steps`` in order and stop at the first step that is not ok (RT-04); every later step is recorded as
    ``not run`` (RT-10)."""
    records: list[StepRecord] = []
    for i, step in enumerate(steps):
        rec = run_fn(step, repo_abs)
        records.append(rec)
        _say(rec, label)
        if rec.result != p.STATUS_OK:
            records += [not_run_record(s, repo_abs) for s in steps[i + 1:]]
            break
    return records


def _presence_record(text: str, repo_abs: Path) -> StepRecord:
    """The pseudo-step of an RT-02 refusal: no subprocess, exit 2, the refusal text as stderr tail."""
    return StepRecord(step=p.PRESENCE_STEP, argv=[], exit_code=p.EXIT_REFUSED, wall_ms=None,
                      stderr_tail=redact_repo(text, repo_abs), result=p.STATUS_REFUSED)


def run_trial(trial: str, repo_abs: Path, repo_display: str, run_fn: RunFn = run_step) -> tuple[dict[str, Any], int]:
    """RT-02..RT-04 for one trial already accepted by RT-01: presence check, the steps, the log. Returns
    (run_log object, exit code) and writes ``<R>/out/run_trial/<t>/run_log.json``."""
    steps = trial_steps(trial, repo_abs)
    refusal = presence_refusal(trial, presence_facts(repo_abs, trial))
    if refusal:
        print(refusal, file=sys.stderr)
        records = [_presence_record(refusal, repo_abs)] + [not_run_record(s, repo_abs) for s in steps]
    else:
        records = run_steps(steps, repo_abs, run_fn, trial)
    log = trial_log(trial, repo_display, records, utc_now())
    write_log(repo_abs, trial, {p.RUN_LOG_JSON: json_text(log)})
    stop = next((r for r in records if r.result in (p.STATUS_REFUSED, p.STATUS_FAILED)), None)
    return log, runner_exit_code(log["status"], stop.exit_code if stop else 0)


def run_development(repo_abs: Path, repo_display: str, run_fn: RunFn = run_step,
                    trials: Sequence[str] = p.DEVELOPMENT_TRIALS) -> tuple[dict[str, Any], int]:
    """RT-06: every development trial in order, stop at the first one that is not ok (naming trial and step), then
    the summary steps only if all succeeded; writes the development run_log.json and run_log.md."""
    logs: list[dict[str, Any]] = []
    code = 0
    for i, trial in enumerate(trials):
        refusal = allowlist_refusal(trial)       # RT-01 also here: the list is imported, but stay explicit
        if refusal:
            print(refusal, file=sys.stderr)
            return {}, p.EXIT_REFUSED
        log, code = run_trial(trial, repo_abs, repo_display, run_fn)
        logs.append(log)
        if code != 0:
            stop = log["refused_step"] or log["failed_step"]
            print(f"development run stopped at trial {trial}, step {stop} (exit {code})", file=sys.stderr)
            break
    not_run = list(trials[len(logs):])
    summary = summary_steps(trials)
    records = (run_steps(summary, repo_abs, run_fn, p.DEVELOPMENT_DIR_NAME) if code == 0
               else [not_run_record(s, repo_abs) for s in summary])
    dev = development_log(repo_display, logs, not_run, records, utc_now())
    write_log(repo_abs, p.DEVELOPMENT_DIR_NAME, {p.RUN_LOG_JSON: json_text(dev), p.RUN_LOG_MD: development_md(dev)})
    if code == 0:
        stop = next((r for r in records if r.result in (p.STATUS_REFUSED, p.STATUS_FAILED)), None)
        code = runner_exit_code(dev["status"], stop.exit_code if stop else 0)
    return dev, code


def main(argv: Sequence[str] | None = None, run_fn: RunFn = run_step) -> int:
    """Parse, check RT-01 first, then RT-08, then run. Returns the exit code (0 ok, 2 refused, else failed)."""
    a = _parser().parse_args(argv)
    if a.trial is not None:
        refusal = allowlist_refusal(a.trial)
        if refusal:
            print(refusal, file=sys.stderr)
            return p.EXIT_REFUSED
    repo_display = "." if a.repo is None else a.repo
    repo_abs = p.REPO if a.repo is None else Path(a.repo).resolve()
    bad = repo_refusal(repo_abs)
    if bad:
        print(bad, file=sys.stderr)
        return p.EXIT_REFUSED
    if a.development:
        _dev, code = run_development(repo_abs, repo_display, run_fn)
    else:
        _log, code = run_trial(a.trial, repo_abs, repo_display, run_fn)
    print(f"run_trial: exit {code}; log in out/run_trial/{a.trial or p.DEVELOPMENT_DIR_NAME}/")
    return code


if __name__ == "__main__":
    sys.exit(main())
