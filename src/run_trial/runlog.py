"""run_log.json / run_log.md texts (spec 06 section 3.2) and the runner's only writer (RT-08).

The text builders are pure (the timestamp is an argument). ``write_log`` refuses any path that does not lie inside
``<R>/out/run_trial/``: the runner itself never writes anywhere else (RT-08; stages write their own folders).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import params as p
from .execute import StepRecord

__all__ = ["utc_now", "trial_log", "development_log", "json_text", "development_md", "log_dir", "write_log"]


def utc_now() -> str:
    """Current UTC instant (run logs only; never in a stage output)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stop(records: Sequence[StepRecord]) -> tuple[str, str]:
    """(status, name of the stopping step) of a list of records: the first record that is neither ok nor
    ``not run`` decides (RT-04)."""
    for r in records:
        if r.result in (p.STATUS_REFUSED, p.STATUS_FAILED):
            return r.result, r.step
    return p.STATUS_OK, ""


def trial_log(trial: str, repo_display: str, records: Sequence[StepRecord], generated_utc: str,
              note: str = "") -> dict[str, Any]:
    """Per-trial run_log.json object (spec 3.2): ``trial_id, repo, tool_version, generated_utc, steps, status,
    refused_step``; ``failed_step`` names a failed step the same way, ``note`` carries the RT-10 sentence. Pure."""
    status, stop = _stop(records)
    if status != p.STATUS_OK and not note:
        note = ("the run stopped at this step; later steps were not run and outputs from an earlier run remain in "
                "their folders (RT-10)")
    return {"trial_id": trial, "repo": repo_display, "tool_version": p.TOOL_VERSION, "generated_utc": generated_utc,
            "steps": [r.as_dict() for r in records], "status": status,
            "refused_step": stop if status == p.STATUS_REFUSED else "",
            "failed_step": stop if status == p.STATUS_FAILED else "", "note": note}


def development_log(repo_display: str, trial_logs: Sequence[Mapping[str, Any]], not_run: Sequence[str],
                    summary: Sequence[StepRecord], generated_utc: str) -> dict[str, Any]:
    """Development run_log.json object (spec 3.2, RT-06): ``trials`` in DEVELOPMENT_TRIALS order (the trials that
    ran), ``not_run_trials``, ``stopped_at`` = {trial, step} of the first stop or {}, ``summary_steps``. Pure."""
    stopped: dict[str, str] = {}
    status = p.STATUS_OK
    for t in trial_logs:
        if t["status"] != p.STATUS_OK:
            stopped = {"trial": t["trial_id"], "step": t["refused_step"] or t["failed_step"]}
            status = t["status"]
            break
    if not stopped:
        st, step = _stop(summary)
        if st != p.STATUS_OK:
            stopped, status = {"trial": p.DEVELOPMENT_DIR_NAME, "step": step}, st
    note = ""
    if stopped:
        note = ("the run stopped; later trials and steps, and the summary steps (incl. --results), were not run, "
                "so results.md was not regenerated from a partial chain; outputs from an earlier run remain (RT-10)")
    return {"repo": repo_display, "tool_version": p.TOOL_VERSION, "generated_utc": generated_utc,
            "trials": list(trial_logs), "not_run_trials": list(not_run), "stopped_at": stopped,
            "summary_steps": [r.as_dict() for r in summary], "status": status, "note": note}


def json_text(data: Mapping[str, Any]) -> str:
    """Indent 1, keys in insertion order (the spec's field order), one trailing newline."""
    return json.dumps(data, indent=1, ensure_ascii=False) + "\n"


def _ms(v: Any) -> str:
    """A wall_ms cell: the number, or ``-`` for a step that did not run / does not apply."""
    return "-" if v is None else str(v)


def development_md(log: Mapping[str, Any]) -> str:
    """run_log.md: the per-stage processing time table (RT-07; handoff 14.2), one row per trial, then the summary
    steps. Machine-dependent measurement, so it is written only here and never copied into results files (RS-07).
    Pure."""
    cols = ["gate", "stitch", "label", "score", "evaluate", "evaluate_label_recall", "evaluate_rank"]
    lines = ["# Runner processing time per stage (development trials)", "",
             f"Tool {log['tool_version']}; generated {log['generated_utc']}; status **{log['status']}**.", "",
             "Wall-clock time of each stage subprocess in milliseconds (spec 06 RT-07). A machine-dependent "
             "measurement, not a result; `-` = not run or not applicable (label recall runs on keyed trials only).",
             "", "| trial_id | status | " + " | ".join(cols) + " | total_ms |",
             "|---|---|" + "---|" * len(cols) + "---|"]
    for t in log["trials"]:
        by = {s["step"]: s["wall_ms"] for s in t["steps"]}
        total = sum(v for v in by.values() if v is not None)
        lines.append(f"| {t['trial_id']} | {t['status']} | " + " | ".join(_ms(by.get(c)) for c in cols)
                     + f" | {total} |")
    for trial in log["not_run_trials"]:
        lines.append(f"| {trial} | not run | " + " | ".join("-" for _ in cols) + " | - |")
    lines += ["", "## Summary steps", "", "| step | result | wall_ms |", "|---|---|---|"]
    for s in log["summary_steps"]:
        lines.append(f"| {s['step']} | {s['result']} | {_ms(s['wall_ms'])} |")
    if log["stopped_at"]:
        lines += ["", f"Stopped at trial {log['stopped_at']['trial']}, step {log['stopped_at']['step']}. "
                      f"{log['note']}"]
    return "\n".join(lines) + "\n"


def log_dir(repo_abs: Path, name: str) -> Path:
    """``<R>/out/run_trial/<name>`` (name = trial id or ``development``)."""
    return Path(repo_abs) / p.RUN_TRIAL_OUT_REL / name


def _inside(path: Path, root: Path) -> bool:
    """True iff ``path`` lies strictly inside ``root`` (both resolved; case-insensitive on Windows)."""
    a, b = os.path.normcase(str(path.resolve())), os.path.normcase(str(root.resolve()))
    return a.startswith(b.rstrip("\\/") + os.sep)


def write_log(repo_abs: Path, name: str, files: Mapping[str, str]) -> Path:
    """Write ``files`` into ``<R>/out/run_trial/<name>/`` (UTF-8, ``\\n``), each through a temporary file and a
    replace, so a reader never sees half a log. Raises ValueError for any target outside ``<R>/out/run_trial/``
    (RT-08)."""
    root = Path(repo_abs) / p.RUN_TRIAL_OUT_REL
    target = log_dir(repo_abs, name)
    if not _inside(target, root):
        raise ValueError(f"refusing to write outside {root}: {target}")
    target.mkdir(parents=True, exist_ok=True)
    for fname, text in files.items():
        dest = target / fname
        if not _inside(dest, root):
            raise ValueError(f"refusing to write outside {root}: {dest}")
        tmp = target / f".{fname}.tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, dest)
    return target
