"""run_log.json / run_log.md texts (spec 06 section 3.2) and the runner's only writer (RT-08).

The text builders are pure (the timestamp is an argument). ``write_log`` refuses any path that does not lie inside
``<R>/out/run_trial/``: the runner itself never writes anywhere else (RT-08; stages write their own folders).
"""
from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import params as p
from .execute import StepRecord

__all__ = ["utc_now", "trial_log", "development_log", "json_text", "development_md", "log_dir", "write_log",
           "STAGE_COLUMNS", "scenario_of", "db_mb", "wall_stats", "scenario_rows"]

# The per-trial step columns of run_log.md, in run order (RT-03).
STAGE_COLUMNS: tuple[str, ...] = ("gate", "stitch", "label", "score", "evaluate", "evaluate_label_recall",
                                  "evaluate_rank")


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
                    summary: Sequence[StepRecord], generated_utc: str,
                    db_sizes: Mapping[str, int | None] | None = None,
                    stitch_disabled: Sequence[str] = ()) -> dict[str, Any]:
    """Development run_log.json object (spec 3.2, RT-06): ``trials`` in DEVELOPMENT_TRIALS order (the trials that
    ran), ``not_run_trials``, ``stopped_at`` = {trial, step} of the first stop or {}, ``summary_steps``. Pure.

    ``db_sizes`` (PT-02): trial -> DB size in bytes (stat only), written as ``db_size_bytes``; every development
    log, the default one included, gains this key (ATK-EV-46). ``stitch_disabled`` (AB-02) is written as
    ``stitch_disabled_methods`` only when non-empty, so only an ablation log carries that key."""
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
    out: dict[str, Any] = {"repo": repo_display, "tool_version": p.TOOL_VERSION, "generated_utc": generated_utc}
    if stitch_disabled:
        out["stitch_disabled_methods"] = sorted(set(stitch_disabled))
    out.update({"trials": list(trial_logs), "db_size_bytes": dict(db_sizes or {}), "not_run_trials": list(not_run),
                "stopped_at": stopped, "summary_steps": [r.as_dict() for r in summary], "status": status,
                "note": note})
    return out


def json_text(data: Mapping[str, Any]) -> str:
    """Indent 1, keys in insertion order (the spec's field order), one trailing newline."""
    return json.dumps(data, indent=1, ensure_ascii=False) + "\n"


def _ms(v: Any) -> str:
    """A wall_ms cell: the number, or ``-`` for a step that did not run / does not apply."""
    return "-" if v is None else str(v)


def scenario_of(trial: str) -> str:
    """``sNN`` of a trial id ``sNN_tMM`` (the part before the first underscore). Pure."""
    return trial.split("_", 1)[0]


def db_mb(size: int | None) -> str:
    """A DB size cell in MB = 10^6 bytes (PT-02; the unit is stated in run_log.md), 1 decimal; ``-`` if unknown.
    Pure."""
    return "-" if size is None else f"{size / p.DB_MB:.1f}"


def wall_stats(values: Sequence[int]) -> dict[str, Any]:
    """n, mean (1 decimal, ``math.fsum``), min and max of the wall times of one stage in one scenario; mean, min and
    max None when no trial ran it. Pure."""
    vals = list(values)
    if not vals:
        return {"n": 0, "mean": None, "min": None, "max": None}
    return {"n": len(vals), "mean": round(math.fsum(vals) / len(vals), 1), "min": min(vals), "max": max(vals)}


def _trial_walls(t: Mapping[str, Any]) -> dict[str, int]:
    """step -> wall_ms of the steps of one trial log that have a time (not run / not applicable left out)."""
    return {s["step"]: s["wall_ms"] for s in t["steps"] if s.get("wall_ms") is not None}


def scenario_rows(trial_logs: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """PT-01 / PT-02: one row per scenario (``sNN``, in first-seen order of the log): n trials, then per stage of
    ``STAGE_COLUMNS`` and for the per-trial total the ``wall_stats`` over the trials of that scenario that ran the
    stage. Only trials with status ok count, so a stopped trial's partial time cannot pull a mean down. Pure."""
    groups: dict[str, list[dict[str, int]]] = {}
    for t in trial_logs:
        if t["status"] == p.STATUS_OK:
            groups.setdefault(scenario_of(t["trial_id"]), []).append(_trial_walls(t))
    rows = []
    for scen, walls in groups.items():
        row: dict[str, Any] = {"scenario": scen, "n_trials": len(walls)}
        for c in STAGE_COLUMNS:
            row[c] = wall_stats([w[c] for w in walls if c in w])
        row["total_ms"] = wall_stats([sum(w.values()) for w in walls])
        rows.append(row)
    return rows


def _stat_cell(st: Mapping[str, Any], n_trials: int) -> str:
    """``mean (min–max)`` of one stage, or the single value when one trial ran it (ATK-EV-46: a range of one value
    says nothing); ``, k of n`` when only k of the scenario's n trials ran it; ``-`` if none."""
    if not st["n"]:
        return "-"
    cell = str(st["min"]) if st["n"] == 1 else f"{st['mean']:.1f} ({st['min']}–{st['max']})"
    return cell + (f", {st['n']} of {n_trials}" if st["n"] != n_trials else "")


def development_md(log: Mapping[str, Any]) -> str:
    """run_log.md: the per-stage processing time table (RT-07; handoff 14.2), one row per trial with its DB size
    (PT-02), the per-scenario table (PT-01 / PT-02: n trials, mean and min–max per stage and in total), then the
    summary steps. Machine-dependent measurement, so it is written only here and never copied into results files
    (RS-07). Pure."""
    cols = list(STAGE_COLUMNS)
    sizes = log.get("db_size_bytes") or {}
    lines = ["# Runner processing time per stage (development trials)", "",
             f"Tool {log['tool_version']}; generated {log['generated_utc']}; status **{log['status']}**.", ""]
    if log.get("stitch_disabled_methods"):
        lines += [f"**ABLATION run: stitch ran with --disable-method {', '.join(log['stitch_disabled_methods'])} "
                  "(spec 06 AB-02); `--results` was not run (AB-09).**", ""]
    lines += ["Wall-clock time of each stage subprocess in milliseconds (spec 06 RT-07). A machine-dependent "
              "measurement, not a result; `-` = not run or not applicable (label recall runs on keyed trials only). "
              "`db_MB` = size of the trial's SQLite DB in MB, 1 MB = 10^6 bytes (PT-02; file size only, the DB is not "
              "opened).",
              "", "| trial_id | status | db_MB | " + " | ".join(cols) + " | total_ms |",
              "|---|---|---|" + "---|" * len(cols) + "---|"]
    for t in log["trials"]:
        by = {s["step"]: s["wall_ms"] for s in t["steps"]}
        total = sum(v for v in by.values() if v is not None)
        lines.append(f"| {t['trial_id']} | {t['status']} | {db_mb(sizes.get(t['trial_id']))} | "
                     + " | ".join(_ms(by.get(c)) for c in cols) + f" | {total} |")
    for trial in log["not_run_trials"]:
        lines.append(f"| {trial} | not run | {db_mb(sizes.get(trial))} | " + " | ".join("-" for _ in cols) + " | - |")
    lines += ["", "## Processing time per scenario", "",
              "Per scenario (`sNN`): the number of trials with status ok, then for each stage and for the per-trial "
              "total the mean wall time in ms with its min–max over those trials (spec 06 PT-01, PT-02); a single "
              "value where one trial ran the step; `k of n` = only k of the n trials run that step. `total_ms` of a "
              "trial sums the steps it ran (label recall only on keyed trials), so totals of keyed and unkeyed "
              "trials cover different step sets. Machine-dependent; never copied into results.md (RS-07).", "",
              "| scenario | n_trials | " + " | ".join(cols) + " | total_ms |",
              "|---|---|" + "---|" * len(cols) + "---|"]
    for r in scenario_rows(log["trials"]):
        lines.append(f"| {r['scenario']} | {r['n_trials']} | "
                     + " | ".join(_stat_cell(r[c], r["n_trials"]) for c in cols)
                     + f" | {_stat_cell(r['total_ms'], r['n_trials'])} |")
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
