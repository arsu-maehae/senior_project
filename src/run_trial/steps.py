"""The steps of one trial and of the development summary, and their argv (RT-03, RT-06). Pure: nothing here
touches the disk or starts a process, so the exact command lines can be unit-tested.

WHY a ``Step`` carries its expected output files: the post-check (RT-09) needs to know which files the stage
documents, and keeping them beside the argv means one place says both what runs and what it must write.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from . import params as p

__all__ = ["Step", "trial_steps", "summary_steps", "step_argv", "display_argv", "expected_paths"]


@dataclass(frozen=True)
class Step:
    """One subprocess: ``python -m <module> <args...> --repo <abs repo>``.

    ``outputs`` are repo-relative POSIX paths of the files the step must (re)write (RT-09)."""
    name: str
    module: str
    args: tuple[str, ...]
    outputs: tuple[str, ...]


def _in(folder: Path, names: Sequence[str]) -> tuple[str, ...]:
    """Repo-relative POSIX paths of ``names`` inside ``folder``."""
    return tuple((folder / n).as_posix() for n in names)


def _trial_dir(stage: str, trial: str) -> Path:
    """``out/<stage>/<trial>`` (repo-relative)."""
    return p.STAGE_OUT_REL[stage] / trial


def trial_steps(trial: str, repo_abs: Path, stitch_disabled: Sequence[str] = ()) -> list[Step]:
    """The RT-03 steps of one trial, in run order.

    ``stitch_disabled`` (spec 06 AB-02): each name is passed to the stitch step only, as ``--disable-method <name>``;
    every other step is unchanged, so the ablation differs from the default chain in the stitch argv alone. Empty
    (the default) gives exactly the pre-ablation argv.

    gate gets an explicit absolute ``--out`` (RT-08: never a default); label recall runs only for keyed trials
    (``KEYED_DEVELOPMENT_TRIALS``: unkeyed trials get no ``label_recall.csv``, data-checker 2026-11-18). The
    allowlist is NOT checked here; the CLI checks it first (RT-01).
    """
    keyed = trial in p.KEYED_DEVELOPMENT_TRIALS
    gate_out = (Path(repo_abs) / p.STAGE_OUT_REL["gate"]).as_posix()
    ev = _trial_dir("evaluate", trial)
    steps = [
        Step("gate", "gate", ("--trial", trial, "--out", gate_out), _in(_trial_dir("gate", trial), p.GATE_FILES)),
        Step("stitch", "stitch", ("--trial", trial, *_disable_args(stitch_disabled)),
             _in(_trial_dir("stitch", trial), p.STITCH_FILES)),
        Step("label", "label", ("--trial", trial), _in(_trial_dir("label", trial), p.LABEL_FILES)),
        Step("score", "score", ("--trial", trial), _in(_trial_dir("score", trial), p.SCORE_FILES)),
        Step("evaluate", "evaluate", ("--trial", trial),
             _in(ev, p.EVAL_LINK_FILES_KEYED if keyed else p.EVAL_LINK_FILES_UNKEYED)),
    ]
    if keyed:
        steps.append(Step("evaluate_label_recall", "evaluate", ("--trial", trial, "--label-recall"),
                          _in(ev, (p.LABEL_RECALL_FILE,))))
    steps.append(Step("evaluate_rank", "evaluate", ("--trial", trial, "--rank"), _in(ev, (p.RANK_FILE,))))
    return steps


def _disable_args(names: Sequence[str]) -> tuple[str, ...]:
    """``--disable-method <name>`` for each name, sorted, so the argv does not depend on the input order. Pure."""
    return tuple(a for n in sorted(set(names)) for a in ("--disable-method", n))


def summary_steps(trials: Sequence[str] = p.DEVELOPMENT_TRIALS, with_results: bool = True) -> list[Step]:
    """The RT-06 summary steps after all development trials succeeded, with the files each one writes: the
    summary folder's files and, where the step rewrites them, every trial's file.

    ``with_results`` False (spec 06 AB-09, an ablation run) leaves out ``evaluate --development --results``: no
    ``dev_check`` verdict may be computed from an ablated stitch output."""
    summ = p.EVAL_SUMMARY_DIR
    keyed = [t for t in trials if t in p.KEYED_DEVELOPMENT_TRIALS]
    link = list(_in(summ, p.LINK_SUMMARY_FILES))
    for t in trials:
        link += _in(_trial_dir("evaluate", t),
                    p.EVAL_LINK_FILES_KEYED if t in p.KEYED_DEVELOPMENT_TRIALS else p.EVAL_LINK_FILES_UNKEYED)
    recall = list(_in(summ, (p.LABEL_RECALL_MD,)))
    recall += [x for t in keyed for x in _in(_trial_dir("evaluate", t), (p.LABEL_RECALL_FILE,))]
    sweep = list(_in(summ, p.RANK_SWEEP_SUMMARY_FILES))
    sweep += [x for t in trials for x in _in(_trial_dir("evaluate", t), (p.RANK_FILE,))]
    steps = [
        Step("evaluate_development", "evaluate", ("--development",), tuple(link)),
        Step("evaluate_development_label_recall", "evaluate", ("--development", "--label-recall"), tuple(recall)),
        Step("evaluate_development_rank_sweep", "evaluate", ("--development", "--rank-sweep"), tuple(sweep)),
    ]
    if with_results:
        steps.append(Step("evaluate_development_results", "evaluate", ("--development", "--results"),
                          _in(summ, p.RESULTS_FILES)))
    return steps


def step_argv(step: Step, python: str, repo_abs: Path) -> list[str]:
    """The exact command line: ``<python> -m <module> <args> --repo <abs repo>`` (RT-03, RT-08)."""
    return [python, "-m", step.module, *step.args, "--repo", Path(repo_abs).as_posix()]


def display_argv(step: Step, repo_abs: Path) -> list[str]:
    """The argv as written to run_log.json: ``python`` for the interpreter and ``<repo>`` for the repo path (also
    inside gate's ``--out``), so the log does not depend on the machine (the same spelling as ``stderr_tail``,
    RT-08)."""
    root = Path(repo_abs).as_posix()
    args = [a.replace(root, "<repo>", 1) if a.startswith(root) else a for a in step.args]
    return ["python", "-m", step.module, *args, "--repo", "<repo>"]


def expected_paths(step: Step, repo_abs: Path) -> list[Path]:
    """Absolute paths of the step's documented output files."""
    return [Path(repo_abs) / rel for rel in step.outputs]
