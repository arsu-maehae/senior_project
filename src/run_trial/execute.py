"""Run one step as a subprocess, time it, and decide its result (RT-03, RT-04, RT-07, RT-09).

The decision functions (``classify``, ``tail_text``, ``stale_or_missing``) are pure; ``run_step`` is the only place
that starts a process. WHY the post-check: exit 0 alone does not prove that a stage wrote its files (ATK-EV-11), so
a step is ``ok`` only if every documented output exists and was rewritten during the step.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import params as p
from .steps import Step, display_argv, expected_paths, step_argv

__all__ = ["StepRecord", "classify", "tail_text", "redact_repo", "stale_or_missing", "file_mtimes", "child_env",
           "kill_tree", "run_step", "not_run_record", "runner_exit_code"]


@dataclass
class StepRecord:
    """One entry of run_log.json ``steps`` (spec 3.2 fields, plus ``result``, ``post_check`` and ``note``, which say
    why a step is not ok or was not run)."""
    step: str
    argv: list[str]
    exit_code: int | None
    wall_ms: int | None
    stderr_tail: str
    result: str
    post_check: list[str] = field(default_factory=list)
    note: str = ""
    stdout: str = ""

    def as_dict(self) -> dict[str, Any]:
        """The JSON object of this step (stdout is printed, not logged)."""
        return {"step": self.step, "argv": list(self.argv), "exit_code": self.exit_code, "wall_ms": self.wall_ms,
                "stderr_tail": self.stderr_tail, "result": self.result, "post_check": list(self.post_check),
                "note": self.note}


def classify(exit_code: int, stderr: str, problems: Sequence[str]) -> str:
    """RT-04 / RT-09: ``refused`` for exit 2 (a stage's own refusal), ``failed`` for any other non-zero exit, for
    exit 2 whose stderr starts with ``usage:`` (argparse: a runner bug, not a refusal) and for exit 0 with a missing
    or stale output; else ``ok``. Pure."""
    if exit_code == 0:
        return p.STATUS_FAILED if problems else p.STATUS_OK
    if exit_code == p.EXIT_REFUSED and not stderr.lstrip().startswith("usage:"):
        return p.STATUS_REFUSED
    return p.STATUS_FAILED


def redact_repo(text: str, repo_abs: Path) -> str:
    """Replace every spelling of the repo path (backslashes or slashes; case-insensitive, as Windows paths are) by
    ``<repo>`` (RT-08), so a log does not carry the machine's folder names. Pure."""
    root = str(Path(repo_abs))
    variants = sorted({root, root.replace("\\", "/"), root.replace("/", "\\")}, key=len, reverse=True)
    out = text
    for v in variants:
        out = re.sub(re.escape(v), "<repo>", out, flags=re.IGNORECASE)
    return out


def tail_text(text: str, repo_abs: Path, n: int = p.STDERR_TAIL_LINES) -> str:
    """The last ``n`` non-empty-trailing lines of ``text`` with the repo path redacted (RT-04, RT-08). Pure."""
    lines = text.rstrip("\r\n").splitlines()
    return redact_repo("\n".join(lines[-n:]), repo_abs)


def file_mtimes(paths: Sequence[Path]) -> dict[Path, float | None]:
    """Modification time of each path (None if it does not exist). The only stat calls of the post-check."""
    out: dict[Path, float | None] = {}
    for path in paths:
        try:
            out[path] = path.stat().st_mtime
        except OSError:
            out[path] = None
    return out


def stale_or_missing(mtimes: Mapping[Path, float | None], started: float, repo_abs: Path,
                     slack: float = p.MTIME_SLACK_S) -> list[str]:
    """RT-09: one message per documented output that is missing or older than the step start (minus ``slack``,
    see ``params.MTIME_SLACK_S``). Pure."""
    out: list[str] = []
    for path, mtime in mtimes.items():
        rel = redact_repo(path.as_posix(), repo_abs)
        if mtime is None:
            out.append(f"missing: {rel}")
        elif mtime < started - slack:
            out.append(f"not rewritten during the step: {rel}")
    return out


def child_env(base: Mapping[str, str]) -> dict[str, str]:
    """The child's environment: the caller's, with UTF-8 standard streams, so that the dash and other non-ASCII
    characters in stage messages reach the log intact on a Windows console code page. Pure."""
    env = dict(base)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def kill_tree(proc: subprocess.Popen) -> None:
    """Terminate a running child and its own children, then wait for it (DR-05, ATK-EV-09). WHY taskkill /T on
    Windows: ``terminate`` stops only the direct child, and a stage started by the runner would keep its files
    open."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True, check=False)
    else:
        proc.terminate()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def run_step(step: Step, repo_abs: Path, *, python: str = sys.executable, cwd: Path = p.REPO,
             env: Mapping[str, str] | None = None) -> StepRecord:
    """Run one step and return its record. ``cwd`` is the code location; every path comes from ``--repo``
    (RT-03, RT-08). Wall time covers the subprocess only (RT-07). Ctrl-C terminates the child before re-raising."""
    argv = step_argv(step, python, repo_abs)
    started = time.time()
    t0 = time.perf_counter_ns()
    proc = subprocess.Popen(argv, cwd=str(cwd), env=child_env(env if env is not None else os.environ),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace")
    try:
        out, err = proc.communicate()
    except BaseException:
        kill_tree(proc)
        raise
    wall_ms = max(1, round((time.perf_counter_ns() - t0) / 1_000_000))
    problems = (stale_or_missing(file_mtimes(expected_paths(step, repo_abs)), started, repo_abs)
                if proc.returncode == 0 else [])
    result = classify(proc.returncode, err, problems)
    note = ""
    if proc.returncode == p.EXIT_REFUSED and result == p.STATUS_FAILED:
        note = "exit 2 with a usage message: the runner built a wrong command line (RT-09)"
    elif problems:
        note = "exit 0 but a documented output is missing or was not rewritten (RT-09)"
    return StepRecord(step=step.name, argv=display_argv(step, repo_abs), exit_code=proc.returncode,
                      wall_ms=wall_ms, stderr_tail=tail_text(err, repo_abs), result=result, post_check=problems,
                      note=note, stdout=redact_repo(out, repo_abs))


def not_run_record(step: Step, repo_abs: Path) -> StepRecord:
    """The record of a step after a stop (RT-10): no exit code, no time, with the note that earlier outputs remain."""
    return StepRecord(step=step.name, argv=display_argv(step, repo_abs), exit_code=None, wall_ms=None,
                      stderr_tail="", result=p.RESULT_NOT_RUN, note=p.NOT_RUN_NOTE)


def runner_exit_code(status: str, exit_code: int | None) -> int:
    """The runner's exit code for a stopped run (RT-04): 2 for ``refused``; for ``failed`` the stage's own non-zero
    code, except that a usage error (exit 2) or a post-check failure (exit 0) gives 1, so that the runner's exit 2
    always means "refused". 0 for ``ok``. Pure."""
    if status == p.STATUS_OK:
        return 0
    if status == p.STATUS_REFUSED:
        return p.EXIT_REFUSED
    if exit_code not in (None, 0, p.EXIT_REFUSED):
        return int(exit_code)
    return p.EXIT_FAILED
