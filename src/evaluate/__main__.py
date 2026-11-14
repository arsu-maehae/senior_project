"""Link accuracy CLI (PLAN T7.6; decision 051), run from the repository root after ``pip install -e .``:

    python -m evaluate --trial <id> [--repo PATH] [--stitch-dir PATH] [--out PATH]
    python -m evaluate --development [--repo PATH]

``--trial`` evaluates one development trial into ``out/evaluate/<trial>/``; ``--development`` evaluates every
trial of ``clock_offset.params.DEVELOPMENT_TRIALS`` in order, then writes ``out/evaluate/development/`` (summary).

The allowlist is checked first, before any file is opened (decision 046 style; 051 item 1): a test trial or a
malformed id is refused with exit code 2 and nothing is created. Any other refusal (051 items 2 and 9) also exits 2
and writes nothing; with ``--development`` every trial is evaluated in memory first, so one refusal writes nothing
at all. Folders are rebuilt on each run through a temporary sibling and a rename.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .inputs import EvalError, check_trial_allowed, repo_relative
from .params import DEVELOPMENT_TRIALS, split_of
from .run import (default_out_dir, default_stitch_dir, evaluate_trial, summary_dir, summary_files, utc_now)
from .writers import replace_folder

REPO = Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    """Arguments: exactly one of --trial / --development."""
    ap = argparse.ArgumentParser(prog="evaluate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trial")
    mode.add_argument("--development", action="store_true")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--stitch-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    return ap


def _one(repo: Path, trial: str, stitch_dir: Path | None, out: Path | None) -> int:
    """Evaluate and write one trial; the allowlist check comes before anything else."""
    check_trial_allowed(trial)
    res = evaluate_trial(repo, trial, split_of(trial), stitch_dir or default_stitch_dir(repo, trial))
    target = out or default_out_dir(repo, trial)
    replace_folder(target, res.files)
    print(repo_relative(target, repo))
    return 0


def _development(repo: Path) -> int:
    """Evaluate all development trials in memory, then write each folder and the summary."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    results = [evaluate_trial(repo, t, split_of(t), default_stitch_dir(repo, t)) for t in DEVELOPMENT_TRIALS]
    for res in results:
        target = default_out_dir(repo, res.trial_id)
        replace_folder(target, res.files)
        print(repo_relative(target, repo))
    target = summary_dir(repo)
    replace_folder(target, summary_files(results, "development", utc_now()))
    print(repo_relative(target, repo))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 on success (prints the folders written), 2 on a refusal (reason on stderr, nothing written)."""
    a = _parser().parse_args(argv)
    repo = a.repo.resolve()
    try:
        if a.development:
            if a.stitch_dir is not None or a.out is not None:
                raise EvalError("refused: --stitch-dir and --out apply to --trial only")
            return _development(repo)
        return _one(repo, a.trial, a.stitch_dir, a.out)
    except EvalError as exc:
        print(str(exc) if str(exc).startswith("refused") else f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
