"""Link accuracy CLI (PLAN T7.6; decision 051), run from the repository root after ``pip install -e .``:

    python -m evaluate --trial <id> [--repo PATH] [--stitch-dir PATH] [--out PATH]
    python -m evaluate --development [--repo PATH]
    python -m evaluate --label-recall --trial <id> [--repo PATH] [--out PATH]
    python -m evaluate --label-recall --development [--repo PATH]
    python -m evaluate --rank --trial <id> [--repo PATH] [--out PATH]
    python -m evaluate --rank --development [--repo PATH]
    python -m evaluate --rank-sweep --development [--repo PATH]
    python -m evaluate --results --development [--repo PATH]

``--trial`` evaluates one development trial into ``out/evaluate/<trial>/``; ``--development`` evaluates every
trial of ``clock_offset.params.DEVELOPMENT_TRIALS`` in order, then writes ``out/evaluate/development/`` (summary).
A ``--out`` folder is checked before anything is written (``lab_common.outdir``, decision 054; review ATK-17): inside
the repository it must lie strictly below ``out/``, and an existing folder may hold only the trial file names
(``OUT_ALLOWED_FILES``), because the folder swap deletes the old folder.

``--label-recall`` (PLAN T8.3; spec 04 LBA-04) runs the labelling recall instead of the link accuracy: it reads
``out/label/<trial>/`` and the approved key, writes ``label_recall.csv`` into the trial folder of each keyed trial
(a trial without a key gets no file) and, with ``--development``, ``label_recall.md`` into the summary folder.

``--rank`` (PLAN T9.5; spec 05_score SCA-06; decisions 065, 066) runs the DEVELOPMENT-ONLY ranking check: it reads
``out/score/<trial>/`` (ranked_paths.csv, b0_ranked.csv, path_node_units.csv), ``out/stitch/<trial>/`` and the
approved key, writes ``rank.csv`` into each trial folder and, with ``--development``, ``rank.md`` and
``rank_totals.csv`` into the summary folder. ``--rank-sweep`` (development only) does the same and adds the stability
sweep (``rank_sweep.csv`` and a sweep section in ``rank.md``); a plain ``--rank --development`` drops an older
``rank_sweep.csv`` so that ``rank.md`` and the sweep file always come from one run.

``--results`` (spec 06_evaluate section 4 C, RS-01..11; DEVELOPMENT only) writes the T10 results tables
``results.md`` and ``results.csv`` into the summary folder: the ranking check is recomputed in memory with all its
refusals and the committed ``rank_totals.csv`` / ``rank.csv`` must equal it byte for byte, otherwise "stale: rerun
python -m evaluate --development --rank" (RS-02). It runs with ``--development`` only (RS-01) and refuses
``--rank``, ``--rank-sweep``, ``--label-recall``, ``--stitch-dir`` and ``--out`` (RS-11).

The evaluations share these folders: each swap carries the others' files over unchanged (``replace_folder``
``keep``), so running them in any order keeps every output. A carried-over CSV / JSON must belong to the trial
being written (``writers.kept_file_refusal``, stage review S06); otherwise the run is refused before any write.

The allowlist is checked first, before any file is opened (decision 046 style; 051 item 1): a test trial or a
malformed id is refused with exit code 2 and nothing is created. Any other refusal (051 items 2 and 9) also exits 2
and writes nothing; with ``--development`` every trial is evaluated in memory first, so one refusal writes nothing
at all. Folders are rebuilt on each run through a temporary sibling and a rename.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Sequence

from lab_common.outdir import out_target_refusal

from .inputs import EvalError, check_trial_allowed, repo_relative
from .label_recall import summary_md as recall_summary_md
from .label_recall import trial_csv as recall_trial_csv
from .label_run import label_trial
from .params import DEVELOPMENT_TRIALS, SPLIT_DEVELOPMENT, split_of
from .rank_report import RANK_FILE, RANK_SUMMARY_FILES
from .rank_report import summary_files as rank_summary_files
from .rank_report import trial_csv as rank_trial_csv
from .rank_run import rank_trial, sweep_of
from .results_report import RESULTS_FILES
from .results_run import development_results
from .run import (default_out_dir, default_stitch_dir, evaluate_trial, summary_dir, summary_files, utc_now)
from .writers import (FACTS_FILE, JSON_FILE, KEYED_FILE, LABEL_RECALL_FILE, LABEL_RECALL_MD, MD_FILE, RUN_INFO_FILE,
                      SUMMARY_CSV, SUMMARY_MD, TOTALS_FILE, kept_file_refusal, replace_folder)

REPO = Path(__file__).resolve().parents[2]
# The link accuracy files of one trial folder (the keyed file only on keyed trials) and of the summary folder.
LINK_TRIAL_FILES: tuple[str, ...] = (KEYED_FILE, FACTS_FILE, TOTALS_FILE, JSON_FILE, MD_FILE, RUN_INFO_FILE)
LINK_SUMMARY_FILES: tuple[str, ...] = (SUMMARY_CSV, SUMMARY_MD, RUN_INFO_FILE)
# The link accuracy and labelling recall names of one trial folder (T7.7, T8.3).
TRIAL_FILES: tuple[str, ...] = LINK_TRIAL_FILES + (LABEL_RECALL_FILE,)
# Every name one trial folder can hold, the ranking check's file included (T9.5): the only entries an existing --out
# folder may contain (decision 054), so that no evaluation refuses or drops another's output.
OUT_ALLOWED_FILES: tuple[str, ...] = TRIAL_FILES + (RANK_FILE,)
# What each evaluation carries over from the others in a trial folder and in the summary folder.
LINK_KEEP: tuple[str, ...] = (LABEL_RECALL_FILE, RANK_FILE)
RECALL_KEEP: tuple[str, ...] = LINK_TRIAL_FILES + (RANK_FILE,)
RANK_KEEP: tuple[str, ...] = TRIAL_FILES
# The results tables (spec 06 section 3.3) live in the summary folder only: every other evaluation keeps them, and
# --results keeps every other evaluation's summary files (rank, link accuracy, label recall).
LINK_SUMMARY_KEEP: tuple[str, ...] = (LABEL_RECALL_MD,) + RANK_SUMMARY_FILES + RESULTS_FILES
RECALL_SUMMARY_KEEP: tuple[str, ...] = LINK_SUMMARY_FILES + RANK_SUMMARY_FILES + RESULTS_FILES
RANK_SUMMARY_KEEP: tuple[str, ...] = LINK_SUMMARY_FILES + (LABEL_RECALL_MD,) + RESULTS_FILES
RESULTS_SUMMARY_KEEP: tuple[str, ...] = LINK_SUMMARY_FILES + (LABEL_RECALL_MD,) + RANK_SUMMARY_FILES
# RS-01 / RS-11 refusal texts.
RESULTS_TEST_REFUSAL = ("refused: results tables on test trials need the T5.7 key lock and an owner-approved test "
                        "allowlist (PLAN 10.4)")
RESULTS_COMBINATION_REFUSAL = ("refused: --results does not combine with --rank, --rank-sweep, --label-recall, "
                               "--stitch-dir or --out")


def _parser() -> argparse.ArgumentParser:
    """Arguments: exactly one of --trial / --development; --label-recall / --rank / --rank-sweep switch the
    evaluation."""
    ap = argparse.ArgumentParser(prog="evaluate", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--trial")
    mode.add_argument("--development", action="store_true")
    ap.add_argument("--label-recall", action="store_true",
                    help="labelling recall (PLAN T8.3) instead of link accuracy")
    ap.add_argument("--rank", action="store_true",
                    help="development ranking check (PLAN T9.5) instead of link accuracy")
    ap.add_argument("--rank-sweep", action="store_true",
                    help="ranking check plus the parameter stability sweep (PLAN T9.5; --development only)")
    ap.add_argument("--results", action="store_true",
                    help="T10 results tables on the development trials (spec 06 section 4 C; --development only)")
    ap.add_argument("--repo", type=Path, default=REPO)
    ap.add_argument("--stitch-dir", type=Path, default=None)
    ap.add_argument("--out", type=Path, default=None)
    return ap


def _trial_target(repo: Path, trial: str, out: Path | None) -> Path:
    """The trial folder to write: ``out/evaluate/<trial>``, or a checked ``--out`` (decision 054 / ATK-17; the
    default folder is rebuilt as before)."""
    if out is None:
        return default_out_dir(repo, trial)
    target = out.resolve()
    reason = out_target_refusal(target, repo, OUT_ALLOWED_FILES)
    if reason:
        raise EvalError(f"refused: {reason}")
    return target


def _check_kept(plans: Sequence[tuple[Path, Mapping[str, str], Sequence[str], str]]) -> None:
    """Every (folder, new files, kept names, trial) of a multi-folder run is checked before the first folder is
    written (stage review S06), so a foreign kept file refuses the whole run with nothing written."""
    for target, files, keep, trial in plans:
        reason = kept_file_refusal(target, files, keep, trial)
        if reason:
            raise EvalError(f"refused: {reason}")


def _one(repo: Path, trial: str, stitch_dir: Path | None, out: Path | None) -> int:
    """Evaluate and write one trial; the allowlist check comes before anything else."""
    check_trial_allowed(trial)
    res = evaluate_trial(repo, trial, split_of(trial), stitch_dir or default_stitch_dir(repo, trial))
    target = _trial_target(repo, trial, out)
    replace_folder(target, res.files, keep=LINK_KEEP, trial_id=trial)
    print(repo_relative(target, repo))
    return 0


def _development(repo: Path) -> int:
    """Evaluate all development trials in memory, then write each folder and the summary."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    results = [evaluate_trial(repo, t, split_of(t), default_stitch_dir(repo, t)) for t in DEVELOPMENT_TRIALS]
    _check_kept([(default_out_dir(repo, r.trial_id), r.files, LINK_KEEP, r.trial_id) for r in results])
    for res in results:
        target = default_out_dir(repo, res.trial_id)
        replace_folder(target, res.files, keep=LINK_KEEP, trial_id=res.trial_id)
        print(repo_relative(target, repo))
    target = summary_dir(repo)
    replace_folder(target, summary_files(results, "development", utc_now()), keep=LINK_SUMMARY_KEEP)
    print(repo_relative(target, repo))
    return 0


def _recall_one(repo: Path, trial: str, out: Path | None) -> int:
    """Labelling recall of one trial: ``label_recall.csv`` into its folder (keyed trials only); allowlist first."""
    check_trial_allowed(trial)
    res = label_trial(repo, trial, split_of(trial))
    target = _trial_target(repo, trial, out)          # --out checked also for a trial without a key (review)
    if res.rows is None:
        print(f"{trial}: no approved key, no {LABEL_RECALL_FILE} (counts: --label-recall --development)")
        return 0
    replace_folder(target, {LABEL_RECALL_FILE: recall_trial_csv(res.rows)}, keep=RECALL_KEEP, trial_id=trial)
    print(repo_relative(target, repo))
    return 0


def _recall_development(repo: Path) -> int:
    """Labelling recall of every development trial, in memory first (one refusal writes nothing), then each keyed
    trial's CSV and the summary report."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    results = [label_trial(repo, t, split_of(t)) for t in DEVELOPMENT_TRIALS]
    texts = {r.trial_id: {LABEL_RECALL_FILE: recall_trial_csv(r.rows)} for r in results if r.rows is not None}
    _check_kept([(default_out_dir(repo, t), f, RECALL_KEEP, t) for t, f in texts.items()])
    for trial, files in texts.items():
        target = default_out_dir(repo, trial)
        replace_folder(target, files, keep=RECALL_KEEP, trial_id=trial)
        print(repo_relative(target, repo))
    target = summary_dir(repo)
    replace_folder(target, {LABEL_RECALL_MD: recall_summary_md(SPLIT_DEVELOPMENT, results)},
                   keep=RECALL_SUMMARY_KEEP)
    print(repo_relative(target, repo))
    return 0


def _rank_one(repo: Path, trial: str, out: Path | None) -> int:
    """Ranking check of one trial: ``rank.csv`` into its folder (every trial: an unkeyed one gets its distribution
    rows only); allowlist first."""
    check_trial_allowed(trial)
    res = rank_trial(repo, trial, split_of(trial))
    target = _trial_target(repo, trial, out)
    replace_folder(target, {RANK_FILE: rank_trial_csv(res)}, keep=RANK_KEEP, trial_id=trial)
    print(repo_relative(target, repo))
    return 0


def _rank_development(repo: Path, sweep: bool) -> int:
    """Ranking check of every development trial, in memory first (one refusal, the sweep's default check included,
    writes nothing), then each trial's rank.csv and the summary files."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    results = [rank_trial(repo, t, split_of(t)) for t in DEVELOPMENT_TRIALS]
    swept = sweep_of(results) if sweep else None
    summary = rank_summary_files(results, SPLIT_DEVELOPMENT, swept)
    texts = {r.trial_id: {RANK_FILE: rank_trial_csv(r)} for r in results}
    _check_kept([(default_out_dir(repo, t), f, RANK_KEEP, t) for t, f in texts.items()])
    for trial, files in texts.items():
        target = default_out_dir(repo, trial)
        replace_folder(target, files, keep=RANK_KEEP, trial_id=trial)
        print(repo_relative(target, repo))
    target = summary_dir(repo)
    replace_folder(target, summary, keep=RANK_SUMMARY_KEEP)
    print(repo_relative(target, repo))
    return 0


def _run_rank(a: argparse.Namespace, repo: Path) -> int:
    """Dispatch of --rank / --rank-sweep; option combinations that do not apply are refused."""
    if a.label_recall:
        raise EvalError("refused: --rank / --rank-sweep and --label-recall are separate evaluations")
    if a.stitch_dir is not None:
        raise EvalError("refused: --stitch-dir does not apply to --rank (the score run fixes the stitch folder)")
    if a.development:
        if a.out is not None:
            raise EvalError("refused: --out applies to --trial only")
        return _rank_development(repo, sweep=a.rank_sweep)
    if a.rank_sweep:
        raise EvalError("refused: --rank-sweep runs over the development trials only (use --development)")
    return _rank_one(repo, a.trial, a.out)


def _results_development(repo: Path) -> int:
    """Results tables of the development trials: everything computed and checked in memory first (allowlist, rank
    checks, RS-02 staleness, RS-10 wording), then the summary folder is rebuilt keeping the other evaluations'
    files."""
    files = development_results(repo)
    target = summary_dir(repo)
    replace_folder(target, files, keep=RESULTS_SUMMARY_KEEP)
    print(repo_relative(target, repo))
    return 0


def _run_results(a: argparse.Namespace, repo: Path) -> int:
    """Dispatch of --results: development only (RS-01), no other evaluation or folder option (RS-11). Both checks
    come before any file is opened."""
    if not a.development:
        raise EvalError(RESULTS_TEST_REFUSAL)
    if a.rank or a.rank_sweep or a.label_recall or a.stitch_dir is not None or a.out is not None:
        raise EvalError(RESULTS_COMBINATION_REFUSAL)
    return _results_development(repo)


def _run(a: argparse.Namespace, repo: Path) -> int:
    """Dispatch on the parsed arguments; option combinations that do not apply are refused."""
    if a.results:
        return _run_results(a, repo)
    if a.rank or a.rank_sweep:
        return _run_rank(a, repo)
    if a.label_recall:
        if a.stitch_dir is not None:
            raise EvalError("refused: --stitch-dir does not apply to --label-recall")
        if a.development:
            if a.out is not None:
                raise EvalError("refused: --out applies to --trial only")
            return _recall_development(repo)
        return _recall_one(repo, a.trial, a.out)
    if a.development:
        if a.stitch_dir is not None or a.out is not None:
            raise EvalError("refused: --stitch-dir and --out apply to --trial only")
        return _development(repo)
    return _one(repo, a.trial, a.stitch_dir, a.out)


def main(argv: Sequence[str] | None = None) -> int:
    """Exit 0 on success (prints the folders written), 2 on a refusal (reason on stderr, nothing written)."""
    a = _parser().parse_args(argv)
    repo = a.repo.resolve()
    try:
        return _run(a, repo)
    except EvalError as exc:
        print(str(exc) if str(exc).startswith("refused") else f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
