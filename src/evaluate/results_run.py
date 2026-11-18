"""Inputs of the T10 results tables (spec 06_evaluate RS-02; decision 072 item 2): the ranking check is recomputed in
memory for every development trial (``rank_run.rank_trial`` with all its refusals), then the rendered
``rank_totals.csv`` and each trial's ``rank.csv`` must equal the committed files byte for byte. WHY: the rank outputs
carry no run_info hash, so freshness is checked by re-rendering; results that cite a stale rank file would describe
something else. Writes nothing.
"""
from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from .inputs import EvalError, check_trial_allowed, repo_relative
from .params import DEVELOPMENT_TRIALS, SPLIT_DEVELOPMENT, split_of
from .rank_report import RANK_FILE, RANK_TOTALS, TOTAL_COLUMNS, total_rows, trial_csv
from .rank_run import TrialRank, rank_trial
from .results_report import results_files
from .run import default_out_dir, summary_dir
from .writers import csv_text

__all__ = ["STALE_HINT", "expected_rank_texts", "stale_files", "read_committed", "development_results"]

STALE_HINT = "rerun python -m evaluate --development --rank"


def expected_rank_texts(repo: Path, results: Sequence[TrialRank], split: str) -> dict[Path, str]:
    """path -> the text the ranking check would write now: the summary rank_totals.csv and each trial's rank.csv."""
    out = {summary_dir(repo) / RANK_TOTALS: csv_text(TOTAL_COLUMNS, total_rows(results, split))}
    for t in results:
        out[default_out_dir(repo, t.trial_id) / RANK_FILE] = trial_csv(t)
    return out


def stale_files(expected: Mapping[Path, str], committed: Mapping[Path, bytes | None]) -> list[Path]:
    """The paths whose committed bytes (None = missing) differ from the expected text encoded as UTF-8. Pure."""
    return [p for p, text in expected.items() if committed.get(p) != text.encode("utf-8")]


def read_committed(paths: Sequence[Path]) -> dict[Path, bytes | None]:
    """path -> file bytes, None when the file is missing."""
    return {p: (p.read_bytes() if p.is_file() else None) for p in paths}


def development_results(repo: Path) -> dict[str, str]:
    """results.md / results.csv texts of the development trials, or EvalError: allowlist first, every rank check of
    ``rank_trial``, then the RS-02 staleness check, then RS-10 inside ``results_files``."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    results = [rank_trial(repo, t, split_of(t)) for t in DEVELOPMENT_TRIALS]
    expected = expected_rank_texts(repo, results, SPLIT_DEVELOPMENT)
    stale = stale_files(expected, read_committed(list(expected)))
    if stale:
        names = ", ".join(repo_relative(p, repo) for p in stale)
        raise EvalError(f"refused: stale: {STALE_HINT} ({names} differ from the ranking check recomputed now)")
    return results_files(results, SPLIT_DEVELOPMENT)
