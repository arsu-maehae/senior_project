"""Inputs of the T10 results tables (spec 06_evaluate RS-02; decision 072 item 2): the ranking check is recomputed in
memory for every development trial (``rank_run.rank_trial`` with all its refusals), then the rendered
``rank_totals.csv`` and each trial's ``rank.csv`` must equal the committed files byte for byte. WHY: the rank outputs
carry no run_info hash, so freshness is checked by re-rendering; results that cite a stale rank file would describe
something else. Writes nothing.

Spec 06 section 10: the weight sensitivity table is computed from the sweep recomputed in memory (``sweep_of``); when
a committed ``rank_sweep.csv`` exists it must equal the re-rendered sweep as well (RS-02 extended to the file the
table cites). AB-06: the results tables are refused when any development stitch ``run_info.json`` records a non-empty
``disabled_methods`` (an ablated stitch run must never feed a ``dev_check``).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .inputs import EvalError, check_trial_allowed, repo_relative
from .params import DEVELOPMENT_TRIALS, SPLIT_DEVELOPMENT, STITCH_RUN_INFO, split_of
from .rank_report import (RANK_FILE, RANK_SWEEP, RANK_TOTALS, SWEEP_COLUMNS, TOTAL_COLUMNS, sweep_rows, total_rows,
                          trial_csv)
from .rank_run import TrialRank, rank_trial, sweep_of
from .results_report import results_files
from .run import default_out_dir, default_stitch_dir, summary_dir
from .writers import csv_text

__all__ = ["STALE_HINT", "SWEEP_STALE_HINT", "expected_rank_texts", "expected_sweep_text", "stale_files",
           "read_committed", "disabled_methods_of", "disabled_methods_refusal", "read_stitch_run_infos",
           "REAL_REPO", "is_real_repo", "guarded_trials", "real_repo_ablation_refusal", "development_results"]

# ATK-EV-42: the real repository (this checkout), for ``real_repo_ablation_refusal``.
REAL_REPO = Path(__file__).resolve().parents[2]

STALE_HINT = "rerun python -m evaluate --development --rank"
SWEEP_STALE_HINT = "rerun python -m evaluate --development --rank-sweep"


def expected_rank_texts(repo: Path, results: Sequence[TrialRank], split: str) -> dict[Path, str]:
    """path -> the text the ranking check would write now: the summary rank_totals.csv and each trial's rank.csv."""
    out = {summary_dir(repo) / RANK_TOTALS: csv_text(TOTAL_COLUMNS, total_rows(results, split))}
    for t in results:
        out[default_out_dir(repo, t.trial_id) / RANK_FILE] = trial_csv(t)
    return out


def expected_sweep_text(sweep: tuple[Any, Sequence[Any], Mapping[str, Any]], split: str) -> str:
    """The rank_sweep.csv text the sweep would write now. Pure."""
    default, points, _check = sweep
    return csv_text(SWEEP_COLUMNS, sweep_rows(default, points, split))


def stale_files(expected: Mapping[Path, str], committed: Mapping[Path, bytes | None]) -> list[Path]:
    """The paths whose committed bytes (None = missing) differ from the expected text encoded as UTF-8. Pure."""
    return [p for p, text in expected.items() if committed.get(p) != text.encode("utf-8")]


def read_committed(paths: Sequence[Path]) -> dict[Path, bytes | None]:
    """path -> file bytes, None when the file is missing."""
    return {p: (p.read_bytes() if p.is_file() else None) for p in paths}


def disabled_methods_of(run_info: Mapping[str, Any]) -> tuple[str, ...]:
    """The ``disabled_methods`` a stitch run_info records (spec 06 AB-05: the key is written only when non-empty, so
    an absent key, None, an empty string or an empty list all mean none). Any other value counts as non-empty, so an
    unexpected spelling refuses instead of passing."""
    value = run_info.get("disabled_methods")
    if value is None or value == "" or (isinstance(value, (list, tuple, dict)) and not value):
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (repr(value),)


def disabled_methods_refusal(run_infos: Mapping[str, Mapping[str, Any]]) -> str:
    """AB-06: the refusal text when any trial's stitch run_info records disabled methods; '' otherwise. Pure."""
    bad = [f"{t} ({';'.join(m)})" for t, info in run_infos.items() if (m := disabled_methods_of(info))]
    if not bad:
        return ""
    return ("refused: --results reads only default stitch runs; stitch run_info.json records disabled_methods for "
            + ", ".join(bad) + " (spec 06 AB-06; ablation runs live in a scratch repo)")


def read_stitch_run_infos(repo: Path, trials: Sequence[str]) -> dict[str, Mapping[str, Any]]:
    """trial -> its stitch run_info.json object. A missing or unreadable file is left out here: ``rank_trial`` then
    refuses it with its own message (``inputs.load_stitch``)."""
    out: dict[str, Mapping[str, Any]] = {}
    for t in trials:
        path = default_stitch_dir(repo, t) / STITCH_RUN_INFO
        try:
            info = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(info, dict):
            out[t] = info
    return out


def _same_or_under(path: Path, root: Path) -> bool:
    """True iff ``path`` equals or lies under ``root`` after resolving links (case-insensitive on Windows)."""
    a, b = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def is_real_repo(repo: Path, real_repo: Path = REAL_REPO) -> bool:
    """True iff ``repo`` resolves to the real repository itself."""
    return _same_or_under(repo, real_repo) and _same_or_under(real_repo, repo)


def guarded_trials(trial: str | None, development: bool) -> tuple[str, ...]:
    """The trials whose stitch run_info the guard may read: every development trial with ``--development``, else the
    one ``--trial`` id only if it is a development trial (a test id is never opened: the stage's allowlist refuses
    it first, 051 item 1). Pure."""
    if development:
        return tuple(DEVELOPMENT_TRIALS)
    return (trial,) if trial in DEVELOPMENT_TRIALS else ()


def real_repo_ablation_refusal(repo: Path, trials: Sequence[str], stitch_dirs: Sequence[Path] = (),
                               real_repo: Path = REAL_REPO) -> str:
    """Spec 06 AB-06 / ATK-EV-42 for every evaluation (link accuracy, --label-recall, --rank, --rank-sweep): in the
    real repository, the refusal text when a stitch run_info.json it would read records non-empty
    ``disabled_methods``; '' otherwise. ``stitch_dirs`` adds an explicit ``--stitch-dir``. A scratch repo is not
    checked, and a default run_info has no such key (AB-05), so default behaviour is unchanged."""
    if not is_real_repo(repo, real_repo):
        return ""
    infos = dict(read_stitch_run_infos(repo, trials))
    for d in stitch_dirs:
        try:
            info = json.loads((Path(d) / STITCH_RUN_INFO).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(info, dict):
            infos[f"--stitch-dir {Path(d).as_posix()}"] = info
    bad = [f"{t} ({';'.join(m)})" for t, info in infos.items() if (m := disabled_methods_of(info))]
    if not bad:
        return ""
    return ("refused: in the real repository evaluate reads only default stitch runs; stitch run_info.json records "
            "disabled_methods for " + ", ".join(bad) + " (spec 06 AB-06; ablation runs live in a scratch repo)")


def development_results(repo: Path) -> dict[str, str]:
    """results.md / results.csv texts of the development trials, or EvalError: allowlist first, AB-06 (no ablated
    stitch run), every rank check of ``rank_trial``, the sweep with its default check, then the RS-02 staleness check
    (rank files, and rank_sweep.csv when present), then RS-10 inside ``results_files``."""
    for trial in DEVELOPMENT_TRIALS:
        check_trial_allowed(trial)
    reason = disabled_methods_refusal(read_stitch_run_infos(repo, DEVELOPMENT_TRIALS))
    if reason:
        raise EvalError(reason)
    results = [rank_trial(repo, t, split_of(t)) for t in DEVELOPMENT_TRIALS]
    swept = sweep_of(results)
    expected = expected_rank_texts(repo, results, SPLIT_DEVELOPMENT)
    stale = stale_files(expected, read_committed(list(expected)))
    if stale:
        names = ", ".join(repo_relative(p, repo) for p in stale)
        raise EvalError(f"refused: stale: {STALE_HINT} ({names} differ from the ranking check recomputed now)")
    sweep_path = summary_dir(repo) / RANK_SWEEP
    if sweep_path.is_file() and stale_files({sweep_path: expected_sweep_text(swept, SPLIT_DEVELOPMENT)},
                                            read_committed([sweep_path])):
        raise EvalError(f"refused: stale: {SWEEP_STALE_HINT} ({repo_relative(sweep_path, repo)} differs from the sweep "
                        "recomputed now)")
    return results_files(results, SPLIT_DEVELOPMENT, swept)
