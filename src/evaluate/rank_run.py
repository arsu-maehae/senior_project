"""Development ranking check, one trial: every check and read first, then the pure assembly (PLAN T9.5; spec 05_score
SCA-06; decisions 065, 066). Writes nothing.

Order: stitch files (hashes vs their run_info, ``inputs.load_stitch``) -> score files (hashes vs the score
run_info, and the score run must have read these stitch files) -> approved key (the existing loader, never a draft;
its ``db_sha256`` must equal the stitch run's DB hash). No DB is opened: every fact comes from these files. WHY the
same refusal style as ``run.evaluate_trial``: a refusal must leave the disk untouched, and the CLI alone holds the
development allowlist, so tests can call ``rank_from_inputs`` directly with synthetic rows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import rank_metrics as rm
from .inputs import EvalError, KeyData, StitchData, load_key, load_stitch
from .rank_inputs import (PATH_VARIANTS, ScoreData, check_key_against_stitch, check_score_against_stitch,
                          default_params, default_score_dir, load_score)
from .rank_sweep import SweepPoint, SweepTrial, components_of, run_sweep
from .run import default_stitch_dir

__all__ = ["KeyPathResult", "ReadingResult", "B0Result", "TrialRank", "rank_from_inputs", "rank_trial", "sweep_of"]


@dataclass(frozen=True)
class KeyPathResult:
    """One key attack path under one variant and reading: its matches and the placement of the first one."""
    key_path: rm.KeyPath
    matched: Mapping[str, float]
    placement: rm.Placement
    shared_uids: tuple[str, ...]        # supporting uids: node reading = key nodes held by the first matches;
                                        # hop reading = the key target 4624 uids that anchor the hop mapping


@dataclass(frozen=True)
class ReadingResult:
    """One (variant, reading) of a keyed attack trial: per key path, the trial-level first match of any key attack
    path, the chance line and the score gap."""
    variant: str
    reading: str
    n: int
    key_paths: tuple[KeyPathResult, ...]
    trial: rm.Placement
    low: float | None
    high: float | None
    high_ids: tuple[str, ...]
    gap: float | None


@dataclass(frozen=True)
class B0Result:
    """H4 inputs of one keyed attack trial: full's top-k expected nodes and recall, and b0's recall at that budget;
    the same with the labelled ``context`` = 0 nodes (NodeScore units) of the top k as budget."""
    k: int
    key_nodes: int
    budget: float
    full_recall: float
    b0_recall: float
    budget_labelled: float
    full_recall_labelled: float
    b0_recall_labelled: float


@dataclass(frozen=True)
class TrialRank:
    """Everything the ranking check produced for one trial (rows and texts are built by ``rank_report``)."""
    trial_id: str
    split: str
    keyed: bool
    attack: bool
    readings: tuple[ReadingResult, ...]
    b0: B0Result | None
    distributions: Mapping[str, Mapping[str, Any]]
    candidates: Mapping[str, tuple[rm.Candidate, ...]]
    sweep_trial: SweepTrial | None
    params: Mapping[str, float]
    inputs: Mapping[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------- pure assembly

def _shared(kp: rm.KeyPath, pl: rm.Placement, nodes: Mapping[str, frozenset[str]], reading: str) -> tuple[str, ...]:
    """Supporting uids of a key path row (see KeyPathResult)."""
    if reading == rm.READING_HOP:
        return kp.anchor_uids
    held = set().union(*(nodes.get(p, frozenset()) for p in pl.first_group)) if pl.first_group else set()
    return tuple(sorted(held & kp.node_uids))


def _reading(variant: str, reading: str, cands: Sequence[rm.Candidate], key_paths: Sequence[rm.KeyPath],
             nodes: Mapping[str, frozenset[str]]) -> ReadingResult:
    """One (variant, reading) of a keyed attack trial."""
    results: list[KeyPathResult] = []
    union: set[str] = set()
    for kp in key_paths:
        hit = rm.matches(kp, cands, nodes, reading)
        pl = rm.placement(cands, hit)
        union |= set(hit)
        results.append(KeyPathResult(kp, hit, pl, _shared(kp, pl, nodes, reading)))
    trial = rm.placement(cands, union)
    low, high, high_ids, gap = rm.score_gap([r.placement.first_score for r in results], cands, union)
    return ReadingResult(variant, reading, len(cands), tuple(results), trial, low, high, high_ids, gap)


def _b0(full: Sequence[rm.Candidate], k: int, key_nodes: frozenset[str], nodes: Mapping[str, frozenset[str]],
        labelled: Mapping[str, frozenset[str]], b0_rows: Sequence[Mapping[str, str]]) -> B0Result:
    """H4 at an equal node budget (rank_metrics module docstring)."""
    sure, cut, slots = rm.inclusion_probabilities(full, k)

    def side(node_sets: Mapping[str, frozenset[str]]) -> tuple[float, float, float]:
        cover = rm.expected_coverage(node_sets, sure, cut, slots)
        budget = sum(cover.values())
        recall = sum(cover.get(u, 0.0) for u in key_nodes) / len(key_nodes) if key_nodes else 0.0
        b0r, _held = rm.b0_recall(b0_rows, budget, key_nodes)
        return budget, recall, b0r

    b, fr, br = side(nodes)
    bl, frl, brl = side(labelled)
    return B0Result(k=k, key_nodes=len(key_nodes), budget=b, full_recall=fr, b0_recall=br, budget_labelled=bl,
                    full_recall_labelled=frl, b0_recall_labelled=brl)


def rank_from_inputs(trial: str, split: str, stitch: StitchData, score: ScoreData, key: KeyData | None,
                     inputs: Mapping[str, str] | None = None) -> TrialRank:
    """The TrialRank of already-checked inputs. Pure. A keyed trial without attack paths (S06) gets no reading rows;
    its scores feed the S06 check. An unkeyed trial gets the distribution only (no right / wrong)."""
    cands = {v: tuple(rm.candidates_of(score.ranked, v)) for v in PATH_VARIANTS}
    dists = {v: rm.distribution(cands[v]) for v in PATH_VARIANTS}
    params = default_params(score)
    if key is None:
        sweep0 = SweepTrial(trial_id=trial, paths=components_of(score.ranked), key_matches=(), keyed=False)
        return TrialRank(trial, split, False, False, (), None, dists, cands, sweep0, params, dict(inputs or {}))
    nodes = rm.path_node_sets(stitch.path_nodes)
    key_paths = rm.build_key_paths(key.data, stitch.hops)
    readings = tuple(_reading(v, r, cands[v], key_paths, nodes) for v in PATH_VARIANTS for r in rm.READINGS
                     if key_paths)
    b0 = None
    if key_paths:
        key_nodes = frozenset().union(*(kp.node_uids for kp in key_paths))
        b0 = _b0(cands["full"], len(key_paths), key_nodes, nodes, rm.unit_node_sets(score.units), score.b0)
    hop_full = [r for r in readings if r.variant == "full" and r.reading == rm.READING_HOP]
    sweep = SweepTrial(trial_id=trial, paths=components_of(score.ranked),
                       key_matches=tuple((r.key_path.path_id, frozenset(r.matched))
                                         for h in hop_full for r in h.key_paths))
    return TrialRank(trial, split, True, bool(key_paths), readings, b0, dists, cands, sweep, params,
                     dict(inputs or {}))


# ---------------------------------------------------------------- reads

def _check_stitch_trial(stitch: StitchData, trial: str) -> None:
    """The stitch folder must be the one of this trial (its run_info ``trial_id``)."""
    if stitch.run_info.get("trial_id") != trial:
        raise EvalError(f"refused: stitch run_info.json trial_id {stitch.run_info.get('trial_id')!r} differs from "
                        f"the trial {trial}")


def rank_trial(repo: Path, trial: str, split: str, stitch_dir: Path | None = None,
               score_dir: Path | None = None) -> TrialRank:
    """Check and read every input of one trial, then assemble; writes nothing. The allowlist is NOT checked here
    (the CLI checks it first, ``inputs.check_trial_allowed``)."""
    repo = Path(repo)
    stitch = load_stitch(Path(stitch_dir) if stitch_dir else default_stitch_dir(repo, trial))
    _check_stitch_trial(stitch, trial)
    score = load_score(Path(score_dir) if score_dir else default_score_dir(repo, trial), trial)
    check_score_against_stitch(score, stitch)
    key = load_key(repo, trial, split)
    check_key_against_stitch(key, stitch)
    inputs = {"score_run_info_sha256": score.run_info_sha256,
              "ranked_paths_sha256": score.file_sha256["ranked_paths.csv"],
              "b0_ranked_sha256": score.file_sha256["b0_ranked.csv"],
              "path_node_units_sha256": score.file_sha256["path_node_units.csv"],
              "stitch_path_nodes_sha256": stitch.file_sha256["path_nodes.csv"],
              "stitch_hops_sha256": stitch.file_sha256["hops.csv"]}
    if key is not None:
        inputs["key_sha256"] = key.sha256
    return rank_from_inputs(trial, split, stitch, score, key, inputs)


# ---------------------------------------------------------------- development sweep

def sweep_of(results: Sequence[TrialRank]) -> tuple[SweepPoint, list[SweepPoint], dict[str, float | int]]:
    """The stability sweep over ``results`` (decision 066): every trial enters the default check, the keyed trials
    the metrics. Every score run must have used the same lambda and w (its run_info ``parameters``); the default
    point is those values. Refused otherwise, because one default cannot describe trials scored with different
    parameters."""
    trials = [t.sweep_trial for t in results if t.sweep_trial is not None]
    if not any(t.keyed for t in trials):
        raise EvalError("refused: the sweep needs at least one keyed trial")
    params = {tuple(sorted(t.params.items())) for t in results}
    if len(params) != 1:
        raise EvalError("refused: the score runs of these trials used different parameters (run_info parameters)")
    p = results[0].params
    return run_sweep(trials, p["lam"], (p["w1"], p["w2"], p["w3"]))
