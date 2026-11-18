"""Development ranking check, one trial: every check and read first, then the pure assembly (PLAN T9.5; spec 05_score
SCA-06; decisions 065, 066). Writes nothing.

Order: stitch files (hashes vs their run_info, ``inputs.load_stitch``) -> score files (hashes vs the score
run_info, and the score run must have read these stitch files) -> score run pins (frozen order table and parameters,
ATK-SC-18) -> label files (each must still have the hash the score run recorded, ATK-SC-18) -> approved key (the
existing loader, never a draft; a keyed development trial without one is refused, ATK-SC-25; its ``db_sha256`` must
equal the stitch run's DB hash). No DB is opened: every fact comes from these files. WHY the
same refusal style as ``run.evaluate_trial``: a refusal must leave the disk untouched, and the CLI alone holds the
development allowlist, so tests can call ``rank_from_inputs`` directly with synthetic rows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from . import rank_metrics as rm
from .inputs import EvalError, KeyData, StitchData, load_key, load_stitch
from .keys import split_list
from .params import is_s06
from .rank_inputs import (PATH_VARIANTS, ScoreData, check_key_against_stitch, check_key_present,
                          check_score_against_label, check_score_against_stitch, check_score_pins, default_label_dir,
                          default_params, default_score_dir, label_file_hashes, load_score, recorded_label_files)
from .rank_sweep import SweepPoint, SweepTrial, components_of, run_sweep
from .run import default_stitch_dir

__all__ = ["KeyPathResult", "ReadingResult", "B0Result", "TrialRank", "check_key_scenario", "b0_unit_uids",
           "labelled_key_nodes",
           "positive_b0_units", "canonical_b0_rows", "rank_from_inputs", "rank_trial", "sweep_of"]


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
    positive: frozenset[str] = frozenset()      # ATK-SC-21: candidates with score > 0 (second chance line)

    @property
    def contested(self) -> bool:
        """EV-03 (decision 070 item 4): more than one candidate of this variant has a written score > 0, so the
        ranking among scored paths can be wrong. Independent of the match reading."""
        return len(self.positive) > 1

    def uncontested_reason(self) -> str:
        """Why a trial is left out of the contested reading ('' when contested). ATK-EV-05: a trial whose only
        positive candidate matches no key attack path is named so the failure stays visible."""
        if self.contested:
            return ""
        if not self.positive:
            return "uncontested — no candidate scored"
        if self.positive & set(self.trial.matched):
            return "uncontested — key path the only scored path"
        return "uncontested — key path not scored"


@dataclass(frozen=True)
class B0Result:
    """H4 inputs of one keyed attack trial: full's top-k expected nodes and recall, and b0's recall at that budget;
    the same with the labelled ``context`` = 0 nodes (NodeScore units) of the top k as budget.

    The labelled recall divides by the **labelled key nodes** (decision 071, spec 06 EV-02): key nodes inside at
    least one canonical ``b0_ranked.csv`` unit. A trial with none has an undefined labelled recall (None), so it is
    left out of the mean instead of counting as 0. ``n_positive_units`` = distinct canonical b0 units with score > 0
    (the b0 contested reading, EV-03 / ATK-EV-14)."""
    k: int
    key_nodes: int
    budget: float
    full_recall: float
    b0_recall: float
    budget_labelled: float
    full_recall_labelled: float | None
    b0_recall_labelled: float | None
    key_nodes_labelled: int = 0
    n_positive_units: int = 0

    @property
    def contested(self) -> bool:
        """EV-03 for b0: more than one distinct labelled unit with score > 0 (ST-05 copies merged first)."""
        return self.n_positive_units > 1


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
    return ReadingResult(variant, reading, len(cands), tuple(results), trial, low, high, high_ids, gap,
                         rm.positive_ids(cands))


def b0_unit_uids(b0_rows: Sequence[Mapping[str, str]]) -> frozenset[str]:
    """Every event uid held by any (canonical) ``b0_ranked.csv`` unit: the nodes b0 can reach at all (071)."""
    return frozenset(u for r in b0_rows for u in split_list(r["event_uids"]))


def labelled_key_nodes(key_nodes: frozenset[str], b0_rows: Sequence[Mapping[str, str]]) -> frozenset[str]:
    """The H4 labelled denominator (decision 071): canonical key nodes inside at least one canonical b0 unit. WHY:
    070 item 1 measures recall on the b0-reachable set, so neither side loses for nodes no labelled unit holds."""
    return key_nodes & b0_unit_uids(b0_rows)


def positive_b0_units(b0_rows: Sequence[Mapping[str, str]]) -> int:
    """Distinct labelled units with score > 0 (EV-03 b0 contested reading). Rows must already be canonical
    (``canonical_b0_rows``): two rows holding the same canonical uid set are ST-05 copies of one unit and count once
    (ATK-EV-14)."""
    return len({frozenset(split_list(r["event_uids"])) for r in b0_rows if rm._num(r["score"], "b0 score") > 0})


def _b0(full: Sequence[rm.Candidate], k: int, key_nodes: frozenset[str], nodes: Mapping[str, frozenset[str]],
        labelled: Mapping[str, frozenset[str]], b0_rows: Sequence[Mapping[str, str]]) -> B0Result:
    """H4 at an equal node budget (rank_metrics module docstring). All-node basis: recall over every key node. Labelled
    basis (071): the same numerator restricted to the labelled key nodes, divided by their number; None when the
    trial has none (undefined, left out of the mean)."""
    sure, cut, slots = rm.inclusion_probabilities(full, k)
    reach = labelled_key_nodes(key_nodes, b0_rows)

    def side(node_sets: Mapping[str, frozenset[str]], targets: frozenset[str]) -> tuple[float, float | None,
                                                                                       float | None]:
        cover = rm.expected_coverage(node_sets, sure, cut, slots)
        budget = sum(cover.values())
        if not targets:
            return budget, None, None
        recall = sum(cover.get(u, 0.0) for u in targets) / len(targets)
        b0r, _held = rm.b0_recall(b0_rows, budget, targets)
        return budget, recall, b0r

    b, fr, br = side(nodes, key_nodes)
    bl, frl, brl = side(labelled, reach)
    return B0Result(k=k, key_nodes=len(key_nodes), budget=b, full_recall=fr or 0.0, b0_recall=br or 0.0,
                    budget_labelled=bl, full_recall_labelled=frl, b0_recall_labelled=brl,
                    key_nodes_labelled=len(reach), n_positive_units=positive_b0_units(b0_rows))


def canonical_b0_rows(rows: Sequence[Mapping[str, str]], alias: Mapping[str, str]) -> list[dict[str, str]]:
    """``b0_ranked.csv`` rows with ST-05 copies in ``event_uids`` replaced by their representative (ATK-SC-16), so
    the H4 budget counts one 4624 once on both sides."""
    return [dict(r, event_uids=";".join(sorted(rm.canonical(split_list(r["event_uids"]), alias)))) for r in rows]


def check_key_scenario(trial: str, n_attack_paths: int) -> None:
    """ATK-EV-15: a keyed S06 trial must name no key attack path, and every other keyed trial at least one. WHY: H5
    and the attack-trial metrics are split by scenario id; a key that disagrees (an attack key that lost its paths, or
    an S06 key naming one) would move a trial between H1-H4 and H5 without anyone noticing."""
    if is_s06(trial) and n_attack_paths:
        raise EvalError(f"refused: approved key of {trial} (scenario S06, no attack) names {n_attack_paths} key "
                        "attack path(s)")
    if not is_s06(trial) and not n_attack_paths:
        raise EvalError(f"refused: approved key of {trial} names no key attack path; only S06 keys may name none")


def rank_from_inputs(trial: str, split: str, stitch: StitchData, score: ScoreData, key: KeyData | None,
                     inputs: Mapping[str, str] | None = None) -> TrialRank:
    """The TrialRank of already-checked inputs. Pure. A keyed S06 trial (no key attack path, ATK-EV-15) gets no
    reading rows; its scores feed the S06 check. An unkeyed trial gets the distribution only (no right / wrong)."""
    cands = {v: tuple(rm.candidates_of(score.ranked, v)) for v in PATH_VARIANTS}
    dists = {v: rm.distribution(cands[v]) for v in PATH_VARIANTS}
    params = default_params(score)
    if key is None:
        sweep0 = SweepTrial(trial_id=trial, paths=components_of(score.ranked), key_matches=(), keyed=False)
        return TrialRank(trial, split, False, False, (), None, dists, cands, sweep0, params, dict(inputs or {}))
    alias = rm.copy_alias_map(stitch.hops)                  # ATK-SC-16: ST-05 copies resolved on every side
    nodes = rm.path_node_sets(stitch.path_nodes, alias)
    key_paths = rm.build_key_paths(key.data, stitch.hops)
    check_key_scenario(trial, len(key_paths))                 # ATK-EV-15, before anything is assembled
    readings = tuple(_reading(v, r, cands[v], key_paths, nodes) for v in PATH_VARIANTS for r in rm.READINGS
                     if key_paths)
    b0 = None
    if key_paths:
        key_nodes = frozenset().union(*(kp.node_uids for kp in key_paths))
        b0 = _b0(cands["full"], len(key_paths), key_nodes, nodes, rm.unit_node_sets(score.units, alias),
                 canonical_b0_rows(score.b0, alias))
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
               score_dir: Path | None = None, label_dir: Path | None = None) -> TrialRank:
    """Check and read every input of one trial, then assemble; writes nothing. The allowlist is NOT checked here
    (the CLI checks it first, ``inputs.check_trial_allowed``)."""
    repo = Path(repo)
    stitch = load_stitch(Path(stitch_dir) if stitch_dir else default_stitch_dir(repo, trial))
    _check_stitch_trial(stitch, trial)
    score = load_score(Path(score_dir) if score_dir else default_score_dir(repo, trial), trial)
    check_score_against_stitch(score, stitch)
    check_score_pins(score)                                                   # ATK-SC-18
    recorded = recorded_label_files(score)                                    # ATK-SC-18
    ldir = Path(label_dir) if label_dir else default_label_dir(repo, trial)
    check_score_against_label(recorded, label_file_hashes(ldir, sorted(recorded)))
    key = load_key(repo, trial, split)
    check_key_present(trial, key)                                             # ATK-SC-25
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
