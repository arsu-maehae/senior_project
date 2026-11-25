"""Output texts of the development ranking check (PLAN T9.5, T10.7; spec 05_score SCA-06, section 5.2; spec
06_evaluate section 4 A; decisions 065, 066, 070, 071).
Pure: every text is built in memory, with no timestamp, ``\\n`` line ends and fixed number formats (6 decimals), so
two runs give byte-identical files.

Files: ``out/evaluate/<trial>/rank.csv`` (one per trial), ``out/evaluate/development/rank.md`` and
``rank_totals.csv``, and with the sweep ``rank_sweep.csv`` plus a sweep section in ``rank.md``. Every CSV row carries
``status_note`` and every Markdown table is headed "DEVELOPMENT numbers, not results" (decision 019; spec SCA-06):
these numbers check the code on development keys; T10 alone reports results. The ``.md`` holds ids, hosts and
numbers only: no account, image or command text (decision 051 item 8).

Decision 070 readings (spec 06 EV-01..08): rank.md opens with the primary readings (top-1, per-key MRR, labelled
H4 recall with the 071 denominator, S06 check), every table with a ranking metric carries the chance line over all
candidates and over score > 0, and the contested reading gets its own totals rows (``ranking_contested``,
``b0_recall_contested``), so the ``ranking`` / ``b0_recall`` rows keep their number and columns.
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Mapping, Sequence

from . import rank_metrics as rm
from .rank_run import B0Result, KeyPathResult, NodePRF, ReadingResult, TrialRank
from .rank_sweep import LAMBDA_GRID, SweepPoint, changed_keys, informativeness, stable_region
from .writers import csv_text, md_header
from .params import H5_MIN_MARGIN, SPLIT_DEVELOPMENT, VERDICT_DECIMALS, is_s06

__all__ = ["RANK_FILE", "RANK_MD", "RANK_TOTALS", "RANK_SWEEP", "RANK_SUMMARY_FILES", "DEV_NOTE", "RANK_COLUMNS",
           "TOTAL_COLUMNS", "SWEEP_COLUMNS", "RECALL_BASIS_ALL", "RECALL_BASIS_LABELLED", "KIND_RANKING", "KIND_B0",
           "KIND_RANKING_CONTESTED", "KIND_B0_CONTESTED", "SCOPE_ALL", "SCOPE_CONTESTED", "PRIMARY_RANKING",
           "PRIMARY_B0", "PATH_VARIANT_ORDER", "PAIRED_SET", "B0_SET", "CHANCE_NA_RECALL", "CHANCE_NA_MARGIN", "f6",
           "trial_rows", "trial_csv", "attack_readings", "contested_ids", "b0_contested_ids", "uncontested_rows",
           "ranking_values", "b0_values", "b0_of", "contested_plan", "r12", "f12", "at_least", "strictly_greater",
           "h5_facts", "s06_facts", "total_rows", "sweep_rows", "KIND_NODE_PRF", "KIND_NODE_PRF_SCENARIO",
           "KIND_AUC_TRIAL", "KIND_AUC_POOLED", "PRF_VARIANT_ORDER", "AUC_CHANCE", "METHOD_AUC", "scenario_of",
           "attack_scenarios", "addendum_rows", "node_prf_pairs", "node_prf_values", "auc_split", "auc_trial_values",
           "auc_values", "SW04_SENTENCE",
           "informative_sentence", "rank_md", "summary_files"]

RANK_FILE = "rank.csv"
RANK_MD = "rank.md"
RANK_TOTALS = "rank_totals.csv"
RANK_SWEEP = "rank_sweep.csv"
RANK_SUMMARY_FILES: tuple[str, ...] = (RANK_MD, RANK_TOTALS, RANK_SWEEP)
DEV_NOTE = "DEVELOPMENT numbers, not results"
TEST_NOTE = "TEST"
# The two H4 recall bases, reported side by side (ATK-SC-14). Decision 070 item 1 makes the labelled basis primary;
# decision 071 fixes its denominator (labelled key nodes = key nodes inside a b0 unit). The all-node basis is beside.
RECALL_BASIS_ALL = "all context-0 nodes (reported beside, 070)"
RECALL_BASIS_LABELLED = "labelled nodes only (b0-reachable, primary, 070/071)"
# Totals row kinds (EV-08: the contested readings get their own kinds, so `ranking` / `b0_recall` rows stay as they
# were) and the reading scopes (spec 06 section 3.1).
KIND_RANKING, KIND_B0 = "ranking", "b0_recall"
KIND_RANKING_CONTESTED, KIND_B0_CONTESTED = "ranking_contested", "b0_recall_contested"
SCOPE_ALL, SCOPE_CONTESTED = "all", "contested"
# The 070 primary column of each row kind (spec 06 section 3.1 `primary_metric`).
PRIMARY_RANKING = "mrr_per_key_expected"
PRIMARY_B0 = "full_recall_labelled_mean;b0_recall_labelled_mean"
PATH_VARIANT_ORDER: tuple[str, ...] = ("full", "b1", "b2")
# H3 and H4 compare against full; under the contested reading both sides use full's contested set (EV-04).
PAIRED_SET = "full"
B0_SET = "b0"
CHANCE_NA_RECALL = "n/a: node recall at an equal node budget, no ranking order to draw at random"
CHANCE_NA_MARGIN = "n/a: score margin across trials, no ranking order to draw at random"
# Spec 06 section 10 (addendum D): node P/R/F1/FNR (D-A) and the path-level ROC-AUC (D-B) get their own row kinds, so
# every earlier row kind keeps its rows (EV-08 style). No verdict, no threshold: no hypothesis was frozen for them.
KIND_NODE_PRF, KIND_NODE_PRF_SCENARIO = "node_prf", "node_prf_scenario"
KIND_AUC_TRIAL, KIND_AUC_POOLED = "auc_trial", "auc_pooled"
PRF_VARIANT_ORDER: tuple[str, ...] = PATH_VARIANT_ORDER + ("b0",)
AUC_CHANCE = 0.5                 # AUC-01: a random score order
METHOD_AUC = "mann_whitney_ties_half_node_match"
# ATK-EV-45: the rank.md sweep column that counts grid points with a positive S06 margin. Never called "held":
# a sweep point is a development sensitivity reading, not an H5 verdict (rank_sweep.csv keeps its own columns).
S06_POINTS_COL = "points with S06 margin > 0"
S06_POINTS_TEXT = ("`points with S06 margin > 0` = grid points where the lowest key attack score exceeds the highest "
                   "S06 score (development sensitivity, not an H5 verdict).")
# Spec 06 SW-04 (owner 2026-11-24): the one sentence both the rank.md sweep section and the results.md sensitivity
# section carry, so neither can be read as a re-tuning of the frozen parameters (066 at 6338884; 068).
SW04_SENTENCE = ("Development-only sensitivity analysis: the sweep never changes a frozen default — λ, "
                 "w1–w3, α, β, a, b and ε stay as frozen in decision 066 at 6338884, and every "
                 "score, rank and H verdict uses only those values (decision 068).")

RANK_COLUMNS: tuple[str, ...] = (
    "status_note", "trial_id", "split", "keyed", "row_kind", "variant", "match_reading", "key_path_id", "key_role",
    "key_hop_ids", "mapped_hop_ids", "unmatched_key_hops", "method", "threshold", "n_candidates", "candidate_count",
    "matched_path_ids", "matched_jaccards", "first_match_path_ids", "first_rank", "tie_size", "matches_in_tie",
    "rank_expected", "rank_optimistic", "rank_pessimistic", "rr_expected", "rr_optimistic", "rr_pessimistic",
    "rr_mean_expected", "top1_expected", "top1_optimistic", "top1_pessimistic", "chance_top1", "chance_rank_expected",
    "chance_rr", "chance_rr_mean", "n_candidates_positive", "chance_pos_top1", "chance_pos_rank_expected",
    "chance_pos_rr", "chance_pos_rr_mean", "first_match_score", "key_attack_score_min", "other_score_max",
    "other_max_path_ids",
    "score_gap", "key_node_count", "supporting_event_uids", "time_delta_ms", "k", "budget_nodes", "full_recall",
    "b0_recall", "budget_nodes_labelled", "full_recall_labelled", "b0_recall_labelled", "score_max", "score_min",
    "score_mean", "n_zero_score", "n_distinct_scores", "top_tie_size",
    # spec 06 section 3.1 (EV-02, EV-03): appended so every earlier column keeps its place
    "contested", "n_positive_units", "key_nodes_labelled",
    # spec 06 section 10 D-A (row_kind node_prf) and D-B (row_kind auc_trial): appended
    "expected_key_nodes_covered", "expected_nodes_held", "node_precision", "node_recall", "node_f1", "node_fnr",
    "auc", "auc_n_pos", "auc_n_neg", "auc_chance")
TOTAL_COLUMNS: tuple[str, ...] = (
    "status_note", "split", "row_kind", "variant", "match_reading", "attack_trials", "key_paths", "key_paths_matched",
    "top1_expected", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic", "mrr_pessimistic",
    "mrr_rr_mean_expected", "mrr_per_key_expected", "mrr_per_key_rr_mean", "chance_top1", "chance_mrr",
    "chance_rr_mean", "chance_pos_top1", "chance_pos_mrr", "chance_pos_rr_mean", "score_gap_min",
    "trials_gap_positive", "s06_trials",
    "s06_max_score", "key_attack_score_min", "s06_margin", "s06_held", "share_attack_trials_above_s06",
    "recall_basis", "full_recall_mean", "b0_recall_mean", "recall_basis_labelled", "full_recall_labelled_mean",
    "b0_recall_labelled_mean",
    "trials_full_above_b0", "trials_full_above_b0_labelled",
    # spec 06 section 3.1 (EV-02..05, EV-08): appended so every earlier column keeps its place
    "reading_scope", "contested_set", "primary_metric", "scope_trial_ids", "chance_per_key_mrr",
    "chance_pos_per_key_mrr", "labelled_recall_trials",
    # ATK-EV-16: why the S06 margin is undefined (empty when defined)
    "s06_reason",
    # spec 06 section 10 D-A (row_kinds node_prf, node_prf_scenario) and D-B (row_kind auc_pooled): appended
    "scenario", "node_precision_mean", "node_recall_mean", "node_f1_mean", "node_fnr_mean", "node_precision_trials",
    "node_recall_trials", "node_f1_trials", "auc", "auc_n_pos", "auc_n_neg", "auc_chance", "auc_trials")
SWEEP_COLUMNS: tuple[str, ...] = (
    "status_note", "point_kind", "lambda_label", "lambda", "w1", "w2", "w3", "top1_expected", "mrr_expected",
    "s06_max_score", "key_attack_score_min", "s06_margin", "s06_held", "same_ranks_as_default",
    "n_key_paths_changed", "changed_key_paths", "key_path_ranks",
    # spec 06 SW-01 (070 primary, hop reading as the sweep): appended
    "mrr_per_key_expected")

_METHOD = {rm.READING_HOP: "hop_jaccard", rm.READING_NODE: "node_jaccard"}
_TIE_NOTE = ("Ties (decision 065): expected rank r - 1 + (t+1)/(m+1) for m matches in a tie group of size t at "
             "competition rank r (= r + (t-1)/2 for m = 1), top-1 credit m/t at r = 1, RR = 1 / rank of the reading; "
             "optimistic r and pessimistic r + t - m as sensitivity. path_id order is never used.")


# ---------------------------------------------------------------- formatting

def f6(value: float | int | None) -> str:
    """6-decimal text; empty for None (one spelling on every run)."""
    return "" if value is None else f"{float(value):.6f}"


def _i(value: int | None) -> str:
    """Integer text; empty for None."""
    return "" if value is None else str(int(value))


def _ids(items: Iterable[str]) -> str:
    """``;``-joined sorted ids."""
    return ";".join(sorted(items))


def _note(split: str) -> str:
    """The ``status_note`` of a row."""
    return DEV_NOTE if split == SPLIT_DEVELOPMENT else TEST_NOTE


def _blank(split: str, trial: str, keyed: bool, kind: str) -> dict[str, str]:
    """A rank.csv row with every column empty except the common ones."""
    row = {c: "" for c in RANK_COLUMNS}
    row.update(status_note=_note(split), trial_id=trial, split=split, keyed="1" if keyed else "0", row_kind=kind)
    return row


def _chance_pos(pl: rm.Placement, positive: frozenset[str]) -> dict[str, float | None]:
    """ATK-SC-21 second chance line (reported beside): a random order of the candidates with score > 0 only, with
    the matches among them."""
    return rm.chance_line(len(positive), len(set(pl.matched) & positive))


def _placement_cells(row: dict[str, str], pl: rm.Placement, n: int, positive: frozenset[str]) -> None:
    """The placement and chance columns of a key-path or trial row (both chance lines, ATK-SC-21)."""
    ch = rm.chance_line(n, len(pl.matched))
    cp = _chance_pos(pl, positive)
    row.update(candidate_count=str(len(pl.matched)), matched_path_ids=_ids(pl.matched),
               first_match_path_ids=_ids(pl.first_group), first_rank=_i(pl.first_rank), tie_size=_i(pl.tie_size),
               matches_in_tie=_i(len(pl.first_group)) if pl.first_group else "",
               rank_expected=f6(pl.rank_expected), rank_optimistic=_i(pl.rank_optimistic),
               rank_pessimistic=_i(pl.rank_pessimistic), rr_expected=f6(pl.rr("expected")),
               rr_optimistic=f6(pl.rr("optimistic")), rr_pessimistic=f6(pl.rr("pessimistic")),
               rr_mean_expected=f6(pl.rr_mean()), top1_expected=f6(pl.top1_expected),
               top1_optimistic=f6(pl.top1_optimistic), top1_pessimistic=f6(pl.top1_pessimistic),
               chance_top1=f6(ch["top1"]), chance_rank_expected=f6(ch["rank"]), chance_rr=f6(ch["rr"]),
               chance_rr_mean=f6(ch["rr_mean"]), n_candidates_positive=str(len(positive)),
               chance_pos_top1=f6(cp["top1"]), chance_pos_rank_expected=f6(cp["rank"]), chance_pos_rr=f6(cp["rr"]),
               chance_pos_rr_mean=f6(cp["rr_mean"]), first_match_score=f6(pl.first_score))


# ---------------------------------------------------------------- rank.csv

def _key_row(t: TrialRank, rr: ReadingResult, kr: KeyPathResult) -> dict[str, str]:
    """One key attack path under one (variant, reading)."""
    kp = kr.key_path
    row = _blank(t.split, t.trial_id, t.keyed, "key_path")
    row.update(variant=rr.variant, match_reading=rr.reading, key_path_id=kp.path_id, key_role=kp.role,
               key_hop_ids=";".join(kp.key_hop_ids), mapped_hop_ids=_ids(kp.mapped_hop_ids),
               unmatched_key_hops=";".join(kp.unmatched_key_hops), method=_METHOD[rr.reading],
               threshold=f6(rm.MATCH_THRESHOLD), n_candidates=str(rr.n),
               matched_jaccards=";".join(f"{p}={f6(j)}" for p, j in sorted(kr.matched.items())),
               key_node_count=str(len(kp.node_uids)), supporting_event_uids=";".join(kr.shared_uids))
    _placement_cells(row, kr.placement, rr.n, rr.positive)
    return row


def _trial_row(t: TrialRank, rr: ReadingResult) -> dict[str, str]:
    """The first match of any key attack path (handoff 14.2 top-1 and MRR are per trial) and the score gap."""
    row = _blank(t.split, t.trial_id, t.keyed, "trial")
    row.update(variant=rr.variant, match_reading=rr.reading, key_path_id=_ids(k.key_path.path_id for k in rr.key_paths),
               method=_METHOD[rr.reading] + "_any_key_attack_path", threshold=f6(rm.MATCH_THRESHOLD),
               n_candidates=str(rr.n), key_attack_score_min=f6(rr.low), other_score_max=f6(rr.high),
               other_max_path_ids=_ids(rr.high_ids), score_gap=f6(rr.gap), k=str(len(rr.key_paths)),
               contested="1" if rr.contested else "0")
    _placement_cells(row, rr.trial, rr.n, rr.positive)
    return row


def _b0_row(t: TrialRank) -> dict[str, str]:
    """H4: full's top-k vs b0 at an equal node budget."""
    b = t.b0
    assert b is not None
    row = _blank(t.split, t.trial_id, t.keyed, "b0_recall")
    row.update(variant="full_vs_b0", method="equal_node_budget", n_candidates=str(len(t.candidates["full"])),
               k=str(b.k), key_node_count=str(b.key_nodes), budget_nodes=f6(b.budget), full_recall=f6(b.full_recall),
               b0_recall=f6(b.b0_recall), budget_nodes_labelled=f6(b.budget_labelled),
               full_recall_labelled=f6(b.full_recall_labelled), b0_recall_labelled=f6(b.b0_recall_labelled),
               contested="1" if b.contested else "0", n_positive_units=str(b.n_positive_units),
               key_nodes_labelled=str(b.key_nodes_labelled))
    return row


def _dist_rows(t: TrialRank) -> list[dict[str, str]]:
    """n and the score distribution per variant (every trial; the only rows of an unkeyed trial)."""
    out: list[dict[str, str]] = []
    for variant, d in t.distributions.items():
        row = _blank(t.split, t.trial_id, t.keyed, "distribution")
        row.update(variant=variant, method="distribution", n_candidates=str(d["n"]), candidate_count=str(d["n"]),
                   score_max=f6(d["max"]), score_min=f6(d["min"]), score_mean=f6(d["mean"]),
                   n_zero_score=str(d["n_zero"]), n_distinct_scores=str(d["n_distinct"]),
                   top_tie_size=str(d["top_tie"]))
        out.append(row)
    return out


def _prf_row(t: TrialRank, p: NodePRF, budget: float | None) -> dict[str, str]:
    """Spec 06 D-A: node P/R/F1/FNR of one variant (``budget_nodes`` = full's expected all-node budget on the b0
    row, NP-02; empty for the path variants, whose top k is fixed by k)."""
    row = _blank(t.split, t.trial_id, t.keyed, KIND_NODE_PRF)
    row.update(variant=p.variant, method=p.method,
               n_candidates=str(len(t.candidates[p.variant])) if p.variant in t.candidates else "",
               k=str(p.k), key_node_count=str(p.key_nodes), budget_nodes=f6(budget) if p.variant == "b0" else "",
               supporting_event_uids=";".join(p.covered_uids), expected_key_nodes_covered=f6(p.covered),
               expected_nodes_held=f6(p.held), node_precision=f6(p.precision), node_recall=f6(p.recall),
               node_f1=f6(p.f1), node_fnr=f6(p.fnr))
    return row


def _auc_row(t: TrialRank, variant: str) -> dict[str, str]:
    """Spec 06 D-B / AUC-03: the per-trial AUC of one variant on one keyed attack trial (node reading); the positive
    candidates are listed in ``matched_path_ids``."""
    pos, neg, pos_ids = auc_split(t, variant)
    auc = rm.mann_whitney_auc(pos, neg)
    row = _blank(t.split, t.trial_id, t.keyed, KIND_AUC_TRIAL)
    row.update(variant=variant, match_reading=rm.READING_NODE, method=METHOD_AUC,
               threshold=f6(rm.MATCH_THRESHOLD), n_candidates=str(len(pos) + len(neg)),
               candidate_count=str(len(pos)), matched_path_ids=_ids(pos_ids), auc=f6(auc), auc_n_pos=str(len(pos)),
               auc_n_neg=str(len(neg)), auc_chance=f6(AUC_CHANCE))
    return row


def trial_rows(t: TrialRank) -> list[dict[str, str]]:
    """Every rank.csv row of one trial: key-path and trial rows per (variant, reading), the b0 row, distributions;
    then (spec 06 section 10, appended so every earlier row keeps its position) the ``node_prf`` rows (full, b1, b2,
    b0) and the ``auc_trial`` rows (full, b1, b2) of a keyed attack trial."""
    rows: list[dict[str, str]] = []
    if t.attack:
        for rr in t.readings:
            rows.extend(_key_row(t, rr, kr) for kr in rr.key_paths)
            rows.append(_trial_row(t, rr))
        if t.b0 is not None:
            rows.append(_b0_row(t))
    rows.extend(_dist_rows(t))
    if t.attack:
        full = next((p for p in t.node_prf if p.variant == "full"), None)
        rows.extend(_prf_row(t, p, None if full is None else full.held) for p in t.node_prf)
        rows.extend(_auc_row(t, v) for v in PATH_VARIANT_ORDER)
    return rows


def trial_csv(t: TrialRank) -> str:
    """The rank.csv text of one trial."""
    return csv_text(RANK_COLUMNS, trial_rows(t))


# ---------------------------------------------------------------- exact comparisons (RS-09)

def r12(value: float) -> float:
    """``value`` rounded to the verdict precision (12 decimals, RS-09 / SC-41)."""
    return round(value, VERDICT_DECIMALS)


def f12(value: float | None) -> str:
    """The compared value as text (``observed_12``); empty for None."""
    return "" if value is None else f"{r12(value):.{VERDICT_DECIMALS}f}"


def at_least(value: float, threshold: float) -> bool:
    """value >= threshold, both at 12 decimals (H1, H2: 0.80 exactly is held, 0.849999 is not)."""
    return r12(value) >= r12(threshold)


def strictly_greater(a: float, b: float) -> bool:
    """a > b, both at 12 decimals (H3, H4, H5 and the per-trial counts: equal at 12 decimals is not greater,
    ATK-EV-02, ATK-EV-22)."""
    return r12(a) > r12(b)


# ---------------------------------------------------------------- totals

def _mean(values: Sequence[float]) -> float | None:
    """fsum mean; None for no values."""
    return math.fsum(values) / len(values) if values else None


def _readings(results: Sequence[TrialRank], variant: str, reading: str) -> list[ReadingResult]:
    """The (variant, reading) result of every attack trial, in trial order."""
    return [rr for t in results if t.attack for rr in t.readings if rr.variant == variant and rr.reading == reading]


def attack_readings(results: Sequence[TrialRank], variant: str, reading: str,
                    trial_ids: Iterable[str] | None = None) -> list[tuple[str, ReadingResult]]:
    """(trial id, result) of every attack trial for one (variant, reading), in trial order; restricted to
    ``trial_ids`` when given (the contested reading)."""
    keep = None if trial_ids is None else set(trial_ids)
    return [(t.trial_id, rr) for t in results if t.attack and (keep is None or t.trial_id in keep)
            for rr in t.readings if rr.variant == variant and rr.reading == reading]


def contested_ids(results: Sequence[TrialRank], variant: str) -> tuple[str, ...]:
    """EV-03: the attack trials where ``variant`` has more than one candidate with score > 0, in trial order. The
    positive set does not depend on the match reading, so the node reading (EV-06) is read."""
    return tuple(tid for tid, rr in attack_readings(results, variant, rm.READING_NODE) if rr.contested)


def b0_contested_ids(results: Sequence[TrialRank]) -> tuple[str, ...]:
    """EV-03 for b0: attack trials with more than one distinct canonical b0 unit with score > 0."""
    return tuple(t.trial_id for t in results if t.attack and t.b0 is not None and t.b0.contested)


def uncontested_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Every (variant, reading, trial) left out of the contested reading with its reason (EV-03, ATK-EV-05), then
    b0's; the reason names "uncontested — key path not scored" when the only scored candidate is a rival."""
    out: list[dict[str, str]] = []
    for variant in PATH_VARIANT_ORDER:
        for reading in rm.READINGS:
            for tid, rr in attack_readings(results, variant, reading):
                if not rr.contested:
                    out.append({"variant": variant, "match_reading": reading, "trial": tid,
                                "n_positive": str(len(rr.positive)), "reason": rr.uncontested_reason()})
    for t in results:
        if t.attack and t.b0 is not None and not t.b0.contested:
            reason = ("uncontested — no labelled unit scored" if t.b0.n_positive_units == 0
                      else "uncontested — one labelled unit scored")
            out.append({"variant": B0_SET, "match_reading": "", "trial": t.trial_id,
                        "n_positive": str(t.b0.n_positive_units), "reason": reason})
    return out


def ranking_values(rrs: Sequence[ReadingResult]) -> dict[str, float | int | None]:
    """Every ranking metric over ``rrs`` as exact floats (fsum means; None over no trial). WHY one function: the
    totals CSV (6 decimals) and the results verdicts (12 decimals, RS-09) must come from the same numbers.
    The per-key chance line (EV-05, ATK-EV-03) uses chance_line(n, m_k) with m_k = candidates matching key path k,
    averaged over key paths, not the per-trial union of matches."""
    kps = [(rr, kr) for rr in rrs for kr in rr.key_paths]
    chances = [rm.chance_line(rr.n, len(rr.trial.matched)) for rr in rrs]
    chances_pos = [_chance_pos(rr.trial, rr.positive) for rr in rrs]                    # ATK-SC-21
    gaps = [rr.gap for rr in rrs if rr.gap is not None]
    return {
        "attack_trials": len(rrs), "key_paths": len(kps),
        "key_paths_matched": sum(1 for _rr, kr in kps if kr.placement.first_rank is not None),
        "top1_expected": _mean([rr.trial.top1_expected for rr in rrs]),
        "top1_optimistic": _mean([rr.trial.top1_optimistic for rr in rrs]),
        "top1_pessimistic": _mean([rr.trial.top1_pessimistic for rr in rrs]),
        "mrr_expected": _mean([rr.trial.rr("expected") for rr in rrs]),
        "mrr_optimistic": _mean([rr.trial.rr("optimistic") for rr in rrs]),
        "mrr_pessimistic": _mean([rr.trial.rr("pessimistic") for rr in rrs]),
        "mrr_rr_mean_expected": _mean([rr.trial.rr_mean() for rr in rrs]),
        "mrr_per_key_expected": _mean([kr.placement.rr("expected") for _rr, kr in kps]),     # EV-01 primary
        "mrr_per_key_rr_mean": _mean([kr.placement.rr_mean() for _rr, kr in kps]),
        "chance_top1": _mean([c["top1"] for c in chances]),
        "chance_mrr": _mean([c["rr"] for c in chances]),
        "chance_rr_mean": _mean([c["rr_mean"] for c in chances]),
        "chance_pos_top1": _mean([c["top1"] for c in chances_pos]),
        "chance_pos_mrr": _mean([c["rr"] for c in chances_pos]),
        "chance_pos_rr_mean": _mean([c["rr_mean"] for c in chances_pos]),
        "chance_per_key_mrr": _mean([rm.chance_line(rr.n, len(kr.placement.matched))["rr"] for rr, kr in kps]),
        "chance_pos_per_key_mrr": _mean([_chance_pos(kr.placement, rr.positive)["rr"] for rr, kr in kps]),
        "score_gap_min": min(gaps) if gaps else None,
        "trials_gap_positive": sum(1 for g in gaps if strictly_greater(g, 0.0)),         # ATK-EV-22
    }


def b0_values(b0s: Sequence[B0Result]) -> dict[str, float | int | None]:
    """H4 totals as exact floats. The labelled means run over the trials whose labelled recall is defined (decision
    071: a trial without labelled key nodes is left out; ``labelled_recall_trials`` says how many entered)."""
    lab = [b for b in b0s if b.full_recall_labelled is not None and b.b0_recall_labelled is not None]
    return {
        "attack_trials": len(b0s), "labelled_recall_trials": len(lab),
        "full_recall_mean": _mean([b.full_recall for b in b0s]),
        "b0_recall_mean": _mean([b.b0_recall for b in b0s]),
        "full_recall_labelled_mean": _mean([float(b.full_recall_labelled or 0.0) for b in lab]),
        "b0_recall_labelled_mean": _mean([float(b.b0_recall_labelled or 0.0) for b in lab]),
        "trials_full_above_b0": sum(1 for b in b0s if strictly_greater(b.full_recall, b.b0_recall)),  # ATK-EV-22
        "trials_full_above_b0_labelled": sum(1 for b in lab                     # ATK-EV-22: at 12 decimals
                                             if strictly_greater(float(b.full_recall_labelled or 0.0),
                                                                 float(b.b0_recall_labelled or 0.0))),
    }


def h5_facts(results: Sequence[TrialRank], variant: str = "full", reading: str = rm.READING_NODE) -> dict[str, Any]:
    """The one S06 check (065 H5; spec 06 RS-05; ATK-EV-04, -15, -16, -21), used by rank_totals.csv / rank.md and by
    the results tables alike.

    - S06 trials are named by scenario id (``params.is_s06``): keyed ones decide, unkeyed ones are reported beside
      with the margin they would give.
    - ``low`` = the lowest first-match score of the key attack paths over the attack trials. If any key attack path
      has no matching candidate it is **undefined** (never computed over the rest).
    - Per S06 trial: its highest score and margin = low - that score. ``margin`` = the minimum over the keyed S06
      trials (= low - the highest keyed S06 score); ``held`` = every keyed margin > 0 at 12 decimals.
    - When undefined, ``margin`` and ``held`` are None and ``reason`` says why, one distinct text per case.
    """
    attack = attack_readings(results, variant, reading)
    unmatched = [f"{tid}:{kr.key_path.path_id}" for tid, rr in attack for kr in rr.key_paths
                 if kr.placement.first_score is None]
    scores = [kr.placement.first_score for _tid, rr in attack for kr in rr.key_paths
              if kr.placement.first_score is not None]
    low = None if unmatched or not scores else min(scores)

    def per_trial(t: TrialRank) -> dict[str, Any]:
        top = max((c.score for c in t.candidates[variant]), default=None)
        return {"trial_id": t.trial_id, "max": top, "margin": None if low is None or top is None else low - top}

    keyed = [per_trial(t) for t in results if t.keyed and is_s06(t.trial_id)]
    unkeyed = [per_trial(t) for t in results if not t.keyed and is_s06(t.trial_id)]
    tops = [k["max"] for k in keyed if k["max"] is not None]
    empty = [k["trial_id"] for k in keyed if k["max"] is None]
    if not keyed:
        reason = "no keyed S06 trial"
    elif unmatched:
        reason = ("unmatched key attack path (" + ";".join(unmatched)
                  + "): no matching candidate, so the lowest key attack score is undefined")
    elif low is None:
        reason = "no key attack scores"
    elif empty:
        reason = "a keyed S06 trial has no candidate path (" + ";".join(empty) + ")"
    else:
        reason = ""
    margins = [k["margin"] for k in keyed]
    margin = None if reason else min(margins)
    held = None if margin is None else all(strictly_greater(m, H5_MIN_MARGIN) for m in margins)
    s06_max = max(tops) if tops else None
    rrs = [rr for _t, rr in attack]
    above = (sum(1 for rr in rrs if rr.low is not None and strictly_greater(rr.low, s06_max)) / len(rrs)
             if rrs and s06_max is not None else None)
    return {"low": low, "unmatched": unmatched, "keyed": keyed, "unkeyed": unkeyed, "s06_max": s06_max,
            "margin": margin, "held": held, "reason": reason, "share_above": above}


def s06_facts(results: Sequence[TrialRank], variant: str, reading: str) -> dict[str, Any]:
    """The S06 columns of a totals row, read from ``h5_facts`` (one function for both outputs, ATK-EV-16)."""
    h = h5_facts(results, variant, reading)
    return {"s06_trials": len(h["keyed"]), "s06_max": h["s06_max"], "low": h["low"], "margin": h["margin"],
            "held": h["held"], "share_above": h["share_above"], "reason": h["reason"]}


def _count(value: float | int | None) -> str:
    """A count cell; empty for None."""
    return "" if value is None else str(int(value))


_RANKING_FLOATS: tuple[str, ...] = (
    "top1_expected", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic", "mrr_pessimistic",
    "mrr_rr_mean_expected", "mrr_per_key_expected", "mrr_per_key_rr_mean", "chance_top1", "chance_mrr",
    "chance_rr_mean", "chance_pos_top1", "chance_pos_mrr", "chance_pos_rr_mean", "chance_per_key_mrr",
    "chance_pos_per_key_mrr", "score_gap_min")


def _ranking_row(split: str, kind: str, variant: str, reading: str, scope: str, contested_set: str,
                 pairs: Sequence[tuple[str, ReadingResult]], s6: Mapping[str, Any] | None) -> dict[str, str]:
    """One totals row of the ranking metrics over ``pairs``; the S06 columns only when ``s6`` is given (H5 has no
    contested reading, spec 06 Q2). Zero trials gives empty metrics (EV-03)."""
    v = ranking_values([rr for _t, rr in pairs])
    row = {c: "" for c in TOTAL_COLUMNS}
    row.update(status_note=_note(split), split=split, row_kind=kind, variant=variant, match_reading=reading,
               reading_scope=scope, contested_set=contested_set, primary_metric=PRIMARY_RANKING,
               scope_trial_ids=";".join(t for t, _rr in pairs))
    for name in ("attack_trials", "key_paths", "key_paths_matched", "trials_gap_positive"):
        row[name] = _count(v[name])
    for name in _RANKING_FLOATS:
        row[name] = f6(v[name])
    if s6 is not None:
        row.update(s06_trials=str(s6["s06_trials"]), s06_max_score=f6(s6["s06_max"]),
                   key_attack_score_min=f6(s6["low"]), s06_margin=f6(s6["margin"]),
                   s06_held="" if s6["held"] is None else str(int(s6["held"])),
                   share_attack_trials_above_s06=f6(s6["share_above"]), s06_reason=s6["reason"])
    return row


def _b0_total_row(split: str, kind: str, scope: str, contested_set: str, trial_ids: Sequence[str],
                  b0s: Sequence[B0Result]) -> dict[str, str]:
    """One H4 totals row over ``b0s`` (labelled basis primary, all-node basis beside)."""
    v = b0_values(b0s)
    row = {c: "" for c in TOTAL_COLUMNS}
    row.update(status_note=_note(split), split=split, row_kind=kind, variant="full_vs_b0",
               attack_trials=_count(v["attack_trials"]), recall_basis=RECALL_BASIS_ALL,
               full_recall_mean=f6(v["full_recall_mean"]), b0_recall_mean=f6(v["b0_recall_mean"]),
               recall_basis_labelled=RECALL_BASIS_LABELLED,
               full_recall_labelled_mean=f6(v["full_recall_labelled_mean"]),
               b0_recall_labelled_mean=f6(v["b0_recall_labelled_mean"]),
               trials_full_above_b0=_count(v["trials_full_above_b0"]),
               trials_full_above_b0_labelled=_count(v["trials_full_above_b0_labelled"]),
               reading_scope=scope, contested_set=contested_set, primary_metric=PRIMARY_B0,
               scope_trial_ids=";".join(trial_ids), labelled_recall_trials=_count(v["labelled_recall_trials"]))
    return row


def b0_of(results: Sequence[TrialRank], trial_ids: Iterable[str] | None = None) -> tuple[list[str], list[B0Result]]:
    """(trial ids, B0Result) of the attack trials, restricted to ``trial_ids`` when given."""
    keep = None if trial_ids is None else set(trial_ids)
    ids: list[str] = []
    b0s: list[B0Result] = []
    for t in results:
        if t.attack and t.b0 is not None and (keep is None or t.trial_id in keep):
            ids.append(t.trial_id)
            b0s.append(t.b0)
    return ids, b0s


def contested_plan() -> list[tuple[str, str]]:
    """(variant, contested set) of every ``ranking_contested`` row: each variant over its own set, then b1 over
    full's set (the paired H3 reading, EV-04)."""
    return [(v, v) for v in PATH_VARIANT_ORDER] + [("b1", PAIRED_SET)]


def total_rows(results: Sequence[TrialRank], split: str) -> list[dict[str, str]]:
    """rank_totals.csv: the ``ranking`` rows per (variant, reading) and the ``b0_recall`` row (reading_scope all,
    unchanged in number, EV-08), then the contested rows: each variant over its own contested set, b1 over full's
    contested set (paired H3, EV-04), and H4 over full's contested set (paired) and over b0's own set (beside)."""
    out: list[dict[str, str]] = []
    for variant in PATH_VARIANT_ORDER:
        for reading in rm.READINGS:
            out.append(_ranking_row(split, KIND_RANKING, variant, reading, SCOPE_ALL, "",
                                    attack_readings(results, variant, reading), s06_facts(results, variant, reading)))
    ids, b0s = b0_of(results)
    out.append(_b0_total_row(split, KIND_B0, SCOPE_ALL, "", ids, b0s))
    sets = {v: contested_ids(results, v) for v in PATH_VARIANT_ORDER}
    for variant, set_name in contested_plan():
        for reading in rm.READINGS:
            out.append(_ranking_row(split, KIND_RANKING_CONTESTED, variant, reading, SCOPE_CONTESTED, set_name,
                                    attack_readings(results, variant, reading, sets[set_name]), None))
    for set_name, set_ids in ((PAIRED_SET, sets[PAIRED_SET]), (B0_SET, b0_contested_ids(results))):
        ids, b0s = b0_of(results, set_ids)
        out.append(_b0_total_row(split, KIND_B0_CONTESTED, SCOPE_CONTESTED, set_name, ids, b0s))
    return out + addendum_rows(results, split)                     # spec 06 section 10, appended after the rest


# ---------------------------------------------------------------- node P/R/F1/FNR and ROC-AUC (spec 06 section 10)

def scenario_of(trial: str) -> str:
    """The scenario id of a trial id (``s02_t00`` -> ``s02``)."""
    return trial.split("_")[0]


def node_prf_pairs(results: Sequence[TrialRank], variant: str,
                   scenario: str | None = None) -> list[tuple[str, NodePRF]]:
    """(trial id, NodePRF) of ``variant`` on every keyed attack trial (NP-03: S06 and unkeyed trials have no key
    nodes and are left out), restricted to one scenario when given; trial order."""
    return [(t.trial_id, p) for t in results if t.attack
            and (scenario is None or scenario_of(t.trial_id) == scenario) for p in t.node_prf if p.variant == variant]


def attack_scenarios(results: Sequence[TrialRank]) -> tuple[str, ...]:
    """Scenario ids of the keyed attack trials, sorted."""
    return tuple(sorted({scenario_of(t.trial_id) for t in results if t.attack}))


def node_prf_values(prfs: Sequence[NodePRF]) -> dict[str, float | int | None]:
    """NP-03 macro means (fsum) of P, R, F1, FNR over the trials where each is defined, with the number of trials
    that entered each mean (P and F1 are undefined when the expected number of nodes held is 0, NP-05). WHY the mean
    of per-trial F1 and not F1 of the mean P and R: each trial is one reconstruction, weighted equally (macro)."""
    ps = [p.precision for p in prfs if p.precision is not None]
    rs = [p.recall for p in prfs if p.recall is not None]
    fs = [p.f1 for p in prfs if p.f1 is not None]
    ns = [p.fnr for p in prfs if p.fnr is not None]
    return {"attack_trials": len(prfs), "node_precision_mean": _mean(ps), "node_recall_mean": _mean(rs),
            "node_f1_mean": _mean(fs), "node_fnr_mean": _mean(ns), "node_precision_trials": len(ps),
            "node_recall_trials": len(rs), "node_f1_trials": len(fs)}


def auc_split(t: TrialRank, variant: str) -> tuple[list[float], list[float], tuple[str, ...]]:
    """(positive scores, negative scores, positive ids) of one keyed trial (AUC-01): positives = candidates
    matching any key attack path under the node reading (EV-06); every other candidate is a negative, so a keyed S06
    trial gives negatives only. An unkeyed trial gives nothing (it is left out)."""
    if not t.keyed:
        return [], [], ()
    hit: set[str] = set()
    for rr in t.readings:
        if rr.variant == variant and rr.reading == rm.READING_NODE:
            hit |= set(rr.trial.matched)
    cands = t.candidates[variant]
    return ([c.score for c in cands if c.path_id in hit], [c.score for c in cands if c.path_id not in hit],
            tuple(sorted(hit)))


def auc_trial_values(t: TrialRank, variant: str) -> dict[str, float | int | None]:
    """AUC-03: AUC, n_pos and n_neg of one keyed attack trial (AUC None when either count is 0)."""
    pos, neg, _ids = auc_split(t, variant)
    return {"auc": rm.mann_whitney_auc(pos, neg), "auc_n_pos": len(pos), "auc_n_neg": len(neg)}


def auc_values(results: Sequence[TrialRank], variant: str) -> dict[str, Any]:
    """AUC-01: the pooled AUC over every keyed trial (attack and S06), with n_pos, n_neg and the pooled trial ids."""
    pos: list[float] = []
    neg: list[float] = []
    ids: list[str] = []
    for t in results:
        if not t.keyed:
            continue
        p, n, _h = auc_split(t, variant)
        pos += p
        neg += n
        ids.append(t.trial_id)
    return {"auc": rm.mann_whitney_auc(pos, neg), "auc_n_pos": len(pos), "auc_n_neg": len(neg),
            "auc_trials": len(ids), "trial_ids": tuple(ids)}


def _prf_total_row(split: str, kind: str, variant: str, scenario: str,
                   pairs: Sequence[tuple[str, NodePRF]]) -> dict[str, str]:
    """One node P/R/F1/FNR totals row (NP-03): the macro means over ``pairs``; no primary metric, no verdict."""
    v = node_prf_values([p for _t, p in pairs])
    row = {c: "" for c in TOTAL_COLUMNS}
    row.update(status_note=_note(split), split=split, row_kind=kind, variant=variant, reading_scope=SCOPE_ALL,
               scenario=scenario, scope_trial_ids=";".join(tid for tid, _p in pairs),
               attack_trials=_count(v["attack_trials"]))
    for name in ("node_precision_mean", "node_recall_mean", "node_f1_mean", "node_fnr_mean"):
        row[name] = f6(v[name])
    for name in ("node_precision_trials", "node_recall_trials", "node_f1_trials"):
        row[name] = _count(v[name])
    return row


def _auc_total_row(results: Sequence[TrialRank], split: str, variant: str) -> dict[str, str]:
    """One ``auc_pooled`` row (AUC-01): pooled over the keyed trials; ``attack_trials`` = keyed attack trials among
    them, ``auc_trials`` = every pooled trial (keyed S06 included)."""
    v = auc_values(results, variant)
    row = {c: "" for c in TOTAL_COLUMNS}
    row.update(status_note=_note(split), split=split, row_kind=KIND_AUC_POOLED, variant=variant,
               match_reading=rm.READING_NODE, reading_scope=SCOPE_ALL, scope_trial_ids=";".join(v["trial_ids"]),
               attack_trials=str(sum(1 for t in results if t.attack)), auc=f6(v["auc"]),
               auc_n_pos=str(v["auc_n_pos"]), auc_n_neg=str(v["auc_n_neg"]), auc_chance=f6(AUC_CHANCE),
               auc_trials=str(v["auc_trials"]))
    return row


def addendum_rows(results: Sequence[TrialRank], split: str) -> list[dict[str, str]]:
    """The spec 06 section 10 totals rows, appended after every earlier row: ``node_prf`` per variant (full, b1, b2,
    b0), ``node_prf_scenario`` per (variant, scenario), ``auc_pooled`` per path variant."""
    out = [_prf_total_row(split, KIND_NODE_PRF, v, "", node_prf_pairs(results, v)) for v in PRF_VARIANT_ORDER]
    out += [_prf_total_row(split, KIND_NODE_PRF_SCENARIO, v, s, node_prf_pairs(results, v, s))
            for v in PRF_VARIANT_ORDER for s in attack_scenarios(results)]
    out += [_auc_total_row(results, split, v) for v in PATH_VARIANT_ORDER]
    return out


# ---------------------------------------------------------------- sweep

def _w(value: float) -> str:
    """A weight as text (6 decimals)."""
    return f6(value)


def sweep_rows(default: SweepPoint, points: Sequence[SweepPoint], split: str) -> list[dict[str, str]]:
    """rank_sweep.csv: the default point first, then every grid / default_w point in grid order."""
    out: list[dict[str, str]] = []
    for p in [default, *points]:
        changed = changed_keys(p, default)
        margin = None if p.attack_min is None or p.s06_max is None else p.attack_min - p.s06_max
        out.append({"status_note": _note(split), "point_kind": p.kind, "lambda_label": p.lam_label,
                    "lambda": f6(p.lam), "w1": _w(p.w[0]), "w2": _w(p.w[1]), "w3": _w(p.w[2]),
                    "top1_expected": f6(p.top1), "mrr_expected": f6(p.mrr), "s06_max_score": f6(p.s06_max),
                    "key_attack_score_min": f6(p.attack_min), "s06_margin": f6(margin),
                    "s06_held": "" if margin is None else str(int(strictly_greater(margin, 0.0))),
                    "same_ranks_as_default": "1" if not changed else "0", "n_key_paths_changed": str(len(changed)),
                    "changed_key_paths": ";".join(changed),
                    "key_path_ranks": ";".join(f"{t}:{k}={f6(r)}" for t, k, r in p.key_ranks),
                    "mrr_per_key_expected": f6(p.mrr_per_key)})
    return out


# ---------------------------------------------------------------- rank.md

def _table(columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """A Markdown table; empty cells shown as ``-``."""
    lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(c, "")) or "-" for c in columns) + " |")
    return lines


def _section(title: str, columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """A titled table headed with the development note."""
    return ["", f"### {title}", "", f"**{DEV_NOTE}.**", ""] + _table(columns, rows)


def _readings_text() -> list[str]:
    """The stated readings (module docstrings, short)."""
    return [
        "## Readings", "",
        "- Key attack paths = key `paths` with role `attack` / `attack_pair`. Hop reading: Jaccard >= 0.5 between a "
        "candidate's `hop_ids` and the stitch hops mapped from the key path's hops (ST-25, `keys.match_key_hop`, as "
        "link accuracy). Node reading (handoff 14.2): Jaccard >= 0.5 between the candidate's `context` = 0 event uids "
        "(stitch `path_nodes.csv`) and the union of the key hops' " + ", ".join(f"`{f}`" for f in rm.KEY_NODE_FIELDS)
        + ". Key `steps` are not read (move / service steps lie inside these fields; dump steps are `context` = 1). "
        "A node match also needs the candidate to hold one of the key path's target logon uids (key "
        "`target_event_uids` that are target 4624 members of a stitch hop; ATK-SC-16), and ST-05 copies "
        "(`rep|copy` items of `member_logon_uids`) are replaced by their representative on every side first.",
        f"- {_TIE_NOTE}",
        "- Primary readings (decision 070; spec 06 EV-01, EV-02, EV-06): H1 = top-1 (expected ties) per attack trial; "
        "H2 / H3 = **per-key MRR** (each key attack path's own expected RR, averaged over key attack paths; "
        "ATK-SC-15); H4 = "
        f"recall on \"{RECALL_BASIS_LABELLED}\": the denominator is the labelled key nodes = key nodes inside at least "
        "one `b0_ranked.csv` unit (decision 071); a trial with none is undefined and left out of the mean, the number "
        "of trials that entered is `labelled_recall_trials`; H5 = the S06 check. The verdict reading is the node "
        "reading; the hop reading is shown beside it.",
        "- Reported beside: per-trial MRR (first candidate matching any key attack path, handoff 14.2), E[1/rank] "
        "beside 1/E[rank] (`*_rr_mean`), optimistic / pessimistic ties, the score gap, and recall on "
        f"\"{RECALL_BASIS_ALL}\". Keyed trials without key attack paths (S06) enter only the S06 check.",
        "- Chance line (EV-05): all n candidates in one tie group (top-1 m/n, rank (n+1)/(m+1), chance_mrr = its "
        "inverse; chance_rr_mean = E[1/rank]); `chance_pos_*` = the same over the candidates with score > 0 only "
        "(ATK-SC-21). "
        "Beside per-key MRR the chance line is per key path (`chance_per_key_mrr`: m_k = candidates matching that key "
        "path, averaged over key paths; ATK-EV-03). Every table that shows a ranking metric shows both chance lines; "
        "the S06 and H4 tables show score margins and node recall, where no random order applies.",
        "- Contested reading (decision 070 item 4; spec 06 EV-03, EV-04; secondary, never a verdict): a variant's "
        "contested attack trials are those where more than one of its candidates has score > 0 (b0: more than one "
        "distinct labelled unit with score > 0, ST-05 copies merged). Every ranking metric is recomputed over each "
        "variant's own contested set; the paired comparisons (H3 full vs b1, H4 full vs b0) use full's contested set "
        "for both sides, and each variant's own set is reported beside. b0 has no paths, so its contested reading is "
        "the H4 recall only. H5 has no contested reading (a subset of attack trials can only raise the lowest key "
        "score). A trial whose only scored candidate is a rival is named \"uncontested — key path not scored\".",
        "- Scores are read as written, with 12 decimals: the value ties are decided on (ATK-SC-24).",
        "- Score gap = lowest first-match score of the key attack paths - highest score of the candidates matching no "
        "key attack path. S06 check: highest S06 score vs the lowest key attack score of the attack trials.",
        "- b0 (H4): budget = expected distinct `context` = 0 nodes of full's top-k paths (k = key attack paths; tie at "
        "the cut by inclusion probability); b0 takes units in rank order up to the budget, the tie group at the cut read "
        "by expectation at node level. `_labelled` = the same with only the labelled `context` = 0 nodes (NodeScore "
        "units) of the top k as budget, and recall over the labelled key nodes (071).",
        "- The path score orders paths; it is not a probability. These checks rank; they do not claim to detect "
        "anything. Hypotheses H1-H5 are expected, to be measured on test trials at T10.",
    ]


def _inputs_section(results: Sequence[TrialRank]) -> list[str]:
    """Input hashes per trial (traceability without a timestamp)."""
    names = ("score_run_info_sha256", "ranked_paths_sha256", "stitch_path_nodes_sha256", "key_sha256")
    rows = [dict({"trial_id": t.trial_id}, **{n: t.inputs.get(n, "")[:16] for n in names}) for t in results]
    return ["", "## Inputs (SHA-256, first 16 hex digits)", ""] + _table(("trial_id",) + names, rows)


def _key_md_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Per key attack path, variant and reading, with the per-key chance line (m_k = candidates matching this key
    path; EV-05) over all candidates and over score > 0."""
    out = []
    for t in results:
        for rr in t.readings:
            for kr in rr.key_paths:
                pl = kr.placement
                ch = rm.chance_line(rr.n, len(pl.matched))
                cp = _chance_pos(pl, rr.positive)
                out.append({"trial": t.trial_id, "key_path": kr.key_path.path_id, "variant": rr.variant,
                            "reading": rr.reading, "first_match": _ids(pl.first_group), "r": _i(pl.first_rank),
                            "t": _i(pl.tie_size), "m": _i(len(pl.first_group)) if pl.first_group else "",
                            "rank_exp": f6(pl.rank_expected), "rank_opt": _i(pl.rank_optimistic),
                            "rank_pess": _i(pl.rank_pessimistic), "rr_exp": f6(pl.rr("expected")),
                            "chance_rr": f6(ch["rr"]), "chance_pos_rr": f6(cp["rr"]),
                            "score": f6(pl.first_score), "n": str(rr.n), "n_pos": str(len(rr.positive))})
    return out


def _trial_md_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Per attack trial, variant and reading: top-1, RR, chance, score gap and the contested flag."""
    out = []
    for t in results:
        for rr in t.readings:
            ch = rm.chance_line(rr.n, len(rr.trial.matched))
            cp = _chance_pos(rr.trial, rr.positive)
            out.append({"trial": t.trial_id, "variant": rr.variant, "reading": rr.reading, "n": str(rr.n),
                        "top1_exp": f6(rr.trial.top1_expected), "rr_exp": f6(rr.trial.rr("expected")),
                        "rr_opt": f6(rr.trial.rr("optimistic")), "rr_pess": f6(rr.trial.rr("pessimistic")),
                        "E[1/rank]": f6(rr.trial.rr_mean()), "chance_top1": f6(ch["top1"]), "chance_rr": f6(ch["rr"]),
                        "chance_E[1/rank]": f6(ch["rr_mean"]), "n_pos": str(len(rr.positive)),
                        "chance_pos_top1": f6(cp["top1"]), "chance_pos_rr": f6(cp["rr"]),
                        "contested": "1" if rr.contested else "0",
                        "attack_min": f6(rr.low), "other_max": f6(rr.high), "gap": f6(rr.gap)})
    return out


def informative_sentence(facts: Mapping[str, Any]) -> str:
    """The ATK-SC-22 statement (decision 069 item 9), built from ``rank_sweep.informativeness``: on development data
    the sweep is not informative, and it never moves a value."""
    n, zero, ties = facts["attack_trials"], facts["all_rivals_zero"], facts["tie_every_weight"]
    tie_text = (f"{', '.join(t.split('_')[0] for t in ties)} {'ties' if len(ties) == 1 else 'tie'} at every weight"
                if ties else "no trial ties at every weight")
    return (f"not informative on development data: in {len(zero)} of {n} attack trials every rival path scores 0 "
            f"and {tie_text}; the sweep reports, it never moves a value")


def _sweep_chance(totals: Sequence[Mapping[str, str]]) -> dict[str, str]:
    """The chance cells beside the sweep's metrics (EV-05): full, hop reading, all attack trials. Over all
    candidates they do not depend on w (n and the hop matches are fixed); over score > 0 they are given at the
    default w, since a weight can move a score to 0."""
    row = next((r for r in totals if r["row_kind"] == KIND_RANKING and r["variant"] == "full"
                and r["match_reading"] == rm.READING_HOP), None)
    names = ("chance_top1", "chance_mrr", "chance_pos_top1", "chance_pos_mrr")
    return {n: (row[n] if row else "") for n in names}


_SWEEP_CHANCE_COLS: tuple[str, ...] = ("chance_top1 (any w)", "chance_mrr (any w)", "chance_pos_top1 (default w)",
                                       "chance_pos_mrr (default w)")


def _with_chance(row: dict[str, str], chance: Mapping[str, str]) -> dict[str, str]:
    """``row`` plus the four sweep chance cells."""
    row.update(zip(_SWEEP_CHANCE_COLS, (chance["chance_top1"], chance["chance_mrr"], chance["chance_pos_top1"],
                                        chance["chance_pos_mrr"])))
    return row


def _sweep_section(default: SweepPoint, points: Sequence[SweepPoint], check: Mapping[str, Any],
                   facts: Mapping[str, Any], chance: Mapping[str, str]) -> list[str]:
    """Default check, the ATK-SC-22 statement, the rank-unchanged grid points per lambda, and the metric range over
    the grid (with the chance line, EV-05). WHY no "stable" claim: with zero-score rivals and full ties no weight can
    change a rank, so an unchanged rank says nothing about robustness (ATK-SC-22)."""
    lines = ["", "## Stability sweep (spec 05 section 5.2 step 2; decision 066)", "",
             "Scores recomputed from `ranked_paths.csv` columns only (L = (1 - e^(-seq_len/lambda)) * edge_score; "
             "score = w1 L + w2 node_score + w3 identity_coherence). The sweep never changes a parameter; it reports.",
             "", SW04_SENTENCE, "", f"- The sweep is {informative_sentence(facts)} (ATK-SC-22).",
             f"- Default check: {check['paths']} paths, max |recomputed - written full score| = "
             f"{check['max_abs_diff']:.3g} (tolerance 1e-6); rank mismatches {check['rank_mismatch']}.",
             f"- Default point: lambda {default.lam:.6f}, w = ({default.w[0]:.6f}, {default.w[1]:.6f}, "
             f"{default.w[2]:.6f}); top-1 (expected) {f6(default.top1)}, MRR (expected, per trial) {f6(default.mrr)}; "
             f"hop reading; chance top-1 {chance['chance_top1'] or '-'}, MRR {chance['chance_mrr'] or '-'} (all "
             f"candidates), {chance['chance_pos_top1'] or '-'} / {chance['chance_pos_mrr'] or '-'} (score > 0)."]
    region = stable_region(points, default)
    rows = [{"lambda": r["lambda"], "grid_points": str(r["grid_points"]), "unchanged_points": str(r["stable_points"]),
             "unchanged_radius": "none changed" if r["stable_radius"] is None else f6(r["stable_radius"]),
             "default_w_unchanged": "1" if r["default_w_stable"] else "0"} for r in region]
    lines += _section("Grid points where no key attack path's expected rank changes (unchanged_radius = Chebyshev "
                      "distance from w = 1/3 to the nearest grid point that changes a rank); not informative on "
                      "development data, see above",
                      ("lambda", "grid_points", "unchanged_points", "unchanged_radius", "default_w_unchanged"), rows)
    grid = [p for p in points if p.kind == "grid"]
    by_lam = []
    for lab, _v in LAMBDA_GRID:
        ps = [p for p in grid if p.lam_label == lab]
        t1 = [p.top1 for p in ps if p.top1 is not None]
        mr = [p.mrr for p in ps if p.mrr is not None]
        pk = [p.mrr_per_key for p in ps if p.mrr_per_key is not None]
        above = [p for p in ps if p.attack_min is not None and p.s06_max is not None and p.attack_min > p.s06_max]
        by_lam.append(_with_chance({"lambda": lab, "top1_min": f6(min(t1) if t1 else None),
                                    "top1_max": f6(max(t1) if t1 else None), "mrr_min": f6(min(mr) if mr else None),
                                    "mrr_max": f6(max(mr) if mr else None),
                                    "per_key_mrr_min": f6(min(pk) if pk else None),
                                    "per_key_mrr_max": f6(max(pk) if pk else None),
                                    S06_POINTS_COL: f"{len(above)}/{len(ps)}"}, chance))
    lines += _section("Metric range over the w grid per lambda (hop reading, expected ties; per-trial MRR and "
                      "per-key MRR side by side). " + S06_POINTS_TEXT,
                      ("lambda", "top1_min", "top1_max", "mrr_min", "mrr_max", "per_key_mrr_min", "per_key_mrr_max")
                      + _SWEEP_CHANCE_COLS + (S06_POINTS_COL,), by_lam)
    dw = [_with_chance({"lambda": p.lam_label, "top1_exp": f6(p.top1), "mrr_exp": f6(p.mrr),
                        "s06_max": f6(p.s06_max), "attack_min": f6(p.attack_min),
                        "changed": ";".join(changed_keys(p, default)) or "none"}, chance)
          for p in points if p.kind == "default_w"]
    lines += _section("Default w at every grid lambda", ("lambda", "top1_exp", "mrr_exp") + _SWEEP_CHANCE_COLS
                      + ("s06_max", "attack_min", "changed"), dw)
    return lines


def _h4_trial_rows(results: Sequence[TrialRank], cols: Sequence[str]) -> list[dict[str, str]]:
    """Per attack trial H4 cells in ``cols`` order: labelled basis first (primary), all-node basis beside."""
    rows = []
    for t in results:
        b = t.b0
        if not t.attack or b is None:
            continue
        rows.append(dict(zip(cols, (t.trial_id, str(b.k), str(b.key_nodes_labelled), f6(b.budget_labelled),
                                    f6(b.full_recall_labelled), f6(b.b0_recall_labelled), str(b.key_nodes),
                                    f6(b.budget), f6(b.full_recall), f6(b.b0_recall), str(b.n_positive_units),
                                    "1" if b.contested else "0"))))
    return rows


def _h4_section(results: Sequence[TrialRank], totals: Sequence[Mapping[str, str]]) -> list[str]:
    """H4 (b0 vs full at an equal node budget), labelled basis first (primary, 070 / 071), all-node basis beside
    (ATK-SC-14: b0, labelled events only, cannot reach every ``context`` = 0 node)."""
    a, lab = RECALL_BASIS_ALL, RECALL_BASIS_LABELLED
    cols = ("trial", "k", f"key_nodes: {lab}", f"budget: {lab}", f"full_recall: {lab}", f"b0_recall: {lab}",
            f"key_nodes: {a}", f"budget: {a}", f"full_recall: {a}", f"b0_recall: {a}", "b0_positive_units",
            "b0_contested")
    out = _section(f"b0 vs full at an equal node budget (H4), labelled basis first; chance line {CHANCE_NA_RECALL}",
                   cols, _h4_trial_rows(results, cols))
    tcols = ("attack_trials", "labelled_recall_trials", f"full_recall_mean: {lab}", f"b0_recall_mean: {lab}",
             f"trials_full_above_b0: {lab}", f"full_recall_mean: {a}", f"b0_recall_mean: {a}",
             f"trials_full_above_b0: {a}")
    trows = [dict(zip(tcols, (r["attack_trials"], r["labelled_recall_trials"], r["full_recall_labelled_mean"],
                              r["b0_recall_labelled_mean"], r["trials_full_above_b0_labelled"],
                              r["full_recall_mean"], r["b0_recall_mean"], r["trials_full_above_b0"])))
             for r in totals if r["row_kind"] == KIND_B0]
    return out + _section("H4 totals, labelled basis first (primary), all-node basis beside", tcols, trows)


_PRIMARY_COLS: tuple[str, ...] = (
    "variant", "match_reading", "attack_trials", "key_paths", "key_paths_matched", "top1_expected", "chance_top1",
    "chance_pos_top1", "mrr_per_key_expected", "chance_per_key_mrr", "chance_pos_per_key_mrr")
_BESIDE_COLS: tuple[str, ...] = (
    "variant", "match_reading", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic",
    "mrr_pessimistic", "chance_mrr", "chance_pos_mrr", "mrr_rr_mean_expected", "chance_rr_mean",
    "chance_pos_rr_mean", "mrr_per_key_rr_mean", "score_gap_min", "trials_gap_positive")
# No s06_held column in rank.md: H5 is a hypothesis about `full` only (065), and a held / not held cell on the b1 /
# b2 rows reads like a verdict on variants that carry no hypothesis. The margin's sign is shown; the H5 dev_check is
# in results.md. rank_totals.csv keeps s06_held (results.md cross-checks against it).
_S06_COLS: tuple[str, ...] = ("variant", "match_reading", "s06_trials", "s06_max_score", "key_attack_score_min",
                              "s06_margin", "share_attack_trials_above_s06", "s06_reason")
_CONTESTED_COLS: tuple[str, ...] = (
    "variant", "match_reading", "contested_set", "attack_trials", "scope_trial_ids", "key_paths", "top1_expected",
    "chance_top1", "chance_pos_top1", "mrr_per_key_expected", "chance_per_key_mrr", "chance_pos_per_key_mrr",
    "mrr_expected", "chance_mrr", "chance_pos_mrr")
_B0_CONTESTED_COLS: tuple[str, ...] = (
    "contested_set", "attack_trials", "scope_trial_ids", "labelled_recall_trials", "full_recall_labelled_mean",
    "b0_recall_labelled_mean", "trials_full_above_b0_labelled", "full_recall_mean", "b0_recall_mean",
    "trials_full_above_b0")


def _primary_section(totals: Sequence[Mapping[str, str]]) -> list[str]:
    """Decision 070 primary readings first (spec 06 section 3.1): top-1, per-key MRR and both chance lines in one
    table; the H4 labelled-basis totals; the S06 check (H5)."""
    ranking = [r for r in totals if r["row_kind"] == KIND_RANKING]
    lines = ["", "## Primary readings (decision 070)", "",
             "H1 top-1 (expected ties), H2 / H3 per-key MRR, H4 labelled-node recall (denominator: labelled key "
             "nodes, decision 071), H5 S06 check. The verdict reading is the node reading (EV-06); the hop reading is "
             "beside it. No verdict is written here: these are DEVELOPMENT numbers (results tables: "
             "`python -m evaluate --development --results`)."]
    lines += _section("Ranking, all attack trials: top-1 and per-key MRR with the chance line over all candidates "
                      "and over score > 0 (per-key chance uses m_k per key path)", _PRIMARY_COLS, ranking)
    b0 = [r for r in totals if r["row_kind"] == KIND_B0]
    lines += _section(f"H4 labelled basis ({RECALL_BASIS_LABELLED}); chance line {CHANCE_NA_RECALL}",
                      ("attack_trials", "labelled_recall_trials", "full_recall_labelled_mean",
                       "b0_recall_labelled_mean", "trials_full_above_b0_labelled"), b0)
    lines += _section(f"S06 check (highest S06 score vs lowest key attack score); H5 concerns `full` only, the b1 / "
                      f"b2 rows are descriptive and carry no hypothesis; the H5 dev_check is in results.md; chance "
                      f"line {CHANCE_NA_MARGIN}", _S06_COLS, ranking)
    return lines


def _contested_section(results: Sequence[TrialRank], totals: Sequence[Mapping[str, str]]) -> list[str]:
    """The contested reading (EV-03, EV-04): each variant's own set, b1 on full's set (paired H3), H4 on full's set
    (paired) and on b0's own set, and every trial left out with its reason (ATK-EV-05). Never a verdict."""
    lines = ["", "## Contested reading (decision 070 item 4; spec 06 EV-03, EV-04; secondary, never a verdict)"]
    lines += _section("Ranking over contested attack trials (contested_set = whose contested trials; b1 on full's "
                      "set = the paired H3 reading)", _CONTESTED_COLS,
                      [r for r in totals if r["row_kind"] == KIND_RANKING_CONTESTED])
    lines += _section(f"H4 over contested attack trials (full's set = paired reading; b0's own set beside); chance "
                      f"line {CHANCE_NA_RECALL}", _B0_CONTESTED_COLS,
                      [r for r in totals if r["row_kind"] == KIND_B0_CONTESTED])
    lines += _section("Attack trials left out of the contested reading, with the reason",
                      ("variant", "match_reading", "trial", "n_positive", "reason"), uncontested_rows(results))
    return lines


def rank_md(results: Sequence[TrialRank], split: str, totals: Sequence[Mapping[str, str]],
            sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]] | None) -> str:
    """The rank.md text: primary readings (070) first, then readings, inputs, the readings reported beside, H4,
    the contested reading, per key path / per trial tables, trials without key attack paths and the sweep."""
    keyed = [t for t in results if t.keyed]
    ranking = [r for r in totals if r["row_kind"] == KIND_RANKING]
    lines = [md_header(split, None), "", f"Development ranking check over {len(results)} trials, split {split} "
             "(spec 05_score SCA-06; spec 06_evaluate section 4 A; decisions 065, 066, 070, 071). Variants full, b1, "
             "b2 rank the stitch paths; b0 ranks label units (spec 05 section 3.6)."]
    lines += _primary_section(totals)
    lines += [""] + _readings_text() + _inputs_section(results)
    lines += ["", "## Reported beside (decision 070)"]
    lines += _section("Per-trial MRR (first match, handoff 14.2), E[1/rank], optimistic / pessimistic ties and the "
                      "score gap, with the chance line over all candidates and over score > 0", _BESIDE_COLS, ranking)
    lines += _h4_section(results, totals)
    lines += _contested_section(results, totals)
    lines += ["", "## Key attack paths"]
    lines += _section("First match per key attack path (chance per key path: m_k = candidates matching it)",
                      ("trial", "key_path", "variant", "reading", "first_match", "r", "t", "m", "rank_exp",
                       "rank_opt", "rank_pess", "rr_exp", "chance_rr", "chance_pos_rr", "score", "n", "n_pos"),
                      _key_md_rows(keyed))
    lines += _section("Per attack trial (first match of any key attack path)",
                      ("trial", "variant", "reading", "n", "top1_exp", "rr_exp", "rr_opt", "rr_pess", "E[1/rank]",
                       "chance_top1", "chance_rr", "chance_E[1/rank]", "n_pos", "chance_pos_top1", "chance_pos_rr",
                       "contested", "attack_min", "other_max", "gap"), _trial_md_rows([t for t in keyed if t.attack]))
    dist = [{"trial": t.trial_id, "keyed": "yes" if t.keyed else "no", "variant": v, "n": str(d["n"]),
             "max": f6(d["max"]), "min": f6(d["min"]), "mean": f6(d["mean"]), "zero": str(d["n_zero"]),
             "distinct": str(d["n_distinct"]), "top_tie": str(d["top_tie"])}
            for t in results if not t.attack for v, d in t.distributions.items()]
    lines += ["", "## Trials without key attack paths (unkeyed: no right / wrong; S06: feeds the S06 check)"]
    lines += _section("n and score distribution", ("trial", "keyed", "variant", "n", "max", "min", "mean", "zero",
                                                   "distinct", "top_tie"), dist)
    if sweep is not None:
        trials = [t.sweep_trial for t in results if t.sweep_trial is not None]
        lines += _sweep_section(*sweep, informativeness(trials), _sweep_chance(totals))
    return "\n".join(lines) + "\n"


def summary_files(results: Sequence[TrialRank], split: str,
                  sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]] | None) -> dict[str, str]:
    """Texts of the summary folder: rank.md, rank_totals.csv and, with the sweep, rank_sweep.csv."""
    totals = total_rows(results, split)
    files = {RANK_MD: rank_md(results, split, totals, sweep), RANK_TOTALS: csv_text(TOTAL_COLUMNS, totals)}
    if sweep is not None:
        default, points, _check = sweep
        files[RANK_SWEEP] = csv_text(SWEEP_COLUMNS, sweep_rows(default, points, split))
    return files
