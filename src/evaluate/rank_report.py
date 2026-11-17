"""Output texts of the development ranking check (PLAN T9.5; spec 05_score SCA-06, section 5.2; decisions 065, 066).
Pure: every text is built in memory, with no timestamp, ``\\n`` line ends and fixed number formats (6 decimals), so
two runs give byte-identical files.

Files: ``out/evaluate/<trial>/rank.csv`` (one per trial), ``out/evaluate/development/rank.md`` and
``rank_totals.csv``, and with the sweep ``rank_sweep.csv`` plus a sweep section in ``rank.md``. Every CSV row carries
``status_note`` and every Markdown table is headed "DEVELOPMENT numbers, not results" (decision 019; spec SCA-06):
these numbers check the code on development keys; T10 alone reports results. The ``.md`` holds ids, hosts and
numbers only: no account, image or command text (decision 051 item 8).
"""
from __future__ import annotations

import math
from typing import Any, Iterable, Mapping, Sequence

from . import rank_metrics as rm
from .rank_run import KeyPathResult, ReadingResult, TrialRank
from .rank_sweep import LAMBDA_GRID, SweepPoint, changed_keys, stable_region
from .writers import csv_text, md_header
from .params import SPLIT_DEVELOPMENT

__all__ = ["RANK_FILE", "RANK_MD", "RANK_TOTALS", "RANK_SWEEP", "RANK_SUMMARY_FILES", "DEV_NOTE", "RANK_COLUMNS",
           "TOTAL_COLUMNS", "SWEEP_COLUMNS", "f6", "trial_rows", "trial_csv", "s06_facts", "total_rows", "sweep_rows",
           "rank_md", "summary_files"]

RANK_FILE = "rank.csv"
RANK_MD = "rank.md"
RANK_TOTALS = "rank_totals.csv"
RANK_SWEEP = "rank_sweep.csv"
RANK_SUMMARY_FILES: tuple[str, ...] = (RANK_MD, RANK_TOTALS, RANK_SWEEP)
DEV_NOTE = "DEVELOPMENT numbers, not results"
TEST_NOTE = "TEST"

RANK_COLUMNS: tuple[str, ...] = (
    "status_note", "trial_id", "split", "keyed", "row_kind", "variant", "match_reading", "key_path_id", "key_role",
    "key_hop_ids", "mapped_hop_ids", "unmatched_key_hops", "method", "threshold", "n_candidates", "candidate_count",
    "matched_path_ids", "matched_jaccards", "first_match_path_ids", "first_rank", "tie_size", "matches_in_tie",
    "rank_expected", "rank_optimistic", "rank_pessimistic", "rr_expected", "rr_optimistic", "rr_pessimistic",
    "top1_expected", "top1_optimistic", "top1_pessimistic", "chance_top1", "chance_rank_expected", "chance_rr",
    "chance_rr_mean", "first_match_score", "key_attack_score_min", "other_score_max", "other_max_path_ids",
    "score_gap", "key_node_count", "supporting_event_uids", "time_delta_ms", "k", "budget_nodes", "full_recall",
    "b0_recall", "budget_nodes_labelled", "full_recall_labelled", "b0_recall_labelled", "score_max", "score_min",
    "score_mean", "n_zero_score", "n_distinct_scores", "top_tie_size")
TOTAL_COLUMNS: tuple[str, ...] = (
    "status_note", "split", "row_kind", "variant", "match_reading", "attack_trials", "key_paths", "key_paths_matched",
    "top1_expected", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic", "mrr_pessimistic",
    "chance_top1", "chance_mrr", "chance_rr_mean", "score_gap_min", "trials_gap_positive", "s06_trials",
    "s06_max_score", "key_attack_score_min", "s06_margin", "s06_held", "share_attack_trials_above_s06",
    "full_recall_mean", "b0_recall_mean", "full_recall_labelled_mean", "b0_recall_labelled_mean",
    "trials_full_above_b0", "trials_full_above_b0_labelled")
SWEEP_COLUMNS: tuple[str, ...] = (
    "status_note", "point_kind", "lambda_label", "lambda", "w1", "w2", "w3", "top1_expected", "mrr_expected",
    "s06_max_score", "key_attack_score_min", "s06_margin", "s06_held", "same_ranks_as_default",
    "n_key_paths_changed", "changed_key_paths", "key_path_ranks")

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


def _placement_cells(row: dict[str, str], pl: rm.Placement, n: int) -> None:
    """The placement and chance columns of a key-path or trial row."""
    ch = rm.chance_line(n, len(pl.matched))
    row.update(candidate_count=str(len(pl.matched)), matched_path_ids=_ids(pl.matched),
               first_match_path_ids=_ids(pl.first_group), first_rank=_i(pl.first_rank), tie_size=_i(pl.tie_size),
               matches_in_tie=_i(len(pl.first_group)) if pl.first_group else "",
               rank_expected=f6(pl.rank_expected), rank_optimistic=_i(pl.rank_optimistic),
               rank_pessimistic=_i(pl.rank_pessimistic), rr_expected=f6(pl.rr("expected")),
               rr_optimistic=f6(pl.rr("optimistic")), rr_pessimistic=f6(pl.rr("pessimistic")),
               top1_expected=f6(pl.top1_expected), top1_optimistic=f6(pl.top1_optimistic),
               top1_pessimistic=f6(pl.top1_pessimistic), chance_top1=f6(ch["top1"]),
               chance_rank_expected=f6(ch["rank"]), chance_rr=f6(ch["rr"]), chance_rr_mean=f6(ch["rr_mean"]),
               first_match_score=f6(pl.first_score))


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
    _placement_cells(row, kr.placement, rr.n)
    return row


def _trial_row(t: TrialRank, rr: ReadingResult) -> dict[str, str]:
    """The first match of any key attack path (handoff 14.2 top-1 and MRR are per trial) and the score gap."""
    row = _blank(t.split, t.trial_id, t.keyed, "trial")
    row.update(variant=rr.variant, match_reading=rr.reading, key_path_id=_ids(k.key_path.path_id for k in rr.key_paths),
               method=_METHOD[rr.reading] + "_any_key_attack_path", threshold=f6(rm.MATCH_THRESHOLD),
               n_candidates=str(rr.n), key_attack_score_min=f6(rr.low), other_score_max=f6(rr.high),
               other_max_path_ids=_ids(rr.high_ids), score_gap=f6(rr.gap), k=str(len(rr.key_paths)))
    _placement_cells(row, rr.trial, rr.n)
    return row


def _b0_row(t: TrialRank) -> dict[str, str]:
    """H4: full's top-k vs b0 at an equal node budget."""
    b = t.b0
    assert b is not None
    row = _blank(t.split, t.trial_id, t.keyed, "b0_recall")
    row.update(variant="full_vs_b0", method="equal_node_budget", n_candidates=str(len(t.candidates["full"])),
               k=str(b.k), key_node_count=str(b.key_nodes), budget_nodes=f6(b.budget), full_recall=f6(b.full_recall),
               b0_recall=f6(b.b0_recall), budget_nodes_labelled=f6(b.budget_labelled),
               full_recall_labelled=f6(b.full_recall_labelled), b0_recall_labelled=f6(b.b0_recall_labelled))
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


def trial_rows(t: TrialRank) -> list[dict[str, str]]:
    """Every rank.csv row of one trial: key-path and trial rows per (variant, reading), the b0 row, distributions."""
    rows: list[dict[str, str]] = []
    if t.attack:
        for rr in t.readings:
            rows.extend(_key_row(t, rr, kr) for kr in rr.key_paths)
            rows.append(_trial_row(t, rr))
        if t.b0 is not None:
            rows.append(_b0_row(t))
    rows.extend(_dist_rows(t))
    return rows


def trial_csv(t: TrialRank) -> str:
    """The rank.csv text of one trial."""
    return csv_text(RANK_COLUMNS, trial_rows(t))


# ---------------------------------------------------------------- totals

def _mean(values: Sequence[float]) -> float | None:
    """fsum mean; None for no values."""
    return math.fsum(values) / len(values) if values else None


def _readings(results: Sequence[TrialRank], variant: str, reading: str) -> list[ReadingResult]:
    """The (variant, reading) result of every attack trial, in trial order."""
    return [rr for t in results if t.attack for rr in t.readings if rr.variant == variant and rr.reading == reading]


def s06_facts(results: Sequence[TrialRank], variant: str, reading: str) -> dict[str, Any]:
    """S06 check (065 H5 reading, development): highest score of every keyed trial without key attack paths vs the
    lowest key attack first-match score over the keyed attack trials; held iff the margin is > 0. Also the share of
    attack trials whose own lowest key attack score lies above the S06 maximum (handoff 14.2 "distribution")."""
    s06 = [t for t in results if t.keyed and not t.attack]
    s06_max = max((c.score for t in s06 for c in t.candidates[variant]), default=None)
    rrs = _readings(results, variant, reading)
    lows = [rr.low for rr in rrs if rr.low is not None]
    low = min(lows) if lows else None
    margin = None if low is None or s06_max is None else low - s06_max
    above = (sum(1 for rr in rrs if rr.low is not None and rr.low > s06_max) / len(rrs)
             if rrs and s06_max is not None else None)
    return {"s06_trials": len(s06), "s06_max": s06_max, "low": low, "margin": margin,
            "held": None if margin is None else margin > 0, "share_above": above}


def total_rows(results: Sequence[TrialRank], split: str) -> list[dict[str, str]]:
    """rank_totals.csv: one row per (variant, reading), then one b0 row."""
    out: list[dict[str, str]] = []
    variants = [v for v in ("full", "b1", "b2")]
    for variant in variants:
        for reading in rm.READINGS:
            rrs = _readings(results, variant, reading)
            kps = [kr for rr in rrs for kr in rr.key_paths]
            chances = [rm.chance_line(rr.n, len(rr.trial.matched)) for rr in rrs]
            gaps = [rr.gap for rr in rrs if rr.gap is not None]
            s6 = s06_facts(results, variant, reading)
            row = {c: "" for c in TOTAL_COLUMNS}
            row.update(status_note=_note(split), split=split, row_kind="ranking", variant=variant,
                       match_reading=reading, attack_trials=str(len(rrs)), key_paths=str(len(kps)),
                       key_paths_matched=str(sum(1 for kr in kps if kr.placement.first_rank is not None)),
                       top1_expected=f6(_mean([rr.trial.top1_expected for rr in rrs])),
                       top1_optimistic=f6(_mean([rr.trial.top1_optimistic for rr in rrs])),
                       top1_pessimistic=f6(_mean([rr.trial.top1_pessimistic for rr in rrs])),
                       mrr_expected=f6(_mean([rr.trial.rr("expected") for rr in rrs])),
                       mrr_optimistic=f6(_mean([rr.trial.rr("optimistic") for rr in rrs])),
                       mrr_pessimistic=f6(_mean([rr.trial.rr("pessimistic") for rr in rrs])),
                       chance_top1=f6(_mean([c["top1"] for c in chances])),
                       chance_mrr=f6(_mean([c["rr"] for c in chances])),
                       chance_rr_mean=f6(_mean([c["rr_mean"] for c in chances])),
                       score_gap_min=f6(min(gaps) if gaps else None),
                       trials_gap_positive=str(sum(1 for g in gaps if g > 0)), s06_trials=str(s6["s06_trials"]),
                       s06_max_score=f6(s6["s06_max"]), key_attack_score_min=f6(s6["low"]),
                       s06_margin=f6(s6["margin"]), s06_held="" if s6["held"] is None else str(int(s6["held"])),
                       share_attack_trials_above_s06=f6(s6["share_above"]))
            out.append(row)
    b0s = [t.b0 for t in results if t.attack and t.b0 is not None]
    row = {c: "" for c in TOTAL_COLUMNS}
    row.update(status_note=_note(split), split=split, row_kind="b0_recall", variant="full_vs_b0",
               attack_trials=str(len(b0s)), full_recall_mean=f6(_mean([b.full_recall for b in b0s])),
               b0_recall_mean=f6(_mean([b.b0_recall for b in b0s])),
               full_recall_labelled_mean=f6(_mean([b.full_recall_labelled for b in b0s])),
               b0_recall_labelled_mean=f6(_mean([b.b0_recall_labelled for b in b0s])),
               trials_full_above_b0=str(sum(1 for b in b0s if b.full_recall > b.b0_recall)),
               trials_full_above_b0_labelled=str(sum(1 for b in b0s if b.full_recall_labelled > b.b0_recall_labelled)))
    out.append(row)
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
                    "s06_held": "" if margin is None else str(int(margin > 0)),
                    "same_ranks_as_default": "1" if not changed else "0", "n_key_paths_changed": str(len(changed)),
                    "changed_key_paths": ";".join(changed),
                    "key_path_ranks": ";".join(f"{t}:{k}={f6(r)}" for t, k, r in p.key_ranks)})
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
        + ". Key `steps` are not read (move / service steps lie inside these fields; dump steps are `context` = 1).",
        f"- {_TIE_NOTE}",
        "- Top-1 and MRR are per attack trial: the first candidate matching any key attack path (handoff 14.2). "
        "Keyed trials without key attack paths (S06) enter only the S06 check.",
        "- Chance line: all n candidates in one tie group (top-1 m/n, rank (n+1)/(m+1), chance_mrr = its inverse); "
        "chance_rr_mean = E[1/rank] of a random order.",
        "- Score gap = lowest first-match score of the key attack paths - highest score of the candidates matching no "
        "key attack path. S06 check: highest S06 score vs the lowest key attack score of the attack trials.",
        "- b0 (H4): budget = expected distinct `context` = 0 nodes of full's top-k paths (k = key attack paths; tie at "
        "the cut by inclusion probability); b0 takes units in rank order up to the budget, the tie group at the cut read "
        "by expectation at node level. `_labelled` = the same with only the labelled `context` = 0 nodes (NodeScore "
        "units) of the top k as budget.",
        "- The path score orders paths; it is not a probability. These checks rank; they do not claim to detect "
        "anything. Hypotheses H1-H5 are expected, to be measured on test trials at T10.",
    ]


def _inputs_section(results: Sequence[TrialRank]) -> list[str]:
    """Input hashes per trial (traceability without a timestamp)."""
    names = ("score_run_info_sha256", "ranked_paths_sha256", "stitch_path_nodes_sha256", "key_sha256")
    rows = [dict({"trial_id": t.trial_id}, **{n: t.inputs.get(n, "")[:16] for n in names}) for t in results]
    return ["", "## Inputs (SHA-256, first 16 hex digits)", ""] + _table(("trial_id",) + names, rows)


def _key_md_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Per key attack path, variant and reading."""
    out = []
    for t in results:
        for rr in t.readings:
            for kr in rr.key_paths:
                pl = kr.placement
                out.append({"trial": t.trial_id, "key_path": kr.key_path.path_id, "variant": rr.variant,
                            "reading": rr.reading, "first_match": _ids(pl.first_group), "r": _i(pl.first_rank),
                            "t": _i(pl.tie_size), "m": _i(len(pl.first_group)) if pl.first_group else "",
                            "rank_exp": f6(pl.rank_expected), "rank_opt": _i(pl.rank_optimistic),
                            "rank_pess": _i(pl.rank_pessimistic), "rr_exp": f6(pl.rr("expected")),
                            "score": f6(pl.first_score), "n": str(rr.n)})
    return out


def _trial_md_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Per attack trial, variant and reading: top-1, RR, chance and score gap."""
    out = []
    for t in results:
        for rr in t.readings:
            ch = rm.chance_line(rr.n, len(rr.trial.matched))
            out.append({"trial": t.trial_id, "variant": rr.variant, "reading": rr.reading, "n": str(rr.n),
                        "top1_exp": f6(rr.trial.top1_expected), "rr_exp": f6(rr.trial.rr("expected")),
                        "rr_opt": f6(rr.trial.rr("optimistic")), "rr_pess": f6(rr.trial.rr("pessimistic")),
                        "chance_top1": f6(ch["top1"]), "chance_rr": f6(ch["rr"]),
                        "attack_min": f6(rr.low), "other_max": f6(rr.high), "gap": f6(rr.gap)})
    return out


def _sweep_section(default: SweepPoint, points: Sequence[SweepPoint], check: Mapping[str, Any]) -> list[str]:
    """Default check, stable region per lambda, and the metric range over the grid."""
    lines = ["", "## Stability sweep (spec 05 section 5.2 step 2; decision 066)", "",
             "Scores recomputed from `ranked_paths.csv` columns only (L = (1 - e^(-seq_len/lambda)) * edge_score; "
             "score = w1 L + w2 node_score + w3 identity_coherence). The sweep never changes a parameter; it reports.",
             "", f"- Default check: {check['paths']} paths, max |recomputed - written full score| = "
             f"{check['max_abs_diff']:.3g} (tolerance 1e-6, the rounding of the written columns); rank mismatches "
             f"{check['rank_mismatch']}.",
             f"- Default point: lambda {default.lam:.6f}, w = ({default.w[0]:.6f}, {default.w[1]:.6f}, "
             f"{default.w[2]:.6f}); top-1 (expected) {f6(default.top1)}, MRR (expected) {f6(default.mrr)}; hop reading."]
    region = stable_region(points, default)
    rows = [{"lambda": r["lambda"], "grid_points": str(r["grid_points"]), "stable_points": str(r["stable_points"]),
             "stable_radius": "all stable" if r["stable_radius"] is None else f6(r["stable_radius"]),
             "default_w_stable": "1" if r["default_w_stable"] else "0"} for r in region]
    lines += _section("Stable region: grid points where no key attack path's expected rank changes (stable_radius = "
                      "Chebyshev distance from w = 1/3 to the nearest unstable grid point)",
                      ("lambda", "grid_points", "stable_points", "stable_radius", "default_w_stable"), rows)
    grid = [p for p in points if p.kind == "grid"]
    by_lam = []
    for lab, _v in LAMBDA_GRID:
        ps = [p for p in grid if p.lam_label == lab]
        t1 = [p.top1 for p in ps if p.top1 is not None]
        mr = [p.mrr for p in ps if p.mrr is not None]
        held = [p for p in ps if p.attack_min is not None and p.s06_max is not None and p.attack_min > p.s06_max]
        by_lam.append({"lambda": lab, "top1_min": f6(min(t1) if t1 else None), "top1_max": f6(max(t1) if t1 else None),
                       "mrr_min": f6(min(mr) if mr else None), "mrr_max": f6(max(mr) if mr else None),
                       "s06_held_points": f"{len(held)}/{len(ps)}"})
    lines += _section("Metric range over the w grid per lambda (hop reading, expected ties)",
                      ("lambda", "top1_min", "top1_max", "mrr_min", "mrr_max", "s06_held_points"), by_lam)
    dw = [{"lambda": p.lam_label, "top1_exp": f6(p.top1), "mrr_exp": f6(p.mrr), "s06_max": f6(p.s06_max),
           "attack_min": f6(p.attack_min), "changed": ";".join(changed_keys(p, default)) or "none"}
          for p in points if p.kind == "default_w"]
    lines += _section("Default w at every grid lambda", ("lambda", "top1_exp", "mrr_exp", "s06_max", "attack_min",
                                                          "changed"), dw)
    return lines


def rank_md(results: Sequence[TrialRank], split: str, totals: Sequence[Mapping[str, str]],
            sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]] | None) -> str:
    """The rank.md text."""
    keyed = [t for t in results if t.keyed]
    lines = [md_header(split, None), "", f"Development ranking check over {len(results)} trials, split {split} "
             "(spec 05_score SCA-06; decisions 065, 066). Variants full, b1, b2 rank the stitch paths; b0 ranks label "
             "units (spec 05 section 3.6).", ""] + _readings_text() + _inputs_section(results)
    lines += ["", "## Totals"]
    lines += _section("Per variant and reading (attack trials)",
                      ("variant", "match_reading", "attack_trials", "key_paths_matched", "top1_expected",
                       "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_optimistic", "mrr_pessimistic",
                       "chance_top1", "chance_mrr", "score_gap_min", "trials_gap_positive"),
                      [r for r in totals if r["row_kind"] == "ranking"])
    lines += _section("S06 check (highest S06 score vs lowest key attack score)",
                      ("variant", "match_reading", "s06_trials", "s06_max_score", "key_attack_score_min", "s06_margin",
                       "s06_held", "share_attack_trials_above_s06"), [r for r in totals if r["row_kind"] == "ranking"])
    b0 = [{"trial": t.trial_id, "k": str(t.b0.k), "key_nodes": str(t.b0.key_nodes), "budget": f6(t.b0.budget),
           "full_recall": f6(t.b0.full_recall), "b0_recall": f6(t.b0.b0_recall),
           "budget_labelled": f6(t.b0.budget_labelled), "full_recall_labelled": f6(t.b0.full_recall_labelled),
           "b0_recall_labelled": f6(t.b0.b0_recall_labelled)} for t in results if t.attack and t.b0 is not None]
    lines += _section("b0 vs full at an equal node budget (H4 reading)",
                      ("trial", "k", "key_nodes", "budget", "full_recall", "b0_recall", "budget_labelled",
                       "full_recall_labelled", "b0_recall_labelled"), b0)
    lines += ["", "## Key attack paths"]
    lines += _section("First match per key attack path", ("trial", "key_path", "variant", "reading", "first_match", "r",
                                                         "t", "m", "rank_exp", "rank_opt", "rank_pess", "rr_exp",
                                                         "score", "n"), _key_md_rows(keyed))
    lines += _section("Per attack trial (first match of any key attack path)",
                      ("trial", "variant", "reading", "n", "top1_exp", "rr_exp", "rr_opt", "rr_pess", "chance_top1",
                       "chance_rr", "attack_min", "other_max", "gap"), _trial_md_rows([t for t in keyed if t.attack]))
    dist = [{"trial": t.trial_id, "keyed": "yes" if t.keyed else "no", "variant": v, "n": str(d["n"]),
             "max": f6(d["max"]), "min": f6(d["min"]), "mean": f6(d["mean"]), "zero": str(d["n_zero"]),
             "distinct": str(d["n_distinct"]), "top_tie": str(d["top_tie"])}
            for t in results if not t.attack for v, d in t.distributions.items()]
    lines += ["", "## Trials without key attack paths (unkeyed: no right / wrong; S06: feeds the S06 check)"]
    lines += _section("n and score distribution", ("trial", "keyed", "variant", "n", "max", "min", "mean", "zero",
                                                   "distinct", "top_tie"), dist)
    if sweep is not None:
        lines += _sweep_section(*sweep)
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
