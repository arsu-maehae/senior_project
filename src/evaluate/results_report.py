"""T10 results tables, DEVELOPMENT only (spec 06_evaluate section 4 C, RS-01..11; decisions 065, 070, 071, 072;
spec 05_score section 7.3). Pure: every text is built in memory from the ranking check's in-memory results, with no
timestamp, no timing and fixed number formats, so a fresh run equals the committed files (RS-07).

WHY recompute and not read rank_totals.csv: the verdicts compare exact values (``math.fsum`` means rounded to 12
decimals, RS-09), which the 6-decimal CSV no longer holds. Every value written here is also checked against the
rendered ``rank_totals.csv`` cell its ``source`` names, so a results row can never disagree with the ranking check it
cites. The staleness check against the committed rank files lives in ``results_run`` (it reads files).

The verdict column is ``dev_check`` while split = development (RS-10): a development check, never a result. Contested
rows and rows reported beside carry no verdict (EV-04).
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from . import rank_metrics as rm
from .inputs import EvalError
from .params import (H1_TOP1_MIN, H2_MRR_PER_KEY_MIN, H3_MIN_DIFFERENCE, H4_MIN_DIFFERENCE, H5_MIN_MARGIN,
                     SPLIT_DEVELOPMENT)
from .rank_report import (AUC_CHANCE, B0_SET, CHANCE_NA_MARGIN, CHANCE_NA_RECALL, KIND_AUC_POOLED, KIND_B0,
                          KIND_B0_CONTESTED, KIND_NODE_PRF, KIND_NODE_PRF_SCENARIO, KIND_RANKING,
                          KIND_RANKING_CONTESTED, PAIRED_SET, PATH_VARIANT_ORDER, PRF_VARIANT_ORDER, SCOPE_ALL,
                          SW04_SENTENCE,
                          SCOPE_CONTESTED, at_least, attack_readings, attack_scenarios, auc_trial_values, auc_values,
                          b0_contested_ids, b0_of, b0_values, contested_ids, f6, f12, h5_facts, informative_sentence,
                          node_prf_pairs, node_prf_values, r12, ranking_values, strictly_greater, total_rows,
                          uncontested_rows)
from .rank_run import TrialRank, sweep_of
from .rank_sweep import SweepPoint, changed_keys, informativeness
from .writers import csv_text, md_header

__all__ = ["RESULTS_MD", "RESULTS_CSV", "RESULTS_FILES", "RESULTS_NOTE", "VERDICT_COLUMN", "RESULTS_COLUMNS",
           "FORBIDDEN_WORDS", "ALLOWED_PHRASE", "LIMITS_H1_H3", "EQUALS_CHANCE_TEXT", "UNDEFINED", "r12", "f12",
           "verdict_text", "equals_chance", "dev_check_cell",
           "at_least", "strictly_greater", "paired_difference", "forbidden_hits", "h5_facts", "result_rows", "results_md", "results_files"]

RESULTS_MD = "results.md"
RESULTS_CSV = "results.csv"
RESULTS_FILES: tuple[str, ...] = (RESULTS_MD, RESULTS_CSV)
RESULTS_NOTE = "DEVELOPMENT — not a result"
# RS-10: named `dev_check` while split = development; renamed `verdict` only for the test run (out of scope).
VERDICT_COLUMN = "dev_check"
RESULTS_COLUMNS: tuple[str, ...] = (
    "status_note", "split", "table", "hypothesis", "variant", "reading_scope", "metric", "is_primary", "observed",
    "observed_12", "threshold", "comparator", VERDICT_COLUMN, "chance_all", "chance_pos", "equals_chance_pos",
    "n_trials", "n_key_paths", "source", "note")
# ATK-EV-19: shown after the verdict in results.md when the observed value is not above the chance line over the
# candidates with score > 0 (observed <= chance_pos at 12 decimals: the ranking adds nothing over a random order of
# the scored paths). The results.csv column keeps its name ``equals_chance_pos``.
EQUALS_CHANCE_TEXT = "not above chance over scored paths"
# ATK-EV-20: the H4 verdict when no attack trial has a labelled key node (the labelled recall is undefined).
UNDEFINED = "undefined"
# RS-10 / RS-08 (ATK-EV-13): a copy of score.report.FORBIDDEN_WORDS / ALLOWED_PHRASE (evaluate must not import score,
# decision 051 item 1 spirit); a test can pin the copy to the original.
FORBIDDEN_WORDS: tuple[str, ...] = ("stolen", "detects", "probability", "confidence", "reduces false positives",
                                    "identifies the attacker")
ALLOWED_PHRASE = "not a probability"
# RS-08: the stated limits of H1-H3, copied from spec 05 section 7.3 and score.report L-SC5. The spec's closing
# wording sentence ("No hypothesis is worded as ...") quotes the forbidden phrases themselves, so it is replaced by
# the wording block (RS-10 forbids those phrases in results.md).
LIMITS_H1_H3: tuple[str, ...] = (
    "Inside one protocol, attack and benign paths have equal LengthScore and NodeScore (L-SC1), so their order comes "
    "from IdentityCoherence, whose definition the answer keys share (Correction K). H1 then measures the ranking "
    "given exposure, not an independent check of identity. Test trials repeat the development scenarios, so the "
    "hypotheses measure repeatability, not generalisation to new attacks (spec 05 section 7.3).",
    "L-SC5: The answer keys use Correction K's definition, so identity agreement with the keys checks the code, not "
    "the definition.",
    "H4 (decision 071): the labelled recall depends on which nodes the Sigma rules label (spec 04); better label "
    "coverage changes its denominator.",
)
WORDING: tuple[str, ...] = (
    "These tables are a development check: the path score ranks candidate paths for an analyst; it is not a "
    "probability. Every hypothesis is expected, to be measured on the test trials (PLAN 10.4, after the key lock "
    "T5.7); the values here check the code on development keys and are never reported as results (decision 019).",
    "An account counted by IdentityCoherence is exposed (a logon session open on the source host when LSASS was read "
    "there), which is not proof that its credentials were taken or used (Correction K).",
)
_N_A_DIFF = "n/a: difference of two variants; the chance line of each side is in its own row"
_HYP = {
    "H1": f"full ranks a key attack path first: top-1 rate (expected ties) >= {H1_TOP1_MIN:.2f}",
    "H2": f"full per-key MRR (each key attack path's own expected reciprocal rank) >= {H2_MRR_PER_KEY_MIN:.2f}",
    "H3": "IdentityCoherence adds ranking value: per-key MRR(full) > per-key MRR(b1), strict (equal = not held)",
    "H4": "full's top-k holds more labelled key nodes than b0 at an equal node budget: mean labelled recall "
          "full > b0 (denominator: labelled key nodes, decision 071)",
    "H5": "full orders the S06 benign paths below the attack paths by score: lowest key attack score - highest S06 "
          "score > 0 in every keyed S06 trial",
}
_NODE = rm.READING_NODE                        # EV-06: the verdict reading


# ---------------------------------------------------------------- verdict text

def verdict_text(held: bool) -> str:
    """The ``dev_check`` cell."""
    return "held" if held else "not held"


def equals_chance(value: float | None, chance_pos: float | None) -> str:
    """``equals_chance_pos`` (ATK-EV-19): "1" when the observed ranking metric is not above the chance line over the
    candidates with score > 0, compared at 12 decimals; "0" when above; "" when either is undefined."""
    if value is None or chance_pos is None:
        return ""
    return "1" if r12(value) <= r12(chance_pos) else "0"


def dev_check_cell(verdict: str, equals_pos: str, coverage: str = "") -> str:
    """The results.md verdict cell: the verdict, " — not above chance over scored paths" when ``equals_pos`` is "1"
    (ATK-EV-19), then the coverage it rests on, e.g. "(5 of 5 attack trials)" (ATK-EV-20)."""
    if not verdict:
        return ""
    text = f"{verdict} — {EQUALS_CHANCE_TEXT}" if equals_pos == "1" else verdict
    return f"{text} {coverage}" if coverage else text


def forbidden_hits(text: str) -> list[str]:
    """``FORBIDDEN_WORDS`` found in ``text`` (case-insensitive) after removing the one allowed phrase (as
    score.report.forbidden_hits). WHY: results.md and results.csv must never carry the claims CLAUDE.md forbids
    (RS-10, ATK-EV-23)."""
    low = text.lower().replace(ALLOWED_PHRASE, " ")
    return [w for w in FORBIDDEN_WORDS if w in low]


# ---------------------------------------------------------------- rows

class _Ctx:
    """The totals rows and in-memory results one results run reads; ``check`` ties every value to its source
    cell."""

    def __init__(self, results: Sequence[TrialRank], split: str) -> None:
        self.results = results
        self.split = split
        self.totals = total_rows(results, split)
        self.sets = {v: contested_ids(results, v) for v in PATH_VARIANT_ORDER}
        self.sets[B0_SET] = b0_contested_ids(results)

    def total(self, kind: str, variant: str, reading: str, cset: str) -> Mapping[str, str]:
        """The rendered totals row with this key (EvalError when missing: the two codes disagree)."""
        for r in self.totals:
            if (r["row_kind"], r["variant"], r["match_reading"], r["contested_set"]) == (kind, variant, reading, cset):
                return r
        raise EvalError(f"refused: internal: no rank_totals row {kind}/{variant}/{reading}/{cset}")

    def ranking(self, variant: str, cset: str | None) -> tuple[dict[str, Any], Mapping[str, str], str]:
        """(exact values, totals row, source prefix) of one variant, node reading, over all attack trials (cset
        None) or over the named contested set."""
        ids = None if cset is None else self.sets[cset]
        vals = ranking_values([rr for _t, rr in attack_readings(self.results, variant, _NODE, ids)])
        kind = KIND_RANKING if cset is None else KIND_RANKING_CONTESTED
        row = self.total(kind, variant, _NODE, cset or "")
        return vals, row, _source(row)

    def b0(self, cset: str | None) -> tuple[dict[str, Any], Mapping[str, str], str]:
        """(exact values, totals row, source prefix) of H4 over all attack trials or a contested set."""
        _ids, b0s = b0_of(self.results, None if cset is None else self.sets[cset])
        kind = KIND_B0 if cset is None else KIND_B0_CONTESTED
        row = self.total(kind, "full_vs_b0", "", cset or "")
        return b0_values(b0s), row, _source(row)


def _source(row: Mapping[str, str]) -> str:
    """The rank_totals.csv row key a results row cites."""
    return (f"rank_totals.csv {row['row_kind']}/{row['variant']}/{row['match_reading'] or '-'}/"
            f"{row['reading_scope']}/{row['contested_set'] or '-'}")


def _check(row: Mapping[str, str], column: str, value: float | int | None, count: bool = False) -> None:
    """The value must equal its rank_totals.csv cell as written (6 decimals or integer)."""
    text = ("" if value is None else str(int(value))) if count else f6(value)
    if row[column] != text:
        raise EvalError(f"refused: internal: results value {text!r} differs from rank_totals.csv {_source(row)} "
                        f"{column} {row[column]!r}")


def _row(split: str, table: str, hyp: str, variant: str, scope: str, metric: str, value: float | int | None, *,
         primary: bool = False, count: bool = False, threshold: str = "", comparator: str = "", verdict: str = "",
         chance: tuple[str, str] = ("", ""), n_trials: int | None = None, n_key: int | None = None,
         source: str = "", note: str = "", compared: float | None = None,
         equals_pos: str = "") -> dict[str, str]:
    """One results.csv row. ``compared`` overrides the 12-decimal cell (H3/H4 differences of rounded values)."""
    if count:
        observed, obs12 = ("" if value is None else str(int(value))), ""
    else:
        observed = f6(value)
        obs12 = f12(compared if compared is not None else value)          # type: ignore[arg-type]
    return {"status_note": RESULTS_NOTE, "split": split, "table": table, "hypothesis": hyp, "variant": variant,
            "reading_scope": scope, "metric": metric, "is_primary": "1" if primary else "0", "observed": observed,
            "observed_12": obs12, "threshold": threshold, "comparator": comparator, VERDICT_COLUMN: verdict,
            "chance_all": chance[0], "chance_pos": chance[1], "equals_chance_pos": equals_pos,
            "n_trials": "" if n_trials is None else str(n_trials),
            "n_key_paths": "" if n_key is None else str(n_key), "source": source, "note": note}


def _set_note(cset: str, variant: str, paired: bool = False) -> str:
    """The note of a contested row: whose contested set it is read over, and whether it is the paired reading of a
    comparison (H3, H4: both sides on full's set, EV-04) or a variant's own set."""
    if paired:
        return f"over {cset}'s contested set (paired reading, EV-04); no verdict"
    if cset == variant:
        return f"over {cset}'s own contested set; no verdict"
    return f"over {cset}'s contested set, reported beside; no verdict"


def _metric(ctx: _Ctx, table: str, variant: str, cset: str | None, metric: str, chance_cols: tuple[str, str],
            primary: bool = False, threshold: str = "", comparator: str = "", verdict: str = "",
            note: str = "", paired: bool = False) -> dict[str, str]:
    """A ranking-metric row (node reading) with its chance cells, checked against rank_totals.csv."""
    vals, trow, src = ctx.ranking(variant, cset)
    _check(trow, metric, vals[metric])
    return _row(ctx.split, table, _HYP.get(table, ""), variant, SCOPE_ALL if cset is None else SCOPE_CONTESTED,
                metric, vals[metric], primary=primary, threshold=threshold, comparator=comparator, verdict=verdict,
                chance=(trow[chance_cols[0]], trow[chance_cols[1]]), n_trials=int(vals["attack_trials"]),
                n_key=int(vals["key_paths"]), source=f"{src}:{metric}",
                note=note or ("" if cset is None else _set_note(cset, variant, paired)),
                equals_pos=equals_chance(vals[metric], vals[chance_cols[1]]))


def _h1(ctx: _Ctx) -> list[dict[str, str]]:
    """H1 (RS-03): top-1 (expected ties), full, node reading, all attack trials, >= 0.80; ties beside; contested."""
    vals, _r, _s = ctx.ranking("full", None)
    held = vals["top1_expected"] is not None and at_least(vals["top1_expected"], H1_TOP1_MIN)
    ch = ("chance_top1", "chance_pos_top1")
    rows = [_metric(ctx, "H1", "full", None, "top1_expected", ch, primary=True, threshold=f"{H1_TOP1_MIN:.2f}",
                    comparator=">=", verdict=verdict_text(held))]
    rows += [_metric(ctx, "H1", "full", None, m, ch, note="tie sensitivity, reported beside")
             for m in ("top1_optimistic", "top1_pessimistic")]
    rows += [_metric(ctx, "H1", v, v, "top1_expected", ch) for v in PATH_VARIANT_ORDER]
    return rows


def _h2(ctx: _Ctx) -> list[dict[str, str]]:
    """H2 (RS-04): per-key MRR, full, >= 0.85; per-trial MRR beside; contested per-key MRR for each variant."""
    vals, _r, _s = ctx.ranking("full", None)
    held = vals["mrr_per_key_expected"] is not None and at_least(vals["mrr_per_key_expected"], H2_MRR_PER_KEY_MIN)
    ch = ("chance_per_key_mrr", "chance_pos_per_key_mrr")
    rows = [_metric(ctx, "H2", "full", None, "mrr_per_key_expected", ch, primary=True,
                    threshold=f"{H2_MRR_PER_KEY_MIN:.2f}", comparator=">=", verdict=verdict_text(held)),
            _metric(ctx, "H2", "full", None, "mrr_expected", ("chance_mrr", "chance_pos_mrr"),
                    note="per-trial MRR (first match, handoff 14.2), reported beside")]
    rows += [_metric(ctx, "H2", v, v, "mrr_per_key_expected", ch) for v in PATH_VARIANT_ORDER]
    return rows


def paired_difference(a: float | None, b: float | None) -> float | None:
    """The compared value of a strict paired comparison (H3, H4): r12(r12(a) - r12(b)), so "equal at 12 decimals"
    is exactly 0 and not held (RS-09, ATK-EV-02); None when a side is undefined."""
    return None if a is None or b is None else r12(r12(a) - r12(b))


def _difference(ctx: _Ctx, table: str, variant: str, scope: str, metric: str, a: float | None, b: float | None,
                verdict: str | None, chance: str, n_trials: int, source: str, note: str,
                threshold: float = 0.0) -> dict[str, str]:
    """A paired difference row: observed a - b (6 decimals), compared value ``paired_difference`` (RS-09).
    ``verdict`` None = a row reported beside; otherwise the primary row's verdict text."""
    diff = None if a is None or b is None else a - b
    comp = paired_difference(a, b)
    return _row(ctx.split, table, _HYP[table], variant, scope, metric, diff, primary=verdict is not None,
                threshold=f"{threshold:.2f}" if verdict is not None else "",
                comparator=">" if verdict is not None else "",
                verdict=verdict or "", chance=(chance, chance),
                n_trials=n_trials, source=source, note=note, compared=comp)


def _h3(ctx: _Ctx) -> list[dict[str, str]]:
    """H3 (RS-04): per-key MRR(full) > per-key MRR(b1), strict at 12 decimals; each side, top-1 rates and the
    top-1 difference beside; the contested reading paired on full's set, b1's own set beside."""
    f, _fr, fsrc = ctx.ranking("full", None)
    b, _br, bsrc = ctx.ranking("b1", None)
    a1, b1v = f["mrr_per_key_expected"], b["mrr_per_key_expected"]
    d = paired_difference(a1, b1v)
    held = d is not None and strictly_greater(d, H3_MIN_DIFFERENCE)
    n = int(f["attack_trials"])
    rows = [_difference(ctx, "H3", "full_vs_b1", SCOPE_ALL, "mrr_per_key_expected_difference", a1, b1v,
                        verdict_text(held),
                        _N_A_DIFF, n, f"{fsrc}:mrr_per_key_expected - {bsrc}:mrr_per_key_expected", "",
                        threshold=H3_MIN_DIFFERENCE)]
    ch = ("chance_per_key_mrr", "chance_pos_per_key_mrr")
    rows += [_metric(ctx, "H3", v, None, "mrr_per_key_expected", ch, note="side of the comparison")
             for v in ("full", "b1")]
    rows += [_metric(ctx, "H3", v, None, "top1_expected", ("chance_top1", "chance_pos_top1"),
                     note="top-1 rate, reported beside") for v in ("full", "b1")]
    rows.append(_difference(ctx, "H3", "full_vs_b1", SCOPE_ALL, "top1_expected_difference", f["top1_expected"],
                            b["top1_expected"], None, _N_A_DIFF, n,
                            f"{fsrc}:top1_expected - {bsrc}:top1_expected", "reported beside"))
    fc, _x, fcsrc = ctx.ranking("full", PAIRED_SET)
    bc, _y, bcsrc = ctx.ranking("b1", PAIRED_SET)
    rows += [_metric(ctx, "H3", v, PAIRED_SET, "mrr_per_key_expected", ch, paired=True) for v in ("full", "b1")]
    rows.append(_difference(ctx, "H3", "full_vs_b1", SCOPE_CONTESTED, "mrr_per_key_expected_difference",
                            fc["mrr_per_key_expected"], bc["mrr_per_key_expected"], None, _N_A_DIFF,
                            int(fc["attack_trials"]), f"{fcsrc}:mrr_per_key_expected - {bcsrc}:mrr_per_key_expected",
                            _set_note(PAIRED_SET, "full_vs_b1", paired=True)))
    rows.append(_metric(ctx, "H3", "b1", "b1", "mrr_per_key_expected", ch))
    return rows


def _b0_metric(ctx: _Ctx, table: str, variant: str, cset: str | None, column: str, count: bool = False,
               primary: bool = False, note: str = "", paired: bool = False) -> dict[str, str]:
    """An H4 value row (full or b0 recall mean, or a count), checked against rank_totals.csv."""
    vals, trow, src = ctx.b0(cset)
    _check(trow, column, vals[column], count=count)
    return _row(ctx.split, table, _HYP["H4"] if table == "H4" else "", variant,
                SCOPE_ALL if cset is None else SCOPE_CONTESTED, column, vals[column], primary=primary, count=count,
                chance=(CHANCE_NA_RECALL, CHANCE_NA_RECALL), n_trials=int(vals["attack_trials"]),
                source=f"{src}:{column}", note=note or ("" if cset is None else _set_note(cset, variant, paired)))


def _h4(ctx: _Ctx) -> list[dict[str, str]]:
    """H4 (RS-05): mean labelled recall full > b0, strict at 12 decimals (071 denominator); each side, the counts and
    the all-node basis beside; the contested reading paired on full's set, b0's own set beside."""
    v, _r, src = ctx.b0(None)
    a, b = v["full_recall_labelled_mean"], v["b0_recall_labelled_mean"]
    d = paired_difference(a, b)
    held = d is not None and strictly_greater(d, H4_MIN_DIFFERENCE)
    verdict = UNDEFINED if not v["labelled_recall_trials"] else verdict_text(held)          # ATK-EV-20
    rows = [_difference(ctx, "H4", "full_vs_b0", SCOPE_ALL, "recall_labelled_mean_difference", a, b, verdict,
                        CHANCE_NA_RECALL, int(v["labelled_recall_trials"]),
                        f"{src}:full_recall_labelled_mean - b0_recall_labelled_mean",
                        f"mean over the {v['labelled_recall_trials']} of {v['attack_trials']} attack trials with "
                        "labelled key nodes (071)", threshold=H4_MIN_DIFFERENCE)]
    rows += [_b0_metric(ctx, "H4", "full", None, "full_recall_labelled_mean", note="side of the comparison"),
             _b0_metric(ctx, "H4", "b0", None, "b0_recall_labelled_mean", note="side of the comparison"),
             _b0_metric(ctx, "H4", "full_vs_b0", None, "labelled_recall_trials", count=True,
                        note="attack trials with labelled key nodes (others undefined, left out, 071)"),
             _b0_metric(ctx, "H4", "full_vs_b0", None, "trials_full_above_b0_labelled", count=True,
                        note="reported beside"),
             _b0_metric(ctx, "H4", "full", None, "full_recall_mean", note="all context-0 nodes, reported beside"),
             _b0_metric(ctx, "H4", "b0", None, "b0_recall_mean", note="all context-0 nodes, reported beside")]
    for cset in (PAIRED_SET, B0_SET):
        cv, _c, csrc = ctx.b0(cset)
        paired = cset == PAIRED_SET
        rows += [_b0_metric(ctx, "H4", "full", cset, "full_recall_labelled_mean", paired=paired),
                 _b0_metric(ctx, "H4", "b0", cset, "b0_recall_labelled_mean", paired=paired)]
        rows.append(_difference(ctx, "H4", "full_vs_b0", SCOPE_CONTESTED, "recall_labelled_mean_difference",
                                cv["full_recall_labelled_mean"], cv["b0_recall_labelled_mean"], None,
                                CHANCE_NA_RECALL, int(cv["labelled_recall_trials"]),
                                f"{csrc}:full_recall_labelled_mean - b0_recall_labelled_mean",
                                _set_note(cset, "full_vs_b0", paired)))
    return rows


def _h5(ctx: _Ctx) -> list[dict[str, str]]:
    """H5 (RS-05): margin > 0 in every keyed S06 trial (full, node reading); the per-trial margins, unkeyed S06
    trials and the share of attack trials above the S06 maximum beside. No contested reading (Q2)."""
    h = h5_facts(ctx.results, "full", _NODE)
    trow = ctx.total(KIND_RANKING, "full", _NODE, "")
    src = _source(trow)
    na = (CHANCE_NA_MARGIN, CHANCE_NA_MARGIN)
    nk = len(h["keyed"])
    _check(trow, "s06_margin", h["margin"])                  # ATK-EV-16: full cross-check with rank_totals.csv
    _check(trow, "s06_max_score", h["s06_max"])
    _check(trow, "key_attack_score_min", h["low"])
    _check(trow, "s06_trials", nk, count=True)
    _check(trow, "s06_held", None if h["held"] is None else int(h["held"]), count=True)
    if trow["s06_reason"] != h["reason"]:
        raise EvalError(f"refused: internal: H5 reason differs from rank_totals.csv {src} s06_reason")
    rows = [_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "s06_margin_min", h["margin"], primary=True,
                 threshold=f"{H5_MIN_MARGIN:.2f}", comparator=">", verdict=verdict_text(bool(h["held"])), chance=na,
                 n_trials=nk, source=f"{src}:s06_margin", note=h["reason"] or "minimum over the keyed S06 trials")]
    rows.append(_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "key_attack_score_min", h["low"], chance=na,
                     source=f"{src}:key_attack_score_min",
                     note="lowest first-match score of the key attack paths over the attack trials"))
    for kind, items in (("keyed", h["keyed"]), ("unkeyed", h["unkeyed"])):
        for k in items:
            note = (f"keyed S06 trial {k['trial_id']}" if kind == "keyed"
                    else f"unkeyed S06 trial {k['trial_id']}: the margin it would give, reported beside (no verdict)")
            rows.append(_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "s06_max_score", k["max"], chance=na,
                             n_trials=1, source=f"out/evaluate/{k['trial_id']}/rank.csv distribution/full:score_max",
                             note=note))
            rows.append(_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "s06_margin", k["margin"], chance=na,
                             n_trials=1, source=f"key_attack_score_min - {k['trial_id']} s06_max_score", note=note))
    _check(trow, "share_attack_trials_above_s06", h["share_above"])
    rows.append(_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "share_attack_trials_above_s06",
                     h["share_above"], chance=na, n_trials=len(attack_readings(ctx.results, "full", _NODE)),
                     source=f"{src}:share_attack_trials_above_s06",
                     note="attack trials whose lowest key attack score lies above the keyed S06 maximum, beside"))
    return rows


def _baselines(ctx: _Ctx) -> list[dict[str, str]]:
    """Baselines side by side (full, b1, b2 ranking metrics; b0 at the equal node budget), reported beside."""
    rows: list[dict[str, str]] = []
    for v in PATH_VARIANT_ORDER:
        rows += [_metric(ctx, "baselines", v, None, "top1_expected", ("chance_top1", "chance_pos_top1")),
                 _metric(ctx, "baselines", v, None, "mrr_per_key_expected",
                         ("chance_per_key_mrr", "chance_pos_per_key_mrr")),
                 _metric(ctx, "baselines", v, None, "mrr_expected", ("chance_mrr", "chance_pos_mrr"))]
    rows += [_b0_metric(ctx, "baselines", "full", None, "full_recall_labelled_mean"),
             _b0_metric(ctx, "baselines", "full", None, "full_recall_mean", note="all context-0 nodes"),
             _b0_metric(ctx, "baselines", "b0", None, "b0_recall_labelled_mean"),
             _b0_metric(ctx, "baselines", "b0", None, "b0_recall_mean", note="all context-0 nodes")]
    return rows


def _contested(ctx: _Ctx) -> list[dict[str, str]]:
    """The contested sets (EV-03): per variant the number of contested attack trials, the trials named in the
    note."""
    n_attack = len(attack_readings(ctx.results, "full", _NODE))
    rows = []
    for v in PATH_VARIANT_ORDER + (B0_SET,):
        ids = ctx.sets[v]
        rows.append(_row(ctx.split, "contested", "", v, SCOPE_CONTESTED, "contested_trials", len(ids), count=True,
                         chance=("", ""), n_trials=n_attack, source="rank.csv trial / b0_recall rows: contested",
                         note=";".join(ids) or "none"))
    return rows


def _recall(ctx: _Ctx) -> list[dict[str, str]]:
    """Recall: labelled basis (primary reading of H4), all-node basis beside."""
    return [_b0_metric(ctx, "recall", "full", None, "full_recall_labelled_mean", primary=True,
                       note="labelled nodes only (b0-reachable, primary, 070/071)"),
            _b0_metric(ctx, "recall", "b0", None, "b0_recall_labelled_mean", primary=True,
                       note="labelled nodes only (b0-reachable, primary, 070/071)"),
            _b0_metric(ctx, "recall", "full", None, "full_recall_mean", note="all context-0 nodes, beside"),
            _b0_metric(ctx, "recall", "b0", None, "b0_recall_mean", note="all context-0 nodes, beside")]


# ---------------------------------------------------------------- spec 06 section 10 (addendum D): no verdict anywhere

TABLE_RECON, TABLE_AUC, TABLE_SWEEP = "reconstruction", "auc", "sensitivity"
CHANCE_NA_PRF = "n/a: node set measure at a fixed node budget, no ranking order to draw at random"
CHANCE_NA_AUC_POS = "n/a: the AUC chance line is 0.5 on any candidate set"
PRF_METRICS: tuple[str, ...] = ("node_precision_mean", "node_recall_mean", "node_f1_mean", "node_fnr_mean")
_PRF_TRIALS = {"node_precision_mean": "node_precision_trials", "node_recall_mean": "node_recall_trials",
               "node_f1_mean": "node_f1_trials", "node_fnr_mean": "node_recall_trials"}
_P_NOTE = ("P = share of the expected held nodes that the key lists; a held event the key does not list counts as "
           "'not in key' (the key lists the move evidence only)")
# SW-03: the sensitivity table never uses this word (checked on its rows and its Markdown block).
SWEEP_BANNED_WORD = "stable"
SWEEP_READING = "hop reading (decision 068: the sweep matches key hops by target logon uids)"
LIMIT_AUC_POOLED = ("AUC-02: the pooled AUC pools scores across trials. A path score is a score for ordering, not a "
                    "probability (Correction J), so the pooled AUC is a summary only.")
LIMIT_AUC_NEGATIVES = ("AUC-03: pooled negatives from other trials and from S06 measure the score level across "
                       "scenarios, which Correction J does not make comparable; the per-trial AUC is shown beside it, "
                       "and an AUC with n_pos or n_neg = 0 is undefined.")


def _find(ctx: _Ctx, kind: str, variant: str, scenario: str = "") -> Mapping[str, str]:
    """The rendered totals row of an addendum row kind (EvalError when missing: the two codes disagree)."""
    for r in ctx.totals:
        if (r["row_kind"], r["variant"], r["scenario"]) == (kind, variant, scenario):
            return r
    raise EvalError(f"refused: internal: no rank_totals row {kind}/{variant}/{scenario or '-'}")


def _addendum_source(row: Mapping[str, str]) -> str:
    """The rank_totals.csv row key of an addendum row (``_source`` plus the scenario when set)."""
    return _source(row) + (f"/{row['scenario']}" if row.get("scenario") else "")


def _reconstruction(ctx: _Ctx) -> list[dict[str, str]]:
    """Spec 06 D-A (NP-01..05): node P/R/F1/FNR of full, b1, b2 and b0, overall (macro mean over attack trials) then
    per scenario; each value checked against its rank_totals.csv cell. No threshold, comparator or dev_check."""
    rows: list[dict[str, str]] = []
    na = (CHANCE_NA_PRF, CHANCE_NA_PRF)
    for v in PRF_VARIANT_ORDER:
        for scenario in ("",) + attack_scenarios(ctx.results):
            vals = node_prf_values([p for _t, p in node_prf_pairs(ctx.results, v, scenario or None)])
            trow = _find(ctx, KIND_NODE_PRF_SCENARIO if scenario else KIND_NODE_PRF, v, scenario)
            where = f"scenario {scenario}" if scenario else "overall: macro mean over attack trials"
            for m in PRF_METRICS:
                _check(trow, m, vals[m])
                note = f"{where}; {_P_NOTE}" if m == "node_precision_mean" else where
                rows.append(_row(ctx.split, TABLE_RECON, "", v, SCOPE_ALL, m, vals[m], chance=na,
                                 n_trials=int(vals[_PRF_TRIALS[m]] or 0),
                                 source=f"{_addendum_source(trow)}:{m}", note=note))
    return rows


def _auc_note(n_pos: int, n_neg: int, auc: float | None) -> str:
    """n_pos / n_neg and, when undefined, why (AUC-03)."""
    base = f"n_pos {n_pos}, n_neg {n_neg}"
    return base + ("; undefined: n_pos or n_neg is 0" if auc is None else "")


def _auc(ctx: _Ctx) -> list[dict[str, str]]:
    """Spec 06 D-B (AUC-01..03): per path variant the pooled AUC with n_pos and n_neg (checked against rank_totals),
    then the per-trial AUC of each keyed attack trial. Chance line 0.5; no verdict."""
    rows: list[dict[str, str]] = []
    ch = (f6(AUC_CHANCE), CHANCE_NA_AUC_POS)
    for v in PATH_VARIANT_ORDER:
        vals = auc_values(ctx.results, v)
        trow = _find(ctx, KIND_AUC_POOLED, v)
        _check(trow, "auc", vals["auc"])
        _check(trow, "auc_n_pos", vals["auc_n_pos"], count=True)
        _check(trow, "auc_n_neg", vals["auc_n_neg"], count=True)
        src = _addendum_source(trow)
        pooled = (f"pooled over the {vals['auc_trials']} keyed trials (keyed S06 included, unkeyed left out); "
                  + _auc_note(vals["auc_n_pos"], vals["auc_n_neg"], vals["auc"]))
        rows.append(_row(ctx.split, TABLE_AUC, "", v, SCOPE_ALL, "auc_pooled", vals["auc"], chance=ch,
                         n_trials=int(vals["auc_trials"]), source=f"{src}:auc", note=pooled))
        for m in ("auc_n_pos", "auc_n_neg"):
            rows.append(_row(ctx.split, TABLE_AUC, "", v, SCOPE_ALL, m, vals[m], count=True, chance=("", ""),
                             n_trials=int(vals["auc_trials"]), source=f"{src}:{m}", note="pooled"))
        for t in ctx.results:
            if not t.attack:
                continue
            tv = auc_trial_values(t, v)
            rows.append(_row(ctx.split, TABLE_AUC, "", v, SCOPE_ALL, "auc_trial", tv["auc"], chance=ch, n_trials=1,
                             source=f"out/evaluate/{t.trial_id}/rank.csv auc_trial/{v}:auc",
                             note=f"trial {t.trial_id}; " + _auc_note(int(tv["auc_n_pos"] or 0),
                                                                     int(tv["auc_n_neg"] or 0), tv["auc"])))
    return rows


def sweep_values(default: SweepPoint, points: Sequence[SweepPoint]) -> dict[str, Any]:
    """SW-02 facts over the grid points (every lambda of the grid x every weight point in steps of 0.1; the
    ``default_w`` check points are not counted): N, points with the same expected rank of every key attack path as
    at the default weights, min / max of top-1, per-trial MRR, per-key MRR and the S06 margin, and the default
    point's values. Pure."""
    grid = [p for p in points if p.kind == "grid"]

    def margin(p: SweepPoint) -> float | None:
        return None if p.attack_min is None or p.s06_max is None else p.attack_min - p.s06_max

    out: dict[str, Any] = {"points": len(grid), "same_ranks": sum(1 for p in grid if not changed_keys(p, default))}
    for name, get in (("top1_expected", lambda p: p.top1), ("mrr_expected", lambda p: p.mrr),
                      ("mrr_per_key_expected", lambda p: p.mrr_per_key), ("s06_margin", margin)):
        vals = [x for x in (get(p) for p in grid) if x is not None]
        out[name] = {"default": get(default), "min": min(vals) if vals else None,
                     "max": max(vals) if vals else None, "undefined": len(grid) - len(vals)}
    return out


_SWEEP_CHANCE = {"top1_expected": ("chance_top1", "chance_pos_top1"), "mrr_expected": ("chance_mrr", "chance_pos_mrr"),
                 "mrr_per_key_expected": ("chance_per_key_mrr", "chance_pos_per_key_mrr")}


def _sensitivity(ctx: _Ctx, sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]]) -> list[dict[str, str]]:
    """Spec 06 D-D (SW-02, SW-03): the weight sensitivity over the sweep grid, hop reading (068), with the chance line
    of full / hop reading beside each ranking metric (over all candidates: any w; over score > 0: default w). The
    default point's values are checked against the full / hop ``ranking`` row of rank_totals.csv. No verdict, no S06
    held count, never the word of SW-03."""
    default, points, _check_facts = sweep
    sv = sweep_values(default, points)
    hop = ctx.total(KIND_RANKING, "full", rm.READING_HOP, "")
    for m in _SWEEP_CHANCE:
        _check(hop, m, sv[m]["default"])
    trials = [t.sweep_trial for t in ctx.results if t.sweep_trial is not None]
    info = informative_sentence(informativeness(trials))
    base = dict(variant="full", scope=SCOPE_ALL)
    rows = [_row(ctx.split, TABLE_SWEEP, "", base["variant"], base["scope"], "sweep_points", sv["points"],
                 count=True, chance=("", ""), source="rank_sweep.csv point_kind grid",
                 note=f"grid points: every lambda of the grid x every weight point in steps of 0.1; {SWEEP_READING}; "
                      f"{info}"),
            _row(ctx.split, TABLE_SWEEP, "", base["variant"], base["scope"], "same_ranks_points", sv["same_ranks"],
                 count=True, chance=("", ""), source="rank_sweep.csv point_kind grid:same_ranks_as_default",
                 note=f"same ranks as at the default weights: {sv['same_ranks']} of {sv['points']} points")]
    for m, (call, cpos) in _SWEEP_CHANCE.items():
        ch = (hop[call], hop[cpos])
        for part in ("default", "min", "max"):
            src = (f"rank_sweep.csv default:{m}" if part == "default" else f"rank_sweep.csv grid:{part}({m})")
            rows.append(_row(ctx.split, TABLE_SWEEP, "", "full", SCOPE_ALL, f"{m}_{part}", sv[m][part], chance=ch,
                             n_trials=int(ranking_values([rr for _t, rr in attack_readings(
                                 ctx.results, "full", rm.READING_HOP)])["attack_trials"]),
                             source=src, note=f"{SWEEP_READING}; chance over score > 0 at the default weights"))
    na = (CHANCE_NA_MARGIN, CHANCE_NA_MARGIN)
    for part in ("default", "min", "max"):
        src = "rank_sweep.csv default:s06_margin" if part == "default" else f"rank_sweep.csv grid:{part}(s06_margin)"
        rows.append(_row(ctx.split, TABLE_SWEEP, "", "full", SCOPE_ALL, f"s06_margin_{part}", sv["s06_margin"][part],
                         chance=na, source=src,
                         note=f"{SWEEP_READING}; grid points with an undefined margin: {sv['s06_margin']['undefined']}"))
    for r in rows:
        if SWEEP_BANNED_WORD in " ".join(r.values()).lower():
            raise EvalError(f"refused: the weight sensitivity rows would contain the word {SWEEP_BANNED_WORD!r}")
    return rows


def result_rows(results: Sequence[TrialRank], split: str = SPLIT_DEVELOPMENT,
                sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]] | None = None
                ) -> list[dict[str, str]]:
    """Every results.csv row, table by table (H1-H5, baselines, contested, recall, then the spec 06 section 10 tables:
    reconstruction quality, pooled ROC-AUC, weight sensitivity). The sweep is computed here when not given
    (``rank_run.sweep_of``, with its default check)."""
    ctx = _Ctx(results, split)
    swept = sweep if sweep is not None else sweep_of(results)
    return (_h1(ctx) + _h2(ctx) + _h3(ctx) + _h4(ctx) + _h5(ctx) + _baselines(ctx) + _contested(ctx) + _recall(ctx)
            + _reconstruction(ctx) + _auc(ctx) + _sensitivity(ctx, swept))


# ---------------------------------------------------------------- results.md

def _table(columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> list[str]:
    """A Markdown table; empty cells shown as ``-``."""
    lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(c, "")) or "-" for c in columns) + " |")
    return lines


def _block(title: str, columns: Sequence[str], rows: Iterable[Mapping[str, Any]], text: str = "") -> list[str]:
    """A titled table headed again with the DEVELOPMENT label (spec 06 section 3.3)."""
    head = ["", f"## {title}", "", f"**{RESULTS_NOTE}.**", ""]
    return head + ([text, ""] if text else []) + _table(columns, rows)


_H_COLS: tuple[str, ...] = ("variant", "reading_scope", "metric", "is_primary", "observed", "observed_12",
                            "threshold", "comparator",
                            VERDICT_COLUMN, "chance_all", "chance_pos", "n_trials", "n_key_paths", "note")


def _coverage(rows: Sequence[Mapping[str, str]], table: str) -> str:
    """The coverage a primary verdict rests on (ATK-EV-20): H4 "(k of n attack trials)" with labelled key nodes,
    H5 "(n keyed S06 trial(s))"; empty for the other tables."""
    if table == "H4":
        r = next(x for x in rows if x["table"] == "H4" and x["metric"] == "labelled_recall_trials"
                 and x["reading_scope"] == SCOPE_ALL)
        return f"({r['observed']} of {r['n_trials']} attack trials)"
    if table == "H5":
        r = next(x for x in rows if x["table"] == "H5" and x["is_primary"] == "1")
        n = int(r["n_trials"] or 0)
        return f"({n} keyed S06 trial{'' if n == 1 else 's'})"
    return ""


def _md_h_rows(rows: Sequence[Mapping[str, str]], table: str) -> list[dict[str, str]]:
    """The rows of one hypothesis table with the results.md verdict cell (``dev_check_cell``)."""
    cov = _coverage(rows, table)
    return [dict(r, **{VERDICT_COLUMN: dev_check_cell(r[VERDICT_COLUMN], r["equals_chance_pos"],
                                                     cov if r["is_primary"] == "1" else "")})
            for r in rows if r["table"] == table]


def _per_key_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """full, node reading: each key attack path's expected rank and RR with its per-key chance line."""
    out = []
    for tid, rr in attack_readings(results, "full", _NODE):
        for kr in rr.key_paths:
            pl = kr.placement
            ch = rm.chance_line(rr.n, len(pl.matched))
            cp = rm.chance_line(len(rr.positive), len(set(pl.matched) & rr.positive))
            out.append({"trial": tid, "key_path": kr.key_path.path_id, "n": str(rr.n),
                        "n_pos": str(len(rr.positive)), "rank_expected": f6(pl.rank_expected),
                        "rr_expected": f6(pl.rr("expected")), "chance_rr": f6(ch["rr"]), "chance_pos_rr": f6(cp["rr"]),
                        "contested": "1" if rr.contested else "0"})
    return out


def _per_trial_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """full, node reading: per attack trial top-1 and RR of the first match, with both chance lines."""
    out = []
    for tid, rr in attack_readings(results, "full", _NODE):
        ch = rm.chance_line(rr.n, len(rr.trial.matched))
        cp = rm.chance_line(len(rr.positive), len(set(rr.trial.matched) & rr.positive))
        out.append({"trial": tid, "n": str(rr.n), "n_pos": str(len(rr.positive)),
                    "top1_expected": f6(rr.trial.top1_expected), "chance_top1": f6(ch["top1"]),
                    "chance_pos_top1": f6(cp["top1"]), "rr_expected": f6(rr.trial.rr("expected")),
                    "chance_rr": f6(ch["rr"]), "chance_pos_rr": f6(cp["rr"]), "contested": "1" if rr.contested else "0"})
    return out


def _recall_trial_rows(results: Sequence[TrialRank]) -> list[dict[str, str]]:
    """Per attack trial H4 recall, labelled basis first."""
    out = []
    for t in results:
        b = t.b0
        if t.attack and b is not None:
            out.append({"trial": t.trial_id, "labelled_key_nodes": str(b.key_nodes_labelled),
                        "full_recall_labelled": f6(b.full_recall_labelled) or "undefined",
                        "b0_recall_labelled": f6(b.b0_recall_labelled) or "undefined",
                        "key_nodes": str(b.key_nodes), "full_recall": f6(b.full_recall),
                        "b0_recall": f6(b.b0_recall), "b0_contested": "1" if b.contested else "0"})
    return out


def _baseline_md(rows: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    """The baselines side by side: one line per variant, b0 with its recall only (decision 072 Q1)."""
    by = {(r["variant"], r["metric"]): r for r in rows if r["table"] == "baselines"}
    na = "n/a: b0 ranks single labelled units, not paths (072 Q1)"
    out = []
    for v in PATH_VARIANT_ORDER:
        t, k, m = by[(v, "top1_expected")], by[(v, "mrr_per_key_expected")], by[(v, "mrr_expected")]
        out.append({"variant": v, "top1_expected": t["observed"], "chance top-1 (all / >0)":
                    f"{t['chance_all']} / {t['chance_pos']}", "per-key MRR": k["observed"],
                    "chance per-key (all / >0)": f"{k['chance_all']} / {k['chance_pos']}",
                    "per-trial MRR": m["observed"], "chance MRR (all / >0)": f"{m['chance_all']} / {m['chance_pos']}",
                    "labelled recall": by[(v, "full_recall_labelled_mean")]["observed"] if v == "full" else "",
                    "all-node recall": by[(v, "full_recall_mean")]["observed"] if v == "full" else ""})
    lab, alln = by[("b0", "b0_recall_labelled_mean")], by[("b0", "b0_recall_mean")]
    out.append({"variant": "b0", "top1_expected": na, "chance top-1 (all / >0)": na, "per-key MRR": na,
                "chance per-key (all / >0)": na, "per-trial MRR": na, "chance MRR (all / >0)": na,
                "labelled recall": lab["observed"], "all-node recall": alln["observed"]})
    return out


_RECON_TEXT = (
    "No verdict: no hypothesis was frozen for these numbers (spec 06 section 10). Per keyed attack trial and variant, "
    "the top-k paths (k = number of key attack paths; a tie group at the cut read by expectation, decisions 065, 068) "
    "hold an expected number of distinct `context` = 0 nodes; R = expected key nodes covered / key nodes, P = expected "
    "key nodes covered / expected nodes held, F1 = 2PR / (P + R) (0 when P = R = 0), FNR = 1 - R. Key nodes = the "
    "`context` = 0 key attack nodes (the H4 all-node basis; ST-05 copies merged, which covers `member_logon_uids` "
    "only). b0 takes labelled units in rank order up to full's expected all-node budget, on the same all-node basis "
    "(NP-02, NP-05). P counts a held event the key does not list as 'not in key': the key lists the move evidence "
    "only, so P is the share of key nodes among the held nodes. P and F1 are undefined (`-`) when the expected number "
    "of nodes held is 0. Per scenario: mean over its attack trials; overall: macro mean over attack trials; S06 and "
    "unkeyed trials have no key nodes and are left out. NP-04 (internal consistency): full's R equals the H4 all-node "
    "full recall of every trial, else the run refuses; the independent check is the data-checker's recomputation.")


# ATK-EV-39: P is E[key nodes covered] / E[nodes held] (a ratio of expectations, decision 076 item 1), and F1 is
# built from that P; both headers say so.
_P_HEAD, _F1_HEAD = "P (ratio of expectations)", "F1 (from P as a ratio of expectations)"


def _reconstruction_md(rows: Sequence[Mapping[str, str]]) -> list[str]:
    """The "Reconstruction quality" block: one line per (scenario or overall, variant) with P, R, F1, FNR."""
    rec = [r for r in rows if r["table"] == TABLE_RECON]
    by: dict[tuple[str, str], dict[str, Mapping[str, str]]] = {}
    for r in rec:
        where = r["source"].split(":")[0].rsplit("/", 1)[-1] if "node_prf_scenario" in r["source"] else "overall"
        by.setdefault((where, r["variant"]), {})[r["metric"]] = r
    order = sorted({w for w, _v in by if w != "overall"}) + ["overall"]
    out = []
    for where in order:
        for v in PRF_VARIANT_ORDER:
            cells = by.get((where, v))
            if not cells:
                continue
            out.append({"scenario": where, "variant": v, _P_HEAD: cells["node_precision_mean"]["observed"],
                        "R": cells["node_recall_mean"]["observed"], _F1_HEAD: cells["node_f1_mean"]["observed"],
                        "FNR": cells["node_fnr_mean"]["observed"],
                        "trials (R / P / F1)": f"{cells['node_recall_mean']['n_trials']} / "
                                               f"{cells['node_precision_mean']['n_trials']} / "
                                               f"{cells['node_f1_mean']['n_trials']}"})
    return _block(f"Reconstruction quality (handoff 14.3 part 1); chance line {CHANCE_NA_PRF}",
                  ("scenario", "variant", _P_HEAD, "R", _F1_HEAD, "FNR", "trials (R / P / F1)"), out, _RECON_TEXT)


def _auc_md(rows: Sequence[Mapping[str, str]]) -> list[str]:
    """The "Pooled ROC-AUC" block: pooled and per-trial AUC per path variant with n_pos, n_neg, chance 0.5 and the
    AUC-02 / AUC-03 limits."""
    out = []
    for r in rows:
        if r["table"] != TABLE_AUC or r["metric"] not in ("auc_pooled", "auc_trial"):
            continue
        out.append({"variant": r["variant"], "scope": "pooled" if r["metric"] == "auc_pooled" else "per trial",
                    "AUC": r["observed"] or "undefined", "chance": r["chance_all"], "note": r["note"]})
    text = ("No verdict. Positives = candidates matching a key attack path (node reading, EV-06) in keyed attack "
            "trials; negatives = every other candidate of a keyed trial (non-matching candidates of attack trials and "
            "every candidate of the keyed S06 trials); unkeyed trials are left out; b0 ranks units, not paths, and is "
            "left out. AUC = Mann–Whitney on the 12-decimal written scores, ties counted 0.5; chance line 0.5.\n\n"
            f"- {LIMIT_AUC_POOLED}\n- {LIMIT_AUC_NEGATIVES}")
    return _block("Pooled ROC-AUC (optional, handoff 14.2)", ("variant", "scope", "AUC", "chance", "note"), out, text)


def _sensitivity_md(rows: Sequence[Mapping[str, str]]) -> list[str]:
    """The "Weight sensitivity (development)" block (SW-02, SW-03, SW-04): the SW-04 sentence first (the sweep never
    moves a frozen value, so the block cannot be read as a re-tuning), then the same-rank count, min / max per metric
    with the default point and the chance line beside, the informativeness sentence and the reading."""
    sw = {r["metric"]: r for r in rows if r["table"] == TABLE_SWEEP}
    if not sw:
        return []
    n, same = sw["sweep_points"]["observed"], sw["same_ranks_points"]["observed"]
    info = sw["sweep_points"]["note"].split(f"{SWEEP_READING}; ", 1)[-1]      # the sentence itself holds "; "
    table = []
    for m, label in (("top1_expected", "top-1 (expected)"), ("mrr_expected", "per-trial MRR"),
                     ("mrr_per_key_expected", "per-key MRR"), ("s06_margin", "S06 margin")):
        d = sw[f"{m}_default"]
        table.append({"metric": label, "default point": d["observed"], "min": sw[f"{m}_min"]["observed"],
                      "max": sw[f"{m}_max"]["observed"], "chance (all candidates, any w)": d["chance_all"],
                      "chance (score > 0, default w)": d["chance_pos"]})
    text = (f"{SW04_SENTENCE} No verdict. Same ranks as at the default weights: {same} of {n} points (every lambda of the grid x every "
            f"weight point in steps of 0.1). Reading: {SWEEP_READING}. The sweep is {info}. Min and max are taken "
            "over the same points; the S06 margin is given as its min and max only (no count of points). Source: "
            "`rank_sweep.csv`.")
    block = _block("Weight sensitivity (development)",
                   ("metric", "default point", "min", "max", "chance (all candidates, any w)",
                    "chance (score > 0, default w)"), table, text)
    if SWEEP_BANNED_WORD in "\n".join(block).lower():
        raise EvalError(f"refused: the weight sensitivity table would contain the word {SWEEP_BANNED_WORD!r}")
    return block


def results_md(results: Sequence[TrialRank], rows: Sequence[Mapping[str, str]], split: str = SPLIT_DEVELOPMENT) -> str:
    """The results.md text (spec 06 section 3.3): header, one table per hypothesis, baselines, contested reading,
    recall, per-key and per-trial MRR, the processing-time pointer, the stated limits and the wording block."""
    n_trials = len(results)
    lines = [md_header(split, None), "",
             f"T10 results tables computed on the {n_trials} development trials (split {split}); every table is a "
             "development check of the code, not a result (decisions 019, 072). Frozen thresholds: decisions 065, "
             "066, 070, 071 (`evaluate.params`). Verdict column `dev_check`, compared on `math.fsum` values rounded "
             "to 12 decimals (RS-09; `observed_12` in results.csv); match reading = node (EV-06); ties by expected "
             "rank (065). The values come from the ranking check recomputed in memory; the committed rank.csv and "
             "rank_totals.csv were checked equal byte for byte (RS-02). Contested rows (070 item 4) are secondary "
             "and carry no verdict. `equals_chance_pos` = 1 (results.csv) and \"not above chance over scored paths\" "
             "after a verdict mean observed ≤ the chance line over the candidates with score > 0, compared at 12 "
             "decimals (ATK-EV-19)."]
    for h in ("H1", "H2", "H3", "H4", "H5"):
        lines += _block(f"{h} — {_HYP[h]}", _H_COLS, _md_h_rows(rows, h))
    base = [r for r in rows if r["table"] == "baselines"]
    lines += _block("Baselines side by side (full, b1, b2, b0; all attack trials, node reading)",
                    ("variant", "top1_expected", "chance top-1 (all / >0)", "per-key MRR", "chance per-key (all / >0)",
                     "per-trial MRR", "chance MRR (all / >0)", "labelled recall", "all-node recall"),
                    _baseline_md(base))
    cont = [{"variant": r["variant"], "contested_trials": r["observed"], "of_attack_trials": r["n_trials"],
             "trials": r["note"]} for r in rows if r["table"] == "contested"]
    lines += _block("Contested reading: contested attack trials per variant (no verdict; values in the H1–H4 tables)",
                    ("variant", "contested_trials", "of_attack_trials", "trials"), cont)
    lines += _block("Attack trials left out of the contested reading, with the reason",
                    ("variant", "match_reading", "trial", "n_positive", "reason"),
                    [r for r in uncontested_rows(results) if r["match_reading"] in ("", _NODE)])
    lines += _block(f"Recall per attack trial (labelled basis primary, all-node basis beside); chance line "
                    f"{CHANCE_NA_RECALL}",
                    ("trial", "labelled_key_nodes", "full_recall_labelled", "b0_recall_labelled", "key_nodes",
                     "full_recall", "b0_recall", "b0_contested"), _recall_trial_rows(results))
    lines += _block("Per-key MRR inputs (full, node reading; chance per key path: m_k = candidates matching it)",
                    ("trial", "key_path", "n", "n_pos", "rank_expected", "rr_expected", "chance_rr", "chance_pos_rr",
                     "contested"), _per_key_rows(results))
    lines += _block("Per-trial MRR inputs (full, node reading; first match of any key attack path)",
                    ("trial", "n", "n_pos", "top1_expected", "chance_top1", "chance_pos_top1", "rr_expected",
                     "chance_rr", "chance_pos_rr", "contested"), _per_trial_rows(results))
    lines += _reconstruction_md(rows) + _auc_md(rows) + _sensitivity_md(rows)
    lines += ["", "## Processing time", "",
              "Processing time per stage is recorded by the runner in `out/run_trial/development/run_log.md` "
              "(machine-dependent; referenced only, never copied here, so this file stays deterministic; RS-07)."]
    lines += ["", "## Stated limits of H1–H3", ""] + [f"- {t}" for t in LIMITS_H1_H3]
    lines += ["", "## Wording", ""] + [f"- {t}" for t in WORDING]
    return "\n".join(lines) + "\n"


def results_files(results: Sequence[TrialRank], split: str = SPLIT_DEVELOPMENT,
                  sweep: tuple[SweepPoint, Sequence[SweepPoint], Mapping[str, Any]] | None = None) -> dict[str, str]:
    """results.md and results.csv texts; EvalError when either would carry a forbidden phrase (RS-10) or the
    split is not development (RS-01: test results need the key lock and an owner-approved test allowlist)."""
    if split != SPLIT_DEVELOPMENT:
        raise EvalError("refused: results tables on test trials need the T5.7 key lock and an owner-approved test "
                        "allowlist (PLAN 10.4)")
    # the two-argument call stays the default path (callers and tests that wrap result_rows(results, split)); the
    # sweep is computed inside result_rows then
    rows = result_rows(results, split) if sweep is None else result_rows(results, split, sweep)
    files = {RESULTS_MD: results_md(results, rows, split), RESULTS_CSV: csv_text(RESULTS_COLUMNS, rows)}
    for name, text in files.items():                           # RS-10, ATK-EV-23: both files are scanned
        hits = forbidden_hits(text)
        if hits:
            raise EvalError(f"refused: {name} would contain forbidden wording: {', '.join(hits)}")
    return files

