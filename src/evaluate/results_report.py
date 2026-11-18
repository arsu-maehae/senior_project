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
                     SPLIT_DEVELOPMENT, VERDICT_DECIMALS)
from .rank_report import (B0_SET, CHANCE_NA_MARGIN, CHANCE_NA_RECALL, KIND_B0, KIND_B0_CONTESTED, KIND_RANKING,
                          KIND_RANKING_CONTESTED, PAIRED_SET, PATH_VARIANT_ORDER, SCOPE_ALL, SCOPE_CONTESTED,
                          attack_readings, b0_contested_ids, b0_of, b0_values, contested_ids, f6, ranking_values,
                          s06_facts, total_rows, uncontested_rows)
from .rank_run import TrialRank
from .writers import csv_text, md_header

__all__ = ["RESULTS_MD", "RESULTS_CSV", "RESULTS_FILES", "RESULTS_NOTE", "VERDICT_COLUMN", "RESULTS_COLUMNS",
           "FORBIDDEN_WORDS", "ALLOWED_PHRASE", "LIMITS_H1_H3", "S06_PREFIX", "r12", "f12", "verdict_text",
           "at_least", "strictly_greater", "paired_difference", "forbidden_hits", "h5_facts", "result_rows", "results_md", "results_files"]

RESULTS_MD = "results.md"
RESULTS_CSV = "results.csv"
RESULTS_FILES: tuple[str, ...] = (RESULTS_MD, RESULTS_CSV)
RESULTS_NOTE = "DEVELOPMENT — not a result"
# RS-10: named `dev_check` while split = development; renamed `verdict` only for the test run (out of scope).
VERDICT_COLUMN = "dev_check"
RESULTS_COLUMNS: tuple[str, ...] = (
    "status_note", "split", "table", "hypothesis", "variant", "reading_scope", "metric", "is_primary", "observed",
    "observed_12", "threshold", "comparator", VERDICT_COLUMN, "chance_all", "chance_pos", "n_trials", "n_key_paths",
    "source", "note")
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
S06_PREFIX = "s06_"
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
    """a > b, both at 12 decimals (H3, H4, H5: equal at 12 decimals = not held, ATK-EV-02)."""
    return r12(a) > r12(b)


def verdict_text(held: bool) -> str:
    """The ``dev_check`` cell."""
    return "held" if held else "not held"


def forbidden_hits(text: str) -> list[str]:
    """``FORBIDDEN_WORDS`` found in ``text`` (case-insensitive) after removing the one allowed phrase (as
    score.report.forbidden_hits). WHY: results.md must never carry the claims CLAUDE.md forbids (RS-10)."""
    low = text.lower().replace(ALLOWED_PHRASE, " ")
    return [w for w in FORBIDDEN_WORDS if w in low]


# ---------------------------------------------------------------- facts

def h5_facts(results: Sequence[TrialRank]) -> dict[str, Any]:
    """H5 inputs (RS-05, ATK-EV-04), full, node reading: the lowest key attack score over the attack trials (None
    with the unmatched key paths named when any key attack path has no matching candidate: it is then undefined and
    never computed over the rest), and per S06 trial its highest full score and margin; keyed S06 trials (keyed, no
    key attack path) decide, unkeyed ``s06_*`` trials are reported beside."""
    attack = attack_readings(results, "full", _NODE)
    unmatched = [f"{tid}:{kr.key_path.path_id}" for tid, rr in attack for kr in rr.key_paths
                 if kr.placement.first_score is None]
    scores = [kr.placement.first_score for _tid, rr in attack for kr in rr.key_paths]
    low = None if unmatched or not scores else min(s for s in scores if s is not None)

    def per_trial(t: TrialRank) -> dict[str, Any]:
        top = max((c.score for c in t.candidates["full"]), default=None)
        margin = None if low is None or top is None else low - top
        return {"trial_id": t.trial_id, "max": top, "margin": margin}

    keyed = [per_trial(t) for t in results if t.keyed and not t.attack]
    unkeyed = [per_trial(t) for t in results if not t.keyed and t.trial_id.startswith(S06_PREFIX)]
    margins = [k["margin"] for k in keyed]
    defined = bool(keyed) and all(m is not None for m in margins)
    held = defined and all(strictly_greater(m, H5_MIN_MARGIN) for m in margins)          # type: ignore[arg-type]
    if not keyed:
        reason = "no keyed S06 trial"
    elif unmatched:
        reason = "lowest key attack score undefined: key attack path without a matching candidate (" + \
                 ";".join(unmatched) + ")"
    elif not defined:
        reason = "a keyed S06 trial has no candidate path, so its highest score is undefined"
    else:
        reason = ""
    return {"low": low, "unmatched": unmatched, "keyed": keyed, "unkeyed": unkeyed,
            "min_margin": min(margins) if defined else None, "held": held, "reason": reason}


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
         source: str = "", note: str = "", compared: float | None = None) -> dict[str, str]:
    """One results.csv row. ``compared`` overrides the 12-decimal cell (H3/H4 differences of rounded values)."""
    if count:
        observed, obs12 = ("" if value is None else str(int(value))), ""
    else:
        observed = f6(value)
        obs12 = f12(compared if compared is not None else value)          # type: ignore[arg-type]
    return {"status_note": RESULTS_NOTE, "split": split, "table": table, "hypothesis": hyp, "variant": variant,
            "reading_scope": scope, "metric": metric, "is_primary": "1" if primary else "0", "observed": observed,
            "observed_12": obs12, "threshold": threshold, "comparator": comparator, VERDICT_COLUMN: verdict,
            "chance_all": chance[0], "chance_pos": chance[1], "n_trials": "" if n_trials is None else str(n_trials),
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
                note=note or ("" if cset is None else _set_note(cset, variant, paired)))


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
                verdict: bool | None, chance: str, n_trials: int, source: str, note: str,
                threshold: float = 0.0) -> dict[str, str]:
    """A paired difference row: observed a - b (6 decimals), compared value ``paired_difference`` (RS-09)."""
    diff = None if a is None or b is None else a - b
    comp = paired_difference(a, b)
    return _row(ctx.split, table, _HYP[table], variant, scope, metric, diff, primary=verdict is not None,
                threshold=f"{threshold:.2f}" if verdict is not None else "",
                comparator=">" if verdict is not None else "",
                verdict="" if verdict is None else verdict_text(verdict), chance=(chance, chance),
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
    rows = [_difference(ctx, "H3", "full_vs_b1", SCOPE_ALL, "mrr_per_key_expected_difference", a1, b1v, held,
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
    rows = [_difference(ctx, "H4", "full_vs_b0", SCOPE_ALL, "recall_labelled_mean_difference", a, b, held,
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
    h = h5_facts(ctx.results)
    trow = ctx.total(KIND_RANKING, "full", _NODE, "")
    src = _source(trow)
    na = (CHANCE_NA_MARGIN, CHANCE_NA_MARGIN)
    nk = len(h["keyed"])
    if len(h["keyed"]) == 1 and h["min_margin"] is not None:
        _check(trow, "s06_margin", h["min_margin"])
    rows = [_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "s06_margin_min", h["min_margin"], primary=True,
                 threshold=f"{H5_MIN_MARGIN:.2f}", comparator=">", verdict=verdict_text(h["held"]), chance=na,
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
    s6 = s06_facts(ctx.results, "full", _NODE)
    _check(trow, "share_attack_trials_above_s06", s6["share_above"])
    rows.append(_row(ctx.split, "H5", _HYP["H5"], "full", SCOPE_ALL, "share_attack_trials_above_s06",
                     s6["share_above"], chance=na, n_trials=len(attack_readings(ctx.results, "full", _NODE)),
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
    rows += [_b0_metric(ctx, "baselines", "b0", None, "b0_recall_labelled_mean"),
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


def result_rows(results: Sequence[TrialRank], split: str = SPLIT_DEVELOPMENT) -> list[dict[str, str]]:
    """Every results.csv row, table by table (H1-H5, baselines, contested, recall)."""
    ctx = _Ctx(results, split)
    return _h1(ctx) + _h2(ctx) + _h3(ctx) + _h4(ctx) + _h5(ctx) + _baselines(ctx) + _contested(ctx) + _recall(ctx)


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


_H_COLS: tuple[str, ...] = ("variant", "reading_scope", "metric", "is_primary", "observed", "threshold", "comparator",
                            VERDICT_COLUMN, "chance_all", "chance_pos", "n_trials", "n_key_paths", "note")


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
                    "labelled recall": "", "all-node recall": ""})
    lab, alln = by[("b0", "b0_recall_labelled_mean")], by[("b0", "b0_recall_mean")]
    out.append({"variant": "b0", "top1_expected": na, "chance top-1 (all / >0)": na, "per-key MRR": na,
                "chance per-key (all / >0)": na, "per-trial MRR": na, "chance MRR (all / >0)": na,
                "labelled recall": lab["observed"], "all-node recall": alln["observed"]})
    return out


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
             "and carry no verdict."]
    for h in ("H1", "H2", "H3", "H4", "H5"):
        lines += _block(f"{h} — {_HYP[h]}", _H_COLS, [r for r in rows if r["table"] == h])
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
    lines += ["", "## Processing time", "",
              "Processing time per stage is recorded by the runner in `out/run_trial/development/run_log.md` "
              "(machine-dependent; referenced only, never copied here, so this file stays deterministic; RS-07)."]
    lines += ["", "## Stated limits of H1–H3", ""] + [f"- {t}" for t in LIMITS_H1_H3]
    lines += ["", "## Wording", ""] + [f"- {t}" for t in WORDING]
    return "\n".join(lines) + "\n"


def results_files(results: Sequence[TrialRank], split: str = SPLIT_DEVELOPMENT) -> dict[str, str]:
    """results.md and results.csv texts; EvalError when results.md would carry a forbidden phrase (RS-10) or the
    split is not development (RS-01: test results need the key lock and an owner-approved test allowlist)."""
    if split != SPLIT_DEVELOPMENT:
        raise EvalError("refused: results tables on test trials need the T5.7 key lock and an owner-approved test "
                        "allowlist (PLAN 10.4)")
    rows = result_rows(results, split)
    md = results_md(results, rows, split)
    hits = forbidden_hits(md)
    if hits:
        raise EvalError(f"refused: results.md would contain forbidden wording: {', '.join(hits)}")
    return {RESULTS_MD: md, RESULTS_CSV: csv_text(RESULTS_COLUMNS, rows)}

