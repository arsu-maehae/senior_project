"""Tables of the cmdline_target ablation (spec 06 section 10 D-F / D-G: AB-03, AB-04, AB-07..AB-10; ATK-EV-37..40,
44). Pure.

The default side is the on-disk ``out/`` (git-ignored), verified by the no-flag control arm of the same ablation run
(ATK-EV-37); the ablated side is the copy of the ablated scratch run under ``out/ablation/no_cmdline/``. Both are
parsed from the same bytes that were hashed, so every value of ``ablation.md`` / ``ablation.csv`` can be traced to a
file whose SHA-256 is in ``run_info.json``.

WHY the hop reading is the headline (AB-08): key hops are mapped to stitch hops by target logon uids (ST-25), which do
not use the command-line evidence the answer keys are built from (decision 020). The node reading uses that evidence,
so it is shown beside, with the label ``NODE_LABEL``; ablation.md opens with both side by side (ATK-EV-38).

WHY there is no threshold, comparator or verdict column (AB-09): no hypothesis was frozen for the ablation, so any
pass / fail would be a post-hoc test. ``difference`` (ablated - default) is a plain arithmetic difference, written
only where both arms average over the same trials (ATK-EV-39).

Every text built here is deterministic: no timestamp, fixed 6-decimal differences, rows in a fixed order.
"""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from evaluate.results_report import forbidden_hits
from stitch.params import METHODS as STITCH_METHODS
from stitch.tiers import TIERS

__all__ = ["BANNER", "NODE_LABEL", "DISABLED", "COLUMNS", "BANNED_COLUMNS", "DEFAULT_SIDE", "HOP_SENTENCE",
           "DIFF_NA", "Side", "side_files", "parse_side", "disabled_problems", "chain_problems", "tier_problems",
           "cmdline_link_problems", "same_trials", "difference", "headline_rows", "contested_rows", "node_rows", "trial_rows",
           "auc_trial_rows", "prf_scenario_rows", "prf_trial_rows", "h4_rows", "denominator_moves",
           "link_method_rows", "tier_rows", "key_hop_rows", "changed_key_hops", "all_rows", "hop_moved",
           "pooled_auc_sentence", "metric_label", "ablation_csv", "ablation_md", "readme_md", "marker_text",
           "text_problems"]

BANNER = "ABLATION (cmdline_target disabled) — DEVELOPMENT, not a result"
NODE_LABEL = ("key built from the same command-line evidence (020, AK-04): node recall falls by construction")
DISABLED: tuple[str, ...] = ("cmdline_target",)
HOP_NOTE = "hop reading: key hops mapped by target logon uids (ST-25), independent of the command-line evidence"
# ATK-EV-37: out/ is git-ignored, so the default side is never called "committed".
DEFAULT_SIDE = "the on-disk out/, verified by the no-flag control arm of this run"
# ATK-EV-38 (owner wording); the second half is written only when no hop-reading value moved (``hop_moved``).
HOP_SENTENCE = ("The hop reading maps key hops by target logons, so it can move only through path assembly and path "
                "scores")
# ATK-EV-39: a mean over different trial sets is not differenced.
DIFF_NA = "n/a: different trial sets"
RATIO_NOTE = "ratio of expectations (E[key nodes covered] / E[nodes held], decision 076 item 1)"

# ablation.csv columns. AB-09: none of BANNED_COLUMNS may ever appear (checked in ``ablation_csv``).
COLUMNS: tuple[str, ...] = ("status_note", "table", "trial_id", "variant", "match_reading", "reading_scope",
                            "contested_set", "item", "metric", "default", "ablated", "difference",
                            "chance_all_default", "chance_all_ablated", "chance_pos_default", "chance_pos_ablated",
                            "n_default", "n_ablated", "source", "note")
BANNED_COLUMNS: tuple[str, ...] = ("threshold", "comparator", "verdict", "dev_check", "held")

T_HEAD, T_CONT, T_NODE, T_TRIAL, T_KEYPATH = "headline_hop", "contested_hop", "node_reading", "trial_hop", "key_path_hop"
T_H4, T_LINKS, T_TIERS, T_KEYHOPS = "h4_denominators", "link_methods", "best_tier", "key_attack_hops"
T_AUC_TRIAL, T_PRF_SCEN, T_PRF_TRIAL = "auc_trial", "node_prf_scenario", "node_prf_trial"

Row = Mapping[str, str]
_PATH_VARIANTS: tuple[str, ...] = ("full", "b1", "b2")
_PRF_VARIANTS: tuple[str, ...] = _PATH_VARIANTS + ("b0",)
# (metric, chance over all candidates, chance over score > 0); "" = no chance line applies.
_RANKING_METRICS: tuple[tuple[str, str, str], ...] = (
    ("attack_trials", "", ""), ("key_paths", "", ""), ("key_paths_matched", "", ""),
    ("top1_expected", "chance_top1", "chance_pos_top1"), ("mrr_expected", "chance_mrr", "chance_pos_mrr"),
    ("mrr_per_key_expected", "chance_per_key_mrr", "chance_pos_per_key_mrr"),
    ("score_gap_min", "", ""), ("trials_gap_positive", "", ""))
_S06_METRICS: tuple[str, ...] = ("s06_trials", "s06_max_score", "key_attack_score_min", "s06_margin")
# The readings compared side by side at the top of ablation.md (ATK-EV-38).
_SIDE_METRICS: tuple[str, ...] = ("key_paths_matched", "top1_expected", "mrr_expected", "mrr_per_key_expected",
                                  "score_gap_min", "s06_margin")
# (totals mean column, its trial-count column, the per-trial rank.csv column it averages)
_PRF_METRICS: tuple[tuple[str, str, str], ...] = (("node_precision_mean", "node_precision_trials", "node_precision"),
                                                  ("node_recall_mean", "node_recall_trials", "node_recall"),
                                                  ("node_f1_mean", "node_f1_trials", "node_f1"),
                                                  ("node_fnr_mean", "node_recall_trials", "node_fnr"))
_PRF_TRIAL_METRICS: tuple[str, ...] = ("node_precision", "node_recall", "node_f1", "node_fnr",
                                       "expected_key_nodes_covered", "expected_nodes_held", "budget_nodes",
                                       "key_node_count")
_TRIAL_METRICS: tuple[tuple[str, str, str], ...] = (
    ("n_candidates", "", ""), ("n_candidates_positive", "", ""),
    ("top1_expected", "chance_top1", "chance_pos_top1"), ("rr_expected", "chance_rr", "chance_pos_rr"),
    ("first_match_score", "", ""), ("key_attack_score_min", "", ""), ("other_score_max", "", ""),
    ("score_gap", "", ""), ("contested", "", ""))
_KEYPATH_METRICS: tuple[tuple[str, str, str], ...] = (
    ("mapped_hop_ids", "", ""), ("candidate_count", "", ""),
    ("rank_expected", "chance_rank_expected", "chance_pos_rank_expected"),
    ("rr_expected", "chance_rr", "chance_pos_rr"))
# AB-10: the H4 denominators and readings per trial (rank.csv b0_recall row).
DENOMINATORS: tuple[str, ...] = ("key_node_count", "key_nodes_labelled", "n_positive_units", "budget_nodes",
                                 "budget_nodes_labelled")
_H4_TRIAL_METRICS: tuple[str, ...] = DENOMINATORS + ("full_recall", "b0_recall", "full_recall_labelled",
                                                     "b0_recall_labelled", "contested")
_H4_TOTAL_METRICS: tuple[str, ...] = ("attack_trials", "labelled_recall_trials", "full_recall_mean", "b0_recall_mean",
                                      "full_recall_labelled_mean", "b0_recall_labelled_mean", "trials_full_above_b0",
                                      "trials_full_above_b0_labelled")
_H4_LABELLED: frozenset[str] = frozenset({"labelled_recall_trials", "full_recall_labelled_mean",
                                          "b0_recall_labelled_mean", "trials_full_above_b0_labelled"})
_KEYHOP_METRICS: tuple[str, ...] = ("hop_id", "match", "best_tier", "rank1", "rank1_tier", "key_session_tier",
                                    "key_session_methods", "candidate_count", "candidate_count_cmd")
CMD_METHOD = "cmdline_target"
SESSION_CMD_ITEM = "rows whose session_methods name cmdline_target"


# ---------------------------------------------------------------- inputs

@dataclass(frozen=True)
class Side:
    """The parsed files of one run (default or ablated). ``sha256`` maps each file (relative to the side's ``out``
    root) to the SHA-256 of the exact bytes that were parsed."""
    totals: tuple[Row, ...]
    rank: Mapping[str, tuple[Row, ...]]
    link_summary: tuple[Row, ...]
    hops: Mapping[str, tuple[Row, ...]]
    links: Mapping[str, tuple[Row, ...]]
    stitch_info: Mapping[str, Mapping[str, Any]]
    eval_info: Mapping[str, Mapping[str, Any]]
    sha256: Mapping[str, str]


def side_files(trials: Sequence[str]) -> list[str]:
    """Every file one side is read from, relative to its ``out`` root (``out/`` or ``out/ablation/no_cmdline/``):
    the development rank_totals.csv and link_accuracy_summary.csv, then per trial rank.csv, evaluate run_info.json,
    stitch hops.csv, links.csv and run_info.json. Pure."""
    out = ["evaluate/development/rank_totals.csv", "evaluate/development/link_accuracy_summary.csv"]
    for t in trials:
        out += [f"evaluate/{t}/rank.csv", f"evaluate/{t}/run_info.json", f"stitch/{t}/hops.csv",
                f"stitch/{t}/links.csv", f"stitch/{t}/run_info.json"]
    return out


def _csv_rows(data: bytes) -> tuple[Row, ...]:
    """Rows of a UTF-8 CSV (BOM tolerated) as dicts."""
    return tuple(csv.DictReader(io.StringIO(data.decode("utf-8-sig"), newline="")))


def parse_side(blobs: Mapping[str, bytes], sha256: Mapping[str, str], trials: Sequence[str]) -> Side:
    """Parse the bytes of ``side_files(trials)``; KeyError when one is missing (the caller read them all). Pure."""
    return Side(totals=_csv_rows(blobs["evaluate/development/rank_totals.csv"]),
                rank={t: _csv_rows(blobs[f"evaluate/{t}/rank.csv"]) for t in trials},
                link_summary=_csv_rows(blobs["evaluate/development/link_accuracy_summary.csv"]),
                hops={t: _csv_rows(blobs[f"stitch/{t}/hops.csv"]) for t in trials},
                links={t: _csv_rows(blobs[f"stitch/{t}/links.csv"]) for t in trials},
                stitch_info={t: json.loads(blobs[f"stitch/{t}/run_info.json"].decode("utf-8")) for t in trials},
                eval_info={t: json.loads(blobs[f"evaluate/{t}/run_info.json"].decode("utf-8")) for t in trials},
                sha256=dict(sha256))


# ---------------------------------------------------------------- checks (each returns problem lines, empty = ok)

def disabled_problems(side: Side, expected: Sequence[str], label: str) -> list[str]:
    """AB-05 / AB-06: every stitch run_info.json of the ablated side carries ``disabled_methods`` == ``expected``;
    with ``expected`` empty (the default side) the key must be absent, as the default code writes it only when
    non-empty. WHY: a mixed or mislabelled input would put a default number in the ablated column or vice versa."""
    out: list[str] = []
    for t, info in side.stitch_info.items():
        if not expected:
            if "disabled_methods" in info:
                out.append(f"{label} stitch/{t}/run_info.json carries disabled_methods {info['disabled_methods']!r}")
        elif info.get("disabled_methods") != list(expected):
            out.append(f"{label} stitch/{t}/run_info.json disabled_methods is {info.get('disabled_methods')!r}, "
                       f"expected {list(expected)!r}")
    return out


def chain_problems(side: Side, label: str) -> list[str]:
    """AB-03 "hash-checked against both runs' files": the stitch hops.csv / links.csv hashes that evaluate wrote into
    its run_info.json (``inputs.stitch_files``) equal the SHA-256 of the stitch files read on the same side, so the
    evaluate outputs of a side were computed from that side's stitch output."""
    out: list[str] = []
    for t, info in side.eval_info.items():
        named = (info.get("inputs") or {}).get("stitch_files") or {}
        for name in ("hops.csv", "links.csv"):
            have = side.sha256.get(f"stitch/{t}/{name}")
            if named.get(name) != have:
                out.append(f"{label} evaluate/{t}/run_info.json names stitch {name} {named.get(name)!r}, "
                           f"but the file read has {have!r}")
    return out


def tier_problems(side: Side, label: str) -> list[str]:
    """The best_tier of each matched key hop in link_accuracy_summary.csv equals hops.csv's best_tier of the hop it
    names (the two files of one side agree)."""
    out: list[str] = []
    for r in side.link_summary:
        if r.get("row_kind") != "hop" or not r.get("hop_id"):
            continue
        tiers = {h["hop_id"]: h.get("best_tier", "") for h in side.hops.get(r["trial_id"], ())}
        if r["hop_id"] not in tiers:
            out.append(f"{label} {r['trial_id']} {r['key_hop_id']}: hop {r['hop_id']} not in hops.csv")
        elif tiers[r["hop_id"]] != r.get("best_tier", ""):
            out.append(f"{label} {r['trial_id']} {r['key_hop_id']}: best_tier {r.get('best_tier')!r} in "
                       f"link_accuracy_summary.csv but {tiers[r['hop_id']]!r} in hops.csv")
    return out


def cmdline_link_problems(side: Side, label: str) -> list[str]:
    """AB-07 / ABA-01 on the ablated side: no links.csv row has method cmdline_target and none names it in
    ``session_methods``."""
    out: list[str] = []
    for t, rows in side.links.items():
        n_method = sum(1 for r in rows if r.get("method") == CMD_METHOD)
        n_session = sum(1 for r in rows if CMD_METHOD in (r.get("session_methods") or "").split(";"))
        if n_method or n_session:
            out.append(f"{label} stitch/{t}/links.csv: {n_method} rows with method {CMD_METHOD}, {n_session} rows "
                       f"naming it in session_methods")
    return out


# ---------------------------------------------------------------- row helpers

# The trial ids one arm averages over; None = not readable (no scope_trial_ids, or a per-trial rank.csv row missing).
TrialSet = frozenset[str] | None
TrialSets = tuple[TrialSet, TrialSet]


def _count(cell: str) -> int | None:
    """A trial-count cell as an integer; None when empty or not an integer (the count is unknown)."""
    try:
        return int(cell)
    except (TypeError, ValueError):
        return None


def same_trials(sets: TrialSets | None, counts: tuple[str, str] = ("", "")) -> bool:
    """NP-06 / ATK-EV-39: do both arms average over the same trials? No ``sets`` = the row is not a mean, so True.
    When the trial ids are readable on both sides they decide; otherwise the trial counts do, and an unknown count
    on either side is False. WHY: ids that cannot be read must never make a mean over 5 trials look comparable with
    a mean over 4, and an unknown count cannot show the trials are the same. Pure."""
    if sets is None:
        return True
    if sets[0] is not None and sets[1] is not None:
        return sets[0] == sets[1]
    c0, c1 = _count(counts[0]), _count(counts[1])
    return c0 is not None and c0 == c1


def difference(default: str, ablated: str, sets: TrialSets | None = None, counts: tuple[str, str] = ("", "")) -> str:
    """ablated - default: an integer when both cells are integers (counts), else 6 decimals when both are numbers,
    else ``""``. ``-0.000000`` is written as ``0.000000``. ``DIFF_NA`` when ``sets`` / ``counts`` (the trials each
    arm averages over and their counts) do not show the same trials (``same_trials``; ATK-EV-39: a difference of
    means over different trials is not a change). Pure."""
    if not same_trials(sets, counts):
        return DIFF_NA
    try:
        return str(int(ablated) - int(default))
    except (TypeError, ValueError):
        pass
    try:
        d, a = float(default), float(ablated)
    except (TypeError, ValueError):
        return ""
    x = round(a - d, 6)
    return f"{(x if x != 0 else 0.0):.6f}"


def _row(table: str, metric: str, d: Row | None, a: Row | None, *, col: str = "", chance: tuple[str, str] = ("", ""),
         n_col: str = "", trial: str = "", variant: str = "", reading: str = "", scope: str = "", cset: str = "",
         item: str = "", source: str = "", note: str = "", values: tuple[str, str] | None = None,
         sets: TrialSets | None = None, count_col: str = "") -> dict[str, str]:
    """One ablation.csv row: ``col`` (default ``metric``) read from the default row ``d`` and the ablated row ``a``
    (a missing row gives ``""``), or the explicit ``values``; the chance cells and ``n`` from the same rows;
    ``sets`` and the trial counts in ``count_col`` (default ``n_col``) see ``difference``."""
    c = col or metric

    def get(r: Row | None, k: str) -> str:
        return "" if (r is None or not k) else str(r.get(k, "") or "")

    dv, av = values if values is not None else (get(d, c), get(a, c))
    counts = (get(d, count_col or n_col), get(a, count_col or n_col))
    if not same_trials(sets, counts):
        note = "; ".join(x for x in (note, _trials_note(sets, counts)) if x)
    return {"status_note": BANNER, "table": table, "trial_id": trial, "variant": variant, "match_reading": reading,
            "reading_scope": scope, "contested_set": cset, "item": item, "metric": metric, "default": dv,
            "ablated": av, "difference": difference(dv, av, sets, counts), "chance_all_default": get(d, chance[0]),
            "chance_all_ablated": get(a, chance[0]), "chance_pos_default": get(d, chance[1]),
            "chance_pos_ablated": get(a, chance[1]), "n_default": get(d, n_col), "n_ablated": get(a, n_col),
            "source": source, "note": note}


def _trials_note(sets: TrialSets, counts: tuple[str, str]) -> str:
    """Why a row is ``DIFF_NA``: the trial ids of both arms when both are readable, else the trial counts (``?`` =
    unknown), so the reader can trace the decision."""
    if sets[0] is not None and sets[1] is not None:
        return f"trials default {';'.join(sorted(sets[0])) or '-'} / ablated {';'.join(sorted(sets[1])) or '-'}"
    return f"trial ids not readable; trial counts default {counts[0] or '?'} / ablated {counts[1] or '?'}"


def _scope(r: Row | None) -> TrialSet:
    """The trial ids a totals row averages over (``scope_trial_ids``); None when the row is missing or the cell is
    empty (not readable: the trial counts decide, ``same_trials``)."""
    ids = frozenset(x for x in ((r or {}).get("scope_trial_ids", "") or "").split(";") if x)
    return ids or None


def _scopes(d: Row | None, a: Row | None) -> TrialSets:
    """(default, ablated) trial sets of a pair of totals rows."""
    return _scope(d), _scope(a)


def _totals_index(totals: Sequence[Row]) -> dict[tuple[str, str, str, str, str], Row]:
    """rank_totals.csv rows by (row_kind, variant, match_reading, contested_set, scenario); ValueError on a
    duplicate key (the key would not identify one row)."""
    out: dict[tuple[str, str, str, str, str], Row] = {}
    for r in totals:
        k = (r.get("row_kind", ""), r.get("variant", ""), r.get("match_reading", ""), r.get("contested_set", ""),
             r.get("scenario", ""))
        if k in out:
            raise ValueError(f"rank_totals.csv has two rows for {k}")
        out[k] = r
    return out


def _union_keys(*seqs: Iterable[Any]) -> list[Any]:
    """Keys in first-seen order over the sequences (default side first)."""
    seen: dict[Any, None] = {}
    for s in seqs:
        for k in s:
            seen.setdefault(k, None)
    return list(seen)


def _rank_rows(side: Side, trial: str, kind: str, variant: str, reading: str) -> list[Row]:
    """rank.csv rows of one trial with the given row_kind / variant / match_reading."""
    return [r for r in side.rank.get(trial, ()) if r.get("row_kind") == kind and r.get("variant") == variant
            and r.get("match_reading", "") == reading]


def _defined_trials(side: Side, kind: str, variant: str, column: str, within: TrialSet) -> TrialSet:
    """The trials of ``within`` whose rank.csv row (kind, variant) has a non-empty ``column``: the trials a mean of
    that column averages over (an undefined value is left out of the mean, decision 076 item 4). None (not readable)
    when ``within`` is None or a trial of it has no such rank.csv row: a missing row cannot tell defined from
    undefined."""
    if within is None:
        return None
    out = set()
    for t in within:
        rows = _rank_rows(side, t, kind, variant, "")
        if not rows:
            return None
        if rows[0].get(column) or "":
            out.add(t)
    return frozenset(out)


# ---------------------------------------------------------------- tables

def headline_rows(d: Side, a: Side) -> list[dict[str, str]]:
    """AB-08 headline, hop reading: per path variant top-1, per-trial MRR and per-key MRR with both chance lines,
    the score gap, the S06 margin inputs; then node P/R/F1/FNR (full, b1, b2, b0) and the pooled AUC (full, b1, b2),
    which are node based and carry ``NODE_LABEL``. Means carry their trial counts and are differenced only over the
    same trials (ATK-EV-39)."""
    di, ai = _totals_index(d.totals), _totals_index(a.totals)
    rows: list[dict[str, str]] = []
    for v in _PATH_VARIANTS:
        k = ("ranking", v, "hop", "", "")
        dr, ar = di.get(k), ai.get(k)
        src = f"rank_totals.csv ranking/{v}/hop"
        for m, ca, cp in _RANKING_METRICS:
            rows.append(_row(T_HEAD, m, dr, ar, chance=(ca, cp), n_col="attack_trials", variant=v, reading="hop",
                             scope="all", source=f"{src}:{m}", note=HOP_NOTE, sets=_scopes(dr, ar)))
        rows += _s06_rows(T_HEAD, v, "hop", dr, ar, src)
    rows += _prf_rows(T_HEAD, d, a, di, ai, "")
    for v in _PATH_VARIANTS:
        k = ("auc_pooled", v, "node", "", "")
        dr, ar = di.get(k), ai.get(k)
        for m in ("auc", "auc_n_pos", "auc_n_neg"):
            rows.append(_row(T_HEAD, m, dr, ar, chance=("auc_chance", "") if m == "auc" else ("", ""),
                             n_col="auc_trials", variant=v, reading="node", scope="all",
                             source=f"rank_totals.csv auc_pooled/{v}:{m}", sets=_scopes(dr, ar),
                             note=f"pooled path-level AUC, positives by node match (AUC-01..03); {NODE_LABEL}"))
    return rows


def _s06_rows(table: str, v: str, reading: str, dr: Row | None, ar: Row | None, src: str) -> list[dict[str, str]]:
    """The S06 margin inputs of one ranking row pair, with the reason when the margin is undefined."""
    reason = "; ".join(x for x in (f"default: {dr.get('s06_reason')}" if dr and dr.get("s06_reason") else "",
                                   f"ablated: {ar.get('s06_reason')}" if ar and ar.get("s06_reason") else "") if x)
    note = "S06 margin = lowest key attack score - highest S06 score; " + (reason or "no reason written")
    if reading == "node":
        note = f"{note}; {NODE_LABEL}"
    return [_row(table, m, dr, ar, variant=v, reading=reading, scope="all", source=f"{src}:{m}", note=note)
            for m in _S06_METRICS]


def _prf_rows(table: str, d: Side, a: Side, di: Mapping[Any, Row], ai: Mapping[Any, Row],
              scenario: str) -> list[dict[str, str]]:
    """Node P/R/F1/FNR means of every variant, overall (``scenario`` "") or of one scenario: the trial count beside
    each mean, the difference only over the same trials (per-trial rank.csv cells), P and F1 labelled as ratios of
    expectations (ATK-EV-39)."""
    kind = "node_prf_scenario" if scenario else "node_prf"
    rows: list[dict[str, str]] = []
    for v in _PRF_VARIANTS:
        k = (kind, v, "", "", scenario)
        dr, ar = di.get(k), ai.get(k)
        where = f"scenario {scenario}" if scenario else "overall"
        for m, n_col, per_trial in _PRF_METRICS:
            sets = (_defined_trials(d, "node_prf", v, per_trial, _scope(dr)),
                    _defined_trials(a, "node_prf", v, per_trial, _scope(ar)))
            ratio = f"; {RATIO_NOTE}" if m in ("node_precision_mean", "node_f1_mean") else ""
            rows.append(_row(table, m, dr, ar, n_col=n_col, variant=v, reading="node", scope="all",
                             item=scenario, sets=sets, source=f"rank_totals.csv {kind}/{v}/{scenario or 'all'}:{m}",
                             note=f"top-k node {m} over context-0 key nodes ({where}; NP-01..05){ratio}; "
                                  f"{NODE_LABEL}"))
    return rows


def contested_rows(d: Side, a: Side) -> list[dict[str, str]]:
    """The contested reading (070 item 4, EV-03/04), hop reading: every ``ranking_contested`` hop row of either side
    (variant and contested set; full's set is the paired set), with the contested trial ids. A set that is empty on
    one side shows its row with ``attack_trials`` 0 there; a contested set that differs between the arms gives
    ``DIFF_NA``."""
    di, ai = _totals_index(d.totals), _totals_index(a.totals)
    keys = _union_keys([k for k in di if k[0] == "ranking_contested" and k[2] == "hop"],
                       [k for k in ai if k[0] == "ranking_contested" and k[2] == "hop"])
    rows: list[dict[str, str]] = []
    for k in keys:
        dr, ar = di.get(k), ai.get(k)
        src = f"rank_totals.csv ranking_contested/{k[1]}/hop/{k[3]}"
        for m, ca, cp in _RANKING_METRICS:
            rows.append(_row(T_CONT, m, dr, ar, chance=(ca, cp), n_col="attack_trials", variant=k[1], reading="hop",
                             scope="contested", cset=k[3], source=f"{src}:{m}", note=HOP_NOTE,
                             sets=_scopes(dr, ar)))
        rows.append(_row(T_CONT, "contested_trial_ids", dr, ar, col="scope_trial_ids", variant=k[1], reading="hop",
                         scope="contested", cset=k[3], source=f"{src}:scope_trial_ids",
                         note="trials with more than one candidate scored above 0 (EV-03)"))
    return rows


def node_rows(d: Side, a: Side) -> list[dict[str, str]]:
    """AB-08: the node reading beside the headline, same metrics, every row labelled ``NODE_LABEL``."""
    di, ai = _totals_index(d.totals), _totals_index(a.totals)
    rows: list[dict[str, str]] = []
    for v in _PATH_VARIANTS:
        k = ("ranking", v, "node", "", "")
        dr, ar = di.get(k), ai.get(k)
        src = f"rank_totals.csv ranking/{v}/node"
        for m, ca, cp in _RANKING_METRICS:
            rows.append(_row(T_NODE, m, dr, ar, chance=(ca, cp), n_col="attack_trials", variant=v, reading="node",
                             scope="all", source=f"{src}:{m}", note=NODE_LABEL, sets=_scopes(dr, ar)))
        rows += _s06_rows(T_NODE, v, "node", dr, ar, src)
    return rows


def trial_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """Per attack trial, ``full``, hop reading: the trial row (first match) and each key path row of rank.csv, both
    with their chance lines. A trial without such rows (S06, unkeyed) is left out."""
    rows: list[dict[str, str]] = []
    for t in trials:
        dt, at = _rank_rows(d, t, "trial", "full", "hop"), _rank_rows(a, t, "trial", "full", "hop")
        if not dt and not at:
            continue
        dr, ar = (dt[0] if dt else None), (at[0] if at else None)
        for m, ca, cp in _TRIAL_METRICS:
            rows.append(_row(T_TRIAL, m, dr, ar, chance=(ca, cp), trial=t, variant="full", reading="hop",
                             scope="all", source=f"out/evaluate/{t}/rank.csv trial/full/hop:{m}", note=HOP_NOTE))
        dk = {r["key_path_id"]: r for r in _rank_rows(d, t, "key_path", "full", "hop")}
        ak = {r["key_path_id"]: r for r in _rank_rows(a, t, "key_path", "full", "hop")}
        for kp in _union_keys(dk, ak):
            for m, ca, cp in _KEYPATH_METRICS:
                rows.append(_row(T_KEYPATH, m, dk.get(kp), ak.get(kp), chance=(ca, cp), trial=t, variant="full",
                                 reading="hop", scope="all", item=kp,
                                 source=f"out/evaluate/{t}/rank.csv key_path/full/hop/{kp}:{m}", note=HOP_NOTE))
    return rows


def auc_trial_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """ATK-EV-38: the per-trial AUC of each keyed trial and path variant (rank.csv ``auc_trial``) in both arms, with
    n_pos and n_neg; chance line 0.5."""
    rows: list[dict[str, str]] = []
    for t in trials:
        for v in _PATH_VARIANTS:
            dt, at = _rank_rows(d, t, "auc_trial", v, "node"), _rank_rows(a, t, "auc_trial", v, "node")
            if not dt and not at:
                continue
            dr, ar = (dt[0] if dt else None), (at[0] if at else None)
            for m in ("auc", "auc_n_pos", "auc_n_neg"):
                rows.append(_row(T_AUC_TRIAL, m, dr, ar, chance=("auc_chance", "") if m == "auc" else ("", ""),
                                 trial=t, variant=v, reading="node", scope="all",
                                 source=f"out/evaluate/{t}/rank.csv auc_trial/{v}:{m}",
                                 note=f"undefined when n_pos or n_neg is 0 (AUC-03); {NODE_LABEL}"))
    return rows


def prf_scenario_rows(d: Side, a: Side) -> list[dict[str, str]]:
    """ATK-EV-40: node P/R/F1/FNR per scenario (rank_totals ``node_prf_scenario``), every variant, both arms."""
    di, ai = _totals_index(d.totals), _totals_index(a.totals)
    scenarios = _union_keys([k[4] for k in di if k[0] == "node_prf_scenario"],
                            [k[4] for k in ai if k[0] == "node_prf_scenario"])
    rows: list[dict[str, str]] = []
    for s in sorted(scenarios):
        rows += _prf_rows(T_PRF_SCEN, d, a, di, ai, s)
    return rows


def prf_trial_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """ATK-EV-40: node P/R/F1/FNR per keyed attack trial and variant (rank.csv ``node_prf``) with the expected key
    nodes covered, the expected nodes held, b0's budget and the key node count."""
    rows: list[dict[str, str]] = []
    for t in trials:
        for v in _PRF_VARIANTS:
            dt, at = _rank_rows(d, t, "node_prf", v, ""), _rank_rows(a, t, "node_prf", v, "")
            if not dt and not at:
                continue
            dr, ar = (dt[0] if dt else None), (at[0] if at else None)
            for m in _PRF_TRIAL_METRICS:
                ratio = f"; {RATIO_NOTE}" if m in ("node_precision", "node_f1") else ""
                rows.append(_row(T_PRF_TRIAL, m, dr, ar, trial=t, variant=v, reading="node", scope="all",
                                 source=f"out/evaluate/{t}/rank.csv node_prf/{v}:{m}", note=f"{NODE_LABEL}{ratio}"))
    return rows


def h4_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """AB-10: H4 recall on both bases (labelled primary per 070/071, all-node beside) with every denominator per
    attack trial (key nodes, labelled key nodes, b0 units with score > 0, the two budgets), then the totals over all
    attack trials and the contested totals; a total over different trials gives ``DIFF_NA``."""
    rows: list[dict[str, str]] = []
    for t in trials:
        dt, at = _rank_rows(d, t, "b0_recall", "full_vs_b0", ""), _rank_rows(a, t, "b0_recall", "full_vs_b0", "")
        if not dt and not at:
            continue
        for m in _H4_TRIAL_METRICS:
            rows.append(_row(T_H4, m, dt[0] if dt else None, at[0] if at else None, trial=t, variant="full_vs_b0",
                             scope="all", source=f"out/evaluate/{t}/rank.csv b0_recall:{m}",
                             note="n_positive_units = distinct b0 units with score > 0 (ST-05 merged)"
                             if m == "n_positive_units" else ""))
    di, ai = _totals_index(d.totals), _totals_index(a.totals)
    keys = _union_keys([k for k in di if k[0] in ("b0_recall", "b0_recall_contested")],
                       [k for k in ai if k[0] in ("b0_recall", "b0_recall_contested")])
    for k in keys:
        dr, ar = di.get(k), ai.get(k)
        scope = "contested" if k[0] == "b0_recall_contested" else "all"
        for m in _H4_TOTAL_METRICS:
            sets = ((_defined_trials(d, "b0_recall", "full_vs_b0", "full_recall_labelled", _scope(dr)),
                     _defined_trials(a, "b0_recall", "full_vs_b0", "full_recall_labelled", _scope(ar)))
                    if m in _H4_LABELLED else _scopes(dr, ar))
            rows.append(_row(T_H4, m, dr, ar, variant=k[1], scope=scope, cset=k[3], sets=sets,
                             count_col="labelled_recall_trials" if m in _H4_LABELLED else "attack_trials",
                             source=f"rank_totals.csv {k[0]}/{k[3] or 'all'}:{m}"))
        rows.append(_row(T_H4, "scope_trial_ids", dr, ar, variant=k[1], scope=scope, cset=k[3],
                         source=f"rank_totals.csv {k[0]}/{k[3] or 'all'}:scope_trial_ids"))
    return rows


def denominator_moves(rows: Sequence[Row]) -> list[str]:
    """AB-10 / ATK-EV-40: ``where: metric default -> ablated`` for every denominator that differs between the arms:
    the per-trial H4 denominators, the AUC n_pos / n_neg (pooled and per trial) and the expected nodes held of the
    node P/R/F1 (per trial). Empty = nothing moved. Pure."""
    out = []
    for r in rows:
        if r["default"] == r["ablated"]:
            continue
        hit = ((r["table"] == T_H4 and r["trial_id"] and r["metric"] in DENOMINATORS)
               or (r["table"] in (T_HEAD, T_AUC_TRIAL) and r["metric"] in ("auc_n_pos", "auc_n_neg"))
               or (r["table"] == T_PRF_TRIAL and r["metric"] == "expected_nodes_held"))
        if hit:
            where = " ".join(x for x in (r["trial_id"] or "pooled", r["variant"]) if x)
            out.append(f"{where}: {r['metric']} {r['default'] or '-'} -> {r['ablated'] or '-'}")
    return out


def link_method_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """Per trial and over all trials: links.csv row counts per ``method`` (the stitch method order, then any other
    name), plus the rows whose ``session_methods`` name cmdline_target."""
    rows: list[dict[str, str]] = []
    tot_d: Counter[str] = Counter()
    tot_a: Counter[str] = Counter()
    for t in trials:
        cd = Counter(r.get("method", "") for r in d.links.get(t, ()))
        ca = Counter(r.get("method", "") for r in a.links.get(t, ()))
        cd[SESSION_CMD_ITEM] = sum(1 for r in d.links.get(t, ())
                                   if CMD_METHOD in (r.get("session_methods") or "").split(";"))
        ca[SESSION_CMD_ITEM] = sum(1 for r in a.links.get(t, ())
                                   if CMD_METHOD in (r.get("session_methods") or "").split(";"))
        tot_d.update(cd)
        tot_a.update(ca)
        rows += _count_rows(T_LINKS, "link_rows", t, cd, ca, _method_order(cd, ca), f"out/stitch/{t}/links.csv method")
    rows += _count_rows(T_LINKS, "link_rows", "all", tot_d, tot_a, _method_order(tot_d, tot_a),
                        "out/stitch/<t>/links.csv method, summed over the trials")
    return rows


def _method_order(cd: Mapping[str, int], ca: Mapping[str, int]) -> list[str]:
    """The stitch methods in their fixed order, then any other observed name sorted, then the session item."""
    other = sorted((set(cd) | set(ca)) - set(STITCH_METHODS) - {SESSION_CMD_ITEM})
    return list(STITCH_METHODS) + other + [SESSION_CMD_ITEM]


def _count_rows(table: str, metric: str, trial: str, cd: Mapping[str, int], ca: Mapping[str, int],
                items: Sequence[str], source: str) -> list[dict[str, str]]:
    """One row per item with the default and ablated counts (0 when absent)."""
    return [_row(table, metric, None, None, trial=trial, item=i, source=source,
                 values=(str(cd.get(i, 0)), str(ca.get(i, 0)))) for i in items]


def tier_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """Per trial and over all trials: hops.csv ``best_tier`` counts (A..D, then ``(empty)`` and any other value)."""
    rows: list[dict[str, str]] = []
    tot_d: Counter[str] = Counter()
    tot_a: Counter[str] = Counter()
    for t in trials:
        cd = Counter(r.get("best_tier", "") or "(empty)" for r in d.hops.get(t, ()))
        ca = Counter(r.get("best_tier", "") or "(empty)" for r in a.hops.get(t, ()))
        tot_d.update(cd)
        tot_a.update(ca)
        rows += _count_rows(T_TIERS, "hops", t, cd, ca, _tier_order(cd, ca), f"out/stitch/{t}/hops.csv best_tier")
    rows += _count_rows(T_TIERS, "hops", "all", tot_d, tot_a, _tier_order(tot_d, tot_a),
                        "out/stitch/<t>/hops.csv best_tier, summed over the trials")
    return rows


def _tier_order(cd: Mapping[str, int], ca: Mapping[str, int]) -> list[str]:
    """A, B, C, D, then any other observed value sorted."""
    return list(TIERS) + sorted((set(cd) | set(ca)) - set(TIERS))


def key_hop_rows(d: Side, a: Side) -> list[dict[str, str]]:
    """Every key attack hop of link_accuracy_summary.csv (both sides, keyed by trial and key hop id): the mapped hop,
    best_tier, rank-1 facts and the key session's methods in both runs; the best_tier row notes whether the tier
    changed."""
    def index(side: Side) -> dict[tuple[str, str], Row]:
        return {(r["trial_id"], r["key_hop_id"]): r for r in side.link_summary
                if r.get("row_kind") == "hop" and r.get("key_role") == "attack"}
    di, ai = index(d), index(a)
    rows: list[dict[str, str]] = []
    for k in _union_keys(di, ai):
        dr, ar = di.get(k), ai.get(k)
        for m in _KEYHOP_METRICS:
            note = ""
            if m == "best_tier":
                dv, av = (dr or {}).get(m, ""), (ar or {}).get(m, "")
                note = "tier changed" if dv != av else "tier unchanged"
            rows.append(_row(T_KEYHOPS, m, dr, ar, trial=k[0], item=k[1],
                             source=f"evaluate/development/link_accuracy_summary.csv hop/{k[0]}/{k[1]}:{m}",
                             note=note))
    return rows


def changed_key_hops(rows: Sequence[Row]) -> list[str]:
    """``trial key_hop default -> ablated`` for every key attack hop whose best_tier changed. Pure."""
    return [f"{r['trial_id']} {r['item']}: {r['default'] or '-'} -> {r['ablated'] or '-'}" for r in rows
            if r["table"] == T_KEYHOPS and r["metric"] == "best_tier" and r["default"] != r["ablated"]]


def all_rows(d: Side, a: Side, trials: Sequence[str]) -> list[dict[str, str]]:
    """Every ablation.csv row, table by table, in a fixed order."""
    return (headline_rows(d, a) + contested_rows(d, a) + node_rows(d, a) + trial_rows(d, a, trials)
            + auc_trial_rows(d, a, trials) + prf_scenario_rows(d, a) + prf_trial_rows(d, a, trials)
            + h4_rows(d, a, trials) + link_method_rows(d, a, trials) + tier_rows(d, a, trials) + key_hop_rows(d, a))


def hop_moved(rows: Sequence[Row]) -> list[str]:
    """``variant metric default -> ablated`` for every hop-reading headline value (ranking and S06) that differs
    between the arms; empty = the hop reading did not move (ATK-EV-38). Pure."""
    return [f"{r['variant']} {r['metric']} {r['default'] or '-'} -> {r['ablated'] or '-'}" for r in rows
            if r["table"] == T_HEAD and r["match_reading"] == "hop" and r["default"] != r["ablated"]]


def pooled_auc_sentence(rows: Sequence[Row]) -> str:
    """ATK-EV-38: why a pooled-AUC change with a different n_pos is not a ranking-quality change: positives are the
    candidates that match a key path by node Jaccard, so a key path that no longer matches turns its candidate into a
    negative. Empty when n_pos and n_neg are equal in both arms for every variant. Pure."""
    by = {(r["variant"], r["metric"]): r for r in rows if r["table"] == T_HEAD and r["metric"].startswith("auc")}
    parts = []
    for v in _PATH_VARIANTS:
        p, n = by.get((v, "auc_n_pos")), by.get((v, "auc_n_neg"))
        if p and n and (p["default"] != p["ablated"] or n["default"] != n["ablated"]):
            parts.append(f"{v}: n_pos {p['default']}→{p['ablated']}, n_neg {n['default']}→{n['ablated']}")
    if not parts:
        return ""
    return ("Pooled AUC is computed over different positive sets in the two arms (" + "; ".join(parts) + "). This is "
            "not a ranking-quality change: positives are candidates that match a key attack path by node Jaccard, so "
            "key paths that no longer match after the ablation turn their candidates into negatives. The per-trial "
            "AUC below shows each trial's own positives.")


# ---------------------------------------------------------------- texts

def metric_label(metric: str) -> str:
    """The metric name as shown in ablation.md: P and F1 carry "ratio of expectations" (ATK-EV-39). Pure."""
    if metric in ("node_precision_mean", "node_precision"):
        return f"{metric} (P, ratio of expectations)"
    if metric in ("node_f1_mean", "node_f1"):
        return f"{metric} (F1 from P as a ratio of expectations)"
    return metric


def ablation_csv(rows: Sequence[Row]) -> str:
    """ablation.csv: ``COLUMNS`` header then the rows, ``\\n`` line ends. ValueError when a column of
    ``BANNED_COLUMNS`` would appear (AB-09) or a row's keys differ from the columns."""
    banned = [c for c in COLUMNS if any(b in c for b in BANNED_COLUMNS)]
    if banned:
        raise ValueError(f"ablation.csv may not carry a threshold, comparator or verdict column: {banned}")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)
    for r in rows:
        if set(r) != set(COLUMNS):
            raise ValueError(f"row keys differ from the columns: {sorted(set(r) ^ set(COLUMNS))}")
        w.writerow([r[c] for c in COLUMNS])
    return buf.getvalue()


def _pair(r: Row, a: str, b: str) -> str:
    """``default / ablated`` of two cells, ``-`` for empty cells, ``-`` when both are empty."""
    x, y = r.get(a, "") or "-", r.get(b, "") or "-"
    return "-" if x == y == "-" else f"{x} / {y}"


def _md_table(columns: Sequence[tuple[str, Any]], rows: Iterable[Row]) -> list[str]:
    """A Markdown table; each column is (header, cell function or row key)."""
    lines = ["| " + " | ".join(h for h, _ in columns) + " |", "|" + "---|" * len(columns)]
    for r in rows:
        cells = [(f(r) if callable(f) else (r.get(f, "") or "-")) for _h, f in columns]
        lines.append("| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |")
    return lines


def _section(title: str, text: str, columns: Sequence[tuple[str, Any]], rows: Sequence[Row]) -> list[str]:
    """A titled table headed again with the banner (AB-09)."""
    return ["", f"## {title}", "", f"**{BANNER}.**", "", text, ""] + _md_table(columns, rows)


_METRIC_COLS: tuple[tuple[str, Any], ...] = (
    ("variant", "variant"), ("metric", lambda r: metric_label(r["metric"])), ("default", "default"),
    ("ablated", "ablated"), ("difference", "difference"),
    ("chance all (default / ablated)", lambda r: _pair(r, "chance_all_default", "chance_all_ablated")),
    ("chance score > 0 (default / ablated)", lambda r: _pair(r, "chance_pos_default", "chance_pos_ablated")),
    ("trials (default / ablated)", lambda r: _pair(r, "n_default", "n_ablated")))


def _side_by_side(rows: Sequence[Row]) -> list[dict[str, str]]:
    """ATK-EV-38: one line per (variant, metric) with the hop reading first and the node reading beside."""
    hop = {(r["variant"], r["metric"]): r for r in rows if r["table"] == T_HEAD and r["match_reading"] == "hop"}
    node = {(r["variant"], r["metric"]): r for r in rows if r["table"] == T_NODE}
    out = []
    for v in _PATH_VARIANTS:
        for m in _SIDE_METRICS:
            h, n = hop.get((v, m), {}), node.get((v, m), {})
            out.append({"variant": v, "metric": m, "hop default": h.get("default", ""),
                        "hop ablated": h.get("ablated", ""), "hop difference": h.get("difference", ""),
                        "node default": n.get("default", ""), "node ablated": n.get("ablated", ""),
                        "node difference": n.get("difference", "")})
    return out


def ablation_md(rows: Sequence[Row], trials: Sequence[str]) -> str:
    """ablation.md: the banner, how the two arms were produced, the hop and node readings side by side, then one
    banner-headed table per part of AB-03 / AB-08 / AB-10 / ATK-EV-38..40, the moved denominators and the key attack
    hops whose tier changed. No threshold, comparator or verdict column (AB-09)."""
    by: dict[str, list[Row]] = {}
    for r in rows:
        by.setdefault(r["table"], []).append(r)
    head = [r for r in by.get(T_HEAD, []) if r["match_reading"] == "hop"]
    head_node = [r for r in by.get(T_HEAD, []) if r["match_reading"] == "node"]
    moves, changed, moved = denominator_moves(rows), changed_key_hops(rows), hop_moved(rows)
    hop_text = (f"{HOP_SENTENCE}; on development data it did not." if not moved else
                f"{HOP_SENTENCE}; on development data it moved: " + "; ".join(moved) + ".")
    lines = [f"# {BANNER}", "",
             f"Development trials ({len(trials)}): {', '.join(trials)}. Default = {DEFAULT_SIDE} (out/ is "
             "git-ignored; the control arm reran the whole default chain in a scratch copy and matched it, DR-03 "
             "rules). Ablated = `python -m run_trial --development --repo <scratch> --stitch-disable-method "
             "cmdline_target` in a second scratch copy outside the repository (AB-02); stitch then uses no "
             "command-line source-session method and no command-line evidence anywhere in the stitcher (AB-07), "
             "every other stage and every frozen parameter is unchanged, and the answer keys are the same approved "
             "t00 keys (AB-04). Labels (Sigma on event fields), the answer key and process nodes of sessions linked "
             "by the port join or 4648 still contain command text. `--results` was not run on the ablated side, so "
             "there is no development check of H1–H5 for it (AB-09). No hypothesis was frozen for the ablation: "
             "every table shows default and ablated values side by side, with no threshold, comparator or verdict "
             f"column (AB-03, AB-09). `difference` = ablated − default, `{DIFF_NA}` where the arms average over "
             "different trials (ATK-EV-39). P = E[key nodes covered] / E[nodes held], a ratio of expectations; F1 "
             "is built from that P. Ties by expected rank (065). The SHA-256 of every file read on both sides is in "
             "`run_info.json`."]
    lines += ["", "## Hop and node readings side by side (hop first)", "", f"**{BANNER}.**", "",
              f"{hop_text} Node reading label: {NODE_LABEL}.", ""]
    lines += _md_table([(c, c) for c in ("variant", "metric", "hop default", "hop ablated", "hop difference",
                                         "node default", "node ablated", "node difference")], _side_by_side(rows))
    lines += _section("Hop reading (headline, AB-08)",
                      f"{HOP_NOTE}. Per-trial MRR = `mrr_expected` (first match per trial); per-key MRR = "
                      "`mrr_per_key_expected` (070 primary); the chance line beside each ranking metric is over all "
                      "candidates and over candidates with score > 0.", _METRIC_COLS, head)
    auc_text = pooled_auc_sentence(rows)
    lines += _section("Node P/R/F1/FNR and pooled AUC (node based; shown with the headline)",
                      f"Label: {NODE_LABEL}. P/R/F1/FNR over the top-k paths' context-0 nodes (NP-01..05; b0 at "
                      "full's all-node budget), each mean with the trials it averages over; P and F1 are ratios of "
                      "expectations. AUC positives = candidates matching a key attack path by node Jaccard, chance "
                      "line 0.5 (AUC-01..03). " + auc_text, _METRIC_COLS, head_node)
    lines += _section("Per-trial AUC (both arms)", f"Label: {NODE_LABEL}. Chance line 0.5; undefined when n_pos or "
                      "n_neg is 0 (AUC-03).", (("trial", "trial_id"),) + _METRIC_COLS, by.get(T_AUC_TRIAL, []))
    lines += _section("Node P/R/F1/FNR per scenario", f"Label: {NODE_LABEL}. Mean over the scenario's attack trials; "
                      "trial counts beside each mean.", (("scenario", "item"),) + _METRIC_COLS,
                      by.get(T_PRF_SCEN, []))
    lines += _section("Node P/R/F1/FNR per trial", f"Label: {NODE_LABEL}. With the expected key nodes covered, the "
                      "expected nodes held (the P denominator), b0's all-node budget and the key node count.",
                      (("trial", "trial_id"), ("variant", "variant"), ("metric", lambda r: metric_label(r["metric"])),
                       ("default", "default"), ("ablated", "ablated"), ("difference", "difference")),
                      by.get(T_PRF_TRIAL, []))
    lines += _section("Contested reading (hop; EV-03/04)",
                      "Per variant and contested set (full's set is the paired set); `contested_trial_ids` lists "
                      "the trials in the set on each side.",
                      (("variant", "variant"), ("contested set", "contested_set")) + _METRIC_COLS[1:],
                      by.get(T_CONT, []))
    lines += _section("Node reading (beside the headline)", f"Label: {NODE_LABEL}.", _METRIC_COLS,
                      by.get(T_NODE, []))
    lines += _section("Per attack trial, full, hop reading", HOP_NOTE + ".",
                      (("trial", "trial_id"),) + _METRIC_COLS[1:], by.get(T_TRIAL, []))
    lines += _section("Per key attack path, full, hop reading", HOP_NOTE + ".",
                      (("trial", "trial_id"), ("key path", "item")) + _METRIC_COLS[1:], by.get(T_KEYPATH, []))
    moved_text = ("Denominators that moved with the stitch output: " + "; ".join(moves) + "." if moves else
                  "No denominator moved with the stitch output on development data.")
    lines += _section("H4 recall, both bases, with denominators (AB-10)",
                      "Labelled basis (070/071) primary, all-node basis beside; per attack trial the key nodes "
                      "(`key_node_count`), labelled key nodes (`key_nodes_labelled`, the 071 denominator), b0 units "
                      "with score > 0 (`n_positive_units`) and both budgets, then the totals. " + moved_text,
                      (("trial", "trial_id"), ("scope", "reading_scope"), ("set", "contested_set"),
                       ("metric", "metric"), ("default", "default"), ("ablated", "ablated"),
                       ("difference", "difference"), ("note", "note")), by.get(T_H4, []))
    lines += _section("Link rows per method per trial (links.csv)",
                      "Counts of links.csv rows per `method`, and of rows whose `session_methods` name "
                      "cmdline_target; `all` = summed over the trials.",
                      (("trial", "trial_id"), ("method", "item"), ("default", "default"), ("ablated", "ablated"),
                       ("difference", "difference")), by.get(T_LINKS, []))
    lines += _section("best_tier counts per trial (hops.csv)", "`all` = summed over the trials.",
                      (("trial", "trial_id"), ("best_tier", "item"), ("default", "default"), ("ablated", "ablated"),
                       ("difference", "difference")), by.get(T_TIERS, []))
    changed_text = ("Key attack hops whose best_tier changed: " + "; ".join(changed) + "." if changed else
                    "No key attack hop changed best_tier.")
    lines += _section("Key attack hops in both runs (link_accuracy_summary.csv)",
                      "Key hops are mapped by target logon uids (ST-25), so the same key hop is compared in both "
                      "runs. " + changed_text,
                      (("trial", "trial_id"), ("key hop", "item"), ("field", "metric"), ("default", "default"),
                       ("ablated", "ablated"), ("note", "note")), by.get(T_KEYHOPS, []))
    lines += ["", "## Wording", "",
              "- These numbers rank candidate paths on development trials; they are a development check of the "
              "code, not a result (decision 019).",
              "- The ablation shows what the ranking keeps without the command-line source-session method; it makes "
              "no claim beyond these 9 development trials (expected, to be measured on test data only after an "
              "owner decision)."]
    return "\n".join(lines) + "\n"


def readme_md(trials: Sequence[str], files: Sequence[str], arms: Mapping[str, str]) -> str:
    """README.md of ``out/ablation/no_cmdline/``: the banner, what the folder holds, what "no_cmdline" means and
    what still contains command text (ATK-EV-44), and the status of both arms (ATK-EV-37)."""
    lines = [f"# {BANNER}", "",
             "This folder holds the cmdline_target ablation of the 9 development trials (spec 06 section 10, "
             "AB-01..AB-11; decision 020). It was written by `python -m run_trial.ablation`, which ran two arms in "
             "scratch copies outside the repository: a no-flag control arm, compared with the on-disk `out/` "
             "(git-ignored) under the dry-run rules, and the ablated arm with `--stitch-disable-method "
             "cmdline_target`. The ablated outputs were copied here through a temporary folder and a swap, made only "
             "after the tree check passed.", "",
             "- **\"no_cmdline\" means no command-line source-session method**: stitch neither links a source "
             "session through a command line naming the target nor uses command-line evidence for tiers, the name "
             "check or the data limits (AB-07).",
             "- **Command text is still present elsewhere**: the Sigma labels match on `field_values_json` (which "
             "holds command lines), the answer key was built from command lines (020, AK-04), and the process nodes "
             "of sessions linked by the port join or 4648 keep their command text.",
             "- It is **not a result** and carries **no verdict**: no hypothesis was frozen for the ablation (AB-03, "
             "AB-09). `results.md` / `results.csv` were not produced for it.",
             "- No stage reads this folder (AB-06); each copied stage folder holds `ABLATION.txt` with the banner. "
             "The default `out/` was never written by the ablation.",
             "- A re-run replaces the whole folder.", "",
             "Arms: " + "; ".join(f"{k} {v}" for k, v in arms.items()) + ".", "",
             f"Trials: {', '.join(trials)}.", "", "Contents:"]
    lines += [f"- `{f}`" for f in files]
    return "\n".join(lines) + "\n"


def marker_text() -> str:
    """ABLATION.txt, written into every copied stage folder (ATK-EV-42): a reader of a single folder sees the
    banner."""
    return (f"{BANNER}\n\nThis stage folder is a copy of the ablated scratch run (stitch --disable-method "
            "cmdline_target). It is not a default output; no stage reads it (spec 06 AB-06).\n")


def text_problems(texts: Mapping[str, str]) -> list[str]:
    """RS-10 wording scan (``evaluate.results_report.forbidden_hits``) over every written text, and the banner in
    each Markdown file (AB-09)."""
    out: list[str] = []
    for name, text in texts.items():
        hits = forbidden_hits(text)
        if hits:
            out.append(f"{name} would contain forbidden wording: {', '.join(hits)}")
        if name.endswith(".md") and BANNER not in text:
            out.append(f"{name} lacks the banner")
    return out
