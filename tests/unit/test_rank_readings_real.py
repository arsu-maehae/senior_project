"""T10.A acceptance EVA-01..EVA-04 on the nine real development trials (spec 06_evaluate section 7.1; decisions 070, 071, 072;
the answer keys of S02-S07 t00). Slow; read-only on the real folders; DEVELOPMENT numbers, not results (decision 019).

Written from the spec, the decisions and the keys, not from the code: the expected values are the ones the spec and
decision 070 / 071 state (per-key MRR 0.833333; contested {s04_t00, s07_t00}; labelled key nodes 3/4/5/10/10, full 0.830000
vs b0 0.422857, all-node 0.877451 vs 0.260609; chance 0.248333 / 0.376825 and over score > 0 0.900000 / 0.933333). The check
runs through its CLI on a **copy** of `out/stitch`, `out/score`, `out/label` and `ground_truth/approved` in a pytest tmp
folder (the root conftest forbids any write under the real `out/`).

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_rank_readings_real.py
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate import __main__ as em  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402
from test_rank_real import mini_repo  # noqa: E402  (helper only: copies the inputs the ranking check reads)

pytestmark = pytest.mark.slow

DEV = list(DEVELOPMENT_TRIALS)
ATTACK = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00"]
CONTESTED = ["s04_t00", "s07_t00"]


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def dev(tmp_path_factory):
    root = mini_repo(tmp_path_factory.mktemp("rank_readings_real"), DEV)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    return root


def totals(root: Path) -> list[dict[str, str]]:
    return read_csv(root / "out" / "evaluate" / "development" / "rank_totals.csv")


def one(rows, **want):
    (r,) = [x for x in rows if all(x[k] == v for k, v in want.items())]
    return r


def rank_rows(root: Path, trial: str) -> list[dict[str, str]]:
    return read_csv(root / "out" / "evaluate" / trial / "rank.csv")


# ================================================================================================ EVA-01
@pytest.mark.parametrize("reading", ["hop", "node"])
def test_eva01_per_key_mrr_full_is_0_833333_and_per_trial_mrr_0_933333_beside(dev, reading):
    r = one(totals(dev), row_kind="ranking", variant="full", match_reading=reading)
    assert r["mrr_per_key_expected"] == "0.833333" and r["mrr_expected"] == "0.933333"
    assert r["primary_metric"] == "mrr_per_key_expected" and r["reading_scope"] == "all"
    assert (r["attack_trials"], r["key_paths"], r["key_paths_matched"]) == ("5", "6", "6")


def test_eva01_per_key_values_s02_1_s03_1_s04b_0_666667_s05_1_s07_x_and_y_0_666667(dev):
    got = []
    for t in ATTACK:
        for r in rank_rows(dev, t):
            if r["row_kind"] == "key_path" and r["variant"] == "full" and r["match_reading"] == "node":
                got.append((t, r["rr_expected"]))
    assert got == [("s02_t00", "1.000000"), ("s03_t00", "1.000000"), ("s04_t00", "0.666667"), ("s05_t00", "1.000000"),
                   ("s07_t00", "0.666667"), ("s07_t00", "0.666667")]


# ================================================================================================ EVA-02
@pytest.mark.parametrize("variant", ["full", "b1", "b2"])
def test_eva02_contested_trials_are_s04_and_s07_with_identical_values_in_full_b1_b2(dev, variant):
    for t in ATTACK:
        rows = [r for r in rank_rows(dev, t) if r["row_kind"] == "trial" and r["variant"] == variant]
        assert {r["contested"] for r in rows} == {"1" if t in CONTESTED else "0"}, (variant, t)
    for reading in ("hop", "node"):
        r = one(totals(dev), row_kind="ranking_contested", variant=variant, match_reading=reading, contested_set=variant)
        assert r["reading_scope"] == "contested" and r["attack_trials"] == "2"
        assert r["scope_trial_ids"] == "s04_t00;s07_t00"
        assert r["top1_expected"] == "0.750000", (variant, reading)
        assert r["mrr_expected"] == "0.833333" and r["mrr_per_key_expected"] == "0.666667", (variant, reading)


def test_eva02_b0_contested_is_all_five_attack_trials(dev):
    for t in ATTACK:
        (r,) = [x for x in rank_rows(dev, t) if x["row_kind"] == "b0_recall"]
        assert r["contested"] == "1" and int(r["n_positive_units"]) > 1, t
    r = one(totals(dev), row_kind="b0_recall_contested", contested_set="b0")
    assert r["attack_trials"] == "5" and r["scope_trial_ids"] == ";".join(ATTACK) and r["reading_scope"] == "contested"
    paired = one(totals(dev), row_kind="b0_recall_contested", contested_set="full")
    assert paired["attack_trials"] == "2" and paired["scope_trial_ids"] == "s04_t00;s07_t00"


def test_eva02_primary_rows_are_not_replaced_by_the_contested_reading(dev):
    prim = one(totals(dev), row_kind="ranking", variant="full", match_reading="node")
    assert prim["attack_trials"] == "5" and prim["top1_expected"] == "0.900000"
    assert len([r for r in totals(dev) if r["row_kind"] == "ranking"]) == 6
    assert len([r for r in totals(dev) if r["row_kind"] == "b0_recall"]) == 1


# ================================================================================================ EVA-03
def test_eva03_h4_labelled_key_nodes_and_recall_per_trial_by_the_071_denominator(dev):
    got = {}
    for t in ATTACK:
        (r,) = [x for x in rank_rows(dev, t) if x["row_kind"] == "b0_recall"]
        got[t] = (r["key_nodes_labelled"], r["key_node_count"], r["full_recall_labelled"], r["b0_recall_labelled"])
    assert got == {"s02_t00": ("3", "16", "1.000000", "0.000000"),
                   "s03_t00": ("4", "12", "0.750000", "0.714286"),
                   "s04_t00": ("5", "21", "0.500000", "0.300000"),
                   "s05_t00": ("10", "34", "0.900000", "0.500000"),
                   "s07_t00": ("10", "40", "1.000000", "0.600000")}


def test_eva03_h4_means_labelled_primary_and_all_node_beside(dev):
    r = one(totals(dev), row_kind="b0_recall")
    assert (r["full_recall_labelled_mean"], r["b0_recall_labelled_mean"]) == ("0.830000", "0.422857")
    assert (r["full_recall_mean"], r["b0_recall_mean"]) == ("0.877451", "0.260609")
    assert r["attack_trials"] == "5" and r["labelled_recall_trials"] == "5"
    assert r["trials_full_above_b0_labelled"] == "5" and r["trials_full_above_b0"] == "5"
    assert r["reading_scope"] == "all" and "full_recall_labelled_mean" in r["primary_metric"]
    assert r["recall_basis"] == "all context-0 nodes (reported beside, 070)"
    assert r["recall_basis_labelled"] == "labelled nodes only (b0-reachable, primary, 070/071)"


def test_eva03_h4_contested_reading_full_set_paired_b0_set_beside(dev):
    paired = one(totals(dev), row_kind="b0_recall_contested", contested_set="full")
    own = one(totals(dev), row_kind="b0_recall_contested", contested_set="b0")
    # s04 (0.5, 0.3) and s07 (1.0, 0.6): full 0.75, b0 0.45 on full's contested set
    assert (paired["full_recall_labelled_mean"], paired["b0_recall_labelled_mean"]) == ("0.750000", "0.450000")
    assert (own["full_recall_labelled_mean"], own["b0_recall_labelled_mean"]) == ("0.830000", "0.422857")


# ================================================================================================ EVA-04
@pytest.mark.parametrize("reading", ["hop", "node"])
def test_eva04_chance_line_over_all_candidates_and_over_score_above_zero(dev, reading):
    r = one(totals(dev), row_kind="ranking", variant="full", match_reading=reading)
    assert (r["chance_top1"], r["chance_mrr"]) == ("0.248333", "0.376825")
    assert (r["chance_pos_top1"], r["chance_pos_mrr"]) == ("0.900000", "0.933333")


def test_eva04_per_key_chance_line_is_below_the_observed_per_key_mrr_and_uses_m_k(dev):
    r = one(totals(dev), row_kind="ranking", variant="full", match_reading="node")
    assert float(r["chance_per_key_mrr"]) < float(r["mrr_per_key_expected"])
    # s07 has two key paths: each key path row carries its own chance_rr (m_k), not the union's
    rows = [x for x in rank_rows(dev, "s07_t00") if x["row_kind"] == "key_path" and x["variant"] == "full"
            and x["match_reading"] == "node"]
    assert len(rows) == 2 and all(x["chance_rr"] and x["candidate_count"] for x in rows)
