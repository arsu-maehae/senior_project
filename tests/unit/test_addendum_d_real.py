"""Spec 06_evaluate section 10 (addendum D) acceptance on the nine real development trials: NPA-01, AUCA-01, SWA-01, SW-01..SW-04,
AUC-03, NP-03/NP-04, and the unchanged H1-H5 development verdicts. Slow; read-only on the real folders; DEVELOPMENT
numbers, not results (decision 019).

Written from the spec and the numbers the owner gave, not from the code. The CLI runs on a **copy** of `out/stitch`,
`out/score`, `out/label` and `ground_truth/approved` in a pytest tmp folder (the root conftest forbids any write under the
real `out/`): `--rank-sweep --development`, then `--results --development`. Nothing is written under the real tree and no
test-split trial id appears.

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_addendum_d_real.py -m slow
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate import __main__ as em  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402
from test_rank_pins import SW04_SENTENCE  # noqa: E402
from test_rank_real import mini_repo  # noqa: E402  (helper only: copies the inputs the ranking check reads)

pytestmark = pytest.mark.slow

DEV = list(DEVELOPMENT_TRIALS)
ATTACK = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00"]
NOTE = "DEVELOPMENT numbers, not results"


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def dev(tmp_path_factory):
    root = mini_repo(tmp_path_factory.mktemp("addendum_d_real"), DEV)
    assert em.main(["--rank-sweep", "--development", "--repo", str(root)]) == 0
    assert em.main(["--results", "--development", "--repo", str(root)]) == 0
    return root


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


@pytest.fixture(scope="module")
def totals(dev):
    return read_csv(summary(dev) / "rank_totals.csv")


@pytest.fixture(scope="module")
def sweep(dev):
    return read_csv(summary(dev) / "rank_sweep.csv")


@pytest.fixture(scope="module")
def results(dev):
    return read_csv(summary(dev) / "results.csv")


def one(rows, **want):
    (r,) = [x for x in rows if all(x[k] == v for k, v in want.items())]
    return r


def trial_rows(root: Path, trial: str, kind: str) -> list[dict[str, str]]:
    return [r for r in read_csv(root / "out" / "evaluate" / trial / "rank.csv") if r["row_kind"] == kind]


# ================================================================================================ NP (NP-01..04, NPA-01)
PRF = {"full": ("0.795192", "0.877451", "0.830077", "0.122549"),
       "b1": ("0.795192", "0.877451", "0.830077", "0.122549"),
       "b2": ("0.795192", "0.877451", "0.830077", "0.122549"),
       "b0": ("0.452666", "0.260609", "0.321263", "0.739391")}


@pytest.mark.parametrize("variant", ["full", "b1", "b2", "b0"])
def test_np03_overall_node_precision_recall_f1_fnr_are_the_stated_macro_means(totals, variant):
    r = one(totals, row_kind="node_prf", variant=variant)
    got = (r["node_precision_mean"], r["node_recall_mean"], r["node_f1_mean"], r["node_fnr_mean"])
    assert got == PRF[variant]
    assert (r["node_precision_trials"], r["node_recall_trials"], r["node_f1_trials"]) == ("5", "5", "5")
    assert r["scope_trial_ids"] == ";".join(ATTACK)                 # S06 and unkeyed trials are left out (NP-03)


def test_np03_fnr_is_one_minus_recall_and_f1_is_the_harmonic_mean_per_trial(dev):
    for t in ATTACK:
        for r in trial_rows(dev, t, "node_prf"):
            P, R_ = float(r["node_precision"]), float(r["node_recall"])
            assert float(r["node_fnr"]) == pytest.approx(1 - R_, abs=2e-6), (t, r["variant"])
            assert float(r["node_f1"]) == pytest.approx(2 * P * R_ / (P + R_), abs=2e-6), (t, r["variant"])


def test_npa01_per_trial_rows_exist_for_5_attack_trials_times_4_variants(dev):
    got = {(t, r["variant"]) for t in ATTACK for r in trial_rows(dev, t, "node_prf")}
    assert got == {(t, v) for t in ATTACK for v in ("full", "b1", "b2", "b0")} and len(got) == 20


def test_np03_b1_and_b2_equal_full_per_trial_on_development_data(dev):
    for t in ATTACK:
        by = {r["variant"]: r for r in trial_rows(dev, t, "node_prf")}
        for v in ("b1", "b2"):
            for col in ("node_precision", "node_recall", "node_f1", "node_fnr", "expected_key_nodes_covered",
                        "expected_nodes_held"):
                assert by[v][col] == by["full"][col], (t, v, col)


def test_np04_full_recall_equals_the_h4_all_node_full_recall_of_the_same_trial(dev):
    for t in ATTACK:
        (full,) = [r for r in trial_rows(dev, t, "node_prf") if r["variant"] == "full"]
        (h4,) = trial_rows(dev, t, "b0_recall")
        assert full["node_recall"] == h4["full_recall"], t


def test_np05_b0_node_budget_equals_the_expected_nodes_held_of_full(dev):
    for t in ATTACK:
        by = {r["variant"]: r for r in trial_rows(dev, t, "node_prf")}
        assert float(by["b0"]["budget_nodes"]) == pytest.approx(float(by["full"]["expected_nodes_held"]), abs=2e-6), t


def test_np03_the_s06_trial_and_the_unkeyed_trials_have_no_node_prf_row(dev):
    for t in DEV:
        if t not in ATTACK:
            assert trial_rows(dev, t, "node_prf") == [], t


def test_np03_per_scenario_rows_are_means_over_the_scenarios_attack_trials(totals):
    scen = [r for r in totals if r["row_kind"] == "node_prf_scenario" and r["variant"] == "full"]
    assert {r["scenario"] for r in scen} == {"s02", "s03", "s04", "s05", "s07"}


# ================================================================================================ AUC (AUC-01..03, AUCA-01)
POOLED = {"full": "0.972222", "b1": "0.959877", "b2": "0.907407"}


@pytest.mark.parametrize("variant", ["full", "b1", "b2"])
def test_auc01_pooled_auc_with_n_pos_n_neg_and_the_chance_line(totals, variant):
    r = one(totals, row_kind="auc_pooled", variant=variant)
    assert (r["auc"], r["auc_n_pos"], r["auc_n_neg"], r["auc_chance"]) == (POOLED[variant], "6", "27", "0.500000")
    assert r["match_reading"] == "node" and 0.0 <= float(r["auc"]) <= 1.0                         # AUCA-01


def test_auc01_b0_has_no_auc_row(totals):
    assert not [r for r in totals if r["row_kind"] in ("auc_pooled", "auc_trial") and r["variant"] == "b0"]


def test_auca01_n_pos_is_the_number_of_matched_key_paths(totals):
    r = one(totals, row_kind="ranking", variant="full", match_reading="node")
    assert r["key_paths_matched"] == "6" == one(totals, row_kind="auc_pooled", variant="full")["auc_n_pos"]


def test_auc03_per_trial_auc_s04_is_0_875_and_the_other_attack_trials_are_1(dev):
    for t in ATTACK:
        rows = trial_rows(dev, t, "auc_trial")
        assert {r["variant"] for r in rows} == {"full", "b1", "b2"}, t
        for r in rows:
            assert r["auc"] == ("0.875000" if t == "s04_t00" else "1.000000"), (t, r["variant"])
            assert r["auc_chance"] == "0.500000" and r["auc_n_pos"] and r["auc_n_neg"]


def test_auc03_per_trial_n_pos_and_n_neg_are_shown(dev):
    got = {t: (r["auc_n_pos"], r["auc_n_neg"]) for t in ATTACK for r in trial_rows(dev, t, "auc_trial")
           if r["variant"] == "full"}
    assert got == {"s02_t00": ("1", "3"), "s03_t00": ("1", "2"), "s04_t00": ("1", "4"), "s05_t00": ("1", "7"),
                   "s07_t00": ("2", "4")}


def test_auc01_pooled_n_neg_includes_the_keyed_s06_candidates_so_it_exceeds_the_per_trial_sum(dev, totals):
    per_trial = sum(int(r["auc_n_neg"]) for t in ATTACK for r in trial_rows(dev, t, "auc_trial")
                    if r["variant"] == "full")
    assert per_trial == 20 and int(one(totals, row_kind="auc_pooled", variant="full")["auc_n_neg"]) == 27
    assert "s06_t00" in one(totals, row_kind="auc_pooled", variant="full")["scope_trial_ids"].split(";")


def test_auc02_results_md_states_the_pooling_limit_and_the_chance_line(dev):
    md = (summary(dev) / "results.md").read_text(encoding="utf-8")
    assert "Pooled ROC-AUC" in md and "0.5" in md
    assert "not a probability" in md


# ================================================================================================ sweep (SW-01..03, SWA-01)
def test_sw01_the_sweep_has_396_grid_points_and_every_row_has_the_per_key_mrr_column(sweep):
    grid = [r for r in sweep if r["point_kind"] == "grid"]
    assert len(grid) == 396
    assert all(r["mrr_per_key_expected"] != "" for r in sweep)


def test_swa01_per_key_mrr_at_the_default_point_is_0_833333(sweep):
    (d,) = [r for r in sweep if r["point_kind"] == "default"]
    assert d["mrr_per_key_expected"] == "0.833333"


def test_sw03_same_ranks_as_the_default_weights_396_of_396(sweep, results):
    grid = [r for r in sweep if r["point_kind"] == "grid"]
    assert sum(r["same_ranks_as_default"] == "1" for r in grid) == 396
    (r,) = [x for x in results if x["table"] == "sensitivity" and x["metric"] == "same_ranks_points"]
    assert r["observed"] == "396" and r["note"] == "same ranks as at the default weights: 396 of 396 points"


def test_sw02_per_key_mrr_does_not_move_across_the_grid_and_s06_margin_range_is_stated(sweep, results):
    sens = {x["metric"]: x for x in results if x["table"] == "sensitivity"}
    assert sens["mrr_per_key_expected_min"]["observed"] == sens["mrr_per_key_expected_max"]["observed"] == "0.833333"
    assert sens["mrr_per_key_expected_default"]["observed"] == "0.833333"
    assert sens["s06_margin_min"]["observed"] == "-0.432332" and sens["s06_margin_max"]["observed"] == "0.666667"
    grid = [float(r["s06_margin"]) for r in sweep if r["point_kind"] == "grid"]
    assert (round(min(grid), 6), round(max(grid), 6)) == (-0.432332, 0.666667)


def test_sw03_the_sensitivity_table_never_says_stable_and_has_no_s06_held_count(dev):
    md = (summary(dev) / "results.md").read_text(encoding="utf-8")
    block = section(md, "Weight sensitivity (development)")
    assert "stable" not in block.lower() and "held" not in block.lower()
    assert "same ranks as at the default weights" in block.lower()


def test_sw03_chance_at_the_default_point_is_shown_beside_per_key_mrr(results):
    d = next(x for x in results if x["table"] == "sensitivity" and x["metric"] == "mrr_per_key_expected_default")
    assert d["chance_all"] == "0.337831" and d["chance_pos"] == "0.833333"


def test_sw03_the_reading_of_the_sweep_is_named_and_the_sweep_is_called_not_informative(results):
    r = next(x for x in results if x["table"] == "sensitivity" and x["metric"] == "sweep_points")
    assert "hop reading" in r["note"] and "068" in r["note"] and "not informative" in r["note"]
    assert r["observed"] == "396"


def test_sw01_the_sweep_never_moves_a_value_default_row_equals_the_score_run(sweep, totals):
    (d,) = [r for r in sweep if r["point_kind"] == "default"]
    full = one(totals, row_kind="ranking", variant="full", match_reading="hop")
    assert d["top1_expected"] == full["top1_expected"] and d["mrr_expected"] == full["mrr_expected"]
    assert d["mrr_per_key_expected"] == full["mrr_per_key_expected"]


# ================================================================================================ SW-04 sentence in both files
def section(text: str, title_prefix: str) -> str:
    parts = re.split(r"(?m)^## ", text)
    (s,) = [p for p in parts if p.startswith(title_prefix)]
    return s


def test_sw04_the_exact_sentence_is_in_the_results_md_weight_sensitivity_section(dev):
    md = (summary(dev) / "results.md").read_text(encoding="utf-8")
    assert SW04_SENTENCE in section(md, "Weight sensitivity (development)")


def test_sw04_the_exact_sentence_is_in_the_rank_md_sweep_section(dev):
    md = (summary(dev) / "rank.md").read_text(encoding="utf-8")
    assert SW04_SENTENCE in section(md, "Stability sweep")


def test_sw04_the_sentence_opens_the_results_section_so_it_cannot_be_read_as_re_tuning(dev):
    md = (summary(dev) / "results.md").read_text(encoding="utf-8")
    body = section(md, "Weight sensitivity (development)")
    text = [l for l in body.splitlines()[1:] if l.strip() and not l.startswith("|") and not l.startswith("#")
            and not l.startswith("**")]
    assert text[0].startswith(SW04_SENTENCE)


# ================================================================================================ H1-H5 unchanged
def primary(rows, table):
    (r,) = [x for x in rows if x["table"] == table and x["is_primary"] == "1" and x["reading_scope"] == "all"
            and x["dev_check"] != ""]
    return r


def test_the_h1_to_h5_development_verdicts_are_unchanged_by_the_addendum(results):
    got = {t: primary(results, t)["dev_check"] for t in ("H1", "H2", "H3", "H4", "H5")}
    assert got == {"H1": "held", "H2": "not held", "H3": "not held", "H4": "held", "H5": "held"}


def test_the_h_observed_values_and_thresholds_are_unchanged(results):
    h = {t: primary(results, t) for t in ("H1", "H2", "H3", "H4", "H5")}
    assert (h["H1"]["observed"], h["H1"]["threshold"]) == ("0.900000", "0.80")
    assert (h["H2"]["observed"], h["H2"]["threshold"]) == ("0.833333", "0.85")
    assert h["H3"]["observed"] == "0.000000"
    assert float(h["H4"]["observed"]) == pytest.approx(0.830000 - 0.422857, abs=1e-6)
    assert (h["H5"]["observed"], h["H5"]["metric"]) == ("0.305556", "s06_margin_min")


def test_the_new_tables_carry_no_verdict_and_every_row_is_labelled_development(results):
    new = [r for r in results if r["table"] in ("reconstruction", "auc", "sensitivity")]
    assert new and all(r["dev_check"] == "" and r["threshold"] == "" and r["comparator"] == "" for r in new)
    assert all("DEVELOPMENT" in r["status_note"] for r in results)
