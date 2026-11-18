"""T9.5 development ranking check on the nine real development trials (spec 05_score SCA-06, section 5.2, section 7.3;
decisions 065, 066, 068; review ATK-SC-18). Slow; read-only on the real folders; DEVELOPMENT numbers, not results
(decision 019).

Written from the spec and decisions, not from the code. The check is run through its CLI against a **copy** of
`out/stitch`, `out/score`, `out/label` and `ground_truth/approved` in a pytest tmp folder (`--repo`), because the root
conftest forbids any write under the real `out/` and `--development` writes to `<repo>/out/evaluate`. The approved keys
are copied read-only; they are read by the module under test, the tests only compare its numbers with decision 068.

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_rank_real.py   # a missing input FAILS instead of skipping
"""
from __future__ import annotations

import csv
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest
from real_data import missing_input  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from evaluate import __main__ as em  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(DEVELOPMENT_TRIALS)
KEYED_ATTACK = ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00"]
NOTE = "DEVELOPMENT numbers, not results"


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def need_inputs(trials) -> None:
    for t in trials:
        for stage, name in (("stitch", "run_info.json"), ("score", "run_info.json"), ("label", "run_info.json")):
            if not (REPO / "out" / stage / t / name).is_file():
                missing_input(f"{t}: out/{stage}/{t}/{name} missing")


def mini_repo(root: Path, trials) -> Path:
    """A copy of the inputs the ranking check reads, for `trials` (keys only where an approved key exists)."""
    need_inputs(trials)
    for t in trials:
        for stage in ("stitch", "score", "label"):
            shutil.copytree(REPO / "out" / stage / t, root / "out" / stage / t)
        key = REPO / "ground_truth" / "approved" / f"{t}.yaml"
        if key.is_file():
            (root / "ground_truth" / "approved").mkdir(parents=True, exist_ok=True)
            shutil.copy2(key, root / "ground_truth" / "approved" / key.name)
    return root


@pytest.fixture(scope="module")
def dev(tmp_path_factory):
    """The mini repo after `--rank-sweep --development` (read-only afterwards)."""
    root = mini_repo(tmp_path_factory.mktemp("rank_real"), DEV)
    assert em.main(["--rank-sweep", "--development", "--repo", str(root)]) == 0
    return root


def totals(root: Path) -> dict[tuple[str, str], dict[str, str]]:
    return {(r["variant"], r["match_reading"]): r
            for r in read_csv(root / "out" / "evaluate" / "development" / "rank_totals.csv")}


# ================================================================================================ headline numbers (068)
@pytest.mark.parametrize("variant", ["full", "b1", "b2"])
@pytest.mark.parametrize("reading", ["hop", "node"])
def test_development_expected_top1_and_mrr_of_decision_068(dev, variant, reading):
    r = totals(dev)[(variant, reading)]
    assert (r["attack_trials"], r["key_paths"], r["key_paths_matched"]) == ("5", "6", "6")
    assert r["top1_expected"] == "0.900000" and r["mrr_expected"] == "0.933333", (variant, reading)
    assert (r["top1_optimistic"], r["top1_pessimistic"]) == ("1.000000", "0.800000")
    assert (r["mrr_optimistic"], r["mrr_pessimistic"]) == ("1.000000", "0.900000")
    assert float(r["chance_top1"]) == pytest.approx(0.248, abs=5e-4) and float(r["chance_mrr"]) == pytest.approx(0.377, abs=5e-4)
    assert float(r["chance_rr_mean"]) > float(r["chance_mrr"])
    assert {r["status_note"]} == {NOTE}


def test_h3_would_not_hold_on_development_mrr_full_equals_b1(dev):
    """Decision 068: identity changes no within-trial rank on development data, so MRR(full) == MRR(b1) (strict H3 false)."""
    t = totals(dev)
    assert t[("full", "hop")]["mrr_expected"] == t[("b1", "hop")]["mrr_expected"]


def test_s04_track_b_attack_path_is_expected_rank_one_and_a_half(dev):
    rows = read_csv(dev / "out" / "evaluate" / "s04_t00" / "rank.csv")
    for reading in ("hop", "node"):
        (r,) = [x for x in rows if x["row_kind"] == "trial" and x["variant"] == "full" and x["match_reading"] == reading]
        assert (r["first_rank"], r["tie_size"], r["matches_in_tie"]) == ("1", "2", "1")
        assert (r["rank_expected"], r["rank_optimistic"], r["rank_pessimistic"]) == ("1.500000", "1", "2")
        assert r["top1_expected"] == "0.500000" and r["rr_expected"] == "0.666667"
        assert r["score_gap"] == "0.000000" and r["n_candidates"] == "5"
        assert r["chance_top1"] == "0.200000" and r["chance_rank_expected"] == "3.000000"
        (k,) = [x for x in rows if x["row_kind"] == "key_path" and x["variant"] == "full" and x["match_reading"] == reading]
        assert k["key_path_id"] == "s04-B-h1-path" and k["key_role"] in ("attack", "attack_pair")


@pytest.mark.parametrize("trial,key_ids", [("s02_t00", "s02-p1"), ("s03_t00", "s03-p1"), ("s05_t00", "s05-p1")])
def test_single_attack_key_paths_are_expected_rank_one(dev, trial, key_ids):
    rows = read_csv(dev / "out" / "evaluate" / trial / "rank.csv")
    for reading in ("hop", "node"):
        (r,) = [x for x in rows if x["row_kind"] == "trial" and x["variant"] == "full" and x["match_reading"] == reading]
        assert r["key_path_id"] == key_ids and r["rank_expected"] == "1.000000" and r["top1_expected"] == "1.000000", (trial, reading)
        assert float(r["score_gap"]) > 0.5


def test_s05_key_path_is_the_merged_multi_hop_path_matched_at_half_or_more(dev):
    rows = read_csv(dev / "out" / "evaluate" / "s05_t00" / "rank.csv")
    (k,) = [x for x in rows if x["row_kind"] == "key_path" and x["variant"] == "full" and x["match_reading"] == "hop"]
    assert k["matched_path_ids"] == "s05_t00-p0004" and float(k["matched_jaccards"].split("=")[1]) >= 0.5
    assert k["key_hop_ids"].count(";") == 1                                   # two key hops (s05-h1, s05-h2), one stitch path


def test_s07_two_key_attack_paths_share_the_top_tie_group_so_the_trial_is_rank_one(dev):
    rows = read_csv(dev / "out" / "evaluate" / "s07_t00" / "rank.csv")
    (r,) = [x for x in rows if x["row_kind"] == "trial" and x["variant"] == "full" and x["match_reading"] == "hop"]
    assert (r["tie_size"], r["matches_in_tie"], r["candidate_count"]) == ("2", "2", "2")
    assert r["rank_expected"] == "1.000000" and r["top1_expected"] == "1.000000" and r["rank_pessimistic"] == "1"
    for k in [x for x in rows if x["row_kind"] == "key_path" and x["variant"] == "full" and x["match_reading"] == "hop"]:
        assert k["rank_expected"] == "1.500000" and k["top1_expected"] == "0.500000"       # each alone: 2-way tie


def test_s06_check_is_held_for_full_only(dev):
    t = totals(dev)
    assert (t[("full", "hop")]["s06_held"], t[("b1", "hop")]["s06_held"], t[("b2", "hop")]["s06_held"]) == ("1", "0", "0")
    f, b1, b2 = (float(t[(v, "hop")]["s06_margin"]) for v in ("full", "b1", "b2"))
    assert f == pytest.approx(0.306, abs=1e-3) and b1 == pytest.approx(-0.042, abs=1e-3) and b2 == pytest.approx(-0.333, abs=1e-3)
    assert t[("full", "hop")]["s06_trials"] == "1" and float(t[("full", "hop")]["s06_max_score"]) == pytest.approx(0.277778, abs=1e-6)
    assert t[("full", "hop")]["share_attack_trials_above_s06"] == "1.000000"


def test_s06_and_unkeyed_trials_have_distribution_rows_only(dev):
    for t in ("s06_t00", "s02_t01", "s03_t01", "s06_t01"):
        rows = read_csv(dev / "out" / "evaluate" / t / "rank.csv")
        assert {r["row_kind"] for r in rows} == {"distribution"}, t


def test_b0_at_equal_budget_is_below_full_in_every_attack_trial_on_development(dev):
    b0 = next(r for r in read_csv(dev / "out" / "evaluate" / "development" / "rank_totals.csv") if r["row_kind"] == "b0_recall")
    assert float(b0["full_recall_mean"]) == pytest.approx(0.877, abs=1e-3) and float(b0["b0_recall_mean"]) == pytest.approx(0.261, abs=1e-3)
    assert b0["attack_trials"] == "5"
    rows = [r for t in KEYED_ATTACK for r in read_csv(dev / "out" / "evaluate" / t / "rank.csv") if r["row_kind"] == "b0_recall"]
    assert len(rows) == 5 and all(float(r["budget_nodes"]) > 0 for r in rows)
    for r in rows:
        assert 0.0 <= float(r["b0_recall"]) <= 1.0 and 0.0 <= float(r["full_recall"]) <= 1.0, r["trial_id"]


def test_sweep_default_point_equals_written_scores_and_every_point_is_stable_with_402_points(dev):
    rows = read_csv(dev / "out" / "evaluate" / "development" / "rank_sweep.csv")
    assert len(rows) == 403
    d = rows[0]
    assert d["point_kind"] == "default" and d["lambda"] == "1.442695" and d["top1_expected"] == "0.900000" and d["mrr_expected"] == "0.933333"
    assert d["s06_held"] == "1" and d["same_ranks_as_default"] == "1"
    assert all(r["same_ranks_as_default"] == "1" and r["n_key_paths_changed"] == "0" for r in rows), "decision 068: all 402 stable"
    held = {}
    for r in rows[1:]:
        if r["point_kind"] == "grid":
            held[r["lambda_label"]] = held.get(r["lambda_label"], 0) + int(r["s06_held"] == "1")
    assert set(held) == {"0.5", "1", "1/ln2", "2", "3", "5"} and all(44 <= n <= 48 for n in held.values()), held
    assert not (REPO / "out" / "evaluate" / "development" / "rank_sweep.csv.tmp").exists()


def test_the_real_run_is_byte_identical_twice(dev, tmp_path):
    again = mini_repo(tmp_path / "again", DEV)
    assert em.main(["--rank-sweep", "--development", "--repo", str(again)]) == 0
    for rel in ["development/rank.md", "development/rank_totals.csv", "development/rank_sweep.csv"] + [f"{t}/rank.csv" for t in DEV]:
        assert (dev / "out" / "evaluate" / rel).read_bytes() == (again / "out" / "evaluate" / rel).read_bytes(), rel


def test_sweep_leaves_score_parameters_and_the_real_score_folder_unchanged(tmp_path):
    need_inputs(DEV)
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((REPO / "src" / "score").rglob("*.py"))}
    before |= {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((REPO / "out" / "score").rglob("*")) if p.is_file()}
    root = mini_repo(tmp_path / "m", DEV)
    assert em.main(["--rank-sweep", "--development", "--repo", str(root)]) == 0
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before}
    assert after == before


# ================================================================================================ refusals on real data
@pytest.mark.parametrize("trial", ["s02_t05", "s04_t10", "s01_t00", "s07_t03"])
def test_test_trials_are_refused_with_exit_2_and_nothing_is_written_real_repo(tmp_path, capsys, trial):
    out = tmp_path / "o"
    assert em.main(["--rank", "--trial", trial, "--out", str(out)]) == 2
    assert capsys.readouterr().err.startswith("refused:") and not out.exists()
    assert not (REPO / "out" / "evaluate" / trial).exists()


def test_rank_sweep_with_a_trial_and_development_with_out_are_refused_real_repo(tmp_path, capsys):
    assert em.main(["--rank-sweep", "--trial", "s04_t00", "--out", str(tmp_path / "o")]) == 2
    assert em.main(["--rank", "--development", "--out", str(tmp_path / "o")]) == 2
    assert not (tmp_path / "o").exists()
    assert capsys.readouterr().err.count("refused:") == 2


def test_out_over_the_real_src_folder_is_refused_on_a_copy(tmp_path, capsys):
    root = mini_repo(tmp_path / "m", ["s04_t00"])
    (root / "src").mkdir()
    (root / "src" / "keep.py").write_text("x = 1\n", encoding="utf-8")
    assert em.main(["--rank", "--trial", "s04_t00", "--repo", str(root), "--out", str(root / "src")]) == 2
    assert (root / "src" / "keep.py").read_text(encoding="utf-8") == "x = 1\n"
    assert capsys.readouterr().err.startswith("refused:")


# ================================================================================================ committed equals fresh (read-only)
def test_existing_out_evaluate_rank_files_equal_a_fresh_run_if_present(dev):
    base = REPO / "out" / "evaluate"
    names = [f"{t}/rank.csv" for t in DEV] + ["development/rank.md", "development/rank_totals.csv", "development/rank_sweep.csv"]
    present = [n for n in names if (base / n).is_file()]
    if not present:
        pytest.skip("no out/evaluate rank files present")
    stale = [n for n in present if (base / n).read_bytes() != (dev / "out" / "evaluate" / n).read_bytes()]
    assert not stale, f"out/evaluate differs from a fresh run in {stale}; rerun python -m evaluate --rank-sweep --development"
    assert len(present) == len(names), f"partial rank output: missing {sorted(set(names) - set(present))}"


# ================================================================================================ ATK-SC-18 (decision 069 item 6)
def _one(tmp_path, trial="s04_t00"):
    return mini_repo(tmp_path / "m", [trial])


def _rank_one(root, tmp_path, trial="s04_t00"):
    return em.main(["--rank", "--trial", trial, "--repo", str(root), "--out", str(tmp_path / "o")])


def test_atk_sc18_rank_refuses_when_a_label_file_changed_after_the_score_run(tmp_path, capsys):
    """Real score run_info: inputs.label hashes vs the current out/label files (copy)."""
    root = _one(tmp_path)
    p = root / "out" / "label" / "s04_t00" / "node_labels.csv"
    p.write_bytes(p.read_bytes() + b"\n")
    assert _rank_one(root, tmp_path) == 2
    assert capsys.readouterr().err.startswith("refused:") and not (tmp_path / "o").exists()


def test_atk_sc18_rank_refuses_when_the_score_run_used_another_order_table(tmp_path, capsys):
    root = _one(tmp_path)
    p = root / "out" / "score" / "s04_t00" / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    info["order_table_sha256"] = "0" * 64
    p.write_text(json.dumps(info, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert _rank_one(root, tmp_path) == 2
    assert capsys.readouterr().err.startswith("refused:") and not (tmp_path / "o").exists()


def test_atk_sc18_rank_refuses_when_the_score_run_used_other_than_the_frozen_parameters(tmp_path, capsys):
    root = _one(tmp_path)
    p = root / "out" / "score" / "s04_t00" / "run_info.json"
    info = json.loads(p.read_text(encoding="utf-8"))
    info["parameters"].update(w1=0.5, w2=0.25, w3=0.25)
    p.write_text(json.dumps(info, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    assert _rank_one(root, tmp_path) == 2
    assert capsys.readouterr().err.startswith("refused:") and not (tmp_path / "o").exists()


# ================================================================================================ decision 069 item 6, 8, 9 on real data
def test_the_real_score_run_info_passes_every_pin_unmodified(tmp_path):
    root = _one(tmp_path)
    assert _rank_one(root, tmp_path) == 0 and (tmp_path / "o" / "rank.csv").is_file()


@pytest.mark.parametrize("trial", ["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00"])
def test_atk_sc25_a_keyed_development_trial_without_its_approved_key_is_refused_on_a_copy(tmp_path, capsys, trial):
    root = mini_repo(tmp_path / "m", [trial])
    (root / "ground_truth" / "approved" / f"{trial}.yaml").unlink()
    assert em.main(["--rank", "--trial", trial, "--repo", str(root), "--out", str(tmp_path / "o")]) == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and trial in err and not (tmp_path / "o").exists()


@pytest.mark.parametrize("trial", ["s02_t01", "s03_t01", "s06_t01"])
def test_the_unkeyed_development_trials_still_run_without_a_key(tmp_path, trial):
    root = mini_repo(tmp_path / "m", [trial])
    assert not (root / "ground_truth" / "approved" / f"{trial}.yaml").exists()
    assert em.main(["--rank", "--trial", trial, "--repo", str(root), "--out", str(tmp_path / "o")]) == 0


def test_per_key_mrr_and_e_one_over_rank_are_reported_beside_the_primary_numbers_on_development(dev):
    """Decision 069 item 9: primary (trial MRR 0.933333) unchanged; per-key MRR counts the s04 / s07 half-ties per key path."""
    t = totals(dev)
    for key in (("full", "hop"), ("full", "node"), ("b1", "hop"), ("b2", "node")):
        r = t[key]
        assert r["mrr_expected"] == "0.933333"                                           # primary, unchanged
        assert r["mrr_per_key_expected"] == "0.833333" and r["mrr_per_key_rr_mean"] == "0.875000"
        assert r["mrr_rr_mean_expected"] == "0.950000"
        assert float(r["mrr_rr_mean_expected"]) >= float(r["mrr_expected"])               # E[1/rank] >= 1/E[rank]
        assert float(r["chance_rr_mean"]) >= float(r["chance_mrr"])


def test_chance_line_over_candidates_with_score_above_zero_is_reported_and_equals_the_observed_values_on_development(dev):
    """ATK-SC-21: restricted to candidates with score > 0 the chance line is as high as the observed top-1 / MRR (the
    zero-score paths are what the ranking separates). This is the reading the report must show beside 0.248 / 0.377."""
    r = totals(dev)[("full", "hop")]
    assert float(r["chance_top1"]) == pytest.approx(0.248, abs=5e-4)                      # the primary line is unchanged
    assert (r["chance_pos_top1"], r["chance_pos_mrr"], r["chance_pos_rr_mean"]) == ("0.900000", "0.933333", "0.950000")
    assert r["top1_expected"] == r["chance_pos_top1"] and r["mrr_expected"] == r["chance_pos_mrr"]


def test_h4_recall_is_reported_on_both_bases_and_full_is_above_b0_on_both_for_every_attack_trial(dev):
    b0 = next(r for r in read_csv(dev / "out" / "evaluate" / "development" / "rank_totals.csv") if r["row_kind"] == "b0_recall")
    assert b0["recall_basis"] == "all context-0 nodes (065 reading)" and b0["recall_basis_labelled"] == "labelled nodes only (b0-reachable)"
    assert float(b0["full_recall_mean"]) == pytest.approx(0.877, abs=1e-3) and float(b0["b0_recall_mean"]) == pytest.approx(0.261, abs=1e-3)
    assert float(b0["full_recall_labelled_mean"]) == pytest.approx(0.214, abs=1e-3)
    assert float(b0["b0_recall_labelled_mean"]) == pytest.approx(0.121, abs=1e-3)
    assert b0["trials_full_above_b0"] == "5" and b0["trials_full_above_b0_labelled"] == "5"


def test_the_sweep_is_stated_as_not_informative_on_development_data(dev):
    md = (dev / "out" / "evaluate" / "development" / "rank.md").read_text(encoding="utf-8")
    assert "not informative on development data" in md and "ATK-SC-22" in md
    assert "in 4 of 5 attack trials every rival path scores 0" in md and "s04 ties at every weight" in md
