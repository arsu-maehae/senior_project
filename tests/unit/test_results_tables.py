"""T10.A part C: `python -m evaluate --results --development` (spec 06_evaluate RS-01..RS-11, section 6 edge cases ATK-EV-02,
-04, -12, -13; decisions 019, 065, 070, 071, 072).

Written from the spec and decisions, not from the code. Two ways in: the CLI `evaluate.__main__.main` on a fake
development repo (pytest tmp folder, all nine trials), and `results_report.results_files` on synthetic `TrialRank`s for the
threshold-boundary cases. Test ids: RST-01 refusals, RST-02 stale rank files, RST-03 verdicts at 12 decimals, RST-04
H3 / H4 strictness, RST-05 H5, RST-06 table contents, RST-07 determinism, RST-08 labels, wording and pins. Only development
trial ids (and the synthetic non-development id s99_t00 for refusals) are used.

The 12-decimal boundary cases need a value like 0.849999 that no hand-built ranking produces, so they replace the expected
rank of the key path in an assembled `TrialRank` (`dataclasses.replace`); everything else is assembled from a world.
"""
from __future__ import annotations

import csv
import dataclasses
import io
import math
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import rank_fixtures as rf  # noqa: E402
import results_fixtures as R  # noqa: E402
from evaluate import __main__ as em  # noqa: E402
from evaluate import params as ep  # noqa: E402
from evaluate import results_report as rrep  # noqa: E402
from evaluate.params import DEVELOPMENT_TRIALS  # noqa: E402
from evaluate.results_report import results_files  # noqa: E402

NOTE = "DEVELOPMENT — not a result"
HEADER = "# DEVELOPMENT — not a result (decision 019)"
NO_CHANCE = ("n/a",)


def cli(repo: Path, *args: str) -> int:
    return em.main([*args, "--repo", str(repo)])


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


def read_csv_text(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def rows_of(trials) -> list[dict[str, str]]:
    return read_csv_text(results_files(trials, "development")["results.csv"])


def primary(rows, table):
    (r,) = [x for x in rows if x["table"] == table and x["is_primary"] == "1" and x["reading_scope"] == "all"]
    return r


def fresh_repo(tmp_path: Path, name: str = "r", ranked: bool = True, *worlds) -> Path:
    root = tmp_path / name
    R.write_repo_with(root, *worlds)
    if ranked:
        assert cli(root, "--rank", "--development") == 0
    return root


@pytest.fixture(scope="module")
def ranked(tmp_path_factory):
    """A fake repo after `--rank --development` and `--results --development` (read-only afterwards)."""
    root = tmp_path_factory.mktemp("results_dev")
    rf.development_repo(root)
    assert cli(root, "--rank", "--development") == 0
    assert cli(root, "--results", "--development") == 0
    return root


# ---------------------------------------------------------------- injected placements (12-decimal boundary cases)
def set_key_rr(tr, variant: str, rrs: list[float]):
    """`tr` with the node-reading key paths of `variant` placed at expected rank 1 / rr (one rr per key path, in order)."""
    out = []
    for r in tr.readings:
        if r.variant == variant and r.reading == "node":
            assert len(r.key_paths) == len(rrs)
            kps = tuple(dataclasses.replace(k, placement=dataclasses.replace(k.placement, rank_expected=1.0 / x))
                        for k, x in zip(r.key_paths, rrs))
            r = dataclasses.replace(r, key_paths=kps)
        out.append(r)
    return dataclasses.replace(tr, readings=tuple(out))


def set_trial_top1(tr, variant: str, value: float):
    out = []
    for r in tr.readings:
        if r.variant == variant and r.reading == "node":
            r = dataclasses.replace(r, trial=dataclasses.replace(r.trial, top1_expected=value))
        out.append(r)
    return dataclasses.replace(tr, readings=tuple(out))


# ================================================================================================ RST-01 refusals (RS-01, RS-11)
def snap(root: Path):
    return rf.snapshot(root.parent)


@pytest.mark.parametrize("extra", [["--rank"], ["--rank-sweep"], ["--label-recall"], ["--stitch-dir", "X"], ["--out", "X"]])
def test_rst01_results_combined_with_another_evaluation_or_a_folder_option_is_refused_and_writes_nothing(
        tmp_path, capsys, extra):
    root = fresh_repo(tmp_path)
    extra = [str(tmp_path / "x") if a == "X" else a for a in extra]
    before = snap(root)
    assert cli(root, "--results", "--development", *extra) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert snap(root) == before
    assert not (summary(root) / "results.md").exists() and not (tmp_path / "x").exists()


@pytest.mark.parametrize("trial", ["s02_t00", "s04_t00", "s06_t01", "s99_t00"])
def test_rst01_results_with_a_trial_is_refused_for_development_and_non_development_ids_alike(tmp_path, capsys, trial):
    """RS-01: `--results --trial <t>` is refused with the T5.7 key-lock message (a non-development id never reaches a
    file: the repo here is empty)."""
    root = tmp_path / "empty"
    root.mkdir()
    assert cli(root, "--results", "--trial", trial) == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "T5.7" in err and "10.4" in err
    assert not (root / "out").exists() and list(root.iterdir()) == []


def test_rst01_results_with_trial_and_options_is_refused_before_any_file_is_read(tmp_path, capsys):
    root = tmp_path / "empty"
    root.mkdir()
    for extra in (["--rank"], ["--rank-sweep"], ["--label-recall"], ["--out", str(tmp_path / "o")],
                  ["--stitch-dir", str(tmp_path / "s")]):
        assert cli(root, "--results", "--trial", "s99_t00", *extra) == 2, extra
        assert capsys.readouterr().err.startswith("refused:")
    assert not (tmp_path / "o").exists() and not (root / "out").exists()


def test_rst01_the_pure_generator_refuses_a_non_development_split():
    tr = R.assemble(R.solo_world("s02_t00"))
    with pytest.raises(Exception) as exc:
        results_files([tr], "test")
    assert "refused" in str(exc.value) and "5.7" in str(exc.value)


# ================================================================================================ the happy path
def test_results_development_writes_exactly_results_md_and_results_csv_next_to_the_rank_files(ranked):
    names = sorted(p.name for p in summary(ranked).iterdir())
    assert names == ["rank.md", "rank_totals.csv", "results.csv", "results.md"]
    assert not any(p.name.startswith("run_") for p in summary(ranked).iterdir())          # no timing file, no run_info


def test_results_keep_lists_work_both_ways_rank_and_sweep_reruns_keep_results_and_results_keeps_rank_files(tmp_path):
    root = fresh_repo(tmp_path)
    assert cli(root, "--results", "--development") == 0
    before = {n: (summary(root) / n).read_bytes() for n in ("rank.md", "rank_totals.csv", "results.md", "results.csv")}
    assert cli(root, "--results", "--development") == 0                     # a rerun over its own output
    assert {n: (summary(root) / n).read_bytes() for n in before} == before  # keeps rank.md, rank_totals.csv
    assert cli(root, "--rank", "--development") == 0
    assert (summary(root) / "results.md").read_bytes() == before["results.md"]
    assert cli(root, "--rank-sweep", "--development") == 0
    assert {p.name for p in summary(root).iterdir()} == {"rank.md", "rank_totals.csv", "rank_sweep.csv", "results.md",
                                                          "results.csv"}
    assert (summary(root) / "results.csv").read_bytes() == before["results.csv"]
    assert cli(root, "--results", "--development") == 0                     # still fresh: results keep rank_sweep.csv
    assert (summary(root) / "rank_sweep.csv").is_file()


def test_results_run_reads_only_and_writes_nothing_outside_the_summary_folder(tmp_path):
    root = fresh_repo(tmp_path)
    before = rf.snapshot(root)
    assert cli(root, "--results", "--development") == 0
    after = rf.snapshot(root)
    changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    assert changed == {"out/evaluate/development/results.md", "out/evaluate/development/results.csv"}


# ================================================================================================ RST-02 stale rank files
def test_rst02_results_without_the_rank_files_is_refused_stale_with_the_rerun_hint(tmp_path, capsys):
    root = fresh_repo(tmp_path, ranked=False)
    before = rf.snapshot(root)
    assert cli(root, "--results", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "stale" in err and "--rank" in err
    assert rf.snapshot(root) == before


@pytest.mark.parametrize("victim", ["out/evaluate/s04_t00/rank.csv", "out/evaluate/development/rank_totals.csv",
                                    "out/evaluate/s06_t00/rank.csv"])
def test_rst02_a_rank_file_that_differs_from_the_recomputed_ranking_is_refused_stale_and_nothing_is_written(
        tmp_path, capsys, victim):
    root = fresh_repo(tmp_path)
    p = root / victim
    p.write_bytes(p.read_bytes() + b"\n")                                   # one byte: freshness is byte for byte
    before = rf.snapshot(root)
    assert cli(root, "--results", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "stale" in err
    assert rf.snapshot(root) == before and not (summary(root) / "results.md").exists()


def test_rst02_a_stale_rank_file_after_a_score_rerun_is_refused(tmp_path, capsys):
    """The score output changes (the key path scores 0 now), the committed rank files describe the old scores."""
    root = fresh_repo(tmp_path)
    R.rival_only_world("s04_t00").write(root)                                # score + stitch rewritten for s04_t00
    assert cli(root, "--results", "--development") == 2
    assert "stale" in capsys.readouterr().err


def test_rst02_every_rank_refusal_applies_to_results_too(tmp_path, capsys):
    root = fresh_repo(tmp_path)
    (root / "ground_truth" / "approved" / "s04_t00.yaml").unlink()          # ATK-SC-25: keyed trial without its key
    assert cli(root, "--results", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "s04_t00" in err
    root2 = fresh_repo(tmp_path, "r2")
    p = root2 / "out" / "score" / "s04_t00" / "ranked_paths.csv"
    p.write_bytes(p.read_bytes() + b"\n")                                   # a score file changed after its run_info
    assert cli(root2, "--results", "--development") == 2
    assert capsys.readouterr().err.startswith("refused:")
    root3 = fresh_repo(tmp_path, "r3")
    w = rf.tie_world("s04_t00")
    w.lam, w.w = 2.0, (0.5, 0.25, 0.25)                                     # not the frozen parameters
    w.write(root3)
    assert cli(root3, "--results", "--development") == 2
    assert "frozen" in capsys.readouterr().err


# ================================================================================================ RST-03 verdicts at 12 decimals
def solo(trial="s02_t00"):
    return R.assemble(R.solo_world(trial))


def test_rst03_h1_top1_exactly_point_eight_from_thirds_is_held():
    """Five trials with expected top-1 1, 1, 1, 2/3, 1/3 (tie groups of 3 with 2 and 1 key matches): mean 0.8 exactly at
    12 decimals -> held (>= 0.80)."""
    shapes = [(1, 1), (1, 1), (1, 1), (3, 2), (3, 1)]
    trials = [R.assemble(R.tie_group_world(t, a, b))
              for t, (a, b) in zip(["s02_t00", "s03_t00", "s04_t00", "s05_t00", "s07_t00"], shapes)]
    h1 = primary(rows_of(trials), "H1")
    assert h1["observed"] == "0.800000" and h1["observed_12"] == "0.800000000000"
    assert h1["threshold"] == "0.80" and h1["comparator"] == ">=" and h1["dev_check"] == "held"


@pytest.mark.parametrize("value,held", [(0.8, True), (0.8 - 3e-13, True), (0.8 - 1e-12, False), (0.799999, False),
                                         (0.8 + 1e-9, True)])
def test_rst03_h1_boundary_at_twelve_decimals(value, held):
    tr = set_trial_top1(solo(), "full", value)
    h1 = primary(rows_of([tr]), "H1")
    assert h1["dev_check"] == ("held" if held else "not held"), (value, h1["observed_12"])


@pytest.mark.parametrize("value,held", [(0.85, True), (0.8500000000004, True), (0.8499999999996, True),
                                         (0.849999999999, False), (0.849999, False), (0.8500001, True)])
def test_rst03_h2_per_key_mrr_boundary_at_twelve_decimals(value, held):
    """0.849999 is not held; 0.85 is held; a value that rounds to 0.85 at 12 decimals is held (RS-09)."""
    tr = set_key_rr(solo(), "full", [value])
    h2 = primary(rows_of([tr]), "H2")
    assert h2["threshold"] == "0.85" and h2["comparator"] == ">="
    assert h2["dev_check"] == ("held" if held else "not held"), (value, h2["observed_12"])


def two_key_trial_with_rr(full_rrs, b1_rrs):
    tr = R.assemble(R.two_key_world("s07_t00"))
    return set_key_rr(set_key_rr(tr, "full", full_rrs), "b1", b1_rrs)


def test_rst03_equal_per_key_mrr_from_different_sums_is_not_held_for_h3():
    """full [0.1, 0.2] and b1 [0.15, 0.15] are both 0.15 at 12 decimals; in floating point the two means differ by 2.8e-17
    (full above b1), so a plain `>` would call H3 held. RS-09: equal at 12 decimals = not held."""
    full, b1 = [0.1, 0.2], [0.15, 0.15]
    naive_full, naive_b1 = math.fsum(1 / (1 / x) for x in full) / 2, math.fsum(1 / (1 / x) for x in b1) / 2
    assert naive_full > naive_b1 and round(naive_full, 12) == round(naive_b1, 12)           # the precondition of the test
    h3 = primary(rows_of([two_key_trial_with_rr(full, b1)]), "H3")
    assert h3["dev_check"] == "not held" and h3["observed"] == "0.000000" and h3["comparator"] == ">"


@pytest.mark.parametrize("full,b1,held", [([0.7 + 1e-9], [0.7], True), ([0.7 + 4e-13], [0.7], False),
                                          ([0.7], [0.7], False), ([0.7], [0.7 + 1e-9], False)])
def test_rst03_h3_is_strict_at_twelve_decimals(full, b1, held):
    tr = R.assemble(R.solo_world("s02_t00"))
    tr = set_key_rr(set_key_rr(tr, "full", full), "b1", b1)
    h3 = primary(rows_of([tr]), "H3")
    assert h3["dev_check"] == ("held" if held else "not held"), (full, b1, h3["observed_12"])


def test_rst03_observed_12_is_the_compared_value_beside_the_six_decimal_observed():
    tr = set_key_rr(solo(), "full", [0.8500000000004])
    h2 = primary(rows_of([tr]), "H2")
    assert h2["observed"] == "0.850000" and re.fullmatch(r"\d\.\d{12}", h2["observed_12"])
    assert h2["observed_12"] == "0.850000000000"


# ================================================================================================ RST-04 H3 / H4 strictness
def test_rst04_h3_held_when_identity_lifts_the_key_path_above_the_rival_and_top1_is_beside():
    tr = R.assemble(R.identity_world("s02_t00"))
    rows = rows_of([tr])
    h3 = primary(rows, "H3")
    assert h3["dev_check"] == "held" and h3["observed"] == "0.500000"       # difference 1.0 - 0.5
    assert primary(rows, "H1")["dev_check"] == "held" and primary(rows, "H2")["dev_check"] == "held"
    beside = [r for r in rows if r["table"] == "H3" and r["metric"] == "top1_expected" and r["reading_scope"] == "all"]
    assert {r["variant"]: r["observed"] for r in beside} == {"full": "1.000000", "b1": "0.000000"}
    assert all(r["dev_check"] == "" for r in beside)


def test_rst04_h3_not_held_when_full_and_b1_rank_identically():
    tr = R.assemble(rf.tie_world("s04_t00"))
    h3 = primary(rows_of([tr]), "H3")
    assert h3["dev_check"] == "not held" and h3["observed"] == "0.000000"


def test_rst04_h4_strict_full_above_b0_held_equal_not_held():
    good = R.assemble(R.labelled_world("s02_t00"))                         # full 1.0 vs b0 0.5
    h4 = primary(rows_of([good]), "H4")
    assert h4["dev_check"] == "held" and h4["observed"] == "0.500000" and h4["comparator"] == ">"
    w = R.labelled_world("s02_t00")
    w.b0 = [("u1", 4, ["a1"]), ("u2", 4, ["a2"])]                            # b0 takes both labelled nodes: 1.0 = 1.0
    equal = R.assemble(w)
    h4 = primary(rows_of([equal]), "H4")
    assert h4["dev_check"] == "not held" and h4["observed"] == "0.000000"


def test_rst04_h4_leaves_out_a_trial_without_labelled_key_nodes_and_states_the_count():
    good = R.assemble(R.labelled_world("s02_t00"))
    none = R.assemble(R.labelled_world("s03_t00", labelled=False))
    rows = rows_of([good, none])
    h4 = primary(rows, "H4")
    assert h4["observed"] == "0.500000" and h4["dev_check"] == "held" and "1 of 2" in h4["note"]
    (n,) = [r for r in rows if r["table"] == "H4" and r["metric"] == "labelled_recall_trials" and r["reading_scope"] == "all"]
    assert n["observed"] == "1"
    beside = {(r["variant"], r["metric"]): r["observed"] for r in rows if r["table"] == "H4" and r["reading_scope"] == "all"}
    assert beside[("full", "full_recall_labelled_mean")] == "1.000000"           # not 0.5: the undefined trial is not a 0
    assert beside[("full", "full_recall_mean")] == "1.000000" and beside[("b0", "b0_recall_mean")] == "0.250000"


# ================================================================================================ RST-05 H5
def attack_tie():
    return R.assemble(rf.tie_world("s04_t00"))                              # lowest key attack score 0.666667


def test_rst05_h5_held_when_the_lowest_key_attack_score_is_above_every_keyed_s06_score():
    rows = rows_of([attack_tie(), R.benign_trial("s06_t00")])               # benign max 0.25 -> margin 0.416667
    h5 = primary(rows, "H5")
    assert h5["metric"] == "s06_margin_min" and h5["dev_check"] == "held" and h5["observed"] == "0.416667"
    assert h5["threshold"] == "0.00" and h5["comparator"] == ">"
    assert h5["chance_all"].startswith("n/a") and h5["chance_pos"].startswith("n/a")


def test_rst05_h5_not_held_when_a_benign_path_scores_above_and_when_the_margin_is_exactly_zero():
    higher = R.benign_trial("s06_t00", node=1.0, seq_len=2, edge=1.0, ident=1.0)
    h5 = primary(rows_of([attack_tie(), higher]), "H5")
    assert h5["dev_check"] == "not held" and float(h5["observed"]) < 0
    equal = R.benign_trial("s06_t00", node=0.25, seq_len=2, edge=1.0, ident=1.0)       # same components as the key path
    h5 = primary(rows_of([attack_tie(), equal]), "H5")
    assert h5["observed"] == "0.000000" and h5["dev_check"] == "not held"


def test_rst05_unkeyed_s06_trial_is_reported_beside_with_the_margin_it_would_give_and_never_decides():
    unkeyed = R.unkeyed_s06("s06_t01", node=1.0, seq_len=2, edge=1.0, ident=1.0)       # full 0.916667 > key 0.666667
    rows = rows_of([attack_tie(), R.benign_trial("s06_t00"), unkeyed])
    h5 = primary(rows, "H5")
    assert h5["dev_check"] == "held" and h5["observed"] == "0.416667"                  # the unkeyed trial did not decide
    beside = [r for r in rows if r["table"] == "H5" and "s06_t01" in r["note"]]
    assert {r["metric"] for r in beside} == {"s06_max_score", "s06_margin"} and all(r["dev_check"] == "" for r in beside)
    margin = next(r for r in beside if r["metric"] == "s06_margin")
    assert margin["observed"] == "-0.250000" and "unkeyed" in margin["note"]
    keyed = [r for r in rows if r["table"] == "H5" and r["metric"] == "s06_margin" and "unkeyed" not in r["note"]]
    assert [r["observed"] for r in keyed] == ["0.416667"]


def test_rst05_h5_unmatched_key_attack_path_is_not_held_with_a_reason_never_computed_over_the_rest():
    """ATK-EV-04: one attack trial's key path has no matching candidate (node reading), the other attack trial would give a
    positive margin. H5 is not held with the reason written; the unkeyed S06 trial is still reported beside."""
    unmatched = R.assemble(R.hop_only_world("s02_t00"))
    rows = rows_of([unmatched, attack_tie(), R.benign_trial("s06_t00"), R.unkeyed_s06("s06_t01")])
    h5 = primary(rows, "H5")
    assert h5["dev_check"] == "not held" and h5["observed"] == ""
    assert "matching candidate" in h5["note"]
    low = next(r for r in rows if r["table"] == "H5" and r["metric"] == "key_attack_score_min")
    assert low["observed"] == ""                                                       # undefined, not the min of the rest
    assert [r for r in rows if r["table"] == "H5" and "s06_t01" in r["note"]]          # unkeyed S06 beside


def test_rst05_h5_without_any_keyed_s06_trial_is_not_held_with_a_reason():
    h5 = primary(rows_of([attack_tie()]), "H5")
    assert h5["dev_check"] == "not held" and h5["note"]


def test_rst05_h5_has_no_contested_reading_and_the_share_of_attack_trials_above_is_beside():
    rows = rows_of([attack_tie(), R.benign_trial("s06_t00")])
    h5 = [r for r in rows if r["table"] == "H5"]
    assert all(r["reading_scope"] == "all" for r in h5)
    share = next(r for r in h5 if r["metric"] == "share_attack_trials_above_s06")
    assert share["observed"] == "1.000000" and share["dev_check"] == ""


# ================================================================================================ RST-06 table contents
def test_rst06_every_ranking_table_row_shows_both_chance_lines_and_h4_h5_say_n_a(ranked):
    rows = read_csv(summary(ranked) / "results.csv")
    for r in rows:
        if r["table"] in ("H1", "H2", "baselines", "H3") and r["metric"] in (
                "top1_expected", "top1_optimistic", "top1_pessimistic", "mrr_expected", "mrr_per_key_expected"):
            assert r["chance_all"] and not r["chance_all"].startswith("n/a"), r
            assert r["chance_pos"] and not r["chance_pos"].startswith("n/a"), r
            assert 0.0 <= float(r["chance_all"]) <= 1.0 and 0.0 <= float(r["chance_pos"]) <= 1.0
        if r["table"] in ("H4", "H5") or r["metric"].endswith("recall_mean"):
            assert r["chance_all"].startswith("n/a") and r["chance_pos"].startswith("n/a"), r


def test_rst06_contested_reading_for_full_b1_b2_beside_h1_h2_h3_and_b0_beside_h4_never_a_verdict(ranked):
    rows = read_csv(summary(ranked) / "results.csv")
    cont = [r for r in rows if r["reading_scope"] == "contested"]
    assert cont and all(r["dev_check"] == "" and r["is_primary"] == "0" for r in cont)
    assert {r["variant"] for r in cont if r["table"] == "H1"} == {"full", "b1", "b2"}
    assert {r["variant"] for r in cont if r["table"] == "H2"} == {"full", "b1", "b2"}
    assert {"full", "b1"} <= {r["variant"] for r in cont if r["table"] == "H3"}
    assert {"full", "b0", "full_vs_b0"} <= {r["variant"] for r in cont if r["table"] == "H4"}
    assert not [r for r in cont if r["table"] == "H5"]                                   # Q2: none
    assert {"full", "b1", "b2", "b0"} == {r["variant"] for r in rows if r["table"] == "contested"}


def test_rst06_tables_hold_thresholds_comparators_and_exactly_five_primary_verdict_rows(ranked):
    rows = read_csv(summary(ranked) / "results.csv")
    verdict_rows = [r for r in rows if r["dev_check"] != ""]
    assert sorted(r["table"] for r in verdict_rows) == ["H1", "H2", "H3", "H4", "H5"]
    assert {r["table"]: (r["threshold"], r["comparator"]) for r in verdict_rows} == {
        "H1": ("0.80", ">="), "H2": ("0.85", ">="), "H3": ("0.00", ">"), "H4": ("0.00", ">"), "H5": ("0.00", ">")}
    assert {r["dev_check"] for r in verdict_rows} <= {"held", "not held"}
    assert all(r["is_primary"] == "1" for r in verdict_rows)
    for r in rows:
        if r["dev_check"] == "":
            assert r["threshold"] == "" and r["comparator"] == "", r                      # beside rows carry no threshold


def test_rst06_results_csv_columns_and_row_keys(ranked):
    with open(summary(ranked) / "results.csv", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        header = list(reader.fieldnames or [])
        rows = list(reader)
    for col in ("status_note", "split", "table", "hypothesis", "variant", "reading_scope", "metric", "is_primary",
                "observed", "observed_12", "threshold", "comparator", "chance_all", "chance_pos", "n_trials",
                "n_key_paths", "source"):
        assert col in header, col
    assert "dev_check" in header and "verdict" not in header                         # RS-10
    # the old tables keep their rows; spec 06 section 10 adds the three tables below (D-A reconstruction, D-B auc, D-D sensitivity)
    old_tables = {"H1", "H2", "H3", "H4", "H5", "baselines", "contested", "recall"}
    assert old_tables <= {r["table"] for r in rows}
    assert {r["table"] for r in rows} - old_tables <= {"reconstruction", "auc", "sensitivity"}
    assert {r["reading_scope"] for r in rows} == {"all", "contested"}
    assert {r["split"] for r in rows} == {"development"}
    # one row per (table, variant, reading_scope, metric): the paired and own contested rows of H3 / H4 share that key and
    # differ by `source` (spec 06 3.3 does not say how to tell them apart; the source column does)
    keys = [(r["table"], r["variant"], r["reading_scope"], r["metric"], r["source"]) for r in rows]
    assert len(keys) == len(set(keys))
    for r in rows:
        if r["observed"] and r["metric"] not in ("contested_trials", "labelled_recall_trials",
                                                  "trials_full_above_b0_labelled"):
            if r["table"] in ("auc", "sensitivity") and r["metric"] in ("auc_n_pos", "auc_n_neg", "sweep_points",
                                                                         "same_ranks_points"):
                assert re.fullmatch(r"\d+", r["observed"]), r             # counts of the section 10 tables are integers
            else:
                assert re.fullmatch(r"-?\d\.\d{6}", r["observed"]), r


def test_rst06_baselines_and_recall_tables_hold_all_variants_labelled_recall_primary_all_node_beside(ranked):
    rows = read_csv(summary(ranked) / "results.csv")
    base = [r for r in rows if r["table"] == "baselines"]
    assert {r["variant"] for r in base} == {"full", "b1", "b2", "b0"}
    rec = [r for r in rows if r["table"] == "recall"]
    prim = {(r["variant"], r["metric"]) for r in rec if r["is_primary"] == "1"}
    assert prim == {("full", "full_recall_labelled_mean"), ("b0", "b0_recall_labelled_mean")}
    assert {(r["variant"], r["metric"]) for r in rec if r["is_primary"] == "0"} == {
        ("full", "full_recall_mean"), ("b0", "b0_recall_mean")}


# ================================================================================================ RST-07 determinism
def test_rst07_two_runs_are_byte_identical_and_hold_no_timestamp_timing_or_path(tmp_path):
    a, b = fresh_repo(tmp_path, "a"), fresh_repo(tmp_path, "b")
    assert cli(a, "--results", "--development") == 0 and cli(b, "--results", "--development") == 0
    assert cli(a, "--results", "--development") == 0
    for n in ("results.md", "results.csv"):
        assert (summary(a) / n).read_bytes() == (summary(b) / n).read_bytes(), n
        text = (summary(a) / n).read_text(encoding="utf-8")
        assert not re.search(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}", text), n
        for word in ("generated_utc", "wall_ms", "tool_version", str(tmp_path), "AppData"):
            assert word not in text, (n, word)
    assert (summary(a) / "results.md").read_bytes().count(b"\r") == 0


def test_rst07_the_pure_generator_is_deterministic_and_does_not_mutate_its_input():
    trials = [attack_tie(), R.benign_trial("s06_t00"), R.unkeyed_s06("s06_t01")]
    assert results_files(trials, "development") == results_files(trials, "development")


def test_rst07_processing_time_is_only_referenced_never_copied(ranked):
    md = (summary(ranked) / "results.md").read_text(encoding="utf-8")
    assert "out/run_trial/development/run_log.md" in md
    assert not re.search(r"\bwall[_ ]ms\b|\bseconds\b|\bms\b", md.lower())


# ================================================================================================ RST-08 labels, wording, pins
def md_tables(md: str):
    lines = md.splitlines()
    out = []
    for i, ln in enumerate(lines[:-1]):
        if ln.startswith("| ") and lines[i + 1].startswith("|---"):
            j = i - 1
            while j >= 0 and not lines[j].startswith("## "):
                j -= 1
            out.append((j, "\n".join(lines[j:i]) if j >= 0 else ""))
    return out


def test_rst08_the_header_line_and_every_table_carry_the_development_label(ranked):
    md = (summary(ranked) / "results.md").read_text(encoding="utf-8")
    assert md.splitlines()[0] == HEADER
    tables = md_tables(md)
    assert len(tables) >= 8
    for heading_line, block in tables:
        assert heading_line >= 0, "a table without a '## ' heading"
        assert f"**{NOTE}.**" in block, block.splitlines()[0]
    assert md.count(f"**{NOTE}.**") >= len(tables)


def test_rst08_every_csv_row_carries_the_status_note_and_the_split(ranked):
    rows = read_csv(summary(ranked) / "results.csv")
    assert {r["status_note"] for r in rows} == {NOTE} and {r["split"] for r in rows} == {"development"}


def test_rst08_dev_check_column_name_in_csv_and_md(ranked):
    md = (summary(ranked) / "results.md").read_text(encoding="utf-8")
    assert "dev_check" in md
    assert not re.search(r"\|\s*verdict\s*\|", md)
    with open(summary(ranked) / "results.csv", newline="", encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert "dev_check" in header and "verdict" not in header


def test_rst08_forbidden_word_scan_over_results_files_returns_nothing(ranked):
    from score.report import forbidden_hits
    for n in ("results.md", "results.csv"):
        text = (summary(ranked) / n).read_text(encoding="utf-8")
        assert forbidden_hits(text) == [], n
    low = (summary(ranked) / "results.md").read_text(encoding="utf-8").lower()
    for bad in ("reduces false positives", "detects stolen", "identifies the attacker", "confidence %"):
        assert bad not in low
    stripped = low.replace("not a probability", " ")
    for word in ("stolen", "detects", "probability", "confidence"):
        assert word not in stripped, word


def test_rst08_wording_block_and_stated_limits_are_in_results_md(ranked):
    low = (summary(ranked) / "results.md").read_text(encoding="utf-8").lower()
    for needle in ("ranks", "expected, to be measured", "development check", "not a probability", "exposed",
                   "l-sc5", "repeatability, not generalisation", "decision 071"):
        assert needle in low, needle


def test_rst08_evaluates_copy_of_the_forbidden_word_list_equals_score_reports_list():
    from score import report as sr
    assert tuple(rrep.FORBIDDEN_WORDS) == tuple(sr.FORBIDDEN_WORDS)
    assert rrep.ALLOWED_PHRASE == sr.ALLOWED_PHRASE == "not a probability"
    for text in ("this detects stolen accounts", "It reduces false positives", "a PROBABILITY of attack",
                 "this identifies the attacker", "a confidence of 90"):
        assert rrep.forbidden_hits(text) and rrep.forbidden_hits(text) == sr.forbidden_hits(text), text
    assert rrep.forbidden_hits("The path score is for ordering; it is not a probability.") == []


def test_rst08_h_thresholds_are_pinned_to_decisions_065_and_070():
    """H1 0.80, H2 0.85 (065, unchanged by 070 item 3), H3 / H4 / H5 strict (> 0), verdict decimals 12 (RS-09)."""
    assert ep.H1_TOP1_MIN == 0.80 and ep.H2_MRR_PER_KEY_MIN == 0.85
    assert ep.H3_MIN_DIFFERENCE == 0.0 and ep.H4_MIN_DIFFERENCE == 0.0 and ep.H5_MIN_MARGIN == 0.0
    assert ep.VERDICT_DECIMALS == 12
    d065 = (REPO / "docs" / "decisions" / "065-score-baselines-and-success-criteria.md").read_text(encoding="utf-8")
    d070 = (REPO / "docs" / "decisions" / "070-score-freeze-amendment-readings.md").read_text(encoding="utf-8")
    assert "H1 top-1 rate (`full`) ≥ 0.80" in d065 and "H2 MRR (`full`) ≥ 0.85" in d065
    assert "H2 per-key MRR ≥ 0.85" in d070 and "H1 top-1 ≥ 0.80" in d070
    assert "Thresholds unchanged" in d070


def test_rst08_development_list_and_keyed_list_are_unchanged_by_this_spec():
    assert tuple(DEVELOPMENT_TRIALS) == ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00",
                                         "s02_t01", "s03_t01", "s06_t01")
    assert tuple(ep.KEYED_DEVELOPMENT_TRIALS) == ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00")


def test_rs05_h5_wording_is_orders_the_s06_benign_paths_below_the_attack_paths_by_score(ranked):
    md = (summary(ranked) / "results.md").read_text(encoding="utf-8")
    assert "orders the S06 benign paths below the attack paths by score" in md
    h5 = [r for r in read_csv(summary(ranked) / "results.csv") if r["table"] == "H5"]
    assert h5 and all("orders the S06 benign paths below the attack paths by score" in r["hypothesis"] for r in h5)
