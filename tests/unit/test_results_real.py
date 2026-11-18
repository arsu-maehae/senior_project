"""T10.A acceptance RSA-01 on the nine real development trials (spec 06_evaluate section 7.1; decisions 065, 070, 071, 072).
Slow; read-only on the real folders; DEVELOPMENT numbers, not results (decision 019).

Written from the spec and decisions, not from the code. `--rank --development` and then `--results --development` run through
the CLI on a **copy** of the inputs in a pytest tmp folder (the root conftest forbids any write under the real `out/`);
the expected `dev_check` values and numbers are those of spec 06 RSA-01. The committed `out/evaluate/development/results.*`
files, if present, must equal a fresh run (RS-07).

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_results_real.py
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
from test_rank_real import mini_repo  # noqa: E402  (helper only)

pytestmark = pytest.mark.slow

DEV = list(DEVELOPMENT_TRIALS)
NOTE = "DEVELOPMENT — not a result"


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


@pytest.fixture(scope="module")
def dev(tmp_path_factory):
    root = mini_repo(tmp_path_factory.mktemp("results_real"), DEV)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    assert em.main(["--results", "--development", "--repo", str(root)]) == 0
    return root


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


@pytest.fixture(scope="module")
def rows(dev):
    return read_csv(summary(dev) / "results.csv")


def primary(rows, table):
    (r,) = [x for x in rows if x["table"] == table and x["is_primary"] == "1" and x["reading_scope"] == "all"
            and x["dev_check"] != ""]
    return r


def test_rsa01_dev_check_h1_held_h2_not_held_h3_not_held_h4_held_h5_held(rows):
    got = {t: primary(rows, t)["dev_check"] for t in ("H1", "H2", "H3", "H4", "H5")}
    assert got == {"H1": "held", "H2": "not held", "H3": "not held", "H4": "held", "H5": "held"}


def test_rsa01_observed_values_and_thresholds(rows):
    h = {t: primary(rows, t) for t in ("H1", "H2", "H3", "H4", "H5")}
    assert (h["H1"]["observed"], h["H1"]["threshold"], h["H1"]["comparator"]) == ("0.900000", "0.80", ">=")
    assert (h["H2"]["observed"], h["H2"]["threshold"], h["H2"]["comparator"]) == ("0.833333", "0.85", ">=")
    assert h["H3"]["observed"] == "0.000000" and h["H3"]["comparator"] == ">"            # 0.833333 = 0.833333
    assert h["H4"]["observed_12"] != "" and float(h["H4"]["observed"]) == pytest.approx(0.830000 - 0.422857, abs=1e-6)
    assert (h["H5"]["observed"], h["H5"]["metric"]) == ("0.305556", "s06_margin_min")
    for t in ("H1", "H2", "H3", "H4", "H5"):
        assert h[t]["split"] == "development" and h[t]["status_note"] == NOTE


def test_rsa01_h4_sides_labelled_primary_all_node_beside(rows):
    side = {(r["variant"], r["metric"]): r["observed"] for r in rows if r["table"] == "H4" and r["reading_scope"] == "all"}
    assert side[("full", "full_recall_labelled_mean")] == "0.830000" and side[("b0", "b0_recall_labelled_mean")] == "0.422857"
    assert side[("full", "full_recall_mean")] == "0.877451" and side[("b0", "b0_recall_mean")] == "0.260609"


def test_rsa01_h2_h3_sides_chance_lines_and_per_trial_mrr_beside(rows):
    full = next(r for r in rows if r["table"] == "H2" and r["variant"] == "full" and r["metric"] == "mrr_expected")
    assert full["observed"] == "0.933333" and (full["chance_all"], full["chance_pos"]) == ("0.376825", "0.933333")
    h1 = primary(rows, "H1")
    assert (h1["chance_all"], h1["chance_pos"]) == ("0.248333", "0.900000")
    side = {r["variant"]: r["observed"] for r in rows if r["table"] == "H3" and r["metric"] == "mrr_per_key_expected"
            and r["reading_scope"] == "all"}
    assert side == {"full": "0.833333", "b1": "0.833333"}


def test_rsa01_h5_s06_t01_unkeyed_is_beside_with_margin_0_297619_and_does_not_decide(rows):
    beside = [r for r in rows if r["table"] == "H5" and "s06_t01" in r["note"]]
    assert {r["metric"] for r in beside} == {"s06_max_score", "s06_margin"}
    margin = next(r for r in beside if r["metric"] == "s06_margin")
    assert margin["observed"] == "0.297619" and margin["dev_check"] == "" and "unkeyed" in margin["note"]
    keyed = [r for r in rows if r["table"] == "H5" and r["metric"] == "s06_margin" and "s06_t00" in r["note"]]
    assert [r["observed"] for r in keyed] == ["0.305556"]
    assert next(r for r in rows if r["table"] == "H5" and r["metric"] == "share_attack_trials_above_s06")["observed"] == "1.000000"


def test_rsa01_contested_rows_carry_no_verdict_and_h5_has_none(rows):
    cont = [r for r in rows if r["reading_scope"] == "contested"]
    assert cont and all(r["dev_check"] == "" for r in cont)
    assert not [r for r in cont if r["table"] == "H5"]
    sets = {r["variant"]: r["note"] for r in rows if r["table"] == "contested"}
    assert sets["full"] == sets["b1"] == sets["b2"] == "s04_t00;s07_t00"
    assert sets["b0"] == "s02_t00;s03_t00;s04_t00;s05_t00;s07_t00"


def test_rsa01_results_md_labels_wording_and_no_forbidden_words(dev):
    from score.report import forbidden_hits
    md = (summary(dev) / "results.md").read_text(encoding="utf-8")
    assert md.splitlines()[0] == "# DEVELOPMENT — not a result (decision 019)"
    assert md.count(f"**{NOTE}.**") >= 8
    assert forbidden_hits(md) == [] and "dev_check" in md
    assert not re.search(r"\|\s*verdict\s*\|", md)


def test_rsa01_a_fresh_run_equals_the_committed_results_files_if_present(dev):
    base = REPO / "out" / "evaluate" / "development"
    present = [n for n in ("results.md", "results.csv") if (base / n).is_file()]
    if not present:
        pytest.skip("no committed results files present")
    stale = [n for n in present if (base / n).read_bytes() != (summary(dev) / n).read_bytes()]
    assert not stale, f"committed {stale} differ from a fresh run; rerun python -m evaluate --development --results"


def test_rsa01_results_refuse_when_a_copied_rank_file_is_stale(tmp_path, capsys):
    root = mini_repo(tmp_path / "m", DEV)
    assert em.main(["--rank", "--development", "--repo", str(root)]) == 0
    p = root / "out" / "evaluate" / "s04_t00" / "rank.csv"
    p.write_bytes(p.read_bytes() + b"\n")
    assert em.main(["--results", "--development", "--repo", str(root)]) == 2
    assert "stale" in capsys.readouterr().err and not (summary(root) / "results.md").exists()
