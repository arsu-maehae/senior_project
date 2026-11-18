"""T10.F review fixes, evaluate side (decision 075, ATK-EV-15, -16, -19, -20, -21, -22, -23; spec 06_evaluate RS-05, RS-09,
RS-10). Written from record 075 and the spec, not from the code.

Test ids: ATK-EV-15 S06 by scenario id (`s06_` prefix) and the key / scenario refusals; -16 one H5 function for
rank_totals.csv, rank.md and results; -19 `equals_chance_pos`; -20 H4 `undefined` and the coverage text; -21 the four
distinct H5 reasons; -22 `observed_12` in the results.md tables and trial counts at 12 decimals; -23 forbidden-word scan
over results.csv.

Synthetic worlds only (`rank_fixtures`, `results_fixtures`); development ids and the synthetic id s99_t00 only.
"""
from __future__ import annotations

import csv
import dataclasses
import io
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
from evaluate import rank_report as rrep  # noqa: E402
from evaluate import results_report as res  # noqa: E402
from evaluate.inputs import EvalError  # noqa: E402
from evaluate.rank_run import rank_from_inputs  # noqa: E402
from evaluate.results_report import results_files  # noqa: E402

NODE = "node"


# ---------------------------------------------------------------- helpers
def cli(repo: Path, *args: str) -> int:
    return em.main([*args, "--repo", str(repo)])


def summary(root: Path) -> Path:
    return root / "out" / "evaluate" / "development"


def csv_rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text, newline="")))


def rows_of(trials) -> list[dict[str, str]]:
    return csv_rows(results_files(trials, "development")["results.csv"])


def primary(rows, table):
    (r,) = [x for x in rows if x["table"] == table and x["is_primary"] == "1" and x["reading_scope"] == "all"]
    return r


def md_section(md: str, prefix: str) -> list[dict[str, str]]:
    """The first table under the '## <prefix>' heading as a list of {column: cell}."""
    lines = md.splitlines()
    start = next(i for i, ln in enumerate(lines) if re.match(rf"#{{2,3}} {re.escape(prefix)}", ln))
    j = start + 1
    while not lines[j].startswith("| "):
        j += 1
    header = [c.strip() for c in lines[j].strip().strip("|").split("|")]
    out = []
    k = j + 2
    while k < len(lines) and lines[k].startswith("| "):
        cells = [c.strip() for c in lines[k].strip().strip("|").split("|")]
        out.append(dict(zip(header, cells)))
        k += 1
    return out


def md_primary(md: str, table: str) -> dict[str, str]:
    (r,) = [x for x in md_section(md, f"{table} ") if x["is_primary"] == "1" and x["reading_scope"] == "all"]
    return r


def key_role_changed(world: rf.RankWorld, role: str) -> rf.RankWorld:
    world.key_paths = [rf.KP(k.path_id, role, list(k.hops)) for k in world.key_paths]
    return world


def attack_tie() -> object:
    return R.assemble(rf.tie_world("s04_t00"))


def fresh(tmp_path: Path, *worlds, name: str = "r", rank: bool = True) -> Path:
    root = tmp_path / name
    R.write_repo_with(root, *worlds)
    if rank:
        assert cli(root, "--rank", "--development") == 0
    return root


# ================================================================================================ ATK-EV-15
def test_atk_ev_15_s06_is_named_by_the_scenario_id_prefix() -> None:
    assert ep.S06_TRIAL_PREFIX == "s06_"
    for yes in ("s06_t00", "s06_t01"):
        assert ep.is_s06(yes)
    for no in ("s02_t00", "s04_t06", "xs06_t00", "S06_t00", "s060_t00", "s99_t00", ""):
        assert not ep.is_s06(no), no


def test_atk_ev_15_keyed_attack_trial_whose_key_role_is_a_typo_is_refused_pure() -> None:
    """A keyed s04-type trial whose key path role is 'atack' yields no key attack path: refused, never an S06 trial."""
    w = key_role_changed(rf.tie_world("s04_t00"), "atack")
    with pytest.raises(EvalError) as exc:
        R.assemble(w)
    msg = str(exc.value)
    assert msg.startswith("refused:") and "s04_t00" in msg


def test_atk_ev_15_the_same_typo_makes_the_cli_refuse_and_write_no_rank_file(tmp_path, capsys) -> None:
    root = tmp_path / "r"
    R.write_repo_with(root, key_role_changed(rf.tie_world("s04_t00"), "atack"))
    assert cli(root, "--rank", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "s04_t00" in err
    assert not (summary(root) / "rank_totals.csv").exists()
    assert cli(root, "--results", "--development") == 2
    assert not (summary(root) / "results.md").exists()


def test_atk_ev_15_keyed_s06_trial_with_a_key_attack_path_is_refused_pure() -> None:
    with pytest.raises(EvalError) as exc:
        R.assemble(R.solo_world("s06_t00"))             # s06 id, key names an attack path
    msg = str(exc.value)
    assert msg.startswith("refused:") and "s06_t00" in msg


def test_atk_ev_15_keyed_s06_trial_with_a_key_attack_path_makes_the_cli_refuse(tmp_path, capsys) -> None:
    root = tmp_path / "r"
    R.write_repo_with(root, R.solo_world("s06_t00"))
    assert cli(root, "--rank", "--development") == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "s06_t00" in err
    assert not (summary(root) / "rank_totals.csv").exists()


def test_atk_ev_15_a_well_formed_keyed_s06_trial_and_a_keyed_attack_trial_are_accepted() -> None:
    b = R.benign_trial("s06_t00")
    assert b.keyed and not b.attack and b.readings == ()           # S06: no reading rows, feeds H5 only
    t = attack_tie()
    assert t.keyed and t.attack and t.readings


def test_atk_ev_15_s06_membership_follows_the_id_in_h5_not_the_key_content() -> None:
    """keyed s06_* trials decide; unkeyed s06_* trials are beside; an unkeyed non-S06 trial is in neither list."""
    trials = [attack_tie(), R.benign_trial("s06_t00"), R.benign_trial("s06_t01"), R.unkeyed_s06("s06_t01"),
              R.assemble(rf.unkeyed_world("s02_t01"))]
    h = rrep.h5_facts(trials[:3] + [trials[4]], "full", NODE)
    assert [k["trial_id"] for k in h["keyed"]] == ["s06_t00", "s06_t01"]
    assert h["unkeyed"] == []                                      # s02_t01 (unkeyed, not S06) never reaches H5
    h2 = rrep.h5_facts([trials[0], trials[1], trials[3], trials[4]], "full", NODE)
    assert [k["trial_id"] for k in h2["keyed"]] == ["s06_t00"]
    assert [k["trial_id"] for k in h2["unkeyed"]] == ["s06_t01"]


def test_atk_ev_15_pure_assembly_checks_before_anything_else_for_a_key_with_no_attack_path_on_a_non_s06_id() -> None:
    """Direct call of the pure assembly with a key that has only a benign path on an attack-trial id."""
    w = rf.benign_world("s05_t00")
    with pytest.raises(EvalError):
        rank_from_inputs(w.trial, "development", w.stitch_data(), w.score_data(), w.key_data())


# ================================================================================================ ATK-EV-16
@pytest.fixture(scope="module")
def unmatched_repo(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("unmatched") / "r"
    R.write_repo_with(root, R.hop_only_world("s02_t00"))       # key path of s02_t00 has no node-matching candidate
    assert cli(root, "--rank", "--development") == 0
    assert cli(root, "--results", "--development") == 0
    return root


def totals_row(root: Path) -> dict[str, str]:
    (r,) = [x for x in csv_rows((summary(root) / "rank_totals.csv").read_text(encoding="utf-8"))
            if x["row_kind"] == "ranking" and x["variant"] == "full" and x["match_reading"] == NODE
            and x["reading_scope"] == "all"]
    return r


def test_atk_ev_16_unmatched_key_path_leaves_margin_and_held_empty_and_sets_the_reason(unmatched_repo) -> None:
    r = totals_row(unmatched_repo)
    assert r["s06_margin"] == "" and r["s06_held"] == "" and r["key_attack_score_min"] == ""
    assert r["s06_reason"] and "matching candidate" in r["s06_reason"]
    assert "s06_reason" in csv_rows((summary(unmatched_repo) / "rank_totals.csv").read_text(encoding="utf-8"))[0]


def test_atk_ev_16_rank_md_and_results_agree_with_rank_totals(unmatched_repo) -> None:
    reason = totals_row(unmatched_repo)["s06_reason"]
    rank_md = (summary(unmatched_repo) / "rank.md").read_text(encoding="utf-8")
    assert reason in rank_md
    s06 = [r for r in md_section(rank_md, "S06 check") if r["variant"] == "full" and r["match_reading"] == NODE]
    assert len(s06) == 1
    assert s06[0]["s06_margin"] in ("", "-") and s06[0]["s06_held"] in ("", "-") and s06[0]["s06_reason"] == reason
    results = csv_rows((summary(unmatched_repo) / "results.csv").read_text(encoding="utf-8"))
    h5 = primary(results, "H5")
    assert h5["dev_check"] == "not held" and h5["observed"] == "" and h5["note"] == reason
    md = (summary(unmatched_repo) / "results.md").read_text(encoding="utf-8")
    assert "not held" in md_primary(md, "H5")["dev_check"]


def test_atk_ev_16_the_margin_is_never_computed_over_the_matched_trials_only(unmatched_repo) -> None:
    """The other four attack trials give a positive margin on their own; none may leak into the row."""
    r = totals_row(unmatched_repo)
    assert r["s06_margin"] == "" and r["s06_held"] == ""
    assert r["s06_max_score"] != ""                             # the S06 side is still reported
    for row in csv_rows((summary(unmatched_repo) / "results.csv").read_text(encoding="utf-8")):
        if row["table"] == "H5" and row["metric"] == "key_attack_score_min":
            assert row["observed"] == ""


def test_atk_ev_16_one_function_serves_rank_totals_rank_md_and_results() -> None:
    assert rrep.h5_facts is res.h5_facts and "h5_facts" in rrep.__all__
    trials = [attack_tie(), R.benign_trial("s06_t00")]
    h = rrep.h5_facts(trials, "full", NODE)
    s = rrep.s06_facts(trials, "full", NODE)
    assert s["margin"] == h["margin"] and s["held"] == h["held"] and s["reason"] == h["reason"] == ""
    assert primary(rows_of(trials), "H5")["observed"] == f"{h['margin']:.6f}"


def test_atk_ev_16_a_defined_margin_has_an_empty_reason_everywhere(tmp_path) -> None:
    root = fresh(tmp_path)
    assert totals_row(root)["s06_reason"] == "" and totals_row(root)["s06_held"] == "1"
    assert cli(root, "--results", "--development") == 0
    assert primary(csv_rows((summary(root) / "results.csv").read_text(encoding="utf-8")), "H5")["dev_check"] == "held"


# ================================================================================================ ATK-EV-19
def test_atk_ev_19_equals_chance_pos_is_1_when_the_observed_value_equals_the_chance_line() -> None:
    tr = R.assemble(R.solo_world("s02_t00"))                    # one scored path: top-1 1.0, chance over score > 0 1.0
    rows = rows_of([tr])
    h1 = primary(rows, "H1")
    assert h1["observed"] == "1.000000" and h1["chance_pos"] == "1.000000" and h1["equals_chance_pos"] == "1"
    assert primary(rows, "H2")["equals_chance_pos"] == "1"
    assert "equals_chance_pos" in rows[0]


def test_atk_ev_19_equals_chance_pos_is_0_when_the_observed_value_is_above_the_chance_line() -> None:
    rows = rows_of([R.assemble(R.identity_world("s02_t00"))])   # top-1 1.0 vs chance over score > 0 0.5
    h1 = primary(rows, "H1")
    assert h1["chance_pos"] == "0.500000" and h1["equals_chance_pos"] == "0"


def set_top1(tr, value: float):
    out = []
    for r in tr.readings:
        if r.variant == "full" and r.reading == NODE:
            r = dataclasses.replace(r, trial=dataclasses.replace(r.trial, top1_expected=value))
        out.append(r)
    return dataclasses.replace(tr, readings=tuple(out))


@pytest.mark.parametrize("value,flag", [(1.0, "1"), (1.0 - 3e-13, "1"), (1.0 + 3e-13, "1"), (1.0 + 1e-9, "0")])
def test_atk_ev_19_the_equality_is_taken_at_twelve_decimals(value, flag) -> None:
    h1 = primary(rows_of([set_top1(R.assemble(R.solo_world("s02_t00")), value)]), "H1")
    assert h1["equals_chance_pos"] == flag, (value, h1["observed_12"])


def test_atk_ev_19_the_flag_is_empty_where_no_ranking_chance_applies() -> None:
    rows = rows_of([attack_tie(), R.benign_trial("s06_t00")])
    for r in rows:
        if r["table"] in ("H4", "H5"):
            assert r["equals_chance_pos"] == "", r["metric"]


def test_atk_ev_19_results_md_verdict_cell_says_not_above_chance_over_scored_paths() -> None:
    assert res.EQUALS_CHANCE_TEXT == "not above chance over scored paths"
    md = results_files([R.assemble(R.solo_world("s02_t00"))], "development")["results.md"]
    for t in ("H1", "H2"):
        cell = md_primary(md, t)["dev_check"]
        assert cell.startswith("held") and "— not above chance over scored paths" in cell, cell
    md2 = results_files([R.assemble(R.identity_world("s02_t00"))], "development")["results.md"]
    assert md_primary(md2, "H1")["dev_check"] == "held"          # above chance: no flag text
    assert "not above chance" not in md_primary(md2, "H1")["dev_check"]


def test_atk_ev_19_the_csv_verdict_column_keeps_the_bare_verdict() -> None:
    h1 = primary(rows_of([R.assemble(R.solo_world("s02_t00"))]), "H1")
    assert h1["dev_check"] == "held"                              # the flag has its own column; csv cell not decorated


# ================================================================================================ ATK-EV-20
def test_atk_ev_20_h4_is_undefined_when_no_trial_has_a_labelled_key_node() -> None:
    none = R.assemble(R.labelled_world("s02_t00", labelled=False))
    rows = rows_of([none])
    h4 = primary(rows, "H4")
    assert h4["dev_check"] == "undefined" and h4["dev_check"] not in ("held", "not held")
    n = next(r for r in rows if r["table"] == "H4" and r["metric"] == "labelled_recall_trials" and r["reading_scope"] == "all")
    assert n["observed"] == "0"


def test_atk_ev_20_h4_coverage_text_k_of_n_attack_trials_in_results_md() -> None:
    none = R.assemble(R.labelled_world("s02_t00", labelled=False))
    md = results_files([none], "development")["results.md"]
    assert "undefined" in md_primary(md, "H4")["dev_check"] and "(0 of 1 attack trials)" in md_primary(md, "H4")["dev_check"]
    good = R.assemble(R.labelled_world("s02_t00"))
    none2 = R.assemble(R.labelled_world("s03_t00", labelled=False))
    md2 = results_files([good, none2], "development")["results.md"]
    cell = md_primary(md2, "H4")["dev_check"]
    assert cell.startswith("held") and "(1 of 2 attack trials)" in cell, cell


def test_atk_ev_20_h4_with_every_attack_trial_labelled_says_n_of_n() -> None:
    md = results_files([R.assemble(R.labelled_world("s02_t00"))], "development")["results.md"]
    assert "(1 of 1 attack trials)" in md_primary(md, "H4")["dev_check"]


def test_atk_ev_20_h5_coverage_text_counts_the_keyed_s06_trials() -> None:
    one = results_files([attack_tie(), R.benign_trial("s06_t00")], "development")["results.md"]
    assert "(1 keyed S06 trial)" in md_primary(one, "H5")["dev_check"]
    two = results_files([attack_tie(), R.benign_trial("s06_t00"), R.benign_trial("s06_t01")], "development")["results.md"]
    assert "(2 keyed S06 trials)" in md_primary(two, "H5")["dev_check"]


def test_atk_ev_20_the_coverage_adds_no_new_threshold() -> None:
    assert (ep.H1_TOP1_MIN, ep.H2_MRR_PER_KEY_MIN, ep.H3_MIN_DIFFERENCE, ep.H4_MIN_DIFFERENCE, ep.H5_MIN_MARGIN) == (
        0.80, 0.85, 0.0, 0.0, 0.0)
    rows = rows_of([R.assemble(R.labelled_world("s02_t00")), R.assemble(R.labelled_world("s03_t00", labelled=False))])
    assert primary(rows, "H4")["threshold"] == "0.00"


# ================================================================================================ ATK-EV-21
def empty_s06(trial: str = "s06_t00"):
    w = rf.RankWorld(trial=trial)
    w.key_paths = [rf.KP("benign-1", "benign", [])]
    return R.assemble(w)


H5_CASES = {
    "no keyed S06 trial": lambda: [attack_tie()],
    "unmatched key attack path": lambda: [R.assemble(R.hop_only_world("s02_t00")), R.benign_trial("s06_t00")],
    "no key attack scores": lambda: [R.benign_trial("s06_t00")],
    "keyed S06 trial without a candidate path": lambda: [attack_tie(), empty_s06()],
}


def test_atk_ev_21_four_causes_give_four_distinct_nonempty_reasons() -> None:
    reasons = {}
    for name, make in H5_CASES.items():
        h = rrep.h5_facts(make(), "full", NODE)
        assert h["margin"] is None and h["held"] is None, name
        assert h["reason"], name
        reasons[name] = h["reason"]
    assert len(set(reasons.values())) == 4, reasons
    assert "S06" in reasons["no keyed S06 trial"]
    assert "matching candidate" in reasons["unmatched key attack path"]
    assert "s06_t00" in reasons["keyed S06 trial without a candidate path"]


def test_atk_ev_21_each_reason_reaches_results_csv_and_the_verdict_is_not_held() -> None:
    seen = set()
    for name, make in H5_CASES.items():
        trials = make()
        h5 = primary(rows_of(trials), "H5")
        assert h5["dev_check"] == "not held" and h5["observed"] == "" and h5["note"] == \
            rrep.h5_facts(trials, "full", NODE)["reason"], name
        seen.add(h5["note"])
    assert len(seen) == 4


def test_atk_ev_21_each_reason_reaches_rank_totals_s06_reason() -> None:
    seen = set()
    for name, make in H5_CASES.items():
        seen.add(rrep.s06_facts(make(), "full", NODE)["reason"])              # the totals row reads this
    assert len(seen) == 4 and "" not in seen


def test_atk_ev_21_a_defined_margin_has_no_reason() -> None:
    h = rrep.h5_facts([attack_tie(), R.benign_trial("s06_t00")], "full", NODE)
    assert h["reason"] == "" and h["held"] is True and h["margin"] is not None


# ================================================================================================ ATK-EV-22
def test_atk_ev_22_observed_12_is_a_column_of_every_hypothesis_table_in_results_md() -> None:
    md = results_files([attack_tie(), R.benign_trial("s06_t00")], "development")["results.md"]
    for t in ("H1", "H2", "H3", "H4", "H5"):
        rows = md_section(md, f"{t} ")
        assert rows and all("observed_12" in r for r in rows), t
    h1 = md_primary(md, "H1")
    assert re.fullmatch(r"\d\.\d{12}", h1["observed_12"]) and h1["observed"] == f"{float(h1['observed_12']):.6f}"
    assert re.fullmatch(r"-?\d\.\d{12}", md_primary(md, "H5")["observed_12"])


def test_atk_ev_22_the_md_shows_the_compared_value_next_to_the_rounded_one() -> None:
    tr = set_top1(R.assemble(R.solo_world("s02_t00")), 0.8 - 3e-13)
    md = results_files([tr], "development")["results.md"]
    r = md_primary(md, "H1")
    assert r["observed"] == "0.800000" and r["observed_12"] == "0.800000000000" and r["dev_check"].startswith("held")


def b0_pair(full: float, b0: float, *, all_full: float = 0.5, all_b0: float = 0.5):
    tr = R.assemble(R.labelled_world("s02_t00"))
    new = dataclasses.replace(tr.b0, full_recall_labelled=full, b0_recall_labelled=b0, full_recall=all_full,
                              b0_recall=all_b0)
    return new


@pytest.mark.parametrize("delta,count", [(0.0, 0), (3e-13, 0), (-3e-13, 0), (1e-9, 1), (-1e-9, 0)])
def test_atk_ev_22_labelled_trials_above_b0_are_counted_at_twelve_decimals(delta, count) -> None:
    v = rrep.b0_values([b0_pair(0.5 + delta, 0.5)])
    assert v["trials_full_above_b0_labelled"] == count


@pytest.mark.parametrize("delta,count", [(0.0, 0), (3e-13, 0), (1e-9, 1)])
def test_atk_ev_22_all_node_trials_above_b0_are_counted_at_twelve_decimals(delta, count) -> None:
    """Record 075: 'trial counts compared at 12 decimals'."""
    v = rrep.b0_values([b0_pair(0.5, 0.5, all_full=0.5 + delta, all_b0=0.5)])
    assert v["trials_full_above_b0"] == count


def with_gap(tr, gap: float):
    out = []
    for r in tr.readings:
        if r.variant == "full" and r.reading == NODE:
            r = dataclasses.replace(r, gap=gap)
        out.append(r)
    return dataclasses.replace(tr, readings=tuple(out))


@pytest.mark.parametrize("gap,count", [(0.0, 0), (3e-13, 0), (1e-9, 1), (0.25, 1)])
def test_atk_ev_22_trials_with_a_positive_score_gap_are_counted_at_twelve_decimals(gap, count) -> None:
    """Record 075: 'trial counts compared at 12 decimals' (trials_gap_positive)."""
    tr = with_gap(R.assemble(R.solo_world("s02_t00")), gap)
    rr_full = [r for r in tr.readings if r.variant == "full" and r.reading == NODE]
    assert rrep.ranking_values(rr_full)["trials_gap_positive"] == count


def test_atk_ev_22_paired_difference_keeps_the_difference_of_rounded_values() -> None:
    d = res.paired_difference(0.1 + 0.2, 0.3)                   # unequal floats, equal at 12 decimals
    assert d == 0.0
    assert res.paired_difference(None, 0.3) is None
    assert res.paired_difference(0.5, 0.25) == 0.25


# ================================================================================================ ATK-EV-23
def test_atk_ev_23_a_forbidden_phrase_in_a_results_csv_note_refuses_to_write(monkeypatch) -> None:
    real_rows = res.result_rows

    def tainted(results, split):
        rows = [dict(r) for r in real_rows(results, split)]
        rows[0]["note"] = "this detects stolen accounts"
        return rows

    monkeypatch.setattr(res, "result_rows", tainted)
    monkeypatch.setattr(res, "results_md", lambda *a, **k: "# DEVELOPMENT — not a result (decision 019)\nclean\n")
    with pytest.raises(EvalError) as exc:
        results_files([attack_tie()], "development")
    assert str(exc.value).startswith("refused:") and "results.csv" in str(exc.value)


@pytest.mark.parametrize("phrase", ["reduces false positives", "identifies the attacker", "a probability of attack",
                                    "confidence of 90"])
def test_atk_ev_23_every_forbidden_phrase_is_caught_in_the_csv_scan(monkeypatch, phrase) -> None:
    real_rows = res.result_rows
    monkeypatch.setattr(res, "result_rows", lambda r, s: [dict(x, note=phrase) for x in real_rows(r, s)])
    monkeypatch.setattr(res, "results_md", lambda *a, **k: "clean\n")
    with pytest.raises(EvalError):
        results_files([attack_tie()], "development")


def test_atk_ev_23_the_allowed_phrase_in_a_csv_note_is_not_a_hit(monkeypatch) -> None:
    real_rows = res.result_rows
    monkeypatch.setattr(res, "result_rows", lambda r, s: [dict(x, note="the path score is not a probability")
                                                          for x in real_rows(r, s)])
    out = results_files([attack_tie()], "development")
    assert set(out) == {"results.md", "results.csv"}


def test_atk_ev_23_the_untainted_files_pass_the_scan_for_both_files() -> None:
    out = results_files([attack_tie(), R.benign_trial("s06_t00")], "development")
    for name, text in out.items():
        assert res.forbidden_hits(text) == [], name


@pytest.mark.parametrize("value", [0.5, 0.0, 1.0 - 1e-9])
def test_atk_ev_19_below_chance_sets_the_flag_and_the_same_cell_text(value) -> None:
    """Record 075: equals_chance_pos = 1 when observed <= chance_pos at 12 decimals (chance over score > 0 is 1.0 here)."""
    tr = set_top1(R.assemble(R.solo_world("s02_t00")), value)
    rows = rows_of([tr])
    h1 = primary(rows, "H1")
    assert h1["chance_pos"] == "1.000000" and h1["equals_chance_pos"] == "1", (value, h1["observed_12"])
    verdict = "held" if value >= 0.80 else "not held"
    assert h1["dev_check"] == verdict                                            # csv cell stays the bare verdict
    cell = md_primary(results_files([tr], "development")["results.md"], "H1")["dev_check"]
    assert cell == verdict + " — not above chance over scored paths", cell
