"""Spec 06 DR-03, DR-06, DR-07 as amended by decision 074: the comparison of a scratch run with the committed out/
(`run_trial.dryrun_compare`). Written from the spec and decision 074, not from the code. Pure: the files live in a
dict behind the `Reader` / `Lister` callables, so nothing touches the disk.

Covered: identical / equal after normalising / differs / missing / new (both directions, DR-06); the one column
`label_run_sha256` of label_recall.csv (every other column, the row count and the row order byte-identical); EOL-only
difference reported separately (DR-07); the chained proof (forged hash, unequal run_info pair, rank.md 16-hex prefix);
nothing outside the named keys is normalised (ATK-EV-10).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from run_trial import dryrun, dryrun_compare as dc  # noqa: E402

T1, T2 = "s02_t00", "s03_t00"
TS_A, TS_B = "2026-09-01T00:00:00Z", "2026-11-18T12:34:56Z"
COMMITTED, SCRATCH = dc.COMMITTED, dc.SCRATCH


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jtext(obj: Any) -> bytes:
    return (json.dumps(obj, indent=1) + "\n").encode("utf-8")


class Files:
    """Two trees (committed, scratch) in a dict, with the Reader / Lister the Comparer wants."""

    def __init__(self) -> None:
        self.d: dict[tuple[str, str], bytes] = {}

    def put(self, side: str, rel: str, data: bytes | str) -> None:
        self.d[(side, rel)] = data.encode("utf-8") if isinstance(data, str) else data

    def read(self, side: str, rel: str) -> bytes | None:
        return self.d.get((side, rel))

    def names(self, side: str, folder: str) -> set[str]:
        return {rel.rsplit("/", 1)[1] for (s, rel) in self.d if s == side and rel.rsplit("/", 1)[0] == folder}

    def comparer(self) -> dc.Comparer:
        return dc.Comparer(self.read, self.names)


def chain(fk: Files, side: str, trial: str, ts: str, stitch_extra: dict[str, Any] | None = None) -> dict[str, str]:
    """stitch -> label -> score run_info.json of one side, hashes consistent with the bytes they name. Returns the
    SHA-256 of each."""
    stitch = jtext({"generated_utc": ts, "n_rows": 5, **(stitch_extra or {})})
    fk.put(side, f"out/stitch/{trial}/run_info.json", stitch)
    label = jtext({"generated_utc": ts, "stitch_files_sha256": {"run_info.json": sha(stitch), "hops.csv": "ab" * 32},
                   "n_rules": 3})
    fk.put(side, f"out/label/{trial}/run_info.json", label)
    score = jtext({"generated_utc": ts, "inputs": {"label": {"run_info.json": sha(label)},
                                                   "stitch": {"run_info.json": sha(stitch)}}, "w1": 0.4})
    fk.put(side, f"out/score/{trial}/run_info.json", score)
    return {"stitch": sha(stitch), "label": sha(label), "score": sha(score)}


def recall_csv(rows: list[tuple[str, str, str]]) -> str:
    """label_recall.csv-like text: trial_id, labelled (another column), label_run_sha256 (the normalised one)."""
    return "trial_id,labelled,label_run_sha256\n" + "".join(f"{t},{lab},{h}\n" for t, lab, h in rows)


def setup_pair(ts_c: str = TS_A, ts_s: str = TS_B, trials: tuple[str, ...] = (T1,)) -> tuple[Files, dict[str, dict[str, str]]]:
    fk = Files()
    hashes: dict[str, dict[str, str]] = {COMMITTED: {}, SCRATCH: {}}
    for t in trials:
        hashes[COMMITTED][t] = chain(fk, COMMITTED, t, ts_c)["label"]
        hashes[SCRATCH][t] = chain(fk, SCRATCH, t, ts_s)["label"]
    return fk, hashes


def put_recall(fk: Files, hashes: dict[str, dict[str, str]], trials: tuple[str, ...] = (T1,),
               scratch_override: str | None = None) -> None:
    for side in (COMMITTED, SCRATCH):
        rows = [(t, "1", hashes[side][t]) for t in trials]
        for t in trials:
            fk.put(side, f"out/evaluate/{t}/label_recall.csv", recall_csv([r for r in rows if r[0] == t]))
    if scratch_override is not None:
        fk.put(SCRATCH, f"out/evaluate/{trials[0]}/label_recall.csv", scratch_override)


# ------------------------------------------------------------------------------------------------ plain statuses

def test_identical() -> None:
    fk = Files()
    for side in (COMMITTED, SCRATCH):
        fk.put(side, f"out/stitch/{T1}/hops.csv", "a,b\n1,2\n")
    r = fk.comparer().compare_file("stitch", T1, "hops.csv")
    assert r.status == dc.IDENTICAL and r.status in dc.PASSING


def test_differs_reports_first_differing_line() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/stitch/{T1}/hops.csv", "a,b\n1,2\n3,4\n")
    fk.put(SCRATCH, f"out/stitch/{T1}/hops.csv", "a,b\n1,2\n3,5\n")
    r = fk.comparer().compare_file("stitch", T1, "hops.csv")
    assert r.status == dc.DIFFERS and r.status not in dc.PASSING
    assert "line 3" in r.detail


def test_missing_in_scratch_and_new_in_scratch_both_directions() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/gate/{T1}/triggers.csv", "x\n")             # only committed
    fk.put(SCRATCH, f"out/gate/{T1}/extra.csv", "y\n")                  # only scratch
    fk.put(COMMITTED, f"out/gate/{T1}/same.csv", "z\n")
    fk.put(SCRATCH, f"out/gate/{T1}/same.csv", "z\n")
    res = {r.name: r for r in fk.comparer().compare_folder("gate", T1)}
    assert set(res) == {"triggers.csv", "extra.csv", "same.csv"}
    assert res["triggers.csv"].status == dc.MISSING and res["triggers.csv"].status not in dc.PASSING
    assert res["extra.csv"].status == dc.NEW                            # reported, not a mismatch (DR-06)
    assert res["same.csv"].status == dc.IDENTICAL
    assert dc.MISSING != dc.NEW != dc.DIFFERS


def test_evaluate_dev_folder_is_out_evaluate_development() -> None:
    assert dc.folder_rel("evaluate_dev", "development") == "out/evaluate/development"
    assert dc.folder_rel("stitch", T1) == f"out/stitch/{T1}"


# ------------------------------------------------------------------------------------------------ timestamps

def test_run_info_timestamp_only_is_equal_after_normalising_with_count() -> None:
    fk = Files()
    for kind in ("stitch", "score", "evaluate"):
        fk.put(COMMITTED, f"out/{kind}/{T1}/run_info.json", jtext({"generated_utc": TS_A, "k": 1}))
        fk.put(SCRATCH, f"out/{kind}/{T1}/run_info.json", jtext({"generated_utc": TS_B, "k": 1}))
    for kind in ("stitch", "score", "evaluate"):
        r = fk.comparer().compare_file(kind, T1, "run_info.json")
        assert r.status == dc.EQUAL_NORMALISED and r.status in dc.PASSING
        assert r.substitutions == {"generated_utc": 1} and r.differing == {"generated_utc": 1}


def test_gate_normalises_run_utc_only() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/gate/{T1}/run_info.json", jtext({"run_utc": TS_A, "k": 1}))
    fk.put(SCRATCH, f"out/gate/{T1}/run_info.json", jtext({"run_utc": TS_B, "k": 1}))
    assert fk.comparer().compare_file("gate", T1, "run_info.json").status == dc.EQUAL_NORMALISED
    fk.put(COMMITTED, f"out/gate/{T1}/run_info.json", jtext({"generated_utc": TS_A}))
    fk.put(SCRATCH, f"out/gate/{T1}/run_info.json", jtext({"generated_utc": TS_B}))
    assert fk.comparer().compare_file("gate", T1, "run_info.json").status == dc.DIFFERS      # not a gate key


def test_other_json_key_differing_is_differs_even_with_a_timestamp_difference() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/stitch/{T1}/run_info.json", jtext({"generated_utc": TS_A, "n_rows": 5}))
    fk.put(SCRATCH, f"out/stitch/{T1}/run_info.json", jtext({"generated_utc": TS_B, "n_rows": 6}))
    r = fk.comparer().compare_file("stitch", T1, "run_info.json")
    assert r.status == dc.DIFFERS


@pytest.mark.parametrize("c,s", [
    ({"finished_utc": TS_A}, {"finished_utc": TS_B}),                       # a time-like key that is not named
    ({"meta": {"generated_utc": TS_A}}, {"meta": {"generated_utc": TS_B}}),  # the right key at the wrong path
    ({"note": TS_A}, {"note": TS_B}),                                        # a timestamp-like value elsewhere
])
def test_atk_ev_10_timestamp_like_value_outside_the_named_keys_is_not_normalised(c: dict, s: dict) -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/stitch/{T1}/run_info.json", jtext({"generated_utc": TS_A, **c}))
    fk.put(SCRATCH, f"out/stitch/{T1}/run_info.json", jtext({"generated_utc": TS_A, **s}))
    assert fk.comparer().compare_file("stitch", T1, "run_info.json").status == dc.DIFFERS


def test_atk_ev_10_files_without_a_rule_are_never_normalised() -> None:
    fk = Files()
    fk.put(COMMITTED, "out/evaluate/development/results.md", f"generated {TS_A}\n")
    fk.put(SCRATCH, "out/evaluate/development/results.md", f"generated {TS_B}\n")
    fk.put(COMMITTED, f"out/stitch/{T1}/report.md", f"generated_utc {TS_A}\n")
    fk.put(SCRATCH, f"out/stitch/{T1}/report.md", f"generated_utc {TS_B}\n")
    fk.put(COMMITTED, f"out/evaluate/{T1}/other.csv", f"trial_id,generated_utc\n{T1},{TS_A}\n")
    fk.put(SCRATCH, f"out/evaluate/{T1}/other.csv", f"trial_id,generated_utc\n{T1},{TS_B}\n")
    cmp = fk.comparer()
    assert cmp.compare_file("evaluate_dev", "development", "results.md").status == dc.DIFFERS
    assert cmp.compare_file("stitch", T1, "report.md").status == dc.DIFFERS
    assert cmp.compare_file("evaluate", T1, "other.csv").status == dc.DIFFERS


def test_hash_value_in_an_unnamed_column_is_not_normalised() -> None:
    fk, h = setup_pair()
    for side in (COMMITTED, SCRATCH):
        fk.put(side, f"out/evaluate/{T1}/other_recall.csv", recall_csv([(T1, "1", h[side][T1])]))
    assert fk.comparer().compare_file("evaluate", T1, "other_recall.csv").status == dc.DIFFERS


# ------------------------------------------------------------------------------------------------ label_recall.csv

def test_label_recall_csv_only_the_hash_column_differs_is_equal_after_normalising() -> None:
    trials = (T1,)
    fk, h = setup_pair(trials=trials)
    rows_c = [(T1, "1", h[COMMITTED][T1]), (T1, "0", h[COMMITTED][T1]), (T1, "1", h[COMMITTED][T1])]
    rows_s = [(T1, "1", h[SCRATCH][T1]), (T1, "0", h[SCRATCH][T1]), (T1, "1", h[SCRATCH][T1])]
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", recall_csv(rows_c))
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv(rows_s))
    assert h[COMMITTED][T1] != h[SCRATCH][T1]
    r = fk.comparer().compare_file("evaluate", T1, "label_recall.csv")
    assert r.status == dc.EQUAL_NORMALISED, r.detail
    assert r.substitutions == {"column label_run_sha256": 3}            # substitution count per file (DR-07)
    assert r.differing == {"column label_run_sha256": 3}


def test_label_recall_csv_another_column_differs_is_differs() -> None:
    fk, h = setup_pair()
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", h[COMMITTED][T1])]))
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "0", h[SCRATCH][T1])]))
    r = fk.comparer().compare_file("evaluate", T1, "label_recall.csv")
    assert r.status == dc.DIFFERS


def test_label_recall_csv_row_order_change_is_differs() -> None:
    fk, h = setup_pair(trials=(T1, T2))
    # two rows for one trial_id folder is enough: swap them
    r1, r2 = (T1, "1", h[COMMITTED][T1]), (T1, "0", h[COMMITTED][T1])
    s1, s2 = (T1, "1", h[SCRATCH][T1]), (T1, "0", h[SCRATCH][T1])
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", recall_csv([r1, r2]))
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv([s2, s1]))
    assert fk.comparer().compare_file("evaluate", T1, "label_recall.csv").status == dc.DIFFERS


def test_label_recall_csv_row_count_change_is_differs() -> None:
    fk, h = setup_pair()
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv",
           recall_csv([(T1, "1", h[COMMITTED][T1]), (T1, "0", h[COMMITTED][T1])]))
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", h[SCRATCH][T1])]))
    assert fk.comparer().compare_file("evaluate", T1, "label_recall.csv").status == dc.DIFFERS


def test_eol_only_difference_is_reported_separately() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/stitch/{T1}/hops.csv", "a,b\n1,2\n")
    fk.put(SCRATCH, f"out/stitch/{T1}/hops.csv", "a,b\r\n1,2\r\n")
    r = fk.comparer().compare_file("stitch", T1, "hops.csv")
    assert r.status == dc.EOL_ONLY
    assert r.status != dc.DIFFERS and "line ending" in r.status
    assert r.status not in dc.PASSING                                   # still a mismatch for the verdict


def test_eol_only_difference_in_a_normalised_csv_is_also_separate() -> None:
    fk, h = setup_pair()
    text = recall_csv([(T1, "1", h[COMMITTED][T1])])
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", text)
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", text.replace("\n", "\r\n"))
    assert fk.comparer().compare_file("evaluate", T1, "label_recall.csv").status == dc.EOL_ONLY


# ------------------------------------------------------------------------------------------------ chained proof

def test_chain_label_run_info_equal_after_normalising_two_links() -> None:
    fk, _ = setup_pair()
    r = fk.comparer().compare_file("label", T1, "run_info.json")
    assert r.status == dc.EQUAL_NORMALISED, r.detail
    assert r.substitutions.get("generated_utc") == 1
    assert r.substitutions.get("stitch_files_sha256.run_info.json") == 1
    s = fk.comparer().compare_file("score", T1, "run_info.json")
    assert s.status == dc.EQUAL_NORMALISED, s.detail
    assert s.substitutions.get("inputs.label.run_info.json") == 1
    assert s.substitutions.get("inputs.stitch.run_info.json") == 1


def test_forged_hash_not_equal_to_sha256_of_the_named_run_info_is_differs() -> None:
    for forged_side in (SCRATCH, COMMITTED):
        fk, h = setup_pair()
        good = {COMMITTED: h[COMMITTED][T1], SCRATCH: h[SCRATCH][T1]}
        good[forged_side] = "0" * 64
        fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", good[COMMITTED])]))
        fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", good[SCRATCH])]))
        r = fk.comparer().compare_file("evaluate", T1, "label_recall.csv")
        assert r.status == dc.DIFFERS, forged_side
        assert "proof" in r.detail


def test_forged_hash_in_the_run_info_itself_is_differs() -> None:
    """label run_info names a stitch run_info by a hash that is not its SHA-256 (scratch side forged)."""
    fk, _ = setup_pair()
    stitch = fk.read(SCRATCH, f"out/stitch/{T1}/run_info.json")
    assert stitch is not None
    fk.put(SCRATCH, f"out/label/{T1}/run_info.json",
           jtext({"generated_utc": TS_B, "stitch_files_sha256": {"run_info.json": "f" * 64, "hops.csv": "ab" * 32},
                  "n_rules": 3}))
    assert fk.comparer().compare_file("label", T1, "run_info.json").status == dc.DIFFERS


def test_run_info_pair_not_equal_after_normalising_makes_the_dependant_hash_differ() -> None:
    fk = Files()
    hc = chain(fk, COMMITTED, T1, TS_A)
    hs = chain(fk, SCRATCH, T1, TS_B, stitch_extra={"n_rows": 5, "unexpected": True})   # a real difference
    fk.put(COMMITTED, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", hc["label"])]))
    fk.put(SCRATCH, f"out/evaluate/{T1}/label_recall.csv", recall_csv([(T1, "1", hs["label"])]))
    cmp = fk.comparer()
    assert cmp.compare_file("stitch", T1, "run_info.json").status == dc.DIFFERS
    assert cmp.compare_file("label", T1, "run_info.json").status == dc.DIFFERS      # hash inside it does not hide it
    assert cmp.compare_file("evaluate", T1, "label_recall.csv").status == dc.DIFFERS


def test_missing_named_run_info_fails_the_proof() -> None:
    fk, h = setup_pair()
    put_recall(fk, h)
    del fk.d[(SCRATCH, f"out/label/{T1}/run_info.json")]
    assert fk.comparer().compare_file("evaluate", T1, "label_recall.csv").status == dc.DIFFERS


def test_rank_md_compares_the_16_hex_prefix() -> None:
    def rank_md(prefix: str) -> str:
        return ("## Inputs (SHA-256, first 16 hex digits)\n\n"
                "| trial_id | score_run_info_sha256 | ranked_paths_sha256 |\n|---|---|---|\n"
                f"| {T1} | {prefix} | e64819824fb17d3a |\n")

    fk = Files()
    hc, hs = chain(fk, COMMITTED, T1, TS_A), chain(fk, SCRATCH, T1, TS_B)
    fk.put(COMMITTED, "out/evaluate/development/rank.md", rank_md(hc["score"][:16]))
    fk.put(SCRATCH, "out/evaluate/development/rank.md", rank_md(hs["score"][:16]))
    r = fk.comparer().compare_file("evaluate_dev", "development", "rank.md")
    assert r.status == dc.EQUAL_NORMALISED, r.detail
    assert r.substitutions == {"column score_run_info_sha256": 1}
    # a wrong prefix on either side fails the proof
    for side, bad in ((SCRATCH, "0123456789abcdef"), (COMMITTED, "fedcba9876543210")):
        fk2 = Files()
        hc, hs = chain(fk2, COMMITTED, T1, TS_A), chain(fk2, SCRATCH, T1, TS_B)
        vals = {COMMITTED: hc["score"][:16], SCRATCH: hs["score"][:16]}
        vals[side] = bad
        fk2.put(COMMITTED, "out/evaluate/development/rank.md", rank_md(vals[COMMITTED]))
        fk2.put(SCRATCH, "out/evaluate/development/rank.md", rank_md(vals[SCRATCH]))
        assert fk2.comparer().compare_file("evaluate_dev", "development", "rank.md").status == dc.DIFFERS


def test_rank_md_another_column_differing_is_differs() -> None:
    fk = Files()
    hc, hs = chain(fk, COMMITTED, T1, TS_A), chain(fk, SCRATCH, T1, TS_B)

    def md(side_hash: str, other: str) -> str:
        return ("| trial_id | score_run_info_sha256 | ranked_paths_sha256 |\n|---|---|---|\n"
                f"| {T1} | {side_hash} | {other} |\n")

    fk.put(COMMITTED, "out/evaluate/development/rank.md", md(hc["score"][:16], "aaaaaaaaaaaaaaaa"))
    fk.put(SCRATCH, "out/evaluate/development/rank.md", md(hs["score"][:16], "bbbbbbbbbbbbbbbb"))
    assert fk.comparer().compare_file("evaluate_dev", "development", "rank.md").status == dc.DIFFERS


def test_label_recall_md_full_hash_column() -> None:
    def md(h: str) -> str:
        return f"| trial_id | key_sha256 | label_run_info_sha256 |\n|---|---|---|\n| {T1} | {'a' * 64} | {h} |\n"

    fk, hh = setup_pair()
    fk.put(COMMITTED, "out/evaluate/development/label_recall.md", md(hh[COMMITTED][T1]))
    fk.put(SCRATCH, "out/evaluate/development/label_recall.md", md(hh[SCRATCH][T1]))
    r = fk.comparer().compare_file("evaluate_dev", "development", "label_recall.md")
    assert r.status == dc.EQUAL_NORMALISED, r.detail
    fk.put(SCRATCH, "out/evaluate/development/label_recall.md", md("0" * 64))
    assert fk.comparer().compare_file("evaluate_dev", "development", "label_recall.md").status == dc.DIFFERS


def test_evaluate_run_info_stitch_hashes_are_proved() -> None:
    fk = Files()
    hc, hs = chain(fk, COMMITTED, T1, TS_A), chain(fk, SCRATCH, T1, TS_B)

    def ev(ts: str, h: str) -> bytes:
        return jtext({"generated_utc": ts, "inputs": {"stitch_run_info_sha256": h,
                                                      "stitch_files": {"run_info.json": h, "hops.csv": "cd" * 32}}})

    fk.put(COMMITTED, f"out/evaluate/{T1}/run_info.json", ev(TS_A, hc["stitch"]))
    fk.put(SCRATCH, f"out/evaluate/{T1}/run_info.json", ev(TS_B, hs["stitch"]))
    r = fk.comparer().compare_file("evaluate", T1, "run_info.json")
    assert r.status == dc.EQUAL_NORMALISED, r.detail
    assert r.substitutions["inputs.stitch_run_info_sha256"] == 1
    fk.put(SCRATCH, f"out/evaluate/{T1}/run_info.json", ev(TS_B, "9" * 64))
    assert fk.comparer().compare_file("evaluate", T1, "run_info.json").status == dc.DIFFERS


# ------------------------------------------------------------------------------------------------ the list itself

def test_named_list_is_explicit_and_contains_exactly_the_074_values() -> None:
    got = {(r.file, r.label) for r in dc.NORMALISED}
    want = {("run_info.json", "generated_utc"), ("run_info.json", "run_utc"),
            ("run_info.json", "stitch_files_sha256.run_info.json"),
            ("run_info.json", "inputs.label.run_info.json"), ("run_info.json", "inputs.stitch.run_info.json"),
            ("run_info.json", "inputs.stitch_run_info_sha256"),
            ("run_info.json", "inputs.stitch_files.run_info.json"),
            ("rank.md", "column score_run_info_sha256"), ("label_recall.md", "column label_run_info_sha256"),
            ("label_recall.csv", "column label_run_sha256")}
    assert got == want
    rank = next(r for r in dc.NORMALISED if r.file == "rank.md")
    assert rank.hex_len == 16
    assert all(r.hex_len == 64 for r in dc.NORMALISED if r.file != "rank.md")
    assert all(r.kinds for r in dc.NORMALISED)
    assert not any(r.file.endswith(".csv") and r.file != "label_recall.csv" for r in dc.NORMALISED)


# ------------------------------------------------------------------------------------------------ report verdict

def test_report_verdict_new_passes_missing_and_differs_fail() -> None:
    mk = lambda status, name="f.csv": dc.FileResult("stitch", f"out/stitch/{T1}", name, status)   # noqa: E731
    lines, ok = dryrun._report([mk(dc.IDENTICAL), mk(dc.EQUAL_NORMALISED, "g.json"), mk(dc.NEW, "results.md")])
    assert ok and any("results.md" in x and "new" in x for x in lines)                       # reported (DR-06)
    for bad in (dc.DIFFERS, dc.MISSING, dc.EOL_ONLY):
        _, ok2 = dryrun._report([mk(dc.IDENTICAL), mk(bad)])
        assert not ok2, bad
