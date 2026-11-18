"""T10.F review fixes, runner and dry-run side (decision 075, ATK-EV-17, -18 helpers, -24, -25; spec 06_evaluate RT-01,
RT-08, DR-03, DR-05, DR-06). Written from record 075 and the spec, not from the code.

Test ids: ATK-EV-17 folder set / files per folder / `new` is a failure; ATK-EV-24 strict JSON comparison and ISO-8601 UTC
timestamp values only; ATK-EV-25 `run_trial()` checks the allowlist itself, `--repo` links into the real repository are
refused, second Ctrl-C during the scratch deletion; ATK-EV-18 perturbation helpers and the listing of the real tree.

Synthetic folders in pytest tmp folders only; no real `out/` is read or written and no trial DB is opened. Ids: development
ids and the synthetic id s99_t00 only.
"""
from __future__ import annotations

import builtins
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from run_trial import __main__ as rt_main  # noqa: E402
from run_trial import checks, dryrun, dryrun_compare as dc  # noqa: E402
from run_trial import params as p  # noqa: E402

DEV = tuple(p.DEVELOPMENT_TRIALS)
T1, T2 = DEV[0], DEV[1]
TS_A, TS_B = "2026-09-01T00:00:00Z", "2026-11-18T12:34:56Z"
COMMITTED, SCRATCH = dc.COMMITTED, dc.SCRATCH


# ---------------------------------------------------------------- helpers
class Files:
    """Two trees in a dict with the Reader / Lister the Comparer wants (as test_dryrun_compare)."""

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


def raw_json(obj_text: str) -> bytes:
    return (obj_text + "\n").encode("utf-8")


def stitch_info(fk: Files, side: str, body: str) -> None:
    fk.put(side, f"out/stitch/{T1}/run_info.json", raw_json(body))


def compare_stitch(fk: Files) -> dc.FileResult:
    return fk.comparer().compare_file("stitch", T1, "run_info.json")


# ================================================================================================ ATK-EV-24
@pytest.mark.parametrize("a,b", [("1", "1.0"), ("1", "true"), ("0", "false"), ("1.0", "true"), ("0", "null"),
                                 ("1", '"1"'), ("[1]", "[1.0]"), ('{"x": 1}', '{"x": true}')])
def test_atk_ev_24_one_one_point_zero_and_true_are_different_values(a: str, b: str) -> None:
    """Python's == says 1 == 1.0 == True; the serialised comparison must not."""
    fk = Files()
    stitch_info(fk, COMMITTED, f'{{"generated_utc": "{TS_A}", "n": {a}}}')
    stitch_info(fk, SCRATCH, f'{{"generated_utc": "{TS_B}", "n": {b}}}')
    r = compare_stitch(fk)
    assert r.status == dc.DIFFERS and r.status not in dc.PASSING, (a, b)
    # the same pair with identical values is equal after normalising
    fk2 = Files()
    stitch_info(fk2, COMMITTED, f'{{"generated_utc": "{TS_A}", "n": {a}}}')
    stitch_info(fk2, SCRATCH, f'{{"generated_utc": "{TS_B}", "n": {a}}}')
    assert compare_stitch(fk2).status == dc.EQUAL_NORMALISED


def test_atk_ev_24_equal_values_with_only_a_timestamp_difference_stay_equal_after_normalising() -> None:
    fk = Files()
    stitch_info(fk, COMMITTED, f'{{"generated_utc": "{TS_A}", "n": 1, "f": 1.5, "b": true, "z": null}}')
    stitch_info(fk, SCRATCH, f'{{"generated_utc": "{TS_B}", "n": 1, "f": 1.5, "b": true, "z": null}}')
    r = compare_stitch(fk)
    assert r.status == dc.EQUAL_NORMALISED and r.substitutions == {"generated_utc": 1}


@pytest.mark.parametrize("c,s", [("yesterday", "today"), ("2026-09-01", TS_B), ("2026-09-01T00:00:00", TS_B),
                                 ("2026-09-01T00:00:00+00:00", TS_B), ("2026-09-01 00:00:00Z", TS_B),
                                 (TS_A, "not a time"), ("", TS_B), (TS_A + " ", TS_B)])
def test_atk_ev_24_a_non_iso_value_in_a_timestamp_key_makes_the_pair_differ(c: str, s: str) -> None:
    fk = Files()
    stitch_info(fk, COMMITTED, json.dumps({"generated_utc": c, "n": 1}))
    stitch_info(fk, SCRATCH, json.dumps({"generated_utc": s, "n": 1}))
    r = compare_stitch(fk)
    assert r.status == dc.DIFFERS, (c, s)
    assert "ISO" in r.detail or "line" in r.detail


@pytest.mark.parametrize("c,s", [(5, 6), (None, TS_B), ({"t": TS_A}, TS_B), ([TS_A], TS_B), (True, TS_B)])
def test_atk_ev_24_a_non_string_value_in_a_timestamp_key_makes_the_pair_differ(c: Any, s: Any) -> None:
    fk = Files()
    stitch_info(fk, COMMITTED, json.dumps({"generated_utc": c}))
    stitch_info(fk, SCRATCH, json.dumps({"generated_utc": s}))
    assert compare_stitch(fk).status == dc.DIFFERS


def test_atk_ev_24_the_gate_run_utc_key_is_checked_the_same_way() -> None:
    fk = Files()
    fk.put(COMMITTED, f"out/gate/{T1}/run_info.json", raw_json(json.dumps({"run_utc": "x", "k": 1})))
    fk.put(SCRATCH, f"out/gate/{T1}/run_info.json", raw_json(json.dumps({"run_utc": TS_B, "k": 1})))
    assert fk.comparer().compare_file("gate", T1, "run_info.json").status == dc.DIFFERS
    fk.put(COMMITTED, f"out/gate/{T1}/run_info.json", raw_json(json.dumps({"run_utc": TS_A, "k": 1})))
    assert fk.comparer().compare_file("gate", T1, "run_info.json").status == dc.EQUAL_NORMALISED


@pytest.mark.parametrize("value", ["2026-11-18T12:34:56Z", "2026-11-18T12:34:56.1Z", "2026-11-18T12:34:56.123456Z",
                                   "2026-11-18T12:34:56.123456789Z", "1999-01-01T00:00:00Z"])
def test_atk_ev_24_is_iso_utc_accepts_instants_ending_in_z(value: str) -> None:
    assert dc.is_iso_utc(value) is True


@pytest.mark.parametrize("value", ["", "2026-11-18", "2026-11-18T12:34:56", "2026-11-18T12:34:56+00:00",
                                   "2026-11-18 12:34:56Z", "2026-11-18T12:34:56Zx", "x2026-11-18T12:34:56Z",
                                   "2026-11-18T12:34:56Z\n", "2026-11-18T12:34:56.Z", "2026-11-18T12:34:56.1234567890Z",
                                   "2026-11-18T12:34Z", " 2026-11-18T12:34:56Z", None, 5, 1.5, True, ["2026-11-18T12:34:56Z"]])
def test_atk_ev_24_is_iso_utc_rejects_everything_else(value: Any) -> None:
    assert dc.is_iso_utc(value) is False


# ================================================================================================ ATK-EV-17 `new`
def test_atk_ev_17_new_is_a_failure_and_the_allowed_list_is_empty() -> None:
    assert dc.NEW not in dc.PASSING and dc.PASSING == frozenset({dc.IDENTICAL, dc.EQUAL_NORMALISED})
    assert dc.ALLOWED_NEW == frozenset()
    new = dc.FileResult("evaluate_dev", "out/evaluate/development", "results.md", dc.NEW)
    assert dc.is_match(new) is False
    assert dc.is_match(new, frozenset({("out/evaluate/development", "results.md")})) is True     # the explicit opt-in only
    assert dc.is_match(new, frozenset({("out/evaluate/development", "other.md")})) is False
    for ok in (dc.IDENTICAL, dc.EQUAL_NORMALISED):
        assert dc.is_match(dc.FileResult("gate", "f", "n", ok)) is True
    for bad in (dc.DIFFERS, dc.MISSING, dc.EOL_ONLY):
        assert dc.is_match(dc.FileResult("gate", "f", "n", bad)) is False
        assert dc.is_match(dc.FileResult("gate", "f", "n", bad), frozenset({("f", "n")})) is False   # allow-list is for NEW only


def test_atk_ev_17_a_file_only_in_scratch_is_new_and_the_report_fails() -> None:
    fk = Files()
    fk.put(COMMITTED, "out/gate/%s/a.csv" % T1, "x\n")
    fk.put(SCRATCH, "out/gate/%s/a.csv" % T1, "x\n")
    fk.put(SCRATCH, "out/gate/%s/b.csv" % T1, "y\n")
    results = fk.comparer().compare_folder("gate", T1)
    assert {r.name: r.status for r in results} == {"a.csv": dc.IDENTICAL, "b.csv": dc.NEW}
    lines, ok = dryrun._report(results)
    assert not ok and any("b.csv" in x for x in lines)


# ---------------------------------------------------------------- folder set
def make_tree(root: Path, trials: tuple[str, ...], skip: set[str] = frozenset()) -> None:
    for stage in dryrun.COMPARED_STAGES:
        for t in trials:
            rel = (p.STAGE_OUT_REL[stage] / t).as_posix()
            if rel not in skip:
                (root / rel).mkdir(parents=True, exist_ok=True)
    rel = p.EVAL_SUMMARY_DIR.as_posix()
    if rel not in skip:
        (root / rel).mkdir(parents=True, exist_ok=True)


def results_for(folders: set[str], status: str = dc.IDENTICAL) -> list[dc.FileResult]:
    return [dc.FileResult("x", f, "f.csv", status) for f in sorted(folders)]


def test_atk_ev_17_expected_folders_are_five_stages_per_trial_plus_the_summary_folder() -> None:
    want = dryrun.expected_folders(DEV)
    assert len(want) == 9 * 5 + 1 and p.EVAL_SUMMARY_DIR.as_posix() in want
    assert f"out/gate/{T1}" in want and f"out/evaluate/{DEV[-1]}" in want
    assert dryrun.expected_folders((T1,)) == {f"out/{s}/{T1}" for s in ("gate", "stitch", "label", "score", "evaluate")} | {
        "out/evaluate/development"}


def test_atk_ev_17_matching_folder_sets_with_a_matching_file_each_give_no_problem(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    make_tree(a, (T1, T2))
    make_tree(b, (T1, T2))
    want = dryrun.expected_folders((T1, T2))
    assert dryrun.folder_problems(a, b, (T1, T2), results_for(want)) == []


def test_atk_ev_17_a_folder_with_zero_matching_files_fails(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    make_tree(a, (T1,))
    make_tree(b, (T1,))
    want = dryrun.expected_folders((T1,))
    victim = f"out/label/{T1}"
    for status in (dc.DIFFERS, dc.MISSING, dc.NEW, dc.EOL_ONLY):                 # no matching file in the folder
        res = results_for(want - {victim}) + [dc.FileResult("label", victim, "x.csv", status)]
        problems = dryrun.folder_problems(a, b, (T1,), res)
        assert any(victim in x for x in problems), status
    res = results_for(want - {victim})                                           # an empty folder: no file at all
    assert any(victim in x for x in dryrun.folder_problems(a, b, (T1,), res))


def test_atk_ev_17_one_matching_file_among_failures_is_enough_for_the_folder(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    make_tree(a, (T1,))
    make_tree(b, (T1,))
    want = dryrun.expected_folders((T1,))
    victim = f"out/stitch/{T1}"
    res = results_for(want) + [dc.FileResult("stitch", victim, "bad.csv", dc.DIFFERS)]
    assert dryrun.folder_problems(a, b, (T1,), res) == []             # the file mismatch itself is _report's business


def test_atk_ev_17_a_missing_committed_folder_fails(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    victim = f"out/score/{T1}"
    make_tree(a, (T1,), skip={victim})
    make_tree(b, (T1,))
    want = dryrun.expected_folders((T1,))
    res = results_for(want - {victim}) + [dc.FileResult("score", victim, "f.csv", dc.NEW)]
    problems = dryrun.folder_problems(a, b, (T1,), res)
    assert any(victim in x and "committed" in x for x in problems), problems
    assert not any(victim in x and "scratch" in x and "missing" in x for x in problems)


def test_atk_ev_17_a_missing_committed_summary_folder_fails(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    victim = p.EVAL_SUMMARY_DIR.as_posix()
    make_tree(a, (T1,), skip={victim})
    make_tree(b, (T1,))
    problems = dryrun.folder_problems(a, b, (T1,), results_for(dryrun.expected_folders((T1,)) - {victim}))
    assert any(victim in x and "committed" in x for x in problems)


def test_atk_ev_17_a_missing_scratch_folder_fails(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    victim = f"out/gate/{T1}"
    make_tree(a, (T1,))
    make_tree(b, (T1,), skip={victim})
    res = results_for(dryrun.expected_folders((T1,)) - {victim}) + [dc.FileResult("gate", victim, "f.csv", dc.MISSING)]
    problems = dryrun.folder_problems(a, b, (T1,), res)
    assert any(victim in x and "scratch" in x for x in problems), problems


def test_atk_ev_17_a_folder_that_is_not_expected_fails_on_either_side(tmp_path: Path) -> None:
    for side in ("committed", "scratch"):
        a, b = tmp_path / side / "c", tmp_path / side / "s"
        make_tree(a, (T1,))
        make_tree(b, (T1,))
        extra = {"committed": a, "scratch": b}[side] / "out" / "gate" / "s99_t00"
        extra.mkdir(parents=True)
        problems = dryrun.folder_problems(a, b, (T1,), results_for(dryrun.expected_folders((T1,))))
        assert any("s99_t00" in x and side in x for x in problems), (side, problems)


def test_atk_ev_17_dot_folders_such_as_a_stage_swap_folder_are_ignored(tmp_path: Path) -> None:
    a, b = tmp_path / "committed", tmp_path / "scratch"
    make_tree(a, (T1,))
    make_tree(b, (T1,))
    (b / "out" / "score" / ".swap_tmp").mkdir()
    assert dryrun.folder_problems(a, b, (T1,), results_for(dryrun.expected_folders((T1,)))) == []


def test_atk_ev_17_the_folder_set_is_decided_from_the_trial_list_not_from_the_disk(tmp_path: Path) -> None:
    """A trial dropped from both sides is still expected: both sides empty is a problem, not a pass."""
    a, b = tmp_path / "committed", tmp_path / "scratch"
    make_tree(a, (T1,))
    make_tree(b, (T1,))
    problems = dryrun.folder_problems(a, b, (T1, T2), results_for(dryrun.expected_folders((T1,))))
    assert any(T2 in x for x in problems)


# ================================================================================================ ATK-EV-18 helpers
def clock_csv(path: Path, newline: str = "\n") -> None:
    path.write_bytes(newline.join(["trial_id,pair_span_s,offsets_sha256,note", "a,,ff00,x", "b,120,ff01,y",
                                   "c,77,ff02,z", ""]).encode("utf-8"))


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_atk_ev_18_flip_digit_changes_exactly_one_byte_in_the_named_column(tmp_path: Path, newline: str) -> None:
    f = tmp_path / "c.csv"
    clock_csv(f, newline)
    before = f.read_bytes()
    dryrun._flip_digit(f)
    after = f.read_bytes()
    assert len(after) == len(before)
    diff = [i for i, (x, y) in enumerate(zip(before, after)) if x != y]
    assert len(diff) == 1 and chr(after[diff[0]]).isdigit() and chr(before[diff[0]]).isdigit()
    assert before.decode().splitlines()[2].split(",")[1] == "120" and after.decode().splitlines()[2].split(",")[1] == "121"
    assert before.decode().splitlines()[0] == after.decode().splitlines()[0]


def test_atk_ev_18_flip_digit_wraps_nine_to_zero_and_refuses_a_file_without_a_numeric_cell(tmp_path: Path) -> None:
    f = tmp_path / "c.csv"
    f.write_bytes(b"trial_id,pair_span_s\na,19\n")
    dryrun._flip_digit(f)
    assert f.read_bytes() == b"trial_id,pair_span_s\na,10\n"
    g = tmp_path / "g.csv"
    g.write_bytes(b"trial_id,pair_span_s\na,\nb,x\n")
    with pytest.raises(ValueError):
        dryrun._flip_digit(g)
    h = tmp_path / "h.csv"
    h.write_bytes(b"trial_id,other\na,1\n")
    with pytest.raises(ValueError):                                                       # no such column
        dryrun._flip_digit(h)


def fake_run(monkeypatch: pytest.MonkeyPatch, scratch: Path, trial: str, code: int, err: str,
             refused_step: str | None = None, evaluate_info: str | None = None) -> None:
    """Replace the child process of a negative case: write the run_log it would write and return (code, '', err)."""
    def run(argv, holder, capture):
        log_dir = scratch / p.RUN_TRIAL_OUT_REL / trial
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / p.RUN_LOG_JSON).write_text(json.dumps({"refused_step": refused_step or ""}), encoding="utf-8")
        if evaluate_info is not None:
            d = scratch / p.STAGE_OUT_REL["evaluate"] / trial
            d.mkdir(parents=True, exist_ok=True)
            (d / "run_info.json").write_text(evaluate_info, encoding="utf-8")
        return code, "", err
    monkeypatch.setattr(dryrun, "_run", run)


def scratch_with_clock(tmp_path: Path, trial: str) -> tuple[Path, Path]:
    scratch = tmp_path / "scratch"
    f = scratch / p.PROCESSED_REL / f"{trial}{p.OFFSETS_SUFFIX}"
    f.parent.mkdir(parents=True)
    clock_csv(f)
    return scratch, f


def test_atk_ev_18_clock_perturbation_changes_one_scratch_byte_and_passes_only_on_a_gate_refusal(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    scratch, f = scratch_with_clock(tmp_path, T2)
    before = f.read_bytes()
    fake_run(monkeypatch, scratch, T2, 2, "refused: clock offsets SHA-256 differs from the window row", "gate")
    chk = dryrun.negative_clock_perturbation(scratch, dryrun.Child(), T2)
    assert chk.ok, chk.problems
    assert sum(1 for x, y in zip(before, f.read_bytes()) if x != y) == 1
    for code, step, err in ((0, "", ""), (2, "stitch", "SHA-256"), (2, "gate", "something else"), (1, "gate", "SHA-256")):
        s2, _ = scratch_with_clock(tmp_path / f"c{code}{step}", T2)
        fake_run(monkeypatch, s2, T2, code, err, step)
        assert not dryrun.negative_clock_perturbation(s2, dryrun.Child(), T2).ok, (code, step, err)


def key_repo(tmp_path: Path, trial: str) -> tuple[Path, Path]:
    scratch = tmp_path / "scratch"
    key = scratch / "ground_truth" / "approved" / f"{trial}.yaml"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"trial: x\n")
    return scratch, key


def test_atk_ev_18_key_perturbation_appends_a_comment_and_needs_the_new_hash_or_an_evaluate_refusal(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib
    scratch, key = key_repo(tmp_path / "a", T1)
    old = hashlib.sha256(key.read_bytes()).hexdigest()
    new = hashlib.sha256(key.read_bytes() + b"\n# run_trial dry run perturbation (ATK-EV-18)\n").hexdigest()
    fake_run(monkeypatch, scratch, T1, 0, "", evaluate_info=json.dumps({"key_sha256": new}))
    chk = dryrun.negative_key_perturbation(scratch, dryrun.Child(), T1)
    assert chk.ok, chk.problems
    assert key.read_bytes().startswith(b"trial: x\n") and b"# " in key.read_bytes()
    assert hashlib.sha256(key.read_bytes()).hexdigest() == new != old
    # evaluate still carries the old key hash: it read the real ground_truth/, not the scratch one
    s2, _ = key_repo(tmp_path / "b", T1)
    fake_run(monkeypatch, s2, T1, 0, "", evaluate_info=json.dumps({"key_sha256": old}))
    assert not dryrun.negative_key_perturbation(s2, dryrun.Child(), T1).ok
    # a refusal at an evaluate step is accepted; a refusal at gate is not
    s3, _ = key_repo(tmp_path / "c", T1)
    fake_run(monkeypatch, s3, T1, 2, "refused: key", "evaluate_rank")
    assert dryrun.negative_key_perturbation(s3, dryrun.Child(), T1).ok
    s4, _ = key_repo(tmp_path / "d", T1)
    fake_run(monkeypatch, s4, T1, 2, "refused", "gate")
    assert not dryrun.negative_key_perturbation(s4, dryrun.Child(), T1).ok


def test_atk_ev_18_listing_covers_every_file_under_data_processed_and_docs_by_stat_only(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "data" / "processed").mkdir(parents=True)
    (tmp_path / "docs" / "decisions").mkdir(parents=True)
    (tmp_path / "data" / "other").mkdir(parents=True)
    (tmp_path / "data" / "processed" / "s99_t00.sqlite3").write_bytes(b"db")
    (tmp_path / "docs" / "decisions" / "x.md").write_text("x", encoding="utf-8")
    (tmp_path / "data" / "other" / "y.csv").write_text("y", encoding="utf-8")
    opened: list[str] = []
    real_open = builtins.open
    monkeypatch.setattr(builtins, "open", lambda f, *a, **k: (opened.append(str(f)), real_open(f, *a, **k))[1])
    listing = dryrun.stat_listing(tmp_path)
    assert set(listing) == {"data/processed/s99_t00.sqlite3", "docs/decisions/x.md"}
    assert listing["data/processed/s99_t00.sqlite3"][0] == 2
    assert opened == []                                                              # contents never read


def test_atk_ev_18_listing_diff_reports_added_removed_and_changed_and_never_names_a_non_development_db() -> None:
    before = {"docs/a.md": (1, 1), "docs/b.md": (1, 1), f"data/processed/{T1}.sqlite3": (5, 5),
              "data/processed/s99_t00.sqlite3": (5, 5)}
    after = {"docs/a.md": (2, 1), "docs/c.md": (1, 1), f"data/processed/{T1}.sqlite3": (5, 6)}
    out = dryrun.listing_diff(before, after, (T1,))
    assert "added: docs/c.md" in out and "removed: docs/b.md" in out
    assert "changed (size/mtime): docs/a.md" in out and f"changed (size/mtime): data/processed/{T1}.sqlite3" in out
    assert not any("s99_t00" in x for x in out)                                      # the test DB is not named (RT-01)
    assert any("non-development" in x for x in out)
    assert dryrun.listing_diff(before, before, (T1,)) == []


# ================================================================================================ ATK-EV-25
WINDOW_HEADER = "trial_id,start_utc,end_utc\n"


def make_repo(root: Path, trials: tuple[str, ...] = ()) -> Path:
    (root / "data" / "processed").mkdir(parents=True)
    (root / "out").mkdir()
    for t in trials:
        for suf in (p.DB_SUFFIX, p.OFFSETS_SUFFIX, p.CHANGES_SUFFIX):
            (root / "data" / "processed" / f"{t}{suf}").write_bytes(b"")
    (root / "data" / "trial_windows.csv").write_text(WINDOW_HEADER + "".join(f"{t},a,b\n" for t in trials),
                                                     encoding="utf-8")
    return root.resolve()


def snap(root: Path) -> dict[str, tuple[int, int] | None]:
    return {f.relative_to(root).as_posix(): ((f.stat().st_size, f.stat().st_mtime_ns) if f.is_file() else None)
            for f in sorted(root.rglob("*"))}


def boom_run(step: Any, repo_abs: Path) -> Any:
    raise AssertionError(f"a stage was started: {step.name}")


@pytest.mark.parametrize("trial", ["s99_t00", "s02_t02", "s05_t10", "s01_t00", "S02_T00", "", "s02_t00 "])
def test_atk_ev_25_run_trial_function_refuses_a_non_development_id_directly(
        tmp_path: Path, capsys: pytest.CaptureFixture[str], trial: str) -> None:
    repo = make_repo(tmp_path / "r", (trial,) if trial.strip() else ())
    before = snap(repo)
    log, code = rt_main.run_trial(trial, repo, ".", boom_run)
    assert (log, code) == ({}, p.EXIT_REFUSED)
    err = capsys.readouterr().err
    assert err.startswith("refused:") and "allowlist" in err
    assert snap(repo) == before and not (repo / "out" / "run_trial").exists()


def test_atk_ev_25_run_trial_function_refuses_before_any_subprocess_or_presence_check(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = make_repo(tmp_path / "r")                                               # no DB, no window row
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("process started")))
    monkeypatch.setattr(rt_main, "presence_facts", lambda *a, **k: (_ for _ in ()).throw(AssertionError("presence ran")))
    log, code = rt_main.run_trial("s99_t00", repo, ".")                              # default run_fn: the real one
    assert code == 2 and log == {}


def test_atk_ev_25_run_trial_function_still_runs_a_development_trial(tmp_path: Path) -> None:
    repo = make_repo(tmp_path / "r", (T1,))
    calls: list[str] = []

    def ok_run(step: Any, repo_abs: Path) -> Any:
        from run_trial.execute import StepRecord
        from run_trial.steps import display_argv
        calls.append(step.name)
        for rel in step.outputs:
            (repo_abs / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo_abs / rel).write_text("x", encoding="utf-8")
        return StepRecord(step=step.name, argv=display_argv(step, repo_abs), exit_code=0, wall_ms=1, stderr_tail="",
                          result=p.STATUS_OK)

    log, code = rt_main.run_trial(T1, repo, ".", ok_run)
    assert code == 0 and log["status"] == "ok" and calls and calls[0] == "gate"


def make_link(link: Path, target: Path) -> bool:
    """A directory symlink, else (Windows) a junction; False if neither can be made on this machine."""
    try:
        os.symlink(target, link, target_is_directory=True)
        return True
    except (OSError, NotImplementedError, AttributeError):
        pass
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True)
        return r.returncode == 0 and link.exists()
    return False


def test_atk_ev_25_repo_refusal_accepts_the_real_repo_and_an_unrelated_one(tmp_path: Path) -> None:
    real = make_repo(tmp_path / "real")
    other = make_repo(tmp_path / "other")
    assert checks.repo_refusal(real, real) is None
    assert checks.repo_refusal(other, real) is None
    if os.name == "nt":
        assert checks.repo_refusal(Path(str(real).upper()), real) is None              # same folder, other spelling


def test_atk_ev_25_repo_refusal_keeps_the_shape_checks(tmp_path: Path) -> None:
    real = make_repo(tmp_path / "real")
    assert "not an existing directory" in checks.repo_refusal(tmp_path / "nope", real)
    bare = tmp_path / "bare"
    (bare / "data").mkdir(parents=True)
    assert "no out/" in checks.repo_refusal(bare, real)


def test_atk_ev_25_repo_refusal_rejects_a_folder_inside_the_real_repo(tmp_path: Path) -> None:
    real = make_repo(tmp_path / "real")
    inner = make_repo(real / "scratch_inside")
    msg = checks.repo_refusal(inner, real)
    assert msg and msg.startswith("refused:") and "inside" in msg


@pytest.mark.parametrize("which", ["out", "data", "both"])
def test_atk_ev_25_repo_refusal_rejects_a_repo_whose_out_or_data_links_into_the_real_repo(tmp_path: Path, which: str) -> None:
    real = make_repo(tmp_path / "real")
    other = tmp_path / "other"
    other.mkdir()
    for d in ("data", "out"):
        if which in (d, "both"):
            if not make_link(other / d, real / d):
                pytest.skip("directory symlinks and junctions are not permitted on this machine")
        else:
            (other / d).mkdir()
    msg = checks.repo_refusal(other, real)
    assert msg and msg.startswith("refused:") and "resolves inside" in msg and "ATK-EV-25" in msg
    for d in ("data", "out"):
        assert (d + "/" in msg) == (which in (d, "both"))                            # names the offending folder(s)


def test_atk_ev_25_a_link_to_an_unrelated_folder_is_accepted(tmp_path: Path) -> None:
    real = make_repo(tmp_path / "real")
    elsewhere = make_repo(tmp_path / "elsewhere")
    other = tmp_path / "other"
    other.mkdir()
    (other / "data").mkdir()
    if not make_link(other / "out", elsewhere / "out"):
        pytest.skip("directory symlinks and junctions are not permitted on this machine")
    assert checks.repo_refusal(other, real) is None


@pytest.mark.parametrize("argv_extra", [["--trial", T1], ["--development"]])
def test_atk_ev_25_the_cli_refuses_a_linked_repo_and_writes_nothing_into_the_target(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], argv_extra: list[str]) -> None:
    real = make_repo(tmp_path / "real", (T1,))
    other = tmp_path / "other"
    other.mkdir()
    (other / "data").mkdir()
    if not make_link(other / "out", real / "out"):
        pytest.skip("directory symlinks and junctions are not permitted on this machine")
    monkeypatch.setattr(checks.repo_refusal, "__defaults__", (real,))                # the 'real repository' of this test
    before = snap(real)
    assert rt_main.main([*argv_extra, "--repo", str(other)], boom_run) == p.EXIT_REFUSED
    assert "resolves inside" in capsys.readouterr().err
    assert snap(real) == before


# ---------------------------------------------------------------- second Ctrl-C during the scratch deletion
def test_atk_ev_25_a_second_ctrl_c_during_deletion_is_ignored_and_the_deletion_finishes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scratch = tmp_path / "scratch_repo"
    scratch.mkdir()
    (scratch / "f.txt").write_text("x", encoding="utf-8")
    real_delete = dryrun.delete_tree
    calls = {"n": 0}
    handlers: list[Any] = []

    def delete_with_interrupt(path: Path) -> str | None:
        calls["n"] += 1
        handlers.append(signal.getsignal(signal.SIGINT))
        if calls["n"] == 1:
            raise KeyboardInterrupt()                                                # a Ctrl-C that still got through
        return real_delete(path)

    monkeypatch.setattr(dryrun, "delete_tree", delete_with_interrupt)
    before = signal.getsignal(signal.SIGINT)
    assert dryrun._cleanup(dryrun.Child(), scratch) is True
    assert calls["n"] == 2 and not scratch.exists()                                  # retried, then deleted
    assert signal.getsignal(signal.SIGINT) == before                                 # handler restored afterwards
    assert all(h == signal.SIG_IGN for h in handlers)                                # ignored while deleting
    out = capsys.readouterr()
    assert f"scratch repo {scratch} deleted" in out.out.replace("\\\\", "\\")


def test_atk_ev_25_cleanup_reports_a_failed_deletion_as_false(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                              capsys: pytest.CaptureFixture[str]) -> None:
    scratch = tmp_path / "scratch_repo"
    scratch.mkdir()
    monkeypatch.setattr(dryrun, "delete_tree", lambda path: "locked")
    before = signal.getsignal(signal.SIGINT)
    assert dryrun._cleanup(dryrun.Child(), scratch) is False
    assert "NOT deleted" in capsys.readouterr().err and signal.getsignal(signal.SIGINT) == before


def test_atk_ev_25_hard_kill_limit_is_stated_in_the_dry_run_documentation() -> None:
    doc = dryrun.__doc__ or ""
    assert "Hard-kill" in doc and "taskkill" in doc
