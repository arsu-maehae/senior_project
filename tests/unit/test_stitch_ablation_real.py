"""Spec 06_evaluate section 10, stitch switch on real development data (AB-01, AB-05, AB-07). Slow; read-only on the real
folders; DEVELOPMENT numbers, not results (decision 019).

Written from the spec, not from the code. Two checks:
1. `params_dict(StitchParams())` equals the parameter block committed in `out/stitch/<t>/run_info.json` of the nine
   development trials (AB-05: the default code writes exactly what the pre-ablation code wrote; the key
   `disabled_methods` is not there).
2. One real development trial (s04_t00) is stitched in a scratch repo under a pytest tmp folder, by default and with
   `--disable-method cmdline_target`. Only what stitch needs is copied (the DB and its two clock files, the window file,
   the gate folder of the trial), as the dry run does for the whole chain. The default run must reproduce the committed
   `out/stitch/s04_t00` byte for byte (run_info.json up to its timestamp); the ablated run has no `cmdline_target` link
   row, the key hop of the answer key (s04-B-h1 = hop h0024, tier B by the command line only) is `target_only` / tier D,
   and run_info.json / stats.json carry `disabled_methods`.

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_stitch_ablation_real.py
"""
from __future__ import annotations

import csv
import json
import shutil
import sys
from pathlib import Path

import pytest
from real_data import missing_input  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch.__main__ as sm  # noqa: E402
from stitch.index import params_dict  # noqa: E402
from stitch.params import StitchParams  # noqa: E402
from clock_offset.params import DEVELOPMENT_TRIALS  # noqa: E402

pytestmark = pytest.mark.slow

DEV = list(DEVELOPMENT_TRIALS)
TRIAL = "s04_t00"
KEY_HOP = "s04_t00-h0024"
CMD = "cmdline_target"


def need(path: Path) -> Path:
    if not path.is_file():
        missing_input(f"{path} missing")
    return path


def read_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ================================================================================================ AB-05 parameter block
@pytest.mark.parametrize("trial", DEV)
def test_ab05_params_dict_of_the_default_equals_the_committed_parameter_block(trial):
    info = json.loads(need(REPO / "out" / "stitch" / trial / "run_info.json").read_text(encoding="utf-8"))
    now = json.loads(json.dumps(params_dict(StitchParams())))
    assert "disabled_methods" not in now and "disabled_methods" not in info["parameters"]
    assert now == info["parameters"], trial


@pytest.mark.parametrize("trial", DEV)
def test_ab05_no_committed_default_stitch_run_records_disabled_methods(trial):
    info = json.loads(need(REPO / "out" / "stitch" / trial / "run_info.json").read_text(encoding="utf-8"))
    stats = json.loads(need(REPO / "out" / "stitch" / trial / "stats.json").read_text(encoding="utf-8"))
    assert "disabled_methods" not in info and "disabled_methods" not in stats


# ================================================================================================ scratch run of one trial
def scratch_repo(root: Path) -> Path:
    """Only what `python -m stitch --trial s04_t00` reads: DB + clock files, window file, the trial's gate folder."""
    for suf in (".sqlite3", ".clock_offsets.csv", ".clock_changes.csv"):
        src = need(REPO / "data" / "processed" / f"{TRIAL}{suf}")
        (root / "data" / "processed").mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, root / "data" / "processed" / src.name)
    shutil.copy2(need(REPO / "data" / "trial_windows.csv"), root / "data" / "trial_windows.csv")
    gate = REPO / "out" / "gate" / TRIAL
    for f in ("triggers.csv", "unmatched_remote.csv", "supporting.csv", "dispositions.csv", "stats.json"):
        need(gate / f)
    shutil.copytree(gate, root / "out" / "gate" / TRIAL)
    return root


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    """(default folder copy, ablated folder copy), both produced by the CLI in scratch repos (outside the real repo)."""
    out = {}
    for name, extra in (("default", []), ("ablated", ["--disable-method", CMD])):
        root = scratch_repo(tmp_path_factory.mktemp(f"stitch_abl_{name}"))
        assert sm.main(["--trial", TRIAL, "--repo", str(root), *extra]) == 0
        out[name] = root / "out" / "stitch" / TRIAL
    return out


def blobs(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir())}


def without_time(raw: bytes) -> dict:
    d = json.loads(raw)
    d.pop("generated_utc")
    return d


def test_ab05_default_scratch_run_reproduces_the_committed_folder_byte_for_byte(runs):
    committed = REPO / "out" / "stitch" / TRIAL
    mine, theirs = blobs(runs["default"]), blobs(need(committed / "links.csv").parent)
    assert sorted(mine) == sorted(theirs)
    for name in mine:
        if name == "run_info.json":
            assert without_time(mine[name]) == without_time(theirs[name])
        else:
            assert mine[name] == theirs[name], name


def test_ab07_ablated_run_has_no_cmdline_target_link_row_or_session_method(runs):
    rows = read_csv(runs["ablated"] / "links.csv")
    assert rows
    assert not [r for r in rows if r["method"] == CMD]
    assert not [r for r in rows if CMD in (r["session_methods"] or "").split(";")]
    assert not [r for r in rows if r["name_check"] == "match"]


def test_ab07_default_run_does_have_cmdline_target_rows(runs):
    assert [r for r in read_csv(runs["default"] / "links.csv") if r["method"] == CMD]


def test_ab07_key_hop_h0024_is_tier_b_by_default_and_target_only_tier_d_when_disabled(runs):
    def rows(name):
        return [r for r in read_csv(runs[name] / "links.csv") if r["hop_id"] == KEY_HOP]
    default, ablated = rows("default"), rows("ablated")
    assert {r["method"] for r in default} == {CMD}
    assert "B" in {r["confidence_tier"] for r in default}
    assert [(r["method"], r["confidence_tier"]) for r in ablated] == [("target_only", "D")]
    hops = {n: {h["hop_id"]: h for h in read_csv(runs[n] / "hops.csv")} for n in runs}
    assert hops["default"][KEY_HOP]["best_tier"] == "B" and hops["ablated"][KEY_HOP]["best_tier"] == "D"
    assert hops["ablated"][KEY_HOP]["candidate_count"] == "0"


def test_ab01_same_hops_in_both_runs_no_row_lost(runs):
    ids = {n: [h["hop_id"] for h in read_csv(runs[n] / "hops.csv")] for n in runs}
    assert ids["default"] == ids["ablated"]
    # one links.csv group per hop in both runs
    for n in runs:
        assert {r["hop_id"] for r in read_csv(runs[n] / "links.csv")} == set(ids[n])


def test_ab01_run_info_and_stats_carry_disabled_methods_only_in_the_ablated_run(runs):
    for name, want in (("default", None), ("ablated", [CMD])):
        info = json.loads((runs[name] / "run_info.json").read_text(encoding="utf-8"))
        stats = json.loads((runs[name] / "stats.json").read_text(encoding="utf-8"))
        assert info.get("disabled_methods") == want and stats.get("disabled_methods") == want
        assert info["parameters"].get("disabled_methods") == want


def test_ab07_report_names_the_ablation_only_when_set(runs):
    assert "ABLATION" in (runs["ablated"] / "report.md").read_text(encoding="utf-8")
    assert "ABLATION" not in (runs["default"] / "report.md").read_text(encoding="utf-8")


def test_ab07_ablated_run_equals_the_committed_ablation_folder_for_this_trial_when_it_exists(runs):
    """The committed `out/ablation/no_cmdline/stitch/s04_t00` (if present) was made by the same code in a scratch repo, so
    a fresh scratch run must reproduce it (run_info.json up to its timestamp)."""
    committed = REPO / "out" / "ablation" / "no_cmdline" / "stitch" / TRIAL
    if not (committed / "links.csv").is_file():
        pytest.skip("no committed ablation folder")
    mine, theirs = blobs(runs["ablated"]), blobs(committed)
    theirs.pop("ABLATION.txt", None)                        # the driver's banner marker (AB-09), not a stitch file
    assert sorted(mine) == sorted(theirs)
    for name in mine:
        if name == "run_info.json":
            assert without_time(mine[name]) == without_time(theirs[name])
        else:
            assert mine[name] == theirs[name], name
