"""Tests for ``x10_validate --source x10_v2`` (plan 2026-11-15, Task 2; decision 052 and 034).

Written from the plan, not from the code. Synthetic temp repos only; no real trial data is read.
Helpers (row builders, ``_write_db``) come from test_x10_validate.py.

API CONTRACT these tests pin:
  * ``python -m x10_validate run --source {x10,x10_v2} ...`` and ``report --source {x10,x10_v2}``
    (option on the subcommand; default x10 = today's behaviour). ``cli.main(argv, repo=tmp)`` as before.
  * v2 reads ingest reports from ``out/ingest/x10_v2/<trial>/ingest.json`` and writes ONLY under
    ``out/x10_validate_v2/`` (per-trial JSON and report.md); nothing under ``out/x10_validate``. v1 writes only
    under ``out/x10_validate`` and never creates ``out/x10_validate_v2``.
  * v2 scenarios: s01, s04, s05, s07; no quarantine (s05q). v1 scenario list ``cli.X10_SCENARIOS`` is unchanged.
  * v2 ``read_ingest`` refuses (the trial is "skipped", no result written, ``run`` still returns 0) a report whose
    ``source`` is not "x10_v2" (also when the key is missing) or whose ``source_dir`` is not under
    ``data/incoming/x10_v2/``.
  * v2 ``--all`` only picks DBs that have a v2 ingest report (``data/processed/<id>.sqlite3`` is shared with v1).
  * v2 report: counts "validated so far" against the minimum 5 of decision 052; it does not use the 029 words
    "full rerun" / "replace N" and does not say "replacements start at trial_11".
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from x10_validate import cli  # noqa: E402
from test_x10_validate import CHANNELS, HOSTS, T0, _write_db, s02_rows, s04_rows  # noqa: E402

S04_DIR = {"x10": "data/incoming/x10/S04", "x10_v2": "data/incoming/x10_v2/S04"}


def put_ingest(repo: Path, tid: str, folder: str = "x10_v2", *, source="auto", source_dir="auto",
               status: str = "ok") -> None:
    """An ingest.json under out/ingest/<folder>/<tid>/. source/source_dir 'auto' = what the batch writes."""
    rep: dict = {"status": status, "trial_id": tid, "files_missing": [],
                 "files_copied": [{"host": h, "channel": c} for h in HOSTS for c in CHANNELS]}
    src = folder if source == "auto" else source
    if src is not None:
        rep["source"] = src
    num = tid.split("_t")[1]
    rep["source_dir"] = f"{S04_DIR.get(folder, 'data/incoming/' + folder + '/S04')}/trial_{num}" if source_dir == "auto" else source_dir
    p = repo / "out" / "ingest" / folder / tid / "ingest.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rep), encoding="utf-8")


def put_db(repo: Path, tid: str, rows=None) -> Path:
    scen, quar, tr = cli.parse_trial(tid)
    path = cli.db_path(repo, tid)
    _write_db(path, rows if rows is not None else s04_rows(), scenario=scen, trial=tr)
    return path


def files(root: Path) -> set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


def run_cli(repo: Path, *argv: str) -> int:
    return cli.main(list(argv), repo=repo)


# ============================================================================ paths and out dir

def test_v2_run_and_report_write_only_under_out_x10_validate_v2(tmp_path):
    db = put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01")
    before_db = db.read_bytes()
    before = files(tmp_path)
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    new = files(tmp_path) - before
    assert {p.name for p in new} >= {"s04_t01.json", "report.md"}
    assert all("x10_validate_v2" in p.relative_to(tmp_path).parts for p in new), new
    assert not (tmp_path / "out" / "x10_validate").exists()
    assert db.read_bytes() == before_db
    res = json.loads((tmp_path / "out/x10_validate_v2/s04_t01.json").read_text(encoding="utf-8"))
    assert res["trial_id"] == "s04_t01" and res["scenario"] == "s04"


@pytest.mark.parametrize("extra", [[], ["--source", "x10"]])
def test_v1_default_and_explicit_x10_write_only_under_out_x10_validate(tmp_path, extra):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01", folder="x10", source=None, source_dir=None)  # v1 reports have no "source"
    before = files(tmp_path)
    assert run_cli(tmp_path, "run", *extra, "--trials", "s04_t01") == 0
    assert run_cli(tmp_path, "report", *extra) == 0
    new = files(tmp_path) - before
    assert {p.name for p in new} >= {"s04_t01.json", "report.md"}
    assert all("x10_validate" in p.relative_to(tmp_path).parts for p in new), new
    assert not (tmp_path / "out" / "x10_validate_v2").exists()


def test_unknown_source_is_an_argparse_error(tmp_path):
    assert run_cli(tmp_path, "report", "--source", "x10") == 0       # the two choices are accepted ...
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    with pytest.raises(SystemExit) as e:                              # ... anything else is an argparse error
        run_cli(tmp_path, "run", "--source", "x10_v3", "--trials", "s04_t01")
    assert e.value.code == 2


def test_v2_ignores_v1_ingest_folder_and_v1_ignores_v2_folder(tmp_path, capsys):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01", folder="x10", source=None, source_dir=None)
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert "skipped" in capsys.readouterr().out
    assert not (tmp_path / "out/x10_validate_v2/s04_t01.json").exists()

    other = tmp_path / "other"
    put_db(other, "s04_t01")
    put_ingest(other, "s04_t01")  # only a v2 report
    assert run_cli(other, "run", "--trials", "s04_t01") == 0
    assert "skipped" in capsys.readouterr().out
    assert not (other / "out/x10_validate/s04_t01.json").exists()


# ============================================================================ refusing a v1 report as v2

@pytest.mark.parametrize("case,kw", [
    ("source_is_x10", {"source": "x10"}),
    ("source_missing", {"source": None}),
    ("source_dir_under_x10", {"source_dir": "data/incoming/x10/S04/trial_01"}),
    ("source_dir_failed_folder", {"source_dir": "data/incoming/x10_v2_failed/S04/attempt_1"}),
    ("source_dir_elsewhere", {"source_dir": "data/incoming/dryrun/S04/trial_01"}),
])
def test_v2_refuses_a_report_that_is_not_a_v2_ingest(tmp_path, capsys, case, kw):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01", **kw)
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert "skipped" in capsys.readouterr().out
    assert not (tmp_path / "out/x10_validate_v2/s04_t01.json").exists()
    assert not (tmp_path / "out/x10_validate").exists()


def test_v2_refuses_report_with_status_error(tmp_path, capsys):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01", status="error")
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert not (tmp_path / "out/x10_validate_v2/s04_t01.json").exists()


def test_v2_accepts_a_good_report_as_control(tmp_path):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01")
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert (tmp_path / "out/x10_validate_v2/s04_t01.json").is_file()


# ============================================================================ discover and scenarios

def test_v2_all_only_picks_dbs_with_a_v2_ingest_report(tmp_path):
    for t in ("s04_t01", "s04_t02", "s04_t03"):
        put_db(tmp_path, t)
    put_ingest(tmp_path, "s04_t01")                                    # v2 report
    put_ingest(tmp_path, "s04_t02", folder="x10", source=None, source_dir=None)  # v1 report only
    # s04_t03: no report at all
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--all") == 0
    names = sorted(p.name for p in (tmp_path / "out/x10_validate_v2").glob("s0*.json"))
    assert names == ["s04_t01.json"]


def test_v2_all_skips_t00_and_quarantine(tmp_path):
    put_db(tmp_path, "s04_t00")
    put_ingest(tmp_path, "s04_t00")
    q = tmp_path / "data/processed/quarantine/s05q_t01.sqlite3"
    _write_db(q, s02_rows(), scenario="s05", trial="t01")
    put_ingest(tmp_path, "s05q_t01")
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01")
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--all") == 0
    assert sorted(p.name for p in (tmp_path / "out/x10_validate_v2").glob("s0*.json")) == ["s04_t01.json"]


def test_v2_includes_s01(tmp_path):
    """Decision 036 put s01 in DESIGNS; the v2 scenario list s01,s04,s05,s07 must take it."""
    put_db(tmp_path, "s01_t01", s02_rows())
    put_ingest(tmp_path, "s01_t01")
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--all") == 0
    res = json.loads((tmp_path / "out/x10_validate_v2/s01_t01.json").read_text(encoding="utf-8"))
    assert res["scenario"] == "s01" and res["trial_id"] == "s01_t01"
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    assert "s01_t01" in (tmp_path / "out/x10_validate_v2/report.md").read_text(encoding="utf-8")


def test_v1_scenario_list_unchanged():
    assert cli.X10_SCENARIOS == ("s02", "s03", "s04", "s06", "s07")
    assert cli.X10_TRIALS == tuple(f"t{n:02d}" for n in range(1, 11))


def test_v1_report_on_empty_repo_still_lists_the_v1_expected_trials(tmp_path):
    assert run_cli(tmp_path, "report") == 0
    text = (tmp_path / "out/x10_validate/report.md").read_text(encoding="utf-8")
    for tid in ("s02_t01", "s03_t10", "s04_t05", "s06_t01", "s07_t10", "s05q_t01"):
        assert tid in text
    assert "s01_t01" not in text
    assert "trial_11" in text  # the 029 wording stays for v1


def test_v2_report_on_empty_repo_names_no_v1_only_scenario(tmp_path):
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    text = (tmp_path / "out/x10_validate_v2/report.md").read_text(encoding="utf-8")
    for bad in ("s02_t", "s03_t", "s06_t", "s05q"):
        assert bad not in text, bad
    assert not (tmp_path / "out/x10_validate").exists()


# ============================================================================ verdict wording (052)

def six_failing_trials(repo: Path) -> list[str]:
    """Six s04 trials built from the SAME timestamps: their design windows overlap, so criterion f FAILs for each
    (029 verdict would say 'full rerun' for >= 6 of 10)."""
    ids = [f"s04_t0{n}" for n in range(1, 7)]
    for t in ids:
        put_db(repo, t, s04_rows(T0))
        put_ingest(repo, t, folder="x10", source=None, source_dir=None)
        put_ingest(repo, t)
    return ids


def test_v1_wording_is_full_rerun_for_six_failures_the_control(tmp_path):
    ids = six_failing_trials(tmp_path)
    assert run_cli(tmp_path, "run", "--trials", *ids) == 0
    assert run_cli(tmp_path, "report") == 0
    text = (tmp_path / "out/x10_validate/report.md").read_text(encoding="utf-8")
    assert "full rerun" in text  # precondition: the fixture really fails in >= 6 trials


def test_v2_report_counts_against_minimum_five_and_never_says_full_rerun(tmp_path):
    ids = six_failing_trials(tmp_path)
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", *ids) == 0
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    text = (tmp_path / "out/x10_validate_v2/report.md").read_text(encoding="utf-8")
    low = text.lower()
    assert "full rerun" not in low
    assert "replace 6" not in low and "replace 1" not in low
    assert "trial_11" not in low and "replacements start" not in low
    assert "validated so far" in low
    assert re.search(r"minimum\D{0,8}5", low), "report must state the minimum of 5 (decision 052)"
    assert all(t in text for t in ids)


def test_v2_verdict_expected_is_not_a_fixed_ten(tmp_path):
    put_db(tmp_path, "s04_t01")
    put_ingest(tmp_path, "s04_t01")
    assert run_cli(tmp_path, "run", "--source", "x10_v2", "--trials", "s04_t01") == 0
    assert run_cli(tmp_path, "report", "--source", "x10_v2") == 0
    text = (tmp_path / "out/x10_validate_v2/report.md").read_text(encoding="utf-8")
    assert "1 / 10" not in text and "1/10" not in text
