"""RTA-01 (spec 06 section 7.1): the dry run on the real development data. Slow. Read-only on the real repository:
the dry run copies the nine development inputs into a scratch repo in the system temp folder (outside the repository)
and writes only there, so the root conftest's `out/` guard still holds. It never opens a t02-t10 DB (the negative case
uses a zero-byte file it creates itself in the scratch repo).

    REQUIRE_REAL_DATA=1 python -m pytest tests/unit/test_run_trial_real.py   # a missing input FAILS instead of skipping
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from real_data import missing_input

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from run_trial import dryrun  # noqa: E402
from run_trial import params as p  # noqa: E402

pytestmark = pytest.mark.slow


def test_rta01_dry_run_nine_trials_identical_or_equal_after_normalising(capsys: pytest.CaptureFixture[str]) -> None:
    for t in p.DEVELOPMENT_TRIALS:
        for rel in (f"data/processed/{t}.sqlite3", f"data/processed/{t}.clock_offsets.csv",
                    f"data/processed/{t}.clock_changes.csv"):
            if not (REPO / rel).is_file():
                missing_input(f"{rel} is missing")
    if not (REPO / "out" / "evaluate" / "development").is_dir():
        missing_input("committed out/evaluate/development is missing")
    code = dryrun.main([])
    out = capsys.readouterr().out
    assert code == 0, out[-3000:]
    assert "dry run: PASSED" in out
    assert "scratch repo" in out and " deleted" in out                  # reported deleted
    assert "DR-04a" in out and "DR-04b" in out
    assert "FAILED" not in out.split("== negative cases ==")[1].split("== committed tree")[0]
    assert "unchanged" in out.split("== committed tree (DR-06) ==")[1]
    assert "differs" not in out.split("== comparison with the committed out/ ==")[1].split("== negative cases ==")[0]
    # RTA-02: processing time written for every step of the nine trials
    wall = out.split("== per-stage wall time")[1].split("== comparison")[0]
    for t in p.DEVELOPMENT_TRIALS:
        assert f"  {t}: ok" in wall
