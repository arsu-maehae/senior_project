"""T7.7: the clock refusals the stitcher makes again itself (spec 03_stitch section 2: "every input the gate refuses
(quarantined trial, clock-only trial, CO-17), checked again with the same shared functions, so a stale gate folder
cannot be stitched"; STT-01), which the T7.2-T7.6 reports named as untested inside the stitcher:

- CO-17 (spec 08 Q2): a window starting on or after 2026-10-26 (UTC date) is refused when a host WITH events is
  uncorrected (`none` or `stale`); a `wide` host is corrected and runs; a host with no events does not count.
- an incomplete clock-change scan (review 08 SF-4): an offsets file whose `clock_scan` is not `complete` is refused.

Every case is a STALE GATE FOLDER: the gate stats record exactly the window row and the clock-file hashes of the files
on disk, so only the stitcher's own re-check can refuse. Each refusal is checked at `check_allowed` and through
`python -m stitch`, `stitch.check_index` and `stitch.check_links` (exit 2, `refused:` on stderr, nothing written).

Fast, synthetic: a temp repo from `stitch_fixtures.make_repo`; nothing real is opened. Written from the spec, spec 08
CO-17 / SF-4 and the shared refusal texts' meaning, not from the stitcher code.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import clock_fixtures as cf  # noqa: E402
import stitch_fixtures as sf  # noqa: E402
from stitch import check_index as ci  # noqa: E402
from stitch import check_links as cl  # noqa: E402
from stitch.inputs import StitchError, check_allowed  # noqa: E402
from trial_window.params import RAW_TIME_CUTOFF_DATE  # noqa: E402

sm = importlib.import_module("stitch.__main__")

CO17_DAY = "2026-10-26T00:00:00.000Z"          # first instant of the CO-17 date (UTC)
CO17_DAY_END = "2026-10-26T01:00:00.000Z"
DAY_BEFORE_LAST_MS = "2026-10-25T23:59:59.999Z"   # last millisecond before it
DAY_BEFORE_END = "2026-10-26T00:59:59.999Z"
CLIS = {"stitch": sm.main, "check_index": ci.main, "check_links": cl.main}


def co17_repo(tmp_path: Path, start: str, end: str, **hosts: tuple) -> sf.FakeRepo:
    return sf.make_repo(tmp_path, start=start, end=end, offsets=cf.offsets_spec(**hosts))


def assert_cli_refuses(fake: sf.FakeRepo, capsys, needle: str) -> None:
    """Every CLI exits 2 with `refused:` (naming `needle`) and the repo is byte-for-byte unchanged."""
    before = sf.snapshot(fake.repo)
    for name, main in CLIS.items():
        assert main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 2, name
        err = capsys.readouterr().err
        assert err.startswith("refused:") and needle in err, (name, err[:200])
        assert sf.snapshot(fake.repo) == before, name
    assert not (fake.repo / "out" / "stitch").exists()
    assert not (fake.repo / "out" / "stitch_check").exists()


def test_the_co17_date_is_2026_10_26():
    assert RAW_TIME_CUTOFF_DATE.isoformat() == "2026-10-26"


# ================================================================================================ CO-17
@pytest.mark.parametrize("status", ["none", "stale"])
def test_co17_window_on_the_date_with_an_uncorrected_host_with_events_is_refused(tmp_path, status):
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END, ep_03=(None, status, True))
    with pytest.raises(StitchError) as exc:
        check_allowed(fake.paths)
    msg = str(exc.value)
    assert msg.startswith("refused:") and "CO-17" in msg and "ep-03" in msg


@pytest.mark.parametrize("status", ["none", "stale"])
def test_co17_refusal_through_every_cli_writes_nothing(tmp_path, capsys, status):
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END, ep_03=(None, status, True))
    assert_cli_refuses(fake, capsys, "CO-17")


@pytest.mark.parametrize("status", ["none", "stale"])
def test_co17_window_one_millisecond_before_the_date_passes(tmp_path, status):
    """The date is the UTC date of the window START: 23:59:59.999 on 10-25 is before it."""
    fake = co17_repo(tmp_path, DAY_BEFORE_LAST_MS, DAY_BEFORE_END, ep_03=(None, status, True))
    assert check_allowed(fake.paths).trial_id == fake.trial


def test_co17_a_wide_host_on_the_date_runs(tmp_path, capsys):
    """Spec 08 Q2: a wide host is corrected and runs (flagged); the stitcher writes its ten files."""
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END, ep_03=(7000, "wide", True))
    assert check_allowed(fake.paths).trial_id == fake.trial
    assert sm.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 0
    assert len(list((fake.repo / "out" / "stitch" / fake.trial).iterdir())) == 10


def test_co17_an_uncorrected_host_without_events_does_not_refuse(tmp_path):
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END, ep_03=(None, "none", False))
    assert check_allowed(fake.paths).trial_id == fake.trial


def test_co17_every_host_corrected_on_the_date_passes(tmp_path):
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END)
    assert check_allowed(fake.paths).trial_id == fake.trial


def test_co17_an_uncorrected_host_before_the_date_is_not_a_co17_refusal(tmp_path):
    """Before 2026-10-26 the uncorrected host is not refused by CO-17 (it is flagged by ST-02 instead)."""
    fake = co17_repo(tmp_path, sf.WIN_START, sf.WIN_END, ep_03=(None, "none", True))
    assert check_allowed(fake.paths).trial_id == fake.trial


def test_co17_the_gate_stats_match_the_files_so_only_the_stitcher_refuses(tmp_path):
    """The stale-gate case: stats.json records the very window row and clock hashes of the refused trial."""
    fake = co17_repo(tmp_path, CO17_DAY, CO17_DAY_END, ep_03=(None, "none", True))
    stats = fake.stats
    assert stats["window"]["row"] == fake.window_row
    assert stats["clock"]["offsets_sha256"] == sf.sha256_of(fake.paths.offsets_csv)
    assert stats["clock"]["clock_changes_sha256"] == sf.sha256_of(fake.paths.changes_csv)
    with pytest.raises(StitchError):
        check_allowed(fake.paths)


# ================================================================================================ incomplete scan (SF-4)
@pytest.mark.parametrize("scan", ["incomplete", "partial", ""])
def test_clock_scan_not_complete_is_refused(tmp_path, scan):
    fake = sf.make_repo(tmp_path, clock_scan=scan)
    with pytest.raises(StitchError) as exc:
        check_allowed(fake.paths)
    assert str(exc.value).startswith("refused:")


def test_clock_scan_incomplete_names_the_scan(tmp_path):
    fake = sf.make_repo(tmp_path, clock_scan="incomplete")
    with pytest.raises(StitchError) as exc:
        check_allowed(fake.paths)
    assert "scan" in str(exc.value) and "incomplete" in str(exc.value)


def test_clock_scan_incomplete_through_every_cli_writes_nothing(tmp_path, capsys):
    fake = sf.make_repo(tmp_path, clock_scan="incomplete")
    assert fake.stats["clock"]["offsets_sha256"] == sf.sha256_of(fake.paths.offsets_csv)   # a stale gate folder
    assert_cli_refuses(fake, capsys, "incomplete")


def test_clock_scan_complete_passes(tmp_path):
    fake = sf.make_repo(tmp_path, clock_scan="complete")
    assert check_allowed(fake.paths).trial_id == fake.trial


def test_refusal_leaves_an_existing_output_folder_untouched(tmp_path, capsys):
    """A refused re-run must not touch the folder of an earlier good run (spec 2)."""
    fake = sf.make_repo(tmp_path, clock_scan="incomplete")
    folder = fake.repo / "out" / "stitch" / fake.trial
    folder.mkdir(parents=True)
    (folder / "links.csv").write_text("earlier run\n", encoding="utf-8")
    before = sf.snapshot(fake.repo / "out")
    assert sm.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert sf.snapshot(fake.repo / "out") == before
