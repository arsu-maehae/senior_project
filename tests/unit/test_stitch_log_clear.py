"""T7.7: a log clear (Security 1102) through the WHOLE stitcher on synthetic data (ST-63, STT-11 "a log clear between ->
`end_unknown`, not open"; decision 047 item 7: a log clear is Security 1102 only). The unit tests of
`test_stitch_identity.py` cover `sessions_at`; this file runs `python -m stitch --out` on a temp repo and reads
`hop_identity.csv` and the other nine files.

World: the T7.4 writer world of `test_stitch_outputs.py` (its source host ep-01 has the session L5000 of Acct_A, opened
at 0 s, and the look-back session of Acct_B opened before the window at -1900 s; the LSASS read DUMP1 is at 50 s; the
window starts at -1800 s), plus 1102 rows on ep-01 at chosen times:

- between L5000's open and the read            -> both sessions end_unknown (the look-back one too: its open is earlier)
- after the look-back open, before L5000's open -> only the look-back session end_unknown; L5000 open
- exactly at the read instant                  -> end_unknown (the interval is (open, read])
- 1 ms after the read, or a 1102 on another host -> nothing changes
- before the window, after the look-back open  -> the look-back session end_unknown, not counted as open, so
                                                  `session_open_before_window` = 0 (it flags sessions USED as open)
In every case the 1102 uid is in no output file and every row count is unchanged.
Fast, synthetic; written from the spec rules above, not from the implementation.
"""
from __future__ import annotations

import csv
import importlib
import io
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from test_stitch_outputs import FILES, LOOKBACK_UID, SRC, TGT, world_rows, write_gate_csv  # noqa: E402

sm = importlib.import_module("stitch.__main__")

DUMP_OFF = 50.0
L5000 = "L5000"


def run_world(tmp_path: Path, clears: list[tuple[str, float, str]], name: str) -> dict[str, bytes]:
    """Build the world plus 1102 rows (uid, offset s, host), run the stitcher into tmp, return the ten files."""
    rows, trig, sup = world_rows()
    rows += [sf.ev(uid, "Security", 1102, host=host, off=off) for uid, off, host in clears]
    fake = sf.make_repo(tmp_path, rows, name=name)
    write_gate_csv(fake.paths.gate_dir / "triggers.csv", trig, ["event_uid"])
    write_gate_csv(fake.paths.gate_dir / "supporting.csv", sup, ["event_uid"])
    out = tmp_path / f"{name}_out"
    assert sm.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(out)]) == 0
    return {p.name: p.read_bytes() for p in sorted(out.iterdir())}


def table(files: dict[str, bytes], name: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(files[name].decode("utf-8"))))


def identity(files: dict[str, bytes], account: str) -> dict[str, str]:
    (row,) = [r for r in table(files, "hop_identity.csv") if r["account"] == account]
    return row


def rows_per_file(files: dict[str, bytes]) -> dict[str, int]:
    return {n: len(table(files, n)) for n in files if n.endswith(".csv")}


@pytest.fixture(scope="module")
def baseline(tmp_path_factory) -> dict[str, bytes]:
    return run_world(tmp_path_factory.mktemp("lc_base"), [], "base")


def test_baseline_both_sessions_are_open(baseline):
    a, b = identity(baseline, "Acct_A"), identity(baseline, "Acct_B")
    assert a["open_session_uids"] == L5000 and a["end_unknown_session_uids"] == ""
    assert b["open_session_uids"] == LOOKBACK_UID and b["session_open_before_window"] == "1"
    assert b["end_unknown_session_uids"] == ""


def assert_clear_invisible(files: dict[str, bytes], uid: str, baseline: dict[str, bytes]) -> None:
    for n, blob in files.items():
        assert uid.encode() not in blob, f"{uid} found in {n}"
    assert rows_per_file(files) == rows_per_file(baseline)


def test_a_1102_between_the_open_and_the_read_makes_both_sessions_end_unknown(tmp_path, baseline):
    files = run_world(tmp_path, [("CLR-MID", 20.0, SRC)], "mid")
    a, b = identity(files, "Acct_A"), identity(files, "Acct_B")
    assert a["open_session_uids"] == "" and a["end_unknown_session_uids"] == L5000
    assert b["open_session_uids"] == "" and b["end_unknown_session_uids"] == LOOKBACK_UID
    assert b["session_open_before_window"] == "0"
    assert_clear_invisible(files, "CLR-MID", baseline)


def test_a_1102_before_a_session_opens_leaves_that_session_open(tmp_path, baseline):
    files = run_world(tmp_path, [("CLR-EARLY", -10.0, SRC)], "early")
    a, b = identity(files, "Acct_A"), identity(files, "Acct_B")
    assert a["open_session_uids"] == L5000 and a["end_unknown_session_uids"] == ""
    assert b["open_session_uids"] == "" and b["end_unknown_session_uids"] == LOOKBACK_UID
    assert_clear_invisible(files, "CLR-EARLY", baseline)


def test_a_1102_at_the_read_instant_counts_and_one_ms_later_does_not(tmp_path, baseline):
    at_read = run_world(tmp_path, [("CLR-AT", DUMP_OFF, SRC)], "at")
    assert identity(at_read, "Acct_A")["end_unknown_session_uids"] == L5000
    assert identity(at_read, "Acct_A")["open_session_uids"] == ""
    after = run_world(tmp_path, [("CLR-AFTER", DUMP_OFF + 0.001, SRC)], "after")
    assert after["hop_identity.csv"] == baseline["hop_identity.csv"]
    assert_clear_invisible(at_read, "CLR-AT", baseline)
    assert_clear_invisible(after, "CLR-AFTER", baseline)


def test_a_1102_on_another_host_changes_nothing(tmp_path, baseline):
    files = run_world(tmp_path, [("CLR-TGT", 20.0, TGT)], "other_host")
    assert files["hop_identity.csv"] == baseline["hop_identity.csv"]
    assert_clear_invisible(files, "CLR-TGT", baseline)


def test_a_pre_window_1102_after_the_look_back_open_ends_it_and_it_is_not_flagged_as_used(tmp_path, baseline):
    """ST-63: the look-back may read the host's pre-window logon events; a pre-window 1102 is one of them."""
    files = run_world(tmp_path, [("CLR-PREW", -1850.0, SRC)], "prew")
    a, b = identity(files, "Acct_A"), identity(files, "Acct_B")
    assert b["open_session_uids"] == "" and b["end_unknown_session_uids"] == LOOKBACK_UID
    assert b["session_open_before_window"] == "0"
    assert a["open_session_uids"] == L5000 and a["end_unknown_session_uids"] == ""
    assert_clear_invisible(files, "CLR-PREW", baseline)


def test_a_1102_changes_only_the_identity_file(tmp_path, baseline):
    """A log clear is an identity fact only: the hops, links, artefacts and path files are byte-identical."""
    files = run_world(tmp_path, [("CLR-MID2", 20.0, SRC)], "only_identity")
    for n in FILES:
        if n not in ("hop_identity.csv", "run_info.json", "stats.json", "report.md"):
            assert files[n] == baseline[n], n
