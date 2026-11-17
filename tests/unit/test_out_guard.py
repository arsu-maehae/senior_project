"""Tests for the `out/` guard (T7.7, decision 054): `out_guard.snapshot` / `diff` / `report` on temp trees, and the
root `conftest.py` wiring (a session fixture that is autouse and covers the whole `out/` folder). Fast, synthetic."""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

import out_guard as og  # noqa: E402


def tree(root: Path) -> Path:
    (root / "stitch" / "s02_t00").mkdir(parents=True)
    (root / "stitch" / "s02_t00" / "run_info.json").write_text('{"a": 1}\n', encoding="utf-8")
    (root / "gate" / "s02_t00").mkdir(parents=True)
    (root / "gate" / "s02_t00" / "stats.json").write_text("{}\n", encoding="utf-8")
    return root


def bump_mtime(path: Path) -> None:
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))


def test_unchanged_tree_gives_an_empty_diff(tmp_path):
    root = tree(tmp_path / "out")
    d = og.diff(og.snapshot(root), og.snapshot(root))
    assert not d and d == og.OutDiff()


def test_missing_root_snapshots_empty_and_creating_it_shows_as_added(tmp_path):
    before = og.snapshot(tmp_path / "out")
    assert before == {}
    tree(tmp_path / "out")
    d = og.diff(before, og.snapshot(tmp_path / "out"))
    assert "stitch/s02_t00/run_info.json" in d.added and "stitch" in d.added


def test_an_added_file_in_any_subfolder_is_caught(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "gate" / "s02_t00" / "new.csv").write_text("x\n", encoding="utf-8")
    d = og.diff(before, og.snapshot(root))
    assert d.added == ("gate/s02_t00/new.csv",) and not (d.removed or d.changed or d.rewritten)


def test_an_added_empty_folder_is_caught(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "stitch" / ".s02_t00.tmp").mkdir()
    assert og.diff(before, og.snapshot(root)).added == ("stitch/.s02_t00.tmp",)


def test_a_removed_file_is_caught(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "gate" / "s02_t00" / "stats.json").unlink()
    assert og.diff(before, og.snapshot(root)).removed == ("gate/s02_t00/stats.json",)


def test_changed_content_is_caught(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "stitch" / "s02_t00" / "run_info.json").write_text('{"a": 2}\n', encoding="utf-8")
    assert og.diff(before, og.snapshot(root)).changed == ("stitch/s02_t00/run_info.json",)


def test_a_rewrite_with_identical_bytes_is_caught_as_rewritten(tmp_path):
    root = tree(tmp_path / "out")
    target = root / "stitch" / "s02_t00" / "run_info.json"
    before = og.snapshot(root)
    target.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
    bump_mtime(target)                       # make the new time visible whatever the file-system clock resolution
    d = og.diff(before, og.snapshot(root))
    assert d.rewritten == ("stitch/s02_t00/run_info.json",) and not d.changed


def test_reading_a_file_is_not_a_change(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "stitch" / "s02_t00" / "run_info.json").read_bytes()
    assert not og.diff(before, og.snapshot(root))


def test_report_names_paths_and_counts_but_no_content(tmp_path):
    root = tree(tmp_path / "out")
    before = og.snapshot(root)
    (root / "stitch" / "s02_t00" / "run_info.json").write_text('{"secret-ish": 2}\n', encoding="utf-8")
    text = og.report(og.diff(before, og.snapshot(root)))
    assert "changed: 1" in text and "out/stitch/s02_t00/run_info.json" in text and "secret-ish" not in text


def test_report_truncates_long_lists():
    d = og.OutDiff(added=tuple(f"f{i}" for i in range(50)))
    text = og.report(d, limit=3)
    assert "added: 50" in text and "out/f2" in text and "out/f3" not in text and "... 47 more" in text


def test_root_conftest_runs_the_guard_on_the_whole_out_folder_for_every_session():
    """The wiring: a session-scoped autouse fixture in the ROOT conftest (so every collected test, also the
    normaliser tests under src/, is covered), snapshotting REPO/out as a whole, not a list of subfolders."""
    text = (REPO / "conftest.py").read_text(encoding="utf-8")
    assert 'scope="session"' in text and "autouse=True" in text
    assert 'REPO / "out"' in text and "out_guard" in text
