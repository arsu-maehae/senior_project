"""T7.7 / decision 054: the `--out` option of `python -m stitch`, `stitch.check_index` and `stitch.check_links`.

What must hold (054):
- `python -m stitch --out DIR` writes the same ten files into DIR; every file except `run_info.json` is byte-identical
  to a default run, and `run_info.json` differs only in `generated_utc`; the default folder is not created.
- ST-00 comes first: a test trial with `--out` is refused by the allowlist (046) and DIR is never touched.
- Any refusal with `--out` writes nothing into DIR.
- DIR is refused (before anything is written) when it lies inside the repository but not strictly below `out/`
  (the repo root, `out/` itself, `data/`, `src/`, `docs/`, `tests/`, `.git`), when it is an existing file, or (stitch
  only, because the folder is replaced whole) when it is an existing folder holding anything but the ten file names.
  An existing folder holding only those names is rebuilt. The default folder keeps its spec 3 behaviour.
- the check CLIs write their one file into DIR and refuse protected targets the same way.

Fast, synthetic (temp repos from `stitch_fixtures` and the T7.4 writer world); nothing real is opened.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import stitch_fixtures as sf  # noqa: E402
from stitch import check_index as ci  # noqa: E402
from stitch import check_links as cl  # noqa: E402
from stitch import outdir  # noqa: E402
from stitch.errors import StitchError  # noqa: E402
from test_stitch_outputs import FILES, build_repo  # noqa: E402

sm = importlib.import_module("stitch.__main__")


def run(fake, out: Path | None = None, trial: str | None = None) -> int:
    argv = ["--trial", trial or fake.trial, "--repo", str(fake.repo)]
    return sm.main(argv + (["--out", str(out)] if out is not None else []))


def blobs(folder: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(folder.iterdir())}


def without_time(run_info: bytes) -> dict:
    d = json.loads(run_info)
    d.pop("generated_utc")
    return d


# ================================================================================================ python -m stitch --out
def test_output_files_constant_is_the_ten_spec_files():
    assert list(sm.OUTPUT_FILES) == FILES


def test_out_outside_the_repo_writes_the_ten_files_and_not_the_default_folder(tmp_path, capsys):
    fake = build_repo(tmp_path)
    target = tmp_path / "elsewhere" / "run1"
    assert run(fake, target) == 0
    assert sorted(p.name for p in target.iterdir()) == FILES
    assert not (fake.repo / "out" / "stitch").exists()
    assert capsys.readouterr().out.strip() == target.resolve().as_posix()
    assert sorted(p.name for p in target.parent.iterdir()) == ["run1"]          # no .tmp / .old sibling left


def test_out_bytes_equal_a_default_run_except_the_run_info_timestamp(tmp_path):
    fake = build_repo(tmp_path)
    target = tmp_path / "elsewhere"
    assert run(fake) == 0
    assert run(fake, target) == 0
    default, moved = blobs(fake.repo / "out" / "stitch" / fake.trial), blobs(target)
    assert sorted(default) == sorted(moved) == FILES
    for name in FILES:
        if name != "run_info.json":
            assert default[name] == moved[name], name
    assert without_time(default["run_info.json"]) == without_time(moved["run_info.json"])


def test_out_below_the_repo_out_folder_is_allowed(tmp_path):
    fake = build_repo(tmp_path)
    target = fake.repo / "out" / "stitch_alt" / fake.trial
    assert run(fake, target) == 0
    assert sorted(p.name for p in target.iterdir()) == FILES


def test_an_existing_out_folder_holding_only_the_ten_names_is_rebuilt(tmp_path):
    fake = build_repo(tmp_path)
    target = tmp_path / "again"
    assert run(fake, target) == 0
    (target / "links.csv").write_text("old\n", encoding="utf-8")
    assert run(fake, target) == 0
    assert (target / "links.csv").read_text(encoding="utf-8") != "old\n"
    assert sorted(p.name for p in target.iterdir()) == FILES


@pytest.mark.parametrize("extra", ["notes.txt", "sub_folder"])
def test_an_existing_out_folder_with_foreign_entries_is_refused_and_left_untouched(tmp_path, capsys, extra):
    fake = build_repo(tmp_path)
    target = tmp_path / "mine"
    target.mkdir()
    if extra == "sub_folder":
        (target / extra).mkdir()
        (target / extra / "keep.txt").write_text("keep", encoding="utf-8")
    else:
        (target / extra).write_text("keep", encoding="utf-8")
    (target / "links.csv").write_text("keep too\n", encoding="utf-8")
    before = sf.snapshot(tmp_path)
    assert run(fake, target) == 2
    err = capsys.readouterr().err
    assert err.startswith("refused:") and extra in err
    assert sf.snapshot(tmp_path) == before


def test_out_naming_an_existing_file_is_refused(tmp_path, capsys):
    fake = build_repo(tmp_path)
    target = tmp_path / "a_file.txt"
    target.write_text("x", encoding="utf-8")
    before = sf.snapshot(tmp_path)
    assert run(fake, target) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert sf.snapshot(tmp_path) == before


@pytest.mark.parametrize("rel", [".", "out", "data", "data/processed/x", "src", "src/stitch", "docs/x", "tests/x",
                                 ".git/x", "anything_else"])
def test_out_inside_the_repo_but_not_below_out_is_refused_and_nothing_is_written(tmp_path, capsys, rel):
    fake = build_repo(tmp_path)
    (fake.repo / "src").mkdir(exist_ok=True)
    before = sf.snapshot(fake.repo)
    assert run(fake, fake.repo / rel) == 2
    assert "refused:" in capsys.readouterr().err
    assert sf.snapshot(fake.repo) == before


def test_out_with_dot_dot_escaping_out_is_refused(tmp_path, capsys):
    fake = build_repo(tmp_path)
    before = sf.snapshot(fake.repo)
    assert run(fake, fake.repo / "out" / ".." / "data" / "x") == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert sf.snapshot(fake.repo) == before


def test_a_test_trial_with_out_is_refused_by_the_allowlist_and_out_is_never_touched(tmp_path, capsys):
    fake = build_repo(tmp_path)
    target = tmp_path / "never"
    assert run(fake, target, trial="s02_t02") == 2
    assert "046" in capsys.readouterr().err
    assert not target.exists()


def test_a_section_2_refusal_with_out_writes_nothing(tmp_path, capsys):
    fake = build_repo(tmp_path, stats_db_sha_after="0" * 64)
    target = tmp_path / "never"
    assert run(fake, target) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert not target.exists()


def test_the_default_folder_still_replaces_a_stale_file(tmp_path):
    """Spec 3 'rebuilt on every run' is unchanged for the default folder: only an explicit --out is protected."""
    fake = build_repo(tmp_path)
    folder = fake.repo / "out" / "stitch" / fake.trial
    folder.mkdir(parents=True)
    (folder / "stale.txt").write_text("old", encoding="utf-8")
    assert run(fake) == 0
    assert sorted(p.name for p in folder.iterdir()) == FILES


# ================================================================================================ check CLIs --out
@pytest.mark.parametrize("mod,fname", [(ci, "t72_index.json"), (cl, "t73_links.json")], ids=["check_index", "check_links"])
def test_check_cli_out_writes_its_one_file_there_and_not_under_out(tmp_path, mod, fname):
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)])
    target = tmp_path / "chk"
    assert mod.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(target)]) == 0
    assert [p.name for p in target.iterdir()] == [fname]
    assert not (fake.repo / "out" / "stitch_check").exists()
    default = fake.repo / "out" / "stitch_check" / fake.trial / fname
    assert mod.main(["--trial", fake.trial, "--repo", str(fake.repo)]) == 0
    assert default.read_bytes() == (target / fname).read_bytes()


@pytest.mark.parametrize("mod", [ci, cl], ids=["check_index", "check_links"])
@pytest.mark.parametrize("rel", ["data/x", "src", "."])
def test_check_cli_out_inside_the_repo_but_not_below_out_is_refused(tmp_path, capsys, mod, rel):
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)])
    before = sf.snapshot(fake.repo)
    assert mod.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(fake.repo / rel)]) == 2
    assert capsys.readouterr().err.startswith("refused:")
    assert sf.snapshot(fake.repo) == before


@pytest.mark.parametrize("mod", [ci, cl], ids=["check_index", "check_links"])
def test_check_cli_test_trial_with_out_is_refused_and_out_is_never_touched(tmp_path, mod):
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)])
    target = tmp_path / "never"
    assert mod.main(["--trial", "s02_t02", "--repo", str(fake.repo), "--out", str(target)]) == 2
    assert not target.exists()


@pytest.mark.parametrize("mod", [ci, cl], ids=["check_index", "check_links"])
def test_check_cli_out_keeps_other_files_in_the_folder(tmp_path, mod):
    """The check CLIs write one file and delete nothing, so a shared folder is fine."""
    fake = sf.make_repo(tmp_path, [sf.logon("E0", 1.0, 1000)])
    target = tmp_path / "shared"
    target.mkdir()
    (target / "other.txt").write_text("keep", encoding="utf-8")
    assert mod.main(["--trial", fake.trial, "--repo", str(fake.repo), "--out", str(target)]) == 0
    assert (target / "other.txt").read_text(encoding="utf-8") == "keep"


# ================================================================================================ outdir helpers (pure)
def test_protected_reason_outside_the_repo_is_none(tmp_path):
    assert outdir.protected_reason(tmp_path / "x", tmp_path / "repo") is None


@pytest.mark.parametrize("rel,ok", [("out/a", True), ("out/a/b", True), ("out", False), (".", False),
                                    ("outx/a", False), ("data/out/a", False), ("x/out/a", False)])
def test_protected_reason_inside_the_repo_allows_only_below_out(tmp_path, rel, ok):
    repo = tmp_path / "repo"
    assert (outdir.protected_reason(repo / rel, repo) is None) is ok


def test_foreign_entries_of_a_missing_folder_is_empty(tmp_path):
    assert outdir.foreign_entries(tmp_path / "none", ["a"]) == []


def test_foreign_entries_lists_unknown_files_and_every_sub_folder_sorted(tmp_path):
    (tmp_path / "a").write_text("", encoding="utf-8")
    (tmp_path / "z.txt").write_text("", encoding="utf-8")
    (tmp_path / "a_dir").mkdir()
    (tmp_path / "links.csv").mkdir()                    # a folder named like an allowed file still counts
    assert outdir.foreign_entries(tmp_path, ["a", "links.csv"]) == ["a_dir", "links.csv", "z.txt"]


def test_check_out_target_message_names_at_most_three_entries(tmp_path):
    for n in range(5):
        (tmp_path / f"f{n}").write_text("", encoding="utf-8")
    with pytest.raises(StitchError) as exc:
        outdir.check_out_target(tmp_path, tmp_path.parent / "repo", ["x"])
    msg = str(exc.value)
    assert "5 entries" in msg and "f0, f1, f2, ..." in msg and "f3" not in msg


def test_check_out_target_with_allowed_none_accepts_a_folder_with_other_files(tmp_path):
    (tmp_path / "other").write_text("", encoding="utf-8")
    outdir.check_out_target(tmp_path, tmp_path.parent / "repo", None)
