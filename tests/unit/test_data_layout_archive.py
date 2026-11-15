"""Tests for the one-time archive of the old S04/S07 t01-t10 copies (T6c Task 3; plan 2026-11-15; decision 034 with
the 052 amendment; attacker review x10_archive_tooling 2026-11-15, all 14 items).

Written from the plan, the review's "Disposition" column and the brief, not from the code. Synthetic temp repos only
(tests/unit/archive_fixtures.py): tiny fake bytes, no real EVTX, no t02-t10 data, nothing in the real repo is read or
written. `retire-failed` is tested in test_data_layout_retire_failed.py.

API CONTRACT these tests pin (the implementer follows it)
=========================================================
Module ``data_layout.archive``

* ``class ArchiveError(Exception)``: every refusal and every incomplete run. A refusal leaves the whole tree
  byte-for-byte untouched (not even an empty folder is created).
* ``@dataclass(frozen=True) ArchiveSpec(label, scenarios, trials, source_prefix, ...)``: the first four fields are
  positional-or-keyword; any further field must have a default. Constructing a spec that selects ``t00`` may raise
  ``ValueError`` at once, or ``plan_archive`` raises ``ArchiveError``/``ValueError``.
* ``V1``: label ``archive_x10_v1``, scenarios ``("s04", "s07")``, trials ``t01..t10``, source_prefix ``"x10/"``.
  Strict: a listed file that is missing or an unclassified file under the trial's paths is a refusal; ``-wal``/``-shm``
  beside a DB is a refusal.
* ``failed_attempt_spec(scenario, trial, attempt)``: label ``x10_v2_failed_<s>_attempt_<N>``, scenarios ``(s,)``,
  trials ``(t,)``, source_prefix ``"x10_v2/"``; tolerant policy. ``ValueError`` for: scenario not in s01/s04/s05/s07,
  trial not ``t01``..``t10`` (``t00``, ``t1``, ``t010``, ``t11``), anything with ``..`` or a path separator, an attempt
  that is not a positive ``int``.
* ``plan_archive(roots, spec)`` pure, writes NOTHING (no folder either), runs every pre-check (hashes included),
  returns a plan object, raises ``ArchiveError`` on refusal.
* ``execute_archive(roots, plan)`` returns a result with ``.ok``, ``.expected`` and ``.verified`` (ints = number of
  per-trial files in the journal, and how many of them have the destination re-hashed equal to the journal hash AND the
  source gone). ``ok`` is ``expected == verified``. A copy whose hash differs raises ``ArchiveError`` and deletes
  nothing. An incomplete run (a source cannot be unlinked after a bounded
  retry) finishes everything else, writes the report with ``status`` != ``"ok"`` and raises ``ArchiveError``. A run
  with nothing left to do is a no-op that writes nothing and returns an ``ok`` result.
* ``verify_archive(roots, spec)`` read-only, looks at the ARCHIVE side only (the normal paths may by then hold a new
  v2 trial under the same names); returns ``.ok``, ``.expected``, ``.verified``, ``.problems``. Expected = journal
  entries; verified = destination exists and its sha256 equals the journal (V1 raw files: also the original
  ``out/ingest/x10/<id>/ingest.json`` sha). An empty or half archive (missing data file, archive manifest or journal) is
  not ok; a flipped byte counts as not verified.
* Layout written (plan table; ``L`` = label): raw ``data/raw/L/<s>/<t>/...``; DB and clock csv
  ``data/processed/L/<name>``; JSONL ``data/processed/L/jsonl/<id>/``; ``out/normalise/L/<id>/``,
  ``out/clock_offset/L/<id>/``; manifest rows ``data/manifest_L.csv`` (CRLF, same header, ``path`` prefixed ``L/``,
  every other byte of the line unchanged); ``out/L/journal.json`` (every file: source path, sha256, size; written before
  the first copy and so before any delete), ``out/L/archive_report.json`` (ints ``expected`` and ``verified``, string
  ``status``, lists ``trials``, ``files`` (each with ``path``, ``dest``, ``sha256``, ``size``, ``action``),
  ``missing``, ``extra`` (tolerant presets: expected items that are absent / items moved that no record names, e.g.
  ``.sqlite3.tmp``; both ``[]`` for a clean trial), ``orphans`` (all paths in the report are repo-relative posix; ``.part`` files seen, never moved or counted)), ``out/L/archive_report.md``,
  ``out/L/run_log.jsonl`` (one JSON line appended per run that does work; never overwritten). Failed attempts also move
  ``out/ingest/x10_v2/<id>/`` to ``out/ingest/L/<id>/`` and ``out/x10_validate_v2/<id>.json`` to
  ``out/x10_validate_v2/L/<id>.json``.
* Order: journal -> copy every file (``layout.copy_one``, copies via ``shutil.copyfile``) -> write archive manifest ->
  rewrite ``data/manifest.csv`` -> delete sources one by one with ``os.unlink`` (never ``rmtree``), ``rmdir`` of emptied
  folders. A copy whose hash differs deletes nothing.
* Test hooks: module-level ``_checkpoint(name)`` is called (looked up as a module global at call time) at
  ``"after_copy"``, ``"after_archive_manifest"``, ``"before_main_manifest_replace"`` (tmp manifest written, just before
  ``os.replace``), ``"after_main_manifest"``, ``"before_delete"`` (immediately before the first unlink).
* Manifest rewrite: byte level on ``\\r\\n``; a manifest with a BOM, or not ending in ``\\r\\n``, is refused; the lock file
  ``data/manifest.csv.lock`` (same name as the batch ingest) is created exclusively for the whole rewrite and removed
  afterwards (also after a failure); an existing lock is a refusal; just before ``os.replace`` the on-disk bytes must
  still start with the bytes read at the beginning, otherwise ``ArchiveError`` (the appended bytes survive).
  Rows with the same ``path`` are all moved, or the run is refused (different sha for the same path: refused).
* V1 selection: AND of scenario in (s04, s07), trial matching ``^t(0[1-9]|10)$`` and manifest ``source_path`` starting
  ``x10/`` (trailing slash). A manifest row of such a trial whose ``source_path`` starts ``x10_v2/`` is a refusal ("archive
  too late"), as is a folder ``out/ingest/x10_v2/<id>`` for such a trial, UNLESS the archive has already been completed
  (journal complete): then the run is an idempotent no-op.
* ``out/ingest/x10/<id>/`` and ``out/x10_validate/<id>.json`` of archived ids STAY (plan); batch (source x10) treats an
  id listed in ``out/archive_x10_v1/archive_report.json["trials"]`` as "archived, skipped".

CLI (``python -m data_layout.cli``; every subcommand has ``--repo``; ``main(argv)`` returns the exit code, argparse
errors raise ``SystemExit``)
  ``archive-v1 [--execute]``  dry run by default (prints the plan, the ids and counts, the word "dry run"; writes
  nothing); exit 0 only when the plan is clean (or already done), non-zero on refusal.
  ``archive-verify``           verifies V1; exit 0 only when ``expected == verified`` and ``expected > 0``.
  ``retire-failed --scenario s04 --trial t01 --attempt N [--execute]``  see test_data_layout_retire_failed.py.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from data_layout import archive, batch, cli  # noqa: E402
from archive_fixtures import (V1_LABEL, build_v1, csv_line, files_of, make_link, manifest_bytes, sha,  # noqa: E402
                              split_manifest, tree, write)


class Killed(BaseException):
    """Simulated hard stop (BaseException so that ``except Exception`` in the tool cannot swallow it)."""


# ---------- helpers ----------

def roots_of(repo: Path):
    return batch.Roots.from_repo(repo)


def run_archive(repo: Path, spec=None):
    roots = roots_of(repo)
    plan = archive.plan_archive(roots, spec or archive.V1)
    return archive.execute_archive(roots, plan)


def cli_rc(argv: list[str]) -> int:
    try:
        return cli.main(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1


def v1_cli(repo: Path, *extra: str) -> int:
    return cli_rc(["archive-v1", "--repo", str(repo), *extra])


def report_of(repo: Path, label: str = V1_LABEL) -> dict:
    return json.loads((repo / "out" / label / "archive_report.json").read_text(encoding="utf-8"))


def kill_at(monkeypatch, name: str, nth: int = 1) -> None:
    seen = {"n": 0}

    def hook(step: str) -> None:
        if step == name:
            seen["n"] += 1
            if seen["n"] == nth:
                raise Killed(step)
    monkeypatch.setattr(archive, "_checkpoint", hook)


@pytest.fixture
def w(tmp_path):
    return build_v1(tmp_path)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """The tool may sleep between bounded retries; the tests must not wait."""
    monkeypatch.setattr("time.sleep", lambda s: None)


def assert_refused(repo: Path, spec=None, words: tuple[str, ...] = ()) -> str:
    """The run is refused (library and CLI) and the whole tmp tree is byte-for-byte unchanged."""
    before = tree(repo)
    assert v1_cli(repo, "--execute") != 0
    assert tree(repo) == before, "CLI refusal changed the tree"
    with pytest.raises(archive.ArchiveError) as ei:
        run_archive(repo, spec)
    assert tree(repo) == before, "refusal changed the tree"
    msg = str(ei.value).lower()
    if words:
        assert any(x in msg for x in words), f"message {msg!r} names none of {words}"
    return msg


def after_run_reference(tmp_path_factory) -> dict:
    """Tree of a clean uninterrupted V1 run on a fresh world (run folder out/archive_x10_v1 excluded)."""
    ref = tmp_path_factory.mktemp("ref")
    build_v1(ref)
    run_archive(ref)
    return tree(ref, exclude=("out/" + V1_LABEL,))


# ============================================================================ presets and arguments

def test_v1_preset_fields():
    assert archive.V1.label == "archive_x10_v1"
    assert tuple(archive.V1.scenarios) == ("s04", "s07")
    assert tuple(archive.V1.trials) == tuple(f"t{n:02d}" for n in range(1, 11))
    assert "t00" not in archive.V1.trials
    assert archive.V1.source_prefix == "x10/"


def test_failed_attempt_spec_fields():
    s = archive.failed_attempt_spec("s04", "t01", 2)
    assert s.label == "x10_v2_failed_s04_attempt_2"
    assert tuple(s.scenarios) == ("s04",) and tuple(s.trials) == ("t01",)
    assert s.source_prefix == "x10_v2/"


@pytest.mark.parametrize("scenario,trial,attempt", [
    ("s02", "t01", 1), ("s03", "t01", 1), ("s06", "t01", 1), ("s08", "t01", 1), ("../s04", "t01", 1),
    ("s04/..", "t01", 1), ("s040", "t01", 1), ("s04", "..", 1), ("s04", "t00", 1), ("s04", "t11", 1),
    ("s04", "t1", 1), ("s04", "t010", 1), ("s04", "t01/..", 1), ("s04", "t01\\x", 1),
    ("s04", "t01", 0), ("s04", "t01", -1), ("s04", "t01", "1"), ("s04", "t01", "1/../x"), ("s04", "t01", 1.5),
    ("s04", "t01", None),
])
def test_failed_attempt_spec_rejects_unsafe_arguments(scenario, trial, attempt):
    with pytest.raises(ValueError):
        archive.failed_attempt_spec(scenario, trial, attempt)


def test_spec_selecting_t00_is_refused_by_the_plan_builder(w):
    before = tree(w.repo)
    with pytest.raises((archive.ArchiveError, ValueError)):
        spec = archive.ArchiveSpec(label="archive_x10_v1", scenarios=("s04",), trials=("t00", "t01"),
                                   source_prefix="x10/")
        archive.plan_archive(roots_of(w.repo), spec)
    assert tree(w.repo) == before


def test_archive_labels_never_look_like_trial_ids():
    """Item 12: an archived copy must not be mistaken for a live trial by any id pattern in the repo."""
    from x10_validate import cli as vcli
    labels = [archive.V1.label, archive.failed_attempt_spec("s04", "t01", 1).label,
              archive.failed_attempt_spec("s07", "t10", 12).label]
    for label in labels:
        assert not batch.TRIAL_RE.match(label) and not batch.SCENARIO_RE.match(label)
        assert not vcli.TRIAL_RE.match(label)
        assert not fnmatch.fnmatch(label, "s0?_t??") and not fnmatch.fnmatch(label + ".sqlite3", "s0?_t??.sqlite3")
        assert re.fullmatch(r"[a-z0-9_]+", label)
        assert not (label.startswith("s0") and label[3:4] == "_")


# ============================================================================ V1 happy path

def test_v1_full_move_dests_identical_sources_gone(w):
    res = run_archive(w.repo)
    assert res.ok and res.expected == res.verified == len(w.moved)
    for rel in w.moved:
        assert not (w.repo / rel).exists(), f"source left behind: {rel}"
        dest = w.repo / w.dest_of(rel)
        assert dest.is_file() and dest.read_bytes() == w.initial[rel], f"dest wrong: {rel}"
    # emptied trial folders are removed; folders of staying trials are kept
    for tid in w.ids:
        s, t = tid.split("_")
        assert not (w.repo / "data/raw" / s / t).exists()
        assert not (w.repo / "data/processed/jsonl" / tid).exists()
        assert not (w.repo / "out/normalise" / tid).exists()
    assert (w.repo / "data/raw/s04/t00").is_dir()


def test_v1_selection_leaves_everything_else_untouched(w):
    """t00, t1/t010/t11 look-alikes, S04/S07 look-alikes (s040), other scenarios, ingest.json and validator json,
    data/incoming, ground_truth: all byte-identical and in place."""
    run_archive(w.repo)
    for rel in w.stay:
        if rel == "data/manifest.csv":
            continue                                    # rewritten on purpose; checked byte-exact elsewhere
        assert (w.repo / rel).read_bytes() == w.initial[rel], f"staying file changed or gone: {rel}"
    for ident in ("s04_t00", "s07_t00", "s02_t01", "s03_t01", "s04_t1", "s04_t010", "s04_t11", "s14_t01", "s040_t01"):
        assert (w.repo / "data/processed" / f"{ident}.sqlite3").is_file()
    for ident in w.ids:  # plan: out/ingest/x10 and out/x10_validate stay
        assert (w.repo / "out/ingest/x10" / ident / "ingest.json").is_file()
        assert (w.repo / "out/x10_validate" / f"{ident}.json").is_file()


def test_v1_manifest_split_byte_exact(w):
    run_archive(w.repo)
    got = (w.repo / "data/manifest.csv").read_bytes()
    kept = [x for x in w.lines if x not in w.moved_lines]
    assert got == manifest_bytes(kept), "main manifest is not the original minus exactly the moved lines"
    assert not got.startswith(b"\xef\xbb\xbf") and got.endswith(b"\r\n") and b"\n" not in got.replace(b"\r\n", b"")
    assert split_manifest(got) == kept          # other lines unchanged, same order, quoted line intact
    assert len(w.moved_lines) == 3 * len(w.ids)


def test_v1_archive_manifest_bytes(w):
    run_archive(w.repo)
    data = (w.repo / "data/manifest_archive_x10_v1.csv").read_bytes()
    assert data == manifest_bytes([f"{V1_LABEL}/".encode() + x for x in w.moved_lines])
    assert not data.startswith(b"\xef\xbb\xbf") and data.endswith(b"\r\n")
    assert not (w.repo / "data/manifest_archive_x10_v1.csv").name == "manifest.csv"


def test_v1_journal_holds_every_source_hash(w):
    run_archive(w.repo)
    text = (w.repo / "out" / V1_LABEL / "journal.json").read_text(encoding="utf-8")
    for rel in w.moved:
        assert sha(w.initial[rel]) in text, f"journal lacks the hash of {rel}"


def test_v1_report_counts_trials_and_files(w):
    run_archive(w.repo)
    rep = report_of(w.repo)
    assert rep["expected"] == rep["verified"] == len(w.moved)
    assert rep["status"] == "ok"
    assert sorted(rep["trials"]) == sorted(w.ids)
    by_path = {f["path"]: f for f in rep["files"]}
    for rel in w.moved:
        f = by_path[rel]
        assert f["sha256"] == sha(w.initial[rel]) and f["size"] == len(w.initial[rel])
        assert f["dest"] == w.dest_of(rel) and f["action"]
    assert (w.repo / "out" / V1_LABEL / "archive_report.md").is_file()
    log = (w.repo / "out" / V1_LABEL / "run_log.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(log) >= 1 and all(json.loads(line) for line in log)


def test_lock_file_removed_after_a_successful_run(w):
    run_archive(w.repo)
    assert not (w.repo / "data/manifest.csv.lock").exists()


def test_no_archived_trial_is_visible_to_discover_or_overlap(w, monkeypatch):
    """Item 12: x10_validate.discover and answer_key.overlap.shared_trials find nothing that was archived."""
    from x10_validate import cli as vcli
    from answer_key import overlap
    before = set(vcli.discover(w.repo))
    assert set(w.ids) <= before, "fixture should expose the moved ids to discover before the archive"
    run_archive(w.repo)
    after = set(vcli.discover(w.repo))
    assert after == before - set(w.ids)
    opened: list[str] = []
    monkeypatch.setattr(overlap, "shas_in_db", lambda dbp, shas: opened.append(Path(dbp).name) or set())
    overlap.shared_trials(w.repo / "data" / "processed", "s02_t01", ["x"])
    assert opened and not any(Path(n).stem in w.ids for n in opened)
    assert not [p for p in (w.repo / "data/processed").glob("*.sqlite3") if p.stem in w.ids]
    assert not [p for p in (w.repo / "data/processed/quarantine").glob("*.sqlite3")] \
        if (w.repo / "data/processed/quarantine").exists() else True


def test_batch_x10_treats_archived_ids_as_archived_skipped(w, capsys):
    """Item 3: the surviving out/ingest/x10/<id>/ingest.json must not make an x10 batch re-ingest the old trial."""
    run_archive(w.repo)
    ingest = w.repo / "out/ingest/x10/s04_t01/ingest.json"
    before_ingest = ingest.read_bytes()
    capsys.readouterr()
    rc = cli_rc(["batch", "--repo", str(w.repo), "--only", "s04_t01"])
    out = capsys.readouterr().out.lower()
    assert rc == 0, out
    assert "archived" in out
    assert ingest.read_bytes() == before_ingest, "the old ingest report was rewritten"
    assert not (w.repo / "data/raw/s04/t01").exists() and not (w.repo / "data/processed/s04_t01.sqlite3").exists()


# ============================================================================ V1 refusals (nothing moved, nothing deleted)

def test_refuse_raw_hash_differs_from_ingest_json(w):
    p = w.repo / "data/raw/s04/t02/ep-01/security.evtx"
    p.write_bytes(p.read_bytes() + b"x")          # raw, manifest and ingest.json now disagree about the raw file
    assert_refused(w.repo)


def test_refuse_raw_matches_manifest_but_not_ingest_json(w):
    """The manifest alone does not prove the v1 set: ingest.json's files_copied sha must agree too."""
    ij = w.repo / "out/ingest/x10/s04_t02/ingest.json"
    d = json.loads(ij.read_text(encoding="utf-8"))
    d["files_copied"][0]["sha256"] = sha(b"some other file")
    ij.write_text(json.dumps(d), encoding="utf-8")
    assert_refused(w.repo)


def test_refuse_raw_matches_ingest_json_but_not_manifest(w):
    mp = w.repo / "data/manifest.csv"
    data = mp.read_bytes()
    target = sha(w.initial["data/raw/s07/t05/dc01/security.evtx"]).encode()
    mp.write_bytes(data.replace(target, sha(b"tampered").encode(), 1))
    assert_refused(w.repo)


def test_refuse_listed_raw_file_missing(w):
    (w.repo / "data/raw/s04/t10/ep-01/sysmon.evtx").unlink()
    assert_refused(w.repo)


def test_refuse_ingest_json_missing_for_a_moved_id(w):
    (w.repo / "out/ingest/x10/s07_t05/ingest.json").unlink()
    assert_refused(w.repo)


def test_refuse_db_missing_but_clock_csv_present(w):
    """Item 13: clock_offsets.csv is bound to the DB hash; DB and csvs move together or the archive refuses."""
    (w.repo / "data/processed/s04_t01.sqlite3").unlink()
    assert_refused(w.repo)


def test_refuse_unclassified_file_in_raw_trial_folder(w):
    write(w.repo, "data/raw/s04/t02/ep-01/notes.txt", b"who put this here")
    assert_refused(w.repo)


def test_refuse_unclassified_file_in_data_processed(w):
    write(w.repo, "data/processed/s04_t02.weird.dat", b"unknown")
    assert_refused(w.repo)


def test_refuse_per_trial_output_of_another_stage_in_out(w):
    write(w.repo, "out/gate/s04_t01/gate.json", b"{}")
    assert_refused(w.repo)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_refuse_sqlite_sidecar_beside_db(w, suffix):
    """Item 9: -wal/-shm means the DB may be in use; V1 refuses (and never opens the DB)."""
    write(w.repo, f"data/processed/s04_t02.sqlite3{suffix}", b"x")
    assert_refused(w.repo, words=("wal", "shm", "sidecar", "in use", "unclassified"))


def test_refuse_v2_manifest_row_present_archive_too_late(w):
    mp = w.repo / "data/manifest.csv"
    row = csv_line({"path": "s04/t01/ep-01/security.evtx", "sha256": sha(b"new"), "size": "3", "scenario": "s04",
                    "trial": "t01", "host": "ep-01", "channel": "security",
                    "source_path": "x10_v2/S04/trial_01/ENDPOINT-01/x.evtx"})
    mp.write_bytes(mp.read_bytes() + row + b"\r\n")
    assert_refused(w.repo, words=("late", "v2"))


def test_refuse_v2_ingest_folder_present_archive_too_late(w):
    write(w.repo, "out/ingest/x10_v2/s07_t01/ingest.json", b"{}")
    assert_refused(w.repo, words=("late", "v2"))


def test_v2_rows_of_other_scenarios_do_not_block_the_archive(w):
    """Only s04/s07 t01-t10 matter: a v2 row for s05 or for s04 t00-lookalike ids is not 'too late'."""
    mp = w.repo / "data/manifest.csv"
    row = csv_line({"path": "s05/t01/ep-01/security.evtx", "sha256": sha(b"s5"), "size": "2", "scenario": "s05",
                    "trial": "t01", "host": "ep-01", "channel": "security",
                    "source_path": "x10_v2/S05/trial_01/ENDPOINT-01/x.evtx"})
    mp.write_bytes(mp.read_bytes() + row + b"\r\n")
    assert run_archive(w.repo).ok
    assert split_manifest(mp.read_bytes())[-1] == row


def test_refuse_destination_conflict_with_different_hash(w):
    dest = w.repo / "data/raw/archive_x10_v1/s04/t01/ep-01/security.evtx"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"a different file already sits here")
    assert_refused(w.repo)
    assert dest.read_bytes() == b"a different file already sits here"


def test_refuse_junction_as_source_folder(w, tmp_path_factory):
    ext = tmp_path_factory.mktemp("ext")
    real = w.repo / "data/processed/jsonl/s04_t02"
    for p in real.iterdir():
        p.rename(ext / p.name)
    real.rmdir()
    if not make_link(real, ext):
        pytest.skip("cannot create a symlink or junction here")
    ext_before = files_of(ext)
    assert_refused(w.repo, words=("link", "junction", "reparse", "symlink"))
    assert files_of(ext) == ext_before, "files behind the junction were touched"


def test_refuse_junction_as_destination_root(w, tmp_path_factory):
    ext = tmp_path_factory.mktemp("ext_dest")
    link = w.repo / "data/raw/archive_x10_v1"
    if not make_link(link, ext):
        pytest.skip("cannot create a symlink or junction here")
    assert_refused(w.repo, words=("link", "junction", "reparse", "symlink"))
    assert files_of(ext) == {}, "something was copied through the junction"


def test_refuse_manifest_with_bom(w):
    mp = w.repo / "data/manifest.csv"
    mp.write_bytes(b"\xef\xbb\xbf" + mp.read_bytes())
    assert_refused(w.repo, words=("bom",))


def test_refuse_manifest_without_final_newline(w):
    mp = w.repo / "data/manifest.csv"
    mp.write_bytes(mp.read_bytes()[:-2])
    assert_refused(w.repo, words=("newline", "crlf", "end", "terminat"))


def test_duplicate_identical_manifest_rows_are_all_moved_or_refused(w):
    mp = w.repo / "data/manifest.csv"
    dup = w.moved_lines[0]
    mp.write_bytes(mp.read_bytes() + dup + b"\r\n")
    before = tree(w.repo)
    try:
        run_archive(w.repo)
    except archive.ArchiveError:
        assert tree(w.repo) == before, "refused, but not cleanly"
        return
    remaining = split_manifest(mp.read_bytes())
    assert dup not in remaining, "a duplicate row of a moved path was left behind in the main manifest"
    assert all(x not in remaining for x in w.moved_lines)
    arch = split_manifest((w.repo / "data/manifest_archive_x10_v1.csv").read_bytes())
    assert {x.split(b",")[0] for x in arch} >= {f"{V1_LABEL}/".encode() + dup.split(b",")[0]}


def test_refuse_duplicate_manifest_path_with_different_sha(w):
    mp = w.repo / "data/manifest.csv"
    first = w.moved_lines[0].split(b",")
    first[1] = sha(b"other").encode()
    mp.write_bytes(mp.read_bytes() + b",".join(first) + b"\r\n")
    assert_refused(w.repo)


def test_refuse_when_lock_file_exists(w):
    lock = w.repo / "data/manifest.csv.lock"
    lock.write_bytes(b"")
    assert_refused(w.repo, words=("lock",))
    assert lock.exists(), "the tool must not remove a lock it does not own"


def test_part_orphans_are_reported_never_counted_or_moved(w):
    """Item 14: a leftover `.part` (interrupted copy) next to a source file is not evidence."""
    orphan = w.repo / "data/raw/s04/t02/ep-01/security.evtx.part"
    orphan.write_bytes(b"half copy")
    dest_orphan = w.repo / "data/raw/archive_x10_v1/s04/t10/ep-01/sysmon.evtx.part"
    dest_orphan.parent.mkdir(parents=True)
    dest_orphan.write_bytes(b"older half copy")
    res = run_archive(w.repo)
    assert res.ok and res.expected == len(w.moved)
    assert orphan.read_bytes() == b"half copy", "an orphan was moved or deleted"
    rep = report_of(w.repo)
    assert "security.evtx.part" in json.dumps(rep["orphans"])
    assert all(not f["dest"].endswith(".part") for f in rep["files"])
    final = w.repo / "data/raw/archive_x10_v1/s04/t10/ep-01/sysmon.evtx"
    assert final.read_bytes() == w.initial["data/raw/s04/t10/ep-01/sysmon.evtx"]


# ============================================================================ dry run and incoming

def test_dry_run_writes_nothing_and_names_the_plan(w, capsys):
    before = tree(w.repo)
    capsys.readouterr()
    assert v1_cli(w.repo) == 0
    out = capsys.readouterr().out
    assert tree(w.repo) == before, "dry run changed the tree (files, folders or hashes)"
    assert "dry run" in out.lower()
    assert all(i in out for i in w.ids)


def test_plan_archive_alone_writes_nothing(w):
    before = tree(w.repo)
    archive.plan_archive(roots_of(w.repo), archive.V1)
    assert tree(w.repo) == before


def test_dry_run_still_refuses_and_writes_nothing(w):
    (w.repo / "data/raw/s04/t10/ep-01/sysmon.evtx").write_bytes(b"flipped")
    before = tree(w.repo)
    assert v1_cli(w.repo) != 0
    assert tree(w.repo) == before


def test_data_incoming_unchanged_by_success(w):
    inc = w.repo / "data" / "incoming"
    before = tree(inc)
    assert before, "fixture must have an incoming folder"
    run_archive(w.repo)
    assert tree(inc) == before


def test_data_incoming_unchanged_by_refusal(tmp_path):
    w = build_v1(tmp_path)
    write(w.repo, "data/raw/s04/t02/ep-01/notes.txt", b"stray")
    before = tree(w.repo / "data" / "incoming")
    with pytest.raises(archive.ArchiveError):
        run_archive(w.repo)
    assert tree(w.repo / "data" / "incoming") == before


# ============================================================================ idempotence and "too late"

def test_second_execute_is_a_noop_that_writes_nothing(w):
    run_archive(w.repo)
    before = tree(w.repo)
    res = run_archive(w.repo)
    assert res.ok and res.expected == res.verified
    assert tree(w.repo) == before
    assert v1_cli(w.repo, "--execute") == 0
    assert tree(w.repo) == before


def test_second_execute_after_a_v2_ingest_is_a_noop_not_archive_too_late(w):
    """Item 7: once done, v2 rows and out/ingest/x10_v2 for the same ids must not trigger the refusal."""
    run_archive(w.repo)
    mp = w.repo / "data/manifest.csv"
    row = csv_line({"path": "s04/t01/ep-01/security.evtx", "sha256": sha(b"new"), "size": "3", "scenario": "s04",
                    "trial": "t01", "host": "ep-01", "channel": "security",
                    "source_path": "x10_v2/S04/trial_01/ENDPOINT-01/x.evtx"})
    mp.write_bytes(mp.read_bytes() + row + b"\r\n")
    write(w.repo, "data/raw/s04/t01/ep-01/security.evtx", b"new")          # the new trial sits on the normal path
    write(w.repo, "data/processed/s04_t01.sqlite3", b"new db")
    write(w.repo, "out/ingest/x10_v2/s04_t01/ingest.json", b'{"source": "x10_v2"}')
    before = tree(w.repo)
    assert v1_cli(w.repo, "--execute") == 0
    res = run_archive(w.repo)
    assert res.ok
    assert tree(w.repo) == before, "the no-op touched the new v2 trial or the archive"
    assert v1_cli(w.repo) == 0                       # a dry run of a done archive is clean too


# ============================================================================ durability and resume

CHECKPOINTS = ["after_copy", "after_archive_manifest", "before_main_manifest_replace", "after_main_manifest",
               "before_delete"]


@pytest.mark.parametrize("point", CHECKPOINTS)
def test_kill_before_any_delete_keeps_all_sources_then_resume_completes(w, monkeypatch, tmp_path_factory, point):
    ref = after_run_reference(tmp_path_factory)
    original_manifest = (w.repo / "data/manifest.csv").read_bytes()
    with monkeypatch.context() as m:
        kill_at(m, point)
        with pytest.raises(Killed):
            run_archive(w.repo)
    for rel in w.moved:
        assert (w.repo / rel).read_bytes() == w.initial[rel], f"{point}: source gone or changed: {rel}"
    if point in ("after_copy", "after_archive_manifest", "before_main_manifest_replace"):
        assert (w.repo / "data/manifest.csv").read_bytes() == original_manifest
    else:
        assert (w.repo / "data/manifest.csv").read_bytes() == manifest_bytes(
            [x for x in w.lines if x not in w.moved_lines])
    assert not (w.repo / "data/manifest.csv.lock").exists(), "lock leaked by an interrupted run"
    journal = w.repo / "out" / V1_LABEL / "journal.json"
    assert journal.is_file()
    log_before = (w.repo / "out" / V1_LABEL / "run_log.jsonl").read_bytes() \
        if (w.repo / "out" / V1_LABEL / "run_log.jsonl").exists() else b""
    res = run_archive(w.repo)                         # resume
    assert res.ok and res.expected == res.verified == len(w.moved)
    assert tree(w.repo, exclude=("out/" + V1_LABEL,)) == ref
    assert (w.repo / "out" / V1_LABEL / "run_log.jsonl").read_bytes().startswith(log_before)
    assert archive.verify_archive(roots_of(w.repo), archive.V1).ok


def test_kill_after_archive_manifest_does_not_duplicate_archive_rows(w, monkeypatch):
    with monkeypatch.context() as m:
        kill_at(m, "after_archive_manifest")
        with pytest.raises(Killed):
            run_archive(w.repo)
    run_archive(w.repo)
    rows = split_manifest((w.repo / "data/manifest_archive_x10_v1.csv").read_bytes())
    assert len(rows) == len(set(rows)) == len(w.moved_lines)


def test_kill_in_the_middle_of_deleting_then_resume_completes(w, monkeypatch, tmp_path_factory):
    ref = after_run_reference(tmp_path_factory)
    moved_abs = {(w.repo / rel).resolve() for rel in w.moved}
    real, calls = os.unlink, {"n": 0}

    def fake(path, *a, **k):
        if Path(path).resolve() in moved_abs:
            calls["n"] += 1
            if calls["n"] == 3:
                raise Killed("mid delete")
        return real(path, *a, **k)
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", fake)
        with pytest.raises(Killed):
            run_archive(w.repo)
    gone = [rel for rel in w.moved if not (w.repo / rel).exists()]
    assert 0 < len(gone) < len(w.moved)
    for rel in w.moved:                               # every destination exists and is right before the first delete
        assert (w.repo / w.dest_of(rel)).read_bytes() == w.initial[rel]
    assert (w.repo / "data/manifest.csv").read_bytes() == manifest_bytes([x for x in w.lines if x not in w.moved_lines])
    res = run_archive(w.repo)                         # strict V1 must not refuse "listed file missing" on resume
    assert res.ok and res.expected == res.verified == len(w.moved)
    assert tree(w.repo, exclude=("out/" + V1_LABEL,)) == ref


def test_resume_checks_destinations_against_the_journal_hashes(w, monkeypatch):
    """After a partial delete, a destination whose source is already gone is checked against the journal: if it was
    damaged, the resume refuses and deletes nothing more."""
    moved_abs = {(w.repo / rel).resolve() for rel in w.moved}
    real, deleted = os.unlink, []

    def fake(path, *a, **k):
        if Path(path).resolve() in moved_abs:
            if len(deleted) == 1:
                raise Killed("after one delete")
            deleted.append(Path(path).resolve())
        return real(path, *a, **k)
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", fake)
        with pytest.raises(Killed):
            run_archive(w.repo)
    assert len(deleted) == 1
    gone_rel = next(rel for rel in w.moved if (w.repo / rel).resolve() == deleted[0])
    d = w.repo / w.dest_of(gone_rel)
    d.write_bytes(d.read_bytes() + b"!")              # the only remaining copy is damaged
    remaining = {rel for rel in w.moved if (w.repo / rel).exists()}
    with pytest.raises(archive.ArchiveError):
        run_archive(w.repo)
    assert {rel for rel in w.moved if (w.repo / rel).exists()} == remaining, "resume deleted after a bad journal hash"


def test_journal_exists_before_the_first_delete(w, monkeypatch):
    moved_abs = {(w.repo / rel).resolve() for rel in w.moved}
    journal = w.repo / "out" / V1_LABEL / "journal.json"
    real, seen = os.unlink, []

    def fake(path, *a, **k):
        if Path(path).resolve() in moved_abs:
            seen.append(journal.is_file() and all(sha(w.initial[r]) in journal.read_text(encoding="utf-8")
                                                  for r in w.moved))
        return real(path, *a, **k)
    monkeypatch.setattr(os, "unlink", fake)
    run_archive(w.repo)
    assert seen and all(seen), "a source was unlinked before the journal held every hash"


def test_sources_are_deleted_per_file_never_by_rmtree(w, monkeypatch):
    """Item 8: an unlisted file inside a moved folder must survive (V1 would refuse it earlier; the orphan `.part` is
    the one allowed stray), and shutil.rmtree is never called."""
    import shutil
    monkeypatch.setattr(shutil, "rmtree", lambda *a, **k: pytest.fail("rmtree called"))
    orphan = w.repo / "data/processed/jsonl/s04_t02/stray.part"
    orphan.write_bytes(b"x")
    run_archive(w.repo)
    assert orphan.read_bytes() == b"x"


def test_permission_error_on_unlink_is_resumable(w, monkeypatch, tmp_path_factory):
    ref = after_run_reference(tmp_path_factory)
    locked = (w.repo / "data/raw/s04/t02/ep-01/security.evtx").resolve()
    real, state = os.unlink, {"locked": True, "hits": 0}

    def fake(path, *a, **k):
        if state["locked"] and Path(path).resolve() == locked:
            state["hits"] += 1
            raise PermissionError(13, "The process cannot access the file because it is being used", str(path))
        return real(path, *a, **k)
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", fake)
        try:
            res = run_archive(w.repo)
            assert not res.ok
        except archive.ArchiveError:
            pass
        assert 1 <= state["hits"] <= 20, "retry must be bounded"
    assert locked.is_file()                                           # the locked source is still there, intact
    n = len(w.moved)
    rep = report_of(w.repo)
    assert rep["expected"] == n and rep["verified"] == n - 1 and rep["status"] != "ok"
    assert all(not (w.repo / rel).exists() for rel in w.moved if (w.repo / rel).resolve() != locked)
    assert (w.repo / "data/manifest.csv").read_bytes() == manifest_bytes([x for x in w.lines if x not in w.moved_lines])
    assert not (w.repo / "data/manifest.csv.lock").exists()
    res = run_archive(w.repo)                                         # unlocked: the next run completes
    assert res.ok and res.verified == res.expected == n
    assert tree(w.repo, exclude=("out/" + V1_LABEL,)) == ref


def test_cli_exit_code_nonzero_unless_verified_equals_expected(w, monkeypatch):
    locked = (w.repo / "data/raw/s07/t05/dc01/security.evtx").resolve()
    real = os.unlink

    def fake(path, *a, **k):
        if Path(path).resolve() == locked:
            raise PermissionError(13, "locked", str(path))
        return real(path, *a, **k)
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", fake)
        assert v1_cli(w.repo, "--execute") != 0
    assert v1_cli(w.repo, "--execute") == 0
    assert report_of(w.repo)["expected"] == report_of(w.repo)["verified"]


def test_copy_hash_mismatch_deletes_nothing(w, monkeypatch):
    import shutil
    real = shutil.copyfile

    def corrupt(src, dst, *a, **k):
        out = real(src, dst, *a, **k)
        if Path(src).name == "sysmon.evtx" and "s04" in Path(src).parts and "t10" in Path(src).parts:
            with open(dst, "ab") as f:
                f.write(b"!")                                         # the copy is not the source any more
        return out
    before_sources = {rel: (w.repo / rel).read_bytes() for rel in w.moved}
    manifest_before = (w.repo / "data/manifest.csv").read_bytes()
    with monkeypatch.context() as m:
        m.setattr(shutil, "copyfile", corrupt)
        assert v1_cli(w.repo, "--execute") != 0
        with pytest.raises(archive.ArchiveError):
            run_archive(w.repo)
    assert {rel: (w.repo / rel).read_bytes() for rel in w.moved} == before_sources, "a source was deleted or changed"
    assert (w.repo / "data/manifest.csv").read_bytes() == manifest_before
    assert not (w.repo / "data/manifest.csv.lock").exists()


def test_concurrent_manifest_append_between_read_and_replace_is_refused_and_survives(w, monkeypatch):
    """Item 6: a batch append between the read and os.replace must not be lost."""
    mp = w.repo / "data/manifest.csv"
    original = mp.read_bytes()
    row = csv_line({"path": "s05/t01/ep-01/security.evtx", "sha256": sha(b"batch"), "size": "5", "scenario": "s05",
                    "trial": "t01", "host": "ep-01", "channel": "security",
                    "source_path": "x10_v2/S05/trial_01/ENDPOINT-01/x.evtx"}) + b"\r\n"
    lock_seen = []

    def hook(step: str) -> None:
        if step == "before_main_manifest_replace":
            lock_seen.append((w.repo / "data/manifest.csv.lock").exists())
            with open(mp, "ab") as f:
                f.write(row)
    with monkeypatch.context() as m:
        m.setattr(archive, "_checkpoint", hook)
        with pytest.raises(archive.ArchiveError):
            run_archive(w.repo)
    assert lock_seen == [True], "the lock must be held while the manifest is rewritten"
    assert mp.read_bytes() == original + row, "the concurrent append was lost or the manifest was replaced"
    for rel in w.moved:
        assert (w.repo / rel).exists(), "a source was deleted although the manifest rewrite failed"
    assert not (w.repo / "data/manifest.csv.lock").exists()
    res = run_archive(w.repo)                                         # nothing is lost: the resume completes
    assert res.ok
    assert mp.read_bytes() == manifest_bytes([x for x in w.lines if x not in w.moved_lines]) + row


# ============================================================================ verify

def test_verify_ok_after_a_full_run(w):
    res = run_archive(w.repo)
    v = archive.verify_archive(roots_of(w.repo), archive.V1)
    assert v.ok and v.expected == v.verified == res.expected == len(w.moved)
    assert cli_rc(["archive-verify", "--repo", str(w.repo)]) == 0


def test_verify_is_read_only(w):
    run_archive(w.repo)
    before = tree(w.repo)
    archive.verify_archive(roots_of(w.repo), archive.V1)
    cli_rc(["archive-verify", "--repo", str(w.repo)])
    assert tree(w.repo) == before


def test_verify_on_an_empty_archive_fails(w, capsys):
    before = tree(w.repo)
    v = archive.verify_archive(roots_of(w.repo), archive.V1)
    assert not v.ok
    assert cli_rc(["archive-verify", "--repo", str(w.repo)]) != 0
    assert tree(w.repo) == before


def test_verify_on_an_empty_repo_fails(tmp_path):
    (tmp_path / "data").mkdir()
    assert not archive.verify_archive(roots_of(tmp_path), archive.V1).ok
    assert cli_rc(["archive-verify", "--repo", str(tmp_path)]) != 0


def test_verify_detects_a_flipped_byte(w):
    run_archive(w.repo)
    victim = w.repo / w.dest_of("data/raw/s04/t01/dc01/security.evtx")
    b = bytearray(victim.read_bytes())
    b[0] ^= 0x01
    victim.write_bytes(bytes(b))
    v = archive.verify_archive(roots_of(w.repo), archive.V1)
    assert not v.ok and v.verified == v.expected - 1 and v.problems
    assert cli_rc(["archive-verify", "--repo", str(w.repo)]) != 0


@pytest.mark.parametrize("what", ["a data file", "the archive manifest", "the journal", "a jsonl file", "the db"])
def test_verify_fails_on_a_half_archive(w, what):
    run_archive(w.repo)
    target = {"a data file": w.dest_of("data/raw/s07/t05/ep-01/sysmon.evtx"),
              "the archive manifest": "data/manifest_archive_x10_v1.csv",
              "the journal": f"out/{V1_LABEL}/journal.json",
              "a jsonl file": w.dest_of("data/processed/jsonl/s04_t10/ep-01_security.jsonl"),
              "the db": w.dest_of("data/processed/s04_t02.sqlite3")}[what]
    (w.repo / target).unlink()
    assert not archive.verify_archive(roots_of(w.repo), archive.V1).ok
    assert cli_rc(["archive-verify", "--repo", str(w.repo)]) != 0


def test_verify_compares_raw_files_with_the_original_ingest_json_sha(w):
    """Item 11: the archived raw file must still equal files_copied[].sha256 of out/ingest/x10/<id>/ingest.json."""
    run_archive(w.repo)
    ij = w.repo / "out/ingest/x10/s04_t10/ingest.json"
    d = json.loads(ij.read_text(encoding="utf-8"))
    d["files_copied"][0]["sha256"] = sha(b"not what was archived")
    ij.write_text(json.dumps(d), encoding="utf-8")
    assert not archive.verify_archive(roots_of(w.repo), archive.V1).ok


def test_verify_ignores_a_new_trial_that_now_sits_on_the_normal_path(w):
    """After the v2 ingest the normal paths hold different bytes under the same names; verify only looks at the
    archive side, so it stays ok."""
    run_archive(w.repo)
    write(w.repo, "data/raw/s04/t01/dc01/security.evtx", b"the new v2 trial")
    write(w.repo, "data/processed/s04_t01.sqlite3", b"new db")
    assert archive.verify_archive(roots_of(w.repo), archive.V1).ok
