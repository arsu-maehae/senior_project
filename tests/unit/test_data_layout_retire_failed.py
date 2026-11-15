"""Tests for `retire-failed` (T6c Task 3b; decision 052 item 6; attacker review x10_archive_tooling 2026-11-15, items
1, 3, 4, 10 and the shared core items 5-9, 11, 14).

Written from the plan, the review's "Disposition" column and the brief, not from the code. Synthetic temp repos only
(tests/unit/archive_fixtures.py: ``build_failed`` = a repo with staying content plus one ingested failed attempt of
s04 t01 and its attempt folder under data/incoming/x10_v2_failed/S04/attempt_N). No real data is read or written.

The API contract is in the module docstring of test_data_layout_archive.py. What `retire-failed` adds (pinned here):

* ``failed_attempt_spec("s04", "t01", N)`` -> label ``x10_v2_failed_s04_attempt_N``; paths of the archive:
  ``data/raw/L/s04/t01/...``, ``data/processed/L/...`` (DB, ``.tmp``/``-wal``/``-shm``, clock csv),
  ``data/processed/L/jsonl/s04_t01/``, ``out/normalise/L/s04_t01/``, ``out/clock_offset/L/s04_t01/``,
  ``out/ingest/L/s04_t01/`` (the ingest.json/.md of ``out/ingest/x10_v2/s04_t01``), ``out/x10_validate_v2/L/s04_t01.json``,
  manifest rows in ``data/manifest_L.csv`` (path prefixed ``L/``), report/journal/run log in ``out/L/``.
* Mapping incoming <-> ingest: ``source_path`` ``x10_v2/S04/trial_01/<rest>`` of ingest.json, manifest and
  ``clock_files.copied`` corresponds to ``data/incoming/x10_v2_failed/S04/attempt_N/<rest>``.
* Proof it is the failed attempt (item 1): ``out/ingest/x10_v2/<id>/ingest.json`` exists with ``source == "x10_v2"``
  exactly; the attempt folder exists; the sha256 of every file named in ingest.json ``files_copied`` and
  ``clock_files.copied``, of every manifest row of the trial and of every raw file on disk equals the sha256 of the
  attempt-folder file (raw files that no record names, e.g. after a failure before the manifest append, must still
  equal SOME file of the attempt folder). Refuse if ``data/incoming/x10_v2/<S>/trial_NN`` holds the same files (the
  folder was not moved yet); different files there (the retry waiting) are fine. Refuse an id listed in
  ``docs/lab/test_set.csv``, and a trial that is neither an ingest ``status == "error"`` nor a validator result with a
  criterion whose ``status == "FAIL"``. Refuse while another per-trial path of the id is live: ``out/gate``,
  ``out/stitch``, ``out/evaluate``, ``out/answer_key`` folders for the id, or a row of ``data/trial_windows.csv``.
* Tolerant policy (item 4): a missing listed file or an extra file in the trial's own paths is moved (extras) or
  skipped (missing) and listed in the report as ``missing`` / ``extra`` (lists of repo-relative posix paths).
* ``data/incoming`` is never written; the attempt folder stays where the owner put it.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from data_layout import archive, batch, cli  # noqa: E402
from archive_fixtures import (add_failed_trial, blob, build_failed, failed_label, manifest_bytes,  # noqa: E402
                              sha, split_manifest, tree, write)

SCEN, TRIAL = "s04", "t01"
ID = "s04_t01"


class Killed(BaseException):
    pass


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)


def roots_of(repo: Path):
    return batch.Roots.from_repo(repo)


def run_retire(repo: Path, attempt: int = 1, scenario: str = SCEN, trial: str = TRIAL):
    roots = roots_of(repo)
    plan = archive.plan_archive(roots, archive.failed_attempt_spec(scenario, trial, attempt))
    return archive.execute_archive(roots, plan)


def cli_rc(argv: list[str]) -> int:
    try:
        return cli.main(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1


def retire_cli(repo: Path, attempt="1", *extra: str, scenario: str = SCEN, trial: str = TRIAL) -> int:
    return cli_rc(["retire-failed", "--repo", str(repo), "--scenario", scenario, "--trial", trial,
                   "--attempt", str(attempt), *extra])


def report_of(repo: Path, label: str) -> dict:
    return json.loads((repo / "out" / label / "archive_report.json").read_text(encoding="utf-8"))


def assert_refused(repo: Path, attempt: int = 1, scenario: str = SCEN, trial: str = TRIAL) -> str:
    before = tree(repo)
    assert retire_cli(repo, str(attempt), "--execute", scenario=scenario, trial=trial) != 0
    assert tree(repo) == before, "CLI refusal changed the tree"
    with pytest.raises((archive.ArchiveError, ValueError)) as ei:
        run_retire(repo, attempt, scenario, trial)
    assert tree(repo) == before, "refusal changed the tree"
    return str(ei.value).lower()


def live_paths(repo: Path, scenario: str = SCEN, trial: str = TRIAL, label: str | None = None) -> list[str]:
    """Every per-trial location of the id that is still live (everything outside data/incoming and the archives)."""
    tid = f"{scenario}_{trial}"
    found: list[str] = []
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo).as_posix()
        parts = rel.split("/")
        if parts[:2] == ["data", "incoming"] or (label and label in parts) or rel.startswith("data/manifest_"):
            continue
        if any(x.startswith("archive_x10_v1") or x.startswith("x10_v2_failed_") for x in parts):
            continue
        if parts[:4] == ["data", "raw", scenario, trial]:
            found.append(rel)
        elif p.name == tid or p.name.startswith(tid + ".") or p.name.startswith(tid + "_"):
            found.append(rel)
        elif parts[:2] == ["out", "ingest"] and tid in parts:
            found.append(rel)
    for name in ("data/manifest.csv", "data/trial_windows.csv"):
        text = (repo / name).read_text(encoding="utf-8") if (repo / name).exists() else ""
        for line in text.splitlines():
            if line.startswith(f"{scenario}/{trial}/") or line.startswith(tid + ","):
                found.append(f"{name}: {line[:40]}")
    return found


@pytest.fixture
def w(tmp_path):
    return build_failed(tmp_path)


# ============================================================================ the move

def test_retire_moves_every_ingested_file_of_the_failed_attempt(w):
    res = run_retire(w.repo)
    assert res.ok and res.expected == res.verified == len(w.moved)
    for rel in w.moved:
        assert not (w.repo / rel).exists(), f"left on the normal path: {rel}"
        assert (w.repo / w.dest_of(rel)).read_bytes() == w.initial[rel], f"bad copy: {rel}"


def test_retire_destinations_follow_the_label(w):
    run_retire(w.repo)
    lab = failed_label(SCEN, 1)
    assert lab == "x10_v2_failed_s04_attempt_1" == w.label
    base = w.repo
    assert (base / "data/raw" / lab / "s04/t01/ep-01/clock.txt").is_file()            # clock.txt moves with the raw folder
    assert (base / "data/raw" / lab / "s04/t01/dc01/security.evtx").is_file()
    assert (base / "data/processed" / lab / "s04_t01.sqlite3").is_file()
    assert (base / "data/processed" / lab / "s04_t01.clock_offsets.csv").is_file()
    assert (base / "data/processed" / lab / "jsonl/s04_t01/dc01_security.jsonl").is_file()
    assert (base / "out/normalise" / lab / "s04_t01/import_report.json").is_file()
    assert (base / "out/clock_offset" / lab / "s04_t01/clock_offset.json").is_file()
    assert (base / "out/ingest" / lab / "s04_t01/ingest.json").is_file()                # item 3: audit trail kept
    assert (base / "out/x10_validate_v2" / lab / "s04_t01.json").is_file()
    assert (base / f"data/manifest_{lab}.csv").is_file()
    assert (base / "out" / lab / "archive_report.json").is_file() and (base / "out" / lab / "journal.json").is_file()


def test_retire_scan_of_every_per_trial_location_finds_nothing_live(w):
    assert live_paths(w.repo), "fixture must have live paths before the retire"
    run_retire(w.repo)
    assert live_paths(w.repo, label=w.label) == []


def test_retire_frees_the_id_for_the_validator_and_the_ingest_state(w):
    from x10_validate import cli as vcli
    assert ID in vcli.discover(w.repo)
    run_retire(w.repo)
    assert ID not in vcli.discover(w.repo)
    assert not list((w.repo / "out/x10_validate_v2").glob("s04_t01*.json"))
    assert not (w.repo / "out/ingest/x10_v2/s04_t01").exists()
    # the retry would see a clean slate for trial_state
    plan = batch.plan_trial(roots_of(w.repo), w.repo / "data/incoming/x10_v2/S04/trial_01", "s04", "t01", False)
    assert not plan.raw_dir.exists() and not plan.database.exists() and not plan.jsonl_dir.exists()


def test_retire_manifest_split_byte_exact_and_v1_rows_untouched(w):
    original = split_manifest(w.manifest)
    run_retire(w.repo)
    kept = [x for x in original if x not in w.moved_lines]
    assert (w.repo / "data/manifest.csv").read_bytes() == manifest_bytes(kept)
    assert len(kept) == len(original) - len(w.moved_lines) == len(original) - 4
    v1_rows = [x for x in original if b",x10/S04/" in x]
    assert v1_rows and all(x in kept for x in v1_rows)
    arch = (w.repo / f"data/manifest_{w.label}.csv").read_bytes()
    assert arch == manifest_bytes([f"{w.label}/".encode() + x for x in w.moved_lines])
    assert not (w.repo / "data/manifest.csv.lock").exists()


def test_retire_touches_only_the_named_trial(w):
    pre = tree(w.repo)
    run_retire(w.repo)
    post = tree(w.repo)
    moved = set(w.moved)
    for rel, h in pre.items():
        if h is not None and rel not in moved and rel != "data/manifest.csv":
            assert post.get(rel) == h, f"staying file changed or gone: {rel}"
    for rel in ("data/processed/s04_t00.sqlite3", "data/processed/s04_t02.sqlite3", "data/processed/s05_t01.sqlite3",
                "out/ingest/x10_v2/s05_t01/ingest.json", "out/x10_validate_v2/s05_t01.json",
                "data/trial_windows.csv", "docs/lab/test_set.csv", "data/raw/s05/t01/ep-01/security.evtx"):
        assert (w.repo / rel).is_file(), rel


def test_retire_never_touches_data_incoming(w):
    inc = w.repo / "data" / "incoming"
    before = tree(inc)
    run_retire(w.repo)
    assert tree(inc) == before
    assert w.attempt_dir.is_dir(), "the attempt folder is the owner's evidence and stays"


def test_retire_report_counts_and_ids(w):
    run_retire(w.repo)
    rep = report_of(w.repo, w.label)
    assert rep["expected"] == rep["verified"] == len(w.moved) and rep["status"] == "ok"
    assert rep["trials"] == [ID]
    assert {f["path"] for f in rep["files"]} == set(w.moved)
    assert rep["missing"] == [] and rep["extra"] == []


def test_retire_dry_run_default_writes_nothing(w, capsys):
    before = tree(w.repo)
    capsys.readouterr()
    assert retire_cli(w.repo) == 0
    out = capsys.readouterr().out
    assert "dry run" in out.lower() and ID in out and w.label in out
    assert tree(w.repo) == before


def test_retire_cli_execute_moves_and_verifies(w):
    assert retire_cli(w.repo, "1", "--execute") == 0
    assert live_paths(w.repo, label=w.label) == []
    assert archive.verify_archive(roots_of(w.repo), archive.failed_attempt_spec(SCEN, TRIAL, 1)).ok


def test_retire_second_run_is_a_noop(w):
    run_retire(w.repo)
    before = tree(w.repo)
    res = run_retire(w.repo)
    assert res.ok
    assert tree(w.repo) == before
    assert retire_cli(w.repo, "1", "--execute") == 0
    assert tree(w.repo) == before


def test_retire_second_attempt_for_the_same_trial_gets_its_own_archive(w):
    run_retire(w.repo, 1)
    after_first = tree(w.repo, exclude=("out/x10_v2_failed_s04_attempt_2",))
    # the retry is ingested under the same id, fails again, and its attempt folder is attempt_2
    w2 = add_failed_trial(w.repo, attempt=2, variant="b")
    res = run_retire(w.repo, 2)
    assert res.ok and res.expected == len(w2.moved)
    assert w2.label == "x10_v2_failed_s04_attempt_2" != w.label
    for rel in w2.moved:
        assert not (w.repo / rel).exists()
        assert (w.repo / w2.dest_of(rel)).read_bytes() == w2.initial[rel]
    # attempt 1 archive is untouched and still verifies
    for rel, h in after_first.items():
        if "x10_v2_failed_s04_attempt_1" in rel and h is not None:
            assert sha((w.repo / rel).read_bytes()) == h
    assert archive.verify_archive(roots_of(w.repo), archive.failed_attempt_spec(SCEN, TRIAL, 1)).ok
    assert archive.verify_archive(roots_of(w.repo), archive.failed_attempt_spec(SCEN, TRIAL, 2)).ok
    assert live_paths(w.repo, label="x10_v2_failed_s04_attempt_2") == []
    mp = split_manifest((w.repo / "data/manifest.csv").read_bytes())
    assert not any(x.split(b",")[0].startswith(b"s04/t01/") for x in mp)
    a1 = split_manifest((w.repo / "data/manifest_x10_v2_failed_s04_attempt_1.csv").read_bytes())
    a2 = split_manifest((w.repo / "data/manifest_x10_v2_failed_s04_attempt_2.csv").read_bytes())
    assert len(a1) == len(a2) == 4 and not set(a1) & set(a2)


def test_retire_cli_exit_nonzero_when_not_fully_verified(w, monkeypatch):
    import os
    locked = (w.repo / "data/raw/s04/t01/dc01/security.evtx").resolve()
    real = os.unlink

    def fake(path, *a, **k):
        if Path(path).resolve() == locked:
            raise PermissionError(13, "locked", str(path))
        return real(path, *a, **k)
    with monkeypatch.context() as m:
        m.setattr(os, "unlink", fake)
        assert retire_cli(w.repo, "1", "--execute") != 0
    rep = report_of(w.repo, w.label)
    assert rep["verified"] == rep["expected"] - 1
    assert retire_cli(w.repo, "1", "--execute") == 0
    assert live_paths(w.repo, label=w.label) == []


@pytest.mark.parametrize("point", ["after_copy", "after_archive_manifest", "after_main_manifest", "before_delete"])
def test_retire_kill_then_resume(w, monkeypatch, point):
    def hook(step: str) -> None:
        if step == point:
            raise Killed(step)
    with monkeypatch.context() as m:
        m.setattr(archive, "_checkpoint", hook)
        with pytest.raises(Killed):
            run_retire(w.repo)
    for rel in w.moved:
        assert (w.repo / rel).read_bytes() == w.initial[rel], f"{point}: source lost"
    res = run_retire(w.repo)
    assert res.ok and res.expected == res.verified == len(w.moved)
    assert live_paths(w.repo, label=w.label) == []
    assert len(split_manifest((w.repo / f"data/manifest_{w.label}.csv").read_bytes())) == 4


# ============================================================================ tolerant of partial ingests (item 4)

def test_partial_ingest_is_retired(tmp_path):
    """status error, no DB, .sqlite3.tmp/-wal/-shm, a half JSONL, failure before the manifest append, no validator."""
    w = build_failed(tmp_path, partial=True, validator=None)
    before_manifest = (w.repo / "data/manifest.csv").read_bytes()
    res = run_retire(w.repo)
    assert res.ok and res.expected == res.verified == len(w.moved)
    for rel in w.moved:
        assert not (w.repo / rel).exists() and (w.repo / w.dest_of(rel)).read_bytes() == w.initial[rel]
    assert live_paths(w.repo, label=w.label) == []
    assert (w.repo / "data/manifest.csv").read_bytes() == before_manifest, "no manifest rows existed; none may change"
    rep = report_of(w.repo, w.label)
    listed = json.dumps(rep["extra"])
    for tail in (".sqlite3.tmp", ".sqlite3.tmp-wal", ".sqlite3.tmp-shm"):
        assert tail in listed, f"extra item {tail} not listed in the report"


@pytest.mark.parametrize("sidecar", ["-wal", "-shm"])
def test_sqlite_sidecars_beside_a_real_db_are_moved_with_it(w, sidecar):
    write(w.repo, f"data/processed/s04_t01.sqlite3{sidecar}", b"side")
    run_retire(w.repo)
    assert (w.repo / "data/processed" / w.label / f"s04_t01.sqlite3{sidecar}").read_bytes() == b"side"
    assert live_paths(w.repo, label=w.label) == []
    assert f"sqlite3{sidecar}" in json.dumps(report_of(w.repo, w.label)["extra"])


def test_missing_listed_file_is_tolerated_and_listed(w):
    (w.repo / "data/raw/s04/t01/ep-01/sysmon.evtx").unlink()
    (w.repo / "data/processed/s04_t01.sqlite3").unlink()
    res = run_retire(w.repo)
    assert res.ok
    rep = report_of(w.repo, w.label)
    assert "ep-01/sysmon.evtx" in json.dumps(rep["missing"])
    assert rep["expected"] == rep["verified"] == len(w.moved) - 2
    assert live_paths(w.repo, label=w.label) == []


def test_unlisted_extra_file_in_the_trials_own_paths_is_moved_and_listed(w):
    write(w.repo, "data/processed/s04_t01.weird.dat", b"extra")
    run_retire(w.repo)
    assert (w.repo / "data/processed" / w.label / "s04_t01.weird.dat").read_bytes() == b"extra"
    assert "weird.dat" in json.dumps(report_of(w.repo, w.label)["extra"])


def test_part_orphan_beside_a_raw_file_is_reported_not_moved(w):
    orphan = w.repo / "data/raw/s04/t01/dc01/security.evtx.part"
    orphan.write_bytes(b"half")
    res = run_retire(w.repo)
    assert res.ok and res.expected == len(w.moved)
    assert orphan.read_bytes() == b"half"
    assert "security.evtx.part" in json.dumps(report_of(w.repo, w.label)["orphans"])


# ============================================================================ proof that it is the failed attempt (item 1)

def _attempt(w, name: str) -> Path:
    return w.attempt_dir / name


def _tamper_attempt_file(w):
    p = _attempt(w, "DC01/DC01_Security.evtx")
    p.write_bytes(p.read_bytes() + b"x")


def _tamper_raw(w):
    p = w.repo / "data/raw/s04/t01/dc01/security.evtx"
    p.write_bytes(p.read_bytes() + b"x")


def _tamper_manifest_sha(w):
    mp = w.repo / "data/manifest.csv"
    mp.write_bytes(mp.read_bytes().replace(sha(w.initial["data/raw/s04/t01/dc01/security.evtx"]).encode(),
                                           sha(b"other").encode(), 1))


def _tamper_ingest_sha(w):
    ij = w.repo / "out/ingest/x10_v2/s04_t01/ingest.json"
    d = json.loads(ij.read_text(encoding="utf-8"))
    d["files_copied"][0]["sha256"] = sha(b"other")
    ij.write_text(json.dumps(d), encoding="utf-8")


def _tamper_clock_in_ingest(w):
    ij = w.repo / "out/ingest/x10_v2/s04_t01/ingest.json"
    d = json.loads(ij.read_text(encoding="utf-8"))
    d["clock_files"]["copied"][0]["sha256"] = sha(b"other clock")
    ij.write_text(json.dumps(d), encoding="utf-8")


def _remove_attempt_folder(w):
    shutil.rmtree(w.attempt_dir)


def _remove_one_attempt_file(w):
    _attempt(w, "ENDPOINT-01/ENDPOINT-01_Security.evtx").unlink()


def _tamper_attempt_clock(w):
    p = _attempt(w, "EP-01_clock.txt")
    p.write_bytes(p.read_bytes() + b"x")


@pytest.mark.parametrize("breaker", [_tamper_attempt_file, _tamper_raw, _tamper_manifest_sha, _tamper_ingest_sha,
                                      _tamper_clock_in_ingest, _remove_attempt_folder, _remove_one_attempt_file,
                                      _tamper_attempt_clock])
def test_refuse_when_hashes_do_not_agree_across_attempt_folder_manifest_ingest_and_disk(w, breaker):
    breaker(w)
    assert_refused(w.repo)


def test_refuse_the_retry_that_is_already_ingested(tmp_path):
    """The accepted retry sits on the normal paths and in the manifest; the attempt folder holds the OLD bytes."""
    w = build_failed(tmp_path, variant="b")
    for p in sorted(w.attempt_dir.rglob("*")):
        if p.is_file():
            p.write_bytes(blob("the failed attempt " + p.name))
    assert_refused(w.repo)


def test_refuse_a_raw_file_that_matches_no_file_of_the_attempt_folder_even_without_records(tmp_path):
    w = build_failed(tmp_path, partial=True, validator=None)
    write(w.repo, "data/raw/s04/t01/dc01/sysmon.evtx", b"bytes of the retry, not of the failed attempt")
    assert_refused(w.repo)


def test_refuse_when_attempt_number_has_no_folder(w):
    assert_refused(w.repo, attempt=2)


@pytest.mark.parametrize("fake_source", ["missing", "x10", "x10_v3", "", None])
def test_refuse_ingest_json_whose_source_is_not_exactly_x10_v2(w, fake_source):
    ij = w.repo / "out/ingest/x10_v2/s04_t01/ingest.json"
    d = json.loads(ij.read_text(encoding="utf-8"))
    if fake_source == "missing":
        del d["source"]
    else:
        d["source"] = fake_source
    ij.write_text(json.dumps(d), encoding="utf-8")
    assert_refused(w.repo)


def test_refuse_when_ingest_json_is_missing(w):
    (w.repo / "out/ingest/x10_v2/s04_t01/ingest.json").unlink()
    assert_refused(w.repo)


def test_refuse_an_old_v1_trial_of_the_same_scenario(w):
    """s04 t02 only has v1 rows and no x10_v2 ingest report: a wrong trial number must not move it."""
    assert_refused(w.repo, trial="t02")


def test_refuse_the_accepted_trial_of_another_scenario(w):
    """s05 t01 is an accepted v2 trial (ingest ok, validator ok, listed in the test set): never retired."""
    assert_refused(w.repo, scenario="s05", trial="t01")


def test_refuse_when_the_id_is_in_the_test_set(w):
    p = w.repo / "docs/lab/test_set.csv"
    p.write_bytes(p.read_bytes() + b"s04_t01,s04,development,2026-11-21\n")
    assert_refused(w.repo)


def test_refuse_when_the_failed_folder_was_not_moved_yet(w):
    """data/incoming/x10_v2/S04/trial_01 still holds the same files: it is not a finished failure."""
    for name, data in w.attempt_files.items():
        write(w.repo, f"data/incoming/x10_v2/S04/trial_01/{name}", data)
    assert_refused(w.repo)


def test_different_files_waiting_in_incoming_trial_folder_do_not_block(w):
    for name, data in w.attempt_files.items():
        write(w.repo, f"data/incoming/x10_v2/S04/trial_01/{name}", data + b"-the retry")
    assert run_retire(w.repo).ok


@pytest.mark.parametrize("validator,ingest_status", [("pass", "ok"), (None, "ok")])
def test_refuse_a_trial_that_is_neither_a_validator_fail_nor_an_ingest_error(tmp_path, validator, ingest_status):
    w = build_failed(tmp_path, validator=validator, ingest_status=ingest_status)
    assert_refused(w.repo)


@pytest.mark.parametrize("validator,ingest_status", [("fail", "ok"), (None, "error"), ("fail", "error")])
def test_a_validator_fail_or_an_ingest_error_is_enough(tmp_path, validator, ingest_status):
    w = build_failed(tmp_path, validator=validator, ingest_status=ingest_status)
    assert run_retire(w.repo).ok


@pytest.mark.parametrize("live", ["out/gate/s04_t01/gate.json", "out/stitch/s04_t01/links.csv",
                                  "out/evaluate/s04_t01/eval.json", "out/answer_key/s04_t01/key.json"])
def test_refuse_while_another_per_trial_output_is_live(w, live):
    write(w.repo, live, b"{}")
    msg = assert_refused(w.repo)
    assert live.split("/")[1] in msg, "the refusal must report which live path blocks it"


def test_refuse_while_a_trial_windows_row_exists(w):
    mp = w.repo / "data/trial_windows.csv"
    mp.write_bytes(mp.read_bytes() + b"s04_t01,2026-11-20T00:00:00Z\r\n")
    assert_refused(w.repo)


# ============================================================================ argument safety (item 10)

@pytest.mark.parametrize("scenario,trial,attempt", [
    ("s04", "t01", "0"), ("s04", "t01", "-1"), ("s04", "t01", "abc"), ("s04", "t01", "1/../x"), ("s04", "t01", "1.5"),
    ("../s04", "t01", "1"), ("s04", "t00", "1"), ("s04", "t11", "1"), ("s04", "t1", "1"), ("s04", "t010", "1"),
    ("s02", "t01", "1"), ("s03", "t01", "1"), ("s04", "t01/..", "1"), ("s04", "..", "1"),
])
def test_cli_rejects_unsafe_arguments_and_changes_nothing(w, scenario, trial, attempt):
    before = tree(w.repo)
    assert retire_cli(w.repo, attempt, "--execute", scenario=scenario, trial=trial) != 0
    assert tree(w.repo) == before


# ============================================================================ shared-core safety on the failed preset

def test_refuse_manifest_with_bom_or_without_final_newline(tmp_path):
    for name, edit in (("bom", lambda b: b"\xef\xbb\xbf" + b), ("nonl", lambda b: b[:-2])):
        d = tmp_path / name
        d.mkdir()
        w = build_failed(d)
        mp = w.repo / "data/manifest.csv"
        mp.write_bytes(edit(mp.read_bytes()))
        assert_refused(w.repo)


def test_refuse_when_lock_file_exists(w):
    (w.repo / "data/manifest.csv.lock").write_bytes(b"")
    msg = assert_refused(w.repo)
    assert "lock" in msg
    assert (w.repo / "data/manifest.csv.lock").exists()


def test_refuse_destination_conflict(w):
    dest = w.repo / "data/raw" / w.label / "s04/t01/dc01/security.evtx"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"something else")
    assert_refused(w.repo)
    assert dest.read_bytes() == b"something else"


def test_refuse_duplicate_manifest_path_with_different_sha(w):
    mp = w.repo / "data/manifest.csv"
    first = w.moved_lines[0].split(b",")
    first[1] = sha(b"other").encode()
    mp.write_bytes(mp.read_bytes() + b",".join(first) + b"\r\n")
    assert_refused(w.repo)


def test_copy_hash_mismatch_deletes_nothing(w, monkeypatch):
    real = shutil.copyfile

    def corrupt(src, dst, *a, **k):
        out = real(src, dst, *a, **k)
        if Path(src).name == "security.evtx" and "dc01" in Path(src).parts and "t01" in Path(src).parts:
            with open(dst, "ab") as f:
                f.write(b"!")
        return out
    before = {rel: (w.repo / rel).read_bytes() for rel in w.moved}
    manifest = (w.repo / "data/manifest.csv").read_bytes()
    with monkeypatch.context() as m:
        m.setattr(shutil, "copyfile", corrupt)
        assert retire_cli(w.repo, "1", "--execute") != 0
        with pytest.raises(archive.ArchiveError):
            run_retire(w.repo)
    assert {rel: (w.repo / rel).read_bytes() for rel in w.moved} == before
    assert (w.repo / "data/manifest.csv").read_bytes() == manifest


def test_journal_holds_every_source_hash_before_any_delete(w, monkeypatch):
    import os
    moved_abs = {(w.repo / rel).resolve() for rel in w.moved}
    journal = w.repo / "out" / w.label / "journal.json"
    real, seen = os.unlink, []

    def fake(path, *a, **k):
        if Path(path).resolve() in moved_abs:
            seen.append(journal.is_file() and all(sha(w.initial[r]) in journal.read_text(encoding="utf-8")
                                                  for r in w.moved))
        return real(path, *a, **k)
    monkeypatch.setattr(os, "unlink", fake)
    run_retire(w.repo)
    assert seen and all(seen)


def test_retire_a_junction_in_the_trial_paths_is_refused(w, tmp_path_factory):
    from archive_fixtures import make_link
    ext = tmp_path_factory.mktemp("ext")
    real = w.repo / "data/processed/jsonl/s04_t01"
    for p in real.iterdir():
        p.rename(ext / p.name)
    real.rmdir()
    if not make_link(real, ext):
        pytest.skip("cannot create a symlink or junction here")
    before_ext = sorted(p.name for p in ext.iterdir())
    msg = assert_refused(w.repo)
    assert any(x in msg for x in ("link", "junction", "reparse"))
    assert sorted(p.name for p in ext.iterdir()) == before_ext


def test_archive_of_a_failed_attempt_is_invisible_to_the_id_patterns(w):
    import fnmatch
    run_retire(w.repo)
    lab = w.label
    assert not batch.TRIAL_RE.match(lab) and not fnmatch.fnmatch(lab, "s0?_t??")
    from x10_validate import cli as vcli
    assert not vcli.TRIAL_RE.match(lab)
    assert not list((w.repo / "data/processed").glob("s0?_t??.sqlite3")) or all(
        p.stem != ID for p in (w.repo / "data/processed").glob("s0?_t??.sqlite3"))
    assert [p.name for p in (w.repo / "out/x10_validate_v2").glob("*.json") if vcli.TRIAL_RE.match(p.stem)] == [
        "s05_t01.json"]


def test_verify_failed_archive_empty_and_flipped_byte(w):
    spec = archive.failed_attempt_spec(SCEN, TRIAL, 1)
    assert not archive.verify_archive(roots_of(w.repo), spec).ok            # nothing archived yet
    run_retire(w.repo)
    assert archive.verify_archive(roots_of(w.repo), spec).ok
    victim = w.repo / w.dest_of("data/raw/s04/t01/ep-01/clock.txt")
    victim.write_bytes(victim.read_bytes() + b"!")
    v = archive.verify_archive(roots_of(w.repo), spec)
    assert not v.ok and v.verified == v.expected - 1
