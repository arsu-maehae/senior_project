"""Tests for the x10_v2 source of the batch ingest (plan 2026-11-15, Tasks 1 and 4; decision 052, 034).

Written from the plan and CLAUDE.md data rules, not from the code. Synthetic temp repos only; tiny real EVTX
bytes are read from data/raw/s02/t00 and s02/t01 (never t02-t10). Nothing in the real data/ or out/ is written.

API CONTRACT these tests pin (the implementer follows it):

Task 1, source selection
  * ``Roots.from_repo(repo, source="x10")``; fields ``source`` (Path data/incoming/<source>) and ``source_name``;
    ``Roots.x10`` no longer exists; ``ingest_out`` = ``out/ingest/<source_name>``.
  * CLI ``--source {x10,x10_v2}`` (default x10) for ``python -m data_layout.batch`` and ``data_layout.cli batch``;
    any other value is an argparse error (SystemExit 2).
  * ``ingest.json`` carries ``"source": "<source_name>"``.
  * The quarantine folder is valid for x10 only; under x10_v2 it is a "skipped folder" note and is never planned.
  * A missing ``data/incoming/x10_v2`` is not a crash: 0 trials selected.
  * Shadow guard (v2 only, before any write): ``ingest_trial`` reports status "error" (nothing deleted or written
    under data/, even with --force; message mentions the archive) when data/manifest.csv has a row for the same
    scenario/trial whose ``source_path`` does not start with ``x10_v2/``, or when the DB or the raw trial folder
    exists while no manifest row of the trial is a v2 row.

Task 4, clock files (x10_v2 only; module ``data_layout.clock_files`` is tested in test_data_layout_clock_files.py)
  * ``<HOST>_clock.txt`` directly in the trial folder -> ``data/raw/<s>/<t>/<host>/clock.txt`` byte for byte;
    manifest row channel=clock, records/first_event_utc/last_event_utc empty; ``ingest.json["clock_files"]`` =
    {"copied": [...], "ignored": [...], "missing_hosts": [...]}; not in ``files_copied``.
  * Bad name / unknown host / two files for one host / a clock file inside a host subfolder: the trial is refused
    (status "error", the error names the file, NOTHING is written to raw, manifest or DB).
  * A missing clock file is NOT a refusal: status "ok", ``clock_files.missing_hosts`` lists the host, and a
    ``warnings`` entry mentions it.
  * Source x10 keeps ignoring ``*_clock.txt`` exactly as before.

Attacker review x10_archive_tooling 2026-11-15, items 2, 6, 13 (extra API assumptions, x10_v2 only)
  * Stale attempt: a trial that is already complete (DB, ingest.json ok, manifest rows) whose incoming files now
    have DIFFERENT bytes (incoming pre-hash vs ``files_copied`` source sha of the existing ingest.json) is refused
    with a message naming "stale" and "retire-failed", with or without --force; it is never printed as
    "complete, skipped", and the existing DB is never removed.
  * Manifest bytes: appended rows keep the manifest's CRLF endings (no bare LF, no CR CR LF); a manifest with a
    BOM, or not ending in a newline, is refused (status "error", message mentions the manifest, bytes unchanged).
  * Lock: ``data/manifest.csv.lock`` is created exclusively around the manifest appends (evtx rows via
    ``layout.append_manifest``, clock rows via ``clock_files.append_clock_rows``) and removed afterwards, also after
    a failure; a pre-existing lock makes the trial refuse (status "error", message mentions the lock, lock file
    and manifest left as they were, nothing appended).
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from data_layout import batch, cli, layout as L  # noqa: E402

SRC = {
    "system": REPO / "data/raw/s02/t00/ep-01/system.evtx",
    "winrm": REPO / "data/raw/s02/t01/ep-01/winrm.evtx",
    "powershell": REPO / "data/raw/s02/t01/ep-01/powershell.evtx",
}
NAME = {"system": "System", "winrm": "Microsoft-Windows-WinRM_Operational",
        "powershell": "Microsoft-Windows-PowerShell_Operational"}
QDIR = "S05_WRONG_DESIGN_DO_NOT_USE"
OLD_ROW_SOURCE = "x10/S04/trial_01/ENDPOINT-01/ENDPOINT-01_System.evtx"

pytestmark = pytest.mark.skipif(not all(p.exists() for p in SRC.values()), reason="tiny real EVTX missing")


# ---------- helpers ----------

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*")) if p.is_file()}


def put_trial(repo: Path, scen_dir: str, trial_dir: str, source: str = "x10_v2", hosts=("DC-01", "ENDPOINT-01"),
              channels=("system", "winrm", "powershell")) -> Path:
    base = repo / "data/incoming" / source / scen_dir / trial_dir
    for h in hosts:
        (base / h).mkdir(parents=True, exist_ok=True)
        for c in channels:
            (base / h / f"{h}_{NAME[c]}.evtx").write_bytes(SRC[c].read_bytes())
    return base


def clock_bytes(tag: str) -> bytes:
    """Not valid UTF-8 on purpose: the ingest must never decode or re-encode the file."""
    return (f"Tracking dc01.lab.local {tag}\r\n".encode() + b"\xff\xfe\x00odd bytes\r\n" + b"Asia/Bangkok\r\n")


def put_clock(base: Path, rel: str, tag: str | None = None) -> bytes:
    data = clock_bytes(tag or rel)
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return data


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "ground_truth/approved").mkdir(parents=True)
    (tmp_path / "ground_truth/approved/key.json").write_text("{}")
    (tmp_path / "data/raw").mkdir(parents=True)
    (tmp_path / "data/processed").mkdir(parents=True)
    (tmp_path / "data/incoming/x10").mkdir(parents=True)
    (tmp_path / "data/incoming/x10_v2").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def fake_heavy(monkeypatch):
    """Fast stand-ins for convert/import/reconcile (as in test_data_layout_batch.py); record the calls."""
    calls = {"convert": [], "import": []}

    def convert(roots, plan):
        calls["convert"].append(plan.trial_id)
        plan.jsonl_dir.mkdir(parents=True, exist_ok=True)
        (plan.jsonl_dir / "x.jsonl").write_text("{}\n")
        return {"selected_inputs": [], "totals": None}

    def imp(plan):
        calls["import"].append(plan.trial_id)
        plan.database.parent.mkdir(parents=True, exist_ok=True)
        plan.database.write_bytes(b"db")
        return {"events": 0, "events_dedup": 0, "duplicates_exact": 0, "duplicates_near": 0,
                "duration_seconds": 0, "per_file": [], "checks": {}, "status": "ok"}

    monkeypatch.setattr(batch, "run_convert", convert)
    monkeypatch.setattr(batch, "run_import", imp)
    monkeypatch.setattr(batch, "reconcile", lambda *a, **k: {"ok": True, "checks": []})
    return calls


def run(repo: Path, *args: str) -> int:
    return batch.main(["--repo", str(repo), *args])


def run2(repo: Path, *args: str) -> int:
    return run(repo, "--source", "x10_v2", *args)


def report(repo: Path, trial_id: str, source: str = "x10_v2") -> dict:
    return json.loads((repo / "out/ingest" / source / trial_id / "ingest.json").read_text(encoding="utf-8"))


def manifest_rows(repo: Path) -> list[dict]:
    p = repo / "data/manifest.csv"
    if not p.exists():
        return []
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_manifest(repo: Path, rows: list[dict]) -> None:
    p = repo / "data/manifest.csv"
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, L.MANIFEST_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in L.MANIFEST_COLUMNS})


def old_row(scenario: str, trial: str, source_path: str = OLD_ROW_SOURCE, channel: str = "system") -> dict:
    return {"path": f"{scenario}/{trial}/ep-01/{channel}.evtx", "sha256": "0" * 64, "size": "1",
            "scenario": scenario, "trial": trial, "host": "ep-01", "channel": channel, "source_path": source_path,
            "date": "2026-10-01T00:00:00Z", "records": "5", "first_event_utc": "2026-10-01T00:00:00.000000Z",
            "last_event_utc": "2026-10-01T00:01:00.000000Z"}


def make_old_copy(repo: Path, scenario="s04", trial="t01", *, db=True, raw=True, manifest=True) -> None:
    """An old (x10) copy sitting on the normal paths, as before the archive step."""
    if raw:
        p = repo / f"data/raw/{scenario}/{trial}/ep-01/system.evtx"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"old-raw-evidence")
    if db:
        (repo / f"data/processed/{scenario}_{trial}.sqlite3").write_bytes(b"old-db")
        j = repo / f"data/processed/jsonl/{scenario}_{trial}"
        j.mkdir(parents=True, exist_ok=True)
        (j / "old.jsonl").write_text("{}\n")
    if manifest:
        write_manifest(repo, [old_row(scenario, trial)])


def v2_plans(repo: Path):
    plans, _ = batch.discover_trials(batch.Roots.from_repo(repo, source="x10_v2"))
    return {p.trial_id: p for p in plans}


# ============================================================================ Task 1: Roots and CLI

def test_roots_default_source_is_x10(repo):
    r = batch.Roots.from_repo(repo)
    assert r.source_name == "x10"
    assert r.source == repo.resolve() / "data/incoming/x10"
    assert r.ingest_out == repo.resolve() / "out/ingest/x10"
    assert r.incoming == repo.resolve() / "data/incoming"
    assert not hasattr(r, "x10")  # renamed to ``source``


def test_roots_x10_v2(repo):
    r = batch.Roots.from_repo(repo, source="x10_v2")
    assert r.source_name == "x10_v2"
    assert r.source == repo.resolve() / "data/incoming/x10_v2"
    assert r.ingest_out == repo.resolve() / "out/ingest/x10_v2"
    assert r.raw == repo.resolve() / "data/raw" and r.manifest == repo.resolve() / "data/manifest.csv"


@pytest.mark.parametrize("entry", ["batch_main", "cli_batch"])
def test_cli_rejects_unknown_source(repo, entry, capsys):
    def call(src: str) -> int:
        if entry == "batch_main":
            return batch.main(["--repo", str(repo), "--source", src, "--dry-run"])
        return cli.main(["batch", "--repo", str(repo), "--source", src, "--dry-run"])

    assert call("x10") == 0 and call("x10_v2") == 0  # the two choices are accepted ...
    with pytest.raises(SystemExit) as e:             # ... anything else is an argparse error
        call("x10_v3")
    assert e.value.code == 2


def test_cli_batch_subcommand_accepts_x10_v2(repo, fake_heavy, capsys):
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    assert cli.main(["batch", "--repo", str(repo), "--source", "x10_v2", "--dry-run"]) == 0
    assert "s04_t01" in capsys.readouterr().out
    assert cli.main(["batch", "--repo", str(repo), "--source", "x10_v2"]) == 0
    assert (repo / "data/raw/s04/t01/dc01/system.evtx").is_file()
    assert (repo / "out/ingest/x10_v2/s04_t01/ingest.json").is_file()


def test_dry_run_with_missing_v2_folder_is_zero_trials(repo, capsys):
    (repo / "data/incoming/x10_v2").rmdir()
    before = snapshot(repo)
    assert run2(repo, "--dry-run") == 0
    assert "0 trials selected" in capsys.readouterr().out
    assert snapshot(repo) == before and not (repo / "out").exists()


# ============================================================================ Task 1: routing

def test_v2_routes_to_out_ingest_x10_v2_and_records_source(repo, fake_heavy):
    base = put_trial(repo, "S04", "trial_01")
    before_inc = snapshot(repo / "data/incoming")
    assert run2(repo) == 0
    rep = report(repo, "s04_t01")
    assert rep["source"] == "x10_v2" and rep["status"] == "ok" and rep["trial_id"] == "s04_t01"
    assert rep["source_dir"] == "data/incoming/x10_v2/S04/trial_01"
    assert (repo / "out/ingest/x10_v2/s04_t01/ingest.md").is_file()
    assert not (repo / "out/ingest/x10").exists()
    assert snapshot(repo / "data/incoming") == before_inc and base.exists()
    rows = manifest_rows(repo)
    assert len(rows) == 6 and all(r["source_path"].startswith("x10_v2/S04/trial_01/") for r in rows)
    assert (repo / "data/processed/s04_t01.sqlite3").exists()
    assert (repo / "ground_truth/approved/key.json").read_text() == "{}"


def test_v1_report_records_source_x10(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", source="x10", hosts=("DC-01",), channels=("system",))
    assert run(repo) == 0
    rep = report(repo, "s02_t01", source="x10")
    assert rep["source"] == "x10"
    assert not (repo / "out/ingest/x10_v2").exists()


def test_each_source_reads_only_its_own_folder(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", source="x10", hosts=("DC-01",), channels=("system",))
    put_trial(repo, "S04", "trial_01", source="x10_v2", hosts=("DC-01",), channels=("system",))
    assert run2(repo) == 0
    assert fake_heavy["convert"] == ["s04_t01"]
    assert not (repo / "data/raw/s02").exists()
    assert run(repo) == 0  # default = x10
    assert fake_heavy["convert"] == ["s04_t01", "s02_t01"]
    assert (repo / "out/ingest/x10/s02_t01/ingest.json").is_file()
    assert not (repo / "out/ingest/x10/s04_t01").exists()


def test_v2_quarantine_folder_is_a_skipped_note_not_a_trial(repo, fake_heavy, capsys):
    put_trial(repo, QDIR, "trial_01", hosts=("DC-01",), channels=("system",))
    roots = batch.Roots.from_repo(repo, source="x10_v2")
    plans, notes = batch.discover_trials(roots)
    assert plans == []
    assert any(QDIR in n and "skipped" in n for n in notes)
    assert run2(repo) == 0
    assert fake_heavy["convert"] == []
    assert not (repo / "data/raw/quarantine").exists() and not (repo / "data/manifest_quarantine.csv").exists()
    assert not (repo / "out/ingest/x10_v2/s05q_t01").exists()


def test_x10_still_plans_the_quarantine_folder(repo):
    put_trial(repo, QDIR, "trial_01", source="x10", hosts=("DC-01",), channels=("system",))
    plans, _ = batch.discover_trials(batch.Roots.from_repo(repo))
    assert [p.trial_id for p in plans] == ["s05q_t01"]


def test_v2_complete_trial_skipped_unless_force(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run2(repo) == 0 and fake_heavy["convert"] == ["s04_t01"]
    assert run2(repo) == 0 and fake_heavy["convert"] == ["s04_t01"]  # complete -> skipped
    assert run2(repo, "--force") == 0 and fake_heavy["convert"] == ["s04_t01", "s04_t01"]
    assert len(manifest_rows(repo)) == 1


# ============================================================================ Task 1: shadow guard

def assert_refused_untouched(repo: Path, fake_heavy, before: dict, *args: str) -> dict:
    assert run2(repo, *args) == 1
    rep = report(repo, "s04_t01")
    assert rep["status"] == "error" and rep["source"] == "x10_v2"
    assert "archive" in rep["error"].lower()
    assert fake_heavy["convert"] == [] and fake_heavy["import"] == []
    assert snapshot(repo / "data") == before  # no byte of raw, processed, manifest or incoming changed
    return rep


@pytest.mark.parametrize("force", [False, True])
def test_shadow_guard_old_rows_and_db(repo, fake_heavy, force):
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo)
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before, *(["--force"] if force else []))
    assert (repo / "data/processed/s04_t01.sqlite3").read_bytes() == b"old-db"
    assert (repo / "data/processed/jsonl/s04_t01/old.jsonl").is_file()
    assert (repo / "data/raw/s04/t01/ep-01/system.evtx").read_bytes() == b"old-raw-evidence"


@pytest.mark.parametrize("force", [False, True])
def test_shadow_guard_old_manifest_row_alone(repo, fake_heavy, force):
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo, db=False, raw=False)
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before, *(["--force"] if force else []))


@pytest.mark.parametrize("force", [False, True])
def test_shadow_guard_db_without_any_manifest_row(repo, fake_heavy, force):
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo, raw=False, manifest=False)
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before, *(["--force"] if force else []))
    assert (repo / "data/processed/s04_t01.sqlite3").read_bytes() == b"old-db"


@pytest.mark.parametrize("force", [False, True])
def test_shadow_guard_raw_folder_without_v2_row(repo, fake_heavy, force):
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo, db=False, manifest=False)
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before, *(["--force"] if force else []))


def test_shadow_guard_mixed_old_and_v2_rows_refuses(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo)
    write_manifest(repo, [old_row("s04", "t01"),
                          old_row("s04", "t01", "x10_v2/S04/trial_01/ENDPOINT-01/x.evtx", "winrm")])
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before, "--force")


def test_shadow_guard_source_path_prefix_must_be_exactly_x10_v2(repo, fake_heavy):
    """'x10_v2_failed/...' or 'x10_v20/...' is not a v2 row."""
    put_trial(repo, "S04", "trial_01")
    make_old_copy(repo, db=False, raw=False, manifest=False)
    write_manifest(repo, [old_row("s04", "t01", "x10_v2_failed/S04/attempt_1/a.evtx")])
    before = snapshot(repo / "data")
    assert_refused_untouched(repo, fake_heavy, before)


def test_shadow_guard_only_the_same_trial_counts(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    make_old_copy(repo, "s04", "t02")  # old copy of ANOTHER trial id
    old = snapshot(repo / "data/raw/s04/t02"), (repo / "data/processed/s04_t02.sqlite3").read_bytes()
    assert run2(repo) == 0
    assert report(repo, "s04_t01")["status"] == "ok"
    assert snapshot(repo / "data/raw/s04/t02") == old[0]
    assert (repo / "data/processed/s04_t02.sqlite3").read_bytes() == old[1]
    assert "old-raw" in (repo / "data/raw/s04/t02/ep-01/system.evtx").read_text()


def test_shadow_guard_other_scenario_same_trial_number_ok(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    make_old_copy(repo, "s07", "t01")
    assert run2(repo) == 0 and report(repo, "s04_t01")["status"] == "ok"


def test_shadow_guard_allows_a_v2_trial_to_be_rebuilt(repo, fake_heavy):
    """Own v2 rows and DB are not a shadow: --force on a v2 trial works, an interrupted one resumes."""
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run2(repo) == 0
    (repo / "out/ingest/x10_v2/s04_t01/ingest.json").unlink()  # interrupted: DB + v2 rows, no report
    assert run2(repo, "--force") == 0
    assert report(repo, "s04_t01")["status"] == "ok" and len(manifest_rows(repo)) == 1


def test_shadow_guard_not_applied_to_source_x10(repo, fake_heavy):
    """x10 keeps decision 029 behaviour: old manifest rows with the x10/ prefix are its own."""
    put_trial(repo, "S04", "trial_01", source="x10", hosts=("DC-01",), channels=("system",))
    assert run(repo) == 0
    assert run(repo, "--force") == 0
    assert all(r["source_path"].startswith("x10/") for r in manifest_rows(repo))


# ============================================================================ Task 4: clock files copied

HOST_FILES = {"EP-01_clock.txt": "ep-01", "ep-02_clock.txt": "ep-02", "ENDPOINT-03_clock.txt": "ep-03"}


def v2_trial_with_clocks(repo: Path, files=None) -> tuple[Path, dict[str, bytes]]:
    base = put_trial(repo, "S04", "trial_01")
    data = {n: put_clock(base, n) for n in (files if files is not None else HOST_FILES)}
    return base, data


def test_clock_files_copied_byte_identical_with_manifest_rows(repo, fake_heavy):
    base, data = v2_trial_with_clocks(repo)
    before_inc = snapshot(repo / "data/incoming")
    assert run2(repo) == 0
    assert snapshot(repo / "data/incoming") == before_inc
    rep = report(repo, "s04_t01")
    assert rep["status"] == "ok"
    for name, host in HOST_FILES.items():
        dest = repo / f"data/raw/s04/t01/{host}/clock.txt"
        assert dest.read_bytes() == data[name]
    rows = [r for r in manifest_rows(repo) if r["channel"] == "clock"]
    assert sorted(r["path"] for r in rows) == [f"s04/t01/{h}/clock.txt" for h in ("ep-01", "ep-02", "ep-03")]
    for r in rows:
        dest = repo / "data/raw" / r["path"]
        assert r["sha256"] == sha(dest) and int(r["size"]) == dest.stat().st_size
        assert (r["scenario"], r["trial"]) == ("s04", "t01") and r["host"] == dest.parent.name
        assert r["records"] == "" and r["first_event_utc"] == "" and r["last_event_utc"] == ""
        orig = next(n for n, h in HOST_FILES.items() if h == r["host"])
        assert r["source_path"] == f"x10_v2/S04/trial_01/{orig}"
    cf = rep["clock_files"]
    assert len(cf["copied"]) == 3 and cf["missing_hosts"] == [] and isinstance(cf["ignored"], list)
    blob = json.dumps(cf["copied"])
    assert all(sha(repo / "data/raw" / r["path"]) in blob for r in rows)
    assert "clock" in (repo / "out/ingest/x10_v2/s04_t01/ingest.md").read_text(encoding="utf-8").lower()


def test_clock_files_kept_out_of_the_event_log_accounting(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    rep = report(repo, "s04_t01")
    assert len(rep["files_copied"]) == 6  # the evtx files only
    assert all(c["channel"] != "clock" and not c["dest_path"].endswith("clock.txt") for c in rep["files_copied"])
    assert rep["extra_files"] == []
    assert not any(m["channel"] == "clock" for m in rep["files_missing"])
    assert len(rep["files_missing"]) == 20 - 6
    assert not any(i["source_path"].endswith("_clock.txt") for i in rep["files_ignored"])


def test_clock_rows_do_not_change_existing_manifest_lines(repo, fake_heavy):
    write_manifest(repo, [old_row("s02", "t00")])
    before = (repo / "data/manifest.csv").read_bytes()
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    assert (repo / "data/manifest.csv").read_bytes().startswith(before)
    rows = manifest_rows(repo)
    assert len(rows) == 1 + 6 + 3
    assert [r["channel"] for r in rows].count("clock") == 3


def test_clock_file_only_for_some_hosts_and_other_txt_ignored(repo, fake_heavy):
    base, _ = v2_trial_with_clocks(repo, {"EP-01_clock.txt": None})
    (base / "notes.txt").write_text("operator notes")
    assert run2(repo) == 0
    rep = report(repo, "s04_t01")
    assert rep["status"] == "ok" and rep["clock_files"]["missing_hosts"] == ["ep-02", "ep-03"]
    assert sorted(p.name for p in (repo / "data/raw/s04/t01").rglob("*.txt")) == ["clock.txt"]
    assert not (repo / "data/raw/s04/t01/notes.txt").exists()


def test_clock_file_reaches_nothing_else(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    assert not (repo / "data/manifest_quarantine.csv").exists() and not (repo / "data/raw/quarantine").exists()
    assert not list((repo / "data/processed/jsonl").rglob("clock*"))  # not converted


# ---------- missing clock files: ingested anyway, gap recorded ----------

def test_missing_clock_files_are_not_a_refusal(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01")
    assert run2(repo) == 0
    rep = report(repo, "s04_t01")
    assert rep["status"] == "ok" and rep["error"] is None
    assert rep["clock_files"]["missing_hosts"] == ["ep-01", "ep-02", "ep-03"]
    assert rep["clock_files"]["copied"] == []
    assert any("clock" in str(w).lower() for w in rep["warnings"])
    assert not any(r["channel"] == "clock" for r in manifest_rows(repo))
    assert "clock" in (repo / "out/ingest/x10_v2/s04_t01/ingest.md").read_text(encoding="utf-8").lower()
    assert (repo / "data/processed/s04_t01.sqlite3").exists() and len(manifest_rows(repo)) == 6


def test_one_missing_clock_file_is_named_and_warned(repo, fake_heavy):
    v2_trial_with_clocks(repo, {"EP-01_clock.txt": None, "EP-03_clock.txt": None})
    assert run2(repo) == 0
    rep = report(repo, "s04_t01")
    assert rep["status"] == "ok" and rep["clock_files"]["missing_hosts"] == ["ep-02"]
    assert any("ep-02" in str(w).lower() for w in rep["warnings"])
    assert (repo / "data/raw/s04/t01/ep-01/clock.txt").is_file() and not (repo / "data/raw/s04/t01/ep-02/clock.txt").exists()


def test_complete_clock_set_gives_no_clock_warning(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    assert not any("clock" in str(w).lower() for w in report(repo, "s04_t01").get("warnings", []))


def test_trial_without_clock_files_is_complete_and_skipped_on_rerun(repo, fake_heavy):
    put_trial(repo, "S04", "trial_01")
    assert run2(repo) == 0
    assert batch.trial_state(v2_plans(repo)["s04_t01"]) == "complete"
    assert run2(repo) == 0 and fake_heavy["convert"] == ["s04_t01"]


# ---------- refuse overwrite, resume ----------

def test_clock_copy_refuses_to_overwrite_a_different_raw_file(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    dest = repo / "data/raw/s04/t01/ep-01/clock.txt"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"older, different reading")
    assert run2(repo) == 1
    assert dest.read_bytes() == b"older, different reading"
    assert report(repo, "s04_t01")["status"] == "error"


def test_clock_copy_resumes_when_raw_file_has_identical_hash(repo, fake_heavy):
    _, data = v2_trial_with_clocks(repo)
    dest = repo / "data/raw/s04/t01/ep-01/clock.txt"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(data["EP-01_clock.txt"])  # an earlier, interrupted run copied it
    assert run2(repo) == 0
    assert report(repo, "s04_t01")["status"] == "ok"
    rows = [r for r in manifest_rows(repo) if r["channel"] == "clock"]
    assert len(rows) == 3 and dest.read_bytes() == data["EP-01_clock.txt"]


def test_forced_rerun_does_not_duplicate_clock_rows_or_change_files(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    before = snapshot(repo / "data/raw")
    manifest_before = (repo / "data/manifest.csv").read_bytes()
    assert run2(repo, "--force") == 0
    assert snapshot(repo / "data/raw") == before
    assert (repo / "data/manifest.csv").read_bytes() == manifest_before
    assert len(report(repo, "s04_t01")["clock_files"]["copied"]) == 3


def test_complete_state_requires_the_clock_rows_in_the_manifest(repo, fake_heavy):
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    plan = v2_plans(repo)["s04_t01"]
    assert batch.trial_state(plan) == "complete"
    keep = [r for r in manifest_rows(repo) if r["channel"] != "clock"]
    write_manifest(repo, keep)  # simulate: crash before the clock rows were appended
    assert batch.trial_state(plan) != "complete"
    assert run2(repo, "--force") == 0
    rows = manifest_rows(repo)
    assert [r["channel"] for r in rows].count("clock") == 3 and len(rows) == 9
    assert batch.trial_state(plan) == "complete"


# ---------- refusals: never guess ----------

REFUSED = {
    "no_host_in_name": (["clock.txt"], ["clock.txt"]),
    "wrong_separator": (["EP-01-clock.txt"], ["EP-01-clock.txt"]),
    "unknown_host": (["LAPTOP_clock.txt"], ["LAPTOP_clock.txt"]),
    "unknown_lab_number": (["EP-09_clock.txt"], ["EP-09_clock.txt"]),
    "two_files_one_host": (["EP-01_clock.txt", "ENDPOINT-01_clock.txt"], ["EP-01_clock.txt", "ENDPOINT-01_clock.txt"]),
    "inside_host_subfolder": (["ENDPOINT-01/EP-01_clock.txt"], ["EP-01_clock.txt"]),
    "good_files_do_not_save_a_bad_one": (["EP-01_clock.txt", "EP-02_clock.txt", "LAPTOP_clock.txt"], ["LAPTOP_clock.txt"]),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_bad_clock_files_refuse_the_trial_and_write_nothing(repo, fake_heavy, case):
    files, must_name = REFUSED[case]
    base = put_trial(repo, "S04", "trial_01")
    for f in files:
        put_clock(base, f)
    before_inc = snapshot(repo / "data/incoming")
    assert run2(repo) == 1
    rep = report(repo, "s04_t01")
    assert rep["status"] == "error"
    err = rep["error"].lower()
    assert "clock" in err and any(n.lower() in err for n in must_name), rep["error"]
    assert snapshot(repo / "data/incoming") == before_inc
    assert not (repo / "data/raw/s04").exists()
    assert not (repo / "data/manifest.csv").exists()
    assert not (repo / "data/processed/s04_t01.sqlite3").exists()
    assert fake_heavy["convert"] == []


def test_refused_trial_does_not_hide_other_trials_when_keep_going(repo, fake_heavy):
    base = put_trial(repo, "S04", "trial_01")
    put_clock(base, "LAPTOP_clock.txt")
    put_trial(repo, "S04", "trial_02", hosts=("DC-01",), channels=("system",))
    assert run2(repo, "--keep-going") == 1
    assert report(repo, "s04_t01")["status"] == "error" and report(repo, "s04_t02")["status"] == "ok"


# ---------- v1 source keeps ignoring clock files ----------

def test_x10_source_still_ignores_clock_files(repo, fake_heavy):
    base = put_trial(repo, "S02", "trial_01", source="x10")
    for n in ("EP-01_clock.txt", "ep-02_clock.txt", "clock.txt", "LAPTOP_clock.txt", "EP-01-clock.txt"):
        put_clock(base, n)  # even bad names / duplicates are no concern of v1
    (base / "ENDPOINT-01" / "EP-01_clock.txt").write_bytes(b"x")
    assert run(repo) == 0
    rep = report(repo, "s02_t01", source="x10")
    assert rep["status"] == "ok"
    assert list((repo / "data/raw/s02/t01").rglob("*.txt")) == []
    assert not any(r["channel"] == "clock" for r in manifest_rows(repo))
    assert len(rep["files_copied"]) == 6
    assert {i["source_path"].rsplit("/", 1)[-1] for i in rep["files_ignored"]} >= {"EP-01_clock.txt", "clock.txt"}
    assert not any("clock" in str(w).lower() for w in rep.get("warnings", []))
    cf = rep.get("clock_files")
    assert not cf or (cf.get("copied") in ([], None))


# ============================================================================ clock rows are invisible to export-span code

def _span_manifest(repo: Path) -> None:
    rows = [old_row("s04", "t01", "x10_v2/S04/trial_01/a.evtx", "system"),
            {**old_row("s04", "t01", "x10_v2/S04/trial_01/b.evtx", "security"),
             "first_event_utc": "2026-10-01T00:00:30.000000Z", "last_event_utc": "2026-10-01T00:09:00.000000Z",
             "path": "s04/t01/ep-01/security.evtx"}]
    for h in ("ep-01", "ep-02", "ep-03"):
        rows.append({"path": f"s04/t01/{h}/clock.txt", "sha256": "1" * 64, "size": "300", "scenario": "s04",
                     "trial": "t01", "host": h, "channel": "clock", "source_path": f"x10_v2/S04/trial_01/{h}_clock.txt",
                     "date": "2026-10-01T00:20:00Z", "records": "", "first_event_utc": "", "last_event_utc": ""})
    write_manifest(repo, rows)


def test_read_manifest_span_ignores_clock_rows(repo):
    from lab_common.manifest import read_manifest_rows, read_manifest_span
    _span_manifest(repo)
    rows = read_manifest_rows(repo, "s04_t01")
    assert sorted(r["channel"] for r in rows) == ["security", "system"]
    assert read_manifest_span(repo, "s04_t01") == {
        "start_utc": "2026-10-01T00:00:00.000000Z", "end_utc": "2026-10-01T00:09:00.000000Z",
        "source": "data/manifest.csv", "files": 2}


def test_read_manifest_span_none_when_only_clock_rows(repo):
    from lab_common.manifest import read_manifest_span
    _span_manifest(repo)
    keep = [r for r in manifest_rows(repo) if r["channel"] == "clock"]
    write_manifest(repo, keep)
    assert read_manifest_span(repo, "s04_t01") is None


def test_clock_offset_scan_ignores_clock_rows(repo):
    from clock_offset import scan
    _span_manifest(repo)
    shas = scan.manifest_shas(repo, "s04_t01")
    assert set(shas) == {("ep-01", "system"), ("ep-01", "security")}
    assert not any(c == "clock" for _, c in shas)
    assert not any(c == "clock" for _, c in scan.files_to_scan(repo, "s04_t01", shas))


# ============================================================================ attacker review: stale attempt (item 2)

def _complete_v2(repo: Path) -> Path:
    base = put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run2(repo) == 0
    return base


@pytest.mark.parametrize("force", [False, True])
def test_stale_attempt_changed_incoming_bytes_is_refused(repo, fake_heavy, capsys, force):
    base = _complete_v2(repo)
    capsys.readouterr()
    (base / "DC-01" / "DC-01_System.evtx").write_bytes(SRC["powershell"].read_bytes())  # a different attempt
    db = repo / "data/processed/s04_t01.sqlite3"
    before_db, before_data = db.read_bytes(), snapshot(repo / "data/raw")
    manifest_before = (repo / "data/manifest.csv").read_bytes()
    assert run2(repo, *(["--force"] if force else [])) == 1
    out = capsys.readouterr().out
    assert "complete, skipped" not in out
    rep = report(repo, "s04_t01")
    assert rep["status"] == "error"
    err = rep["error"].lower()
    assert "stale" in err and "retire-failed" in err, rep["error"]
    assert db.exists() and db.read_bytes() == before_db
    assert snapshot(repo / "data/raw") == before_data
    assert (repo / "data/manifest.csv").read_bytes() == manifest_before
    assert fake_heavy["convert"] == ["s04_t01"]  # only the first, real run


def test_unchanged_incoming_is_still_skipped_as_complete(repo, fake_heavy, capsys):
    _complete_v2(repo)
    capsys.readouterr()
    assert run2(repo) == 0
    assert "complete, skipped" in capsys.readouterr().out


# ============================================================================ attacker review: manifest bytes (item 6)

def _crlf_manifest(repo: Path) -> bytes:
    write_manifest(repo, [old_row("s02", "t00")])
    data = (repo / "data/manifest.csv").read_bytes()
    assert data.endswith(b"\r\n") and b"\r\r\n" not in data
    return data


def test_v2_append_keeps_crlf_and_existing_bytes(repo, fake_heavy):
    before = _crlf_manifest(repo)
    v2_trial_with_clocks(repo)
    assert run2(repo) == 0
    after = (repo / "data/manifest.csv").read_bytes()
    assert after.startswith(before) and len(after) > len(before)
    assert b"\r\r\n" not in after
    assert re.search(rb"(?<!\r)\n", after) is None, "bare LF found: mixed line endings"
    assert after.endswith(b"\r\n") and not after.startswith(b"\xef\xbb\xbf")
    assert len(manifest_rows(repo)) == 1 + 6 + 3


@pytest.mark.parametrize("variant", ["bom", "no_final_newline"])
def test_v2_refuses_a_malformed_manifest_before_any_append(repo, fake_heavy, variant):
    good = _crlf_manifest(repo)
    bad = b"\xef\xbb\xbf" + good if variant == "bom" else good[:-2]
    (repo / "data/manifest.csv").write_bytes(bad)
    v2_trial_with_clocks(repo)
    assert run2(repo) == 1
    rep = report(repo, "s04_t01")
    assert rep["status"] == "error" and "manifest" in rep["error"].lower()
    assert (repo / "data/manifest.csv").read_bytes() == bad
    assert not (repo / "data/manifest.csv.lock").exists()
    assert fake_heavy["convert"] == []


# ============================================================================ attacker review: lock (item 13)

def test_v2_manifest_append_runs_under_the_lock_and_releases_it(repo, fake_heavy, monkeypatch):
    from data_layout import clock_files
    lock = repo / "data/manifest.csv.lock"
    seen = {"evtx": None, "clock": None}
    real_evtx, real_clock = L.append_manifest, clock_files.append_clock_rows

    def evtx(*a, **k):
        seen["evtx"] = lock.exists()
        return real_evtx(*a, **k)

    def clock(*a, **k):
        seen["clock"] = lock.exists()
        return real_clock(*a, **k)

    monkeypatch.setattr(L, "append_manifest", evtx)
    monkeypatch.setattr(clock_files, "append_clock_rows", clock)
    v2_trial_with_clocks(repo)
    assert not lock.exists()
    assert run2(repo) == 0
    assert seen == {"evtx": True, "clock": True}
    assert not lock.exists()


def test_v2_lock_released_after_a_failed_append(repo, fake_heavy, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(L, "append_manifest", boom)
    put_trial(repo, "S04", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run2(repo) == 1
    assert report(repo, "s04_t01")["status"] == "error"
    assert not (repo / "data/manifest.csv.lock").exists()


def test_v2_stale_lock_refuses_and_is_left_alone(repo, fake_heavy):
    write_manifest(repo, [old_row("s02", "t00")])
    manifest_before = (repo / "data/manifest.csv").read_bytes()
    lock = repo / "data/manifest.csv.lock"
    lock.write_bytes(b"pid 1 left over\n")
    v2_trial_with_clocks(repo)
    assert run2(repo) == 1
    rep = report(repo, "s04_t01")
    assert rep["status"] == "error" and "lock" in rep["error"].lower()
    assert lock.read_bytes() == b"pid 1 left over\n"
    assert (repo / "data/manifest.csv").read_bytes() == manifest_before
    assert not (repo / "data/processed/s04_t01.sqlite3").exists()
    assert fake_heavy["convert"] == []
