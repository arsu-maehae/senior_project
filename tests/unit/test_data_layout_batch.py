"""Tests for the x10 batch ingest driver (data_layout.batch, batch_report, cli `batch`).

Written from CLAUDE.md data rules, decision 030 and the driver requirements, not from the code.
Everything runs in a temp repo; tiny real EVTX files are READ from data/raw and copied into the
temp tree. The real data/, out/ and manifests are never written (the only real-out reads are
out/ingest/x10/s02_t01 and s02_t03 ingest.json).
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from data_layout import batch, batch_report as R, cli  # noqa: E402

SRC = {
    "system": REPO / "data/raw/s02/t00/ep-01/system.evtx",
    "winrm": REPO / "data/raw/s02/t01/ep-01/winrm.evtx",
    "powershell": REPO / "data/raw/s02/t03/ep-01/powershell.evtx",
}
NAME = {"system": "System", "winrm": "Microsoft-Windows-WinRM_Operational",
        "powershell": "Microsoft-Windows-PowerShell_Operational"}
QDIR = "S05_WRONG_DESIGN_DO_NOT_USE"

pytestmark = pytest.mark.skipif(not all(p.exists() for p in SRC.values()), reason="tiny real EVTX missing")


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def snapshot(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob("*")) if p.is_file()}


def put_trial(repo: Path, scen_dir: str, trial_dir: str, hosts=("DC-01", "ENDPOINT-01"),
              channels=("system", "winrm", "powershell"), name_override: dict | None = None) -> Path:
    base = repo / "data/incoming/x10" / scen_dir / trial_dir
    for h in hosts:
        (base / h).mkdir(parents=True, exist_ok=True)
        for c in channels:
            fname = (name_override or {}).get(c, f"{h}_{NAME[c]}.evtx")
            (base / h / fname).write_bytes(SRC[c].read_bytes())
    return base


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "ground_truth/approved").mkdir(parents=True)
    (tmp_path / "ground_truth/approved/key.json").write_text("{}")
    (tmp_path / "data/raw").mkdir(parents=True)
    (tmp_path / "data/processed").mkdir(parents=True)
    (tmp_path / "data/incoming/x10").mkdir(parents=True)
    return tmp_path


@pytest.fixture
def fake_heavy(monkeypatch):
    """Replace convert/import/reconcile so routing tests are fast; record the calls."""
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
        return {"events": 0, "events_dedup": 0, "duplicates_exact": 0, "duplicates_near": 0, "duration_seconds": 0, "per_file": [], "checks": {}, "status": "ok"}

    monkeypatch.setattr(batch, "run_convert", convert)
    monkeypatch.setattr(batch, "run_import", imp)
    monkeypatch.setattr(batch, "reconcile", lambda *a, **k: {"ok": True, "checks": []})
    return calls


def run(repo: Path, *args: str) -> int:
    return batch.main(["--repo", str(repo), *args])


def report(repo: Path, trial_id: str) -> dict:
    return json.loads((repo / "out/ingest/x10" / trial_id / "ingest.json").read_text(encoding="utf-8"))


def manifest_rows(p: Path) -> list[dict]:
    with open(p, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ---------- naming and planning ----------

def test_trial_and_scenario_naming():
    assert batch.trial_of_folder("trial_01") == "t01"
    assert batch.trial_of_folder("trial_10") == "t10"
    assert batch.trial_of_folder("trial_1") is None
    assert batch.scenario_of_folder("S02") == ("s02", False)
    assert batch.scenario_of_folder(QDIR) == ("s05", True)
    assert batch.scenario_of_folder("S05") == ("s05", False)
    assert batch.scenario_of_folder("random") is None


def test_plan_paths_normal_and_quarantine(repo):
    roots = batch.Roots.from_repo(repo)
    n = batch.plan_trial(roots, roots.x10 / "S02/trial_01", "s02", "t01", False)
    assert n.raw_dir == roots.raw / "s02/t01"
    assert n.database == roots.processed / "s02_t01.sqlite3"
    assert n.manifest == repo.resolve() / "data/manifest.csv"
    q = batch.plan_trial(roots, roots.x10 / QDIR / "trial_03", "s05", "t03", True)
    assert q.raw_dir == roots.raw / "quarantine/s05/t03"
    assert q.database == roots.processed / "quarantine/s05q_t03.sqlite3"
    assert q.manifest == repo.resolve() / "data/manifest_quarantine.csv"
    assert "quarantine" in q.jsonl_dir.parts
    assert q.trial_id == "s05q_t03"


def test_check_write_paths_refuses_protected_and_mixed(repo):
    from dataclasses import replace
    roots = batch.Roots.from_repo(repo)
    q = batch.plan_trial(roots, roots.x10 / QDIR / "trial_01", "s05", "t01", True)
    with pytest.raises(batch.IngestError):
        batch.check_write_paths(roots, replace(q, manifest=roots.manifest))
    with pytest.raises(batch.IngestError):
        batch.check_write_paths(roots, replace(q, raw_dir=roots.repo / "ground_truth" / "approved"))
    with pytest.raises(batch.IngestError):
        batch.check_write_paths(roots, replace(q, database=roots.incoming / "x10" / "a.sqlite3"))


def test_discover_notes_unknown_folders(repo):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    (repo / "data/incoming/x10/Junk/trial_01").mkdir(parents=True)
    (repo / "data/incoming/x10/S03/notes").mkdir(parents=True)
    plans, notes = batch.discover_trials(batch.Roots.from_repo(repo))
    assert [p.trial_id for p in plans] == ["s02_t01"]
    assert len(notes) == 2


# ---------- routing end to end (heavy steps faked) ----------

def test_normal_trial_routing_manifest_and_incoming_untouched(repo, fake_heavy):
    base = put_trial(repo, "S02", "trial_01")
    # pre-existing manifest with a t00 row; must stay byte-identical as a prefix
    man = repo / "data/manifest.csv"
    from data_layout import layout as L
    seed = repo / "data/raw/s02/t00/dc01"
    seed.mkdir(parents=True)
    (seed / "system.evtx").write_bytes(SRC["system"].read_bytes())
    L.append_manifest(repo / "data/raw", [L.MapRow("dryrun/x", "s02", "t00", "dc01", "system",
                                                    "s02/t00/dc01/system.evtx", "copy", "ok")], man)
    before_manifest = man.read_bytes()
    before_inc = snapshot(repo / "data/incoming")
    assert run(repo) == 0
    assert snapshot(repo / "data/incoming") == before_inc  # copy, never move/modify
    assert base.exists()
    for h in ("dc01", "ep-01"):
        for c in ("system", "winrm", "powershell"):
            assert (repo / f"data/raw/s02/t01/{h}/{c}.evtx").is_file()
    assert man.read_bytes().startswith(before_manifest)
    rows = manifest_rows(man)
    new = [r for r in rows if r["trial"] == "t01"]
    assert len(new) == 6 and {r["scenario"] for r in new} == {"s02"}
    assert {r["host"] for r in new} == {"dc01", "ep-01"}
    for r in new:  # manifest sha = raw sha
        assert r["sha256"] == sha(repo / "data/raw" / r["path"])
    assert (repo / "data/processed/s02_t01.sqlite3").exists()
    assert not (repo / "data/raw/quarantine").exists()
    assert not (repo / "data/manifest_quarantine.csv").exists()
    assert (repo / "ground_truth/approved/key.json").read_text() == "{}"


def test_quarantine_goes_only_to_quarantine_places(repo, fake_heavy):
    put_trial(repo, QDIR, "trial_02", hosts=("DC-01", "ENDPOINT-02"))
    assert run(repo) == 0
    raw = repo / "data/raw"
    assert sorted(p.name for p in raw.iterdir()) == ["quarantine"]
    assert (raw / "quarantine/s05/t02/dc01/system.evtx").is_file()
    assert (raw / "quarantine/s05/t02/ep-02/winrm.evtx").is_file()
    assert not (repo / "data/manifest.csv").exists()
    q = manifest_rows(repo / "data/manifest_quarantine.csv")
    assert len(q) == 6 and all(r["path"].startswith("quarantine/s05/t02/") for r in q)
    assert (repo / "data/processed/quarantine/s05q_t02.sqlite3").exists()
    assert not (repo / "data/processed/s05_t02.sqlite3").exists()
    assert not (repo / "data/processed/s05q_t02.sqlite3").exists()
    assert any("quarantine" in p.parts for p in (repo / "data/processed/jsonl").rglob("*.jsonl"))
    assert not (repo / "data/processed/jsonl/s05_t02").exists()
    assert report(repo, "s05q_t02")["quarantine"] is True


def test_quarantine_does_not_touch_existing_manifest(repo, fake_heavy):
    man = repo / "data/manifest.csv"
    man.write_text("path,sha256\nkeep,1\n")
    before = man.read_bytes()
    put_trial(repo, QDIR, "trial_01", hosts=("DC-01",))
    put_trial(repo, "S03", "trial_01", hosts=("DC-01",))
    assert run(repo) == 0
    assert man.read_bytes().startswith(before)
    assert all(not r["path"].startswith("quarantine") for r in manifest_rows(man))
    assert all(r["path"].startswith("quarantine/") for r in manifest_rows(repo / "data/manifest_quarantine.csv"))


def test_channel_from_first_record_not_file_name(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("ENDPOINT-03",), channels=("system", "winrm"),
              name_override={"system": "ENDPOINT-03_Security.evtx", "winrm": "whatever.evtx"})
    assert run(repo) == 0
    got = sorted(p.name for p in (repo / "data/raw/s02/t01/ep-03").iterdir())
    assert got == ["system.evtx", "winrm.evtx"]
    assert sha(repo / "data/raw/s02/t01/ep-03/system.evtx") == sha(SRC["system"])


def test_host_name_mapping(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01", "ENDPOINT-01", "ENDPOINT-02", "ENDPOINT-03"),
              channels=("system",))
    assert run(repo) == 0
    assert sorted(p.name for p in (repo / "data/raw/s02/t01").iterdir()) == ["dc01", "ep-01", "ep-02", "ep-03"]


# ---------- missing files ----------

def test_missing_files_recorded_not_invented(repo, fake_heavy):
    put_trial(repo, "S02", "trial_03", hosts=("DC-01", "ENDPOINT-01"), channels=("system", "winrm"))
    assert run(repo) == 0
    rep = report(repo, "s02_t03")
    missing = {(m["host"], m["channel"]) for m in rep["files_missing"]}
    assert len(rep["files_copied"]) == 4
    assert len(missing) == 20 - 4
    assert ("dc01", "security") in missing and ("ep-02", "sysmon") in missing
    assert ("dc01", "system") not in missing
    assert all(m["reason"] for m in rep["files_missing"])
    assert len(list((repo / "data/raw/s02/t03").rglob("*.evtx"))) == 4  # nothing invented
    assert not (repo / "data/raw/s02/t03/ep-02").exists()


def test_missing_slots_pure():
    full = [(h, c) for h in R.EXPECTED_HOSTS for c in R.EXPECTED_CHANNELS]
    assert R.missing_slots(full) == []
    m = R.missing_slots([x for x in full if x != ("dc01", "security")])
    assert [(s["host"], s["channel"]) for s in m] == [("dc01", "security")]
    assert R.extra_files(full + [("dc01", "psclassic")]) == [{"host": "dc01", "channel": "psclassic"}]
    assert R.hash_diff({"a": "1"}, {"a": "1"})["unchanged"] is True
    d = R.hash_diff({"a": "1", "b": "2"}, {"a": "9", "c": "3"})
    assert d["unchanged"] is False and d["changed"] == ["a"] and d["added"] == ["c"] and d["removed"] == ["b"]
    assert R.channel_hint_from_name("DC-01_Microsoft-Windows-Sysmon_Operational.evtx") == "sysmon"
    assert R.channel_hint_from_name("ENDPOINT-01_Security.evtx") == "security"


# ---------- incoming protection ----------

def test_incoming_change_stops_the_run(repo, monkeypatch):
    t1 = put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    put_trial(repo, "S02", "trial_02", hosts=("DC-01",), channels=("system",))
    seen = []

    def convert(roots, plan):
        seen.append(plan.trial_id)
        with open(next(t1.rglob("*.evtx")), "ab") as f:  # simulate a tool touching incoming
            f.write(b"x")
        raise RuntimeError("stop")

    monkeypatch.setattr(batch, "run_convert", convert)
    assert run(repo, "--keep-going") == 1  # a change stops even with --keep-going
    assert seen == ["s02_t01"]
    rep = report(repo, "s02_t01")
    assert rep["status"] == "error" and rep["incoming_hashes"]["unchanged"] is False
    assert "INCOMING FILES CHANGED" in rep["error"]
    assert not (repo / "out/ingest/x10/s02_t02").exists()


def test_incoming_unchanged_recorded(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run(repo) == 0
    h = report(repo, "s02_t01")["incoming_hashes"]
    assert h["unchanged"] is True and h["files"] == 1


# ---------- resumable, flags ----------

def test_complete_trial_skipped_unless_force(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    assert run(repo) == 0
    assert fake_heavy["convert"] == ["s02_t01"]
    manifest_before = (repo / "data/manifest.csv").read_bytes()
    assert run(repo) == 0
    assert fake_heavy["convert"] == ["s02_t01"]  # skipped
    assert run(repo, "--force") == 0
    assert fake_heavy["convert"] == ["s02_t01", "s02_t01"]
    assert (repo / "data/manifest.csv").read_bytes().startswith(manifest_before)
    rows = manifest_rows(repo / "data/manifest.csv")
    assert len(rows) == 1  # no duplicate row after a forced rerun


def test_incomplete_trial_with_db_fails_loudly(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    db = repo / "data/processed/s02_t01.sqlite3"
    db.write_bytes(b"half")
    assert run(repo) == 1
    assert db.read_bytes() == b"half"
    rep = report(repo, "s02_t01")
    assert rep["status"] == "error" and "--force" in rep["error"]
    assert fake_heavy["convert"] == []
    assert run(repo, "--force") == 0


def test_only_and_unknown_only(repo, fake_heavy, capsys):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    put_trial(repo, "S02", "trial_02", hosts=("DC-01",), channels=("system",))
    assert run(repo, "--only", "s02_t09") == 2
    assert fake_heavy["convert"] == []
    assert run(repo, "--only", "s02_t02") == 0
    assert fake_heavy["convert"] == ["s02_t02"]
    assert not (repo / "data/raw/s02/t01").exists()


def test_scenarios_filter(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    put_trial(repo, "S03", "trial_01", hosts=("DC-01",), channels=("system",))
    put_trial(repo, QDIR, "trial_01", hosts=("DC-01",), channels=("system",))
    assert run(repo, "--scenarios", "s03") == 0
    assert fake_heavy["convert"] == ["s03_t01"]
    assert run(repo, "--scenarios", "s02,s05q") == 0
    assert sorted(fake_heavy["convert"]) == ["s02_t01", "s03_t01", "s05q_t01"]


def test_dry_run_writes_nothing(repo, fake_heavy, capsys):
    put_trial(repo, "S02", "trial_01")
    put_trial(repo, QDIR, "trial_01", hosts=("DC-01",))
    before = snapshot(repo)
    dirs = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_dir())
    assert run(repo, "--dry-run") == 0
    assert snapshot(repo) == before
    assert sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*") if p.is_dir()) == dirs
    assert fake_heavy["convert"] == []
    out = capsys.readouterr().out
    assert "s02_t01" in out and "s05q_t01" in out


def test_ground_truth_never_written(repo, fake_heavy):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    put_trial(repo, QDIR, "trial_01", hosts=("DC-01",), channels=("system",))
    before = snapshot(repo / "ground_truth")
    assert run(repo) == 0
    assert snapshot(repo / "ground_truth") == before
    assert not any(p.is_dir() for p in (repo / "ground_truth").iterdir() if p.name != "approved")


def test_cli_batch_subcommand(repo, fake_heavy, capsys):
    put_trial(repo, "S02", "trial_01", hosts=("DC-01",), channels=("system",))
    assert cli.main(["batch", "--repo", str(repo), "--dry-run"]) == 0
    assert "s02_t01" in capsys.readouterr().out
    assert cli.main(["batch", "--repo", str(repo)]) == 0
    assert (repo / "data/raw/s02/t01/dc01/system.evtx").is_file()


# ---------- one real end-to-end ----------

def test_end_to_end_real_tiny_evtx(repo):
    put_trial(repo, "S02", "trial_01", hosts=("ENDPOINT-01",), channels=("system", "winrm"))
    assert run(repo) == 0
    rep = report(repo, "s02_t01")
    assert rep["status"] == "ok" and rep["reconcile"]["ok"] is True
    assert (repo / "data/processed/s02_t01.sqlite3").exists()
    import sqlite3
    con = sqlite3.connect(repo / "data/processed/s02_t01.sqlite3")
    n = con.execute("select count(*) from events").fetchone()[0]
    con.close()
    assert n == rep["import"]["events"]
    assert (repo / "out/ingest/x10/s02_t01/ingest.md").is_file()


# ---------- recorded real results (read only) ----------

@pytest.mark.parametrize("tid,copied,missing", [
    ("s02_t01", 20, set()),
    ("s02_t03", 18, {("dc01", "security"), ("dc01", "sysmon")}),
])
def test_real_recorded_ingests(tid, copied, missing):
    p = REPO / "out/ingest/x10" / tid / "ingest.json"
    if not p.exists():
        pytest.skip("real ingest report absent")
    d = json.loads(p.read_text(encoding="utf-8"))
    assert d["status"] == "ok"
    assert len(d["files_copied"]) == copied
    assert {(m["host"], m["channel"]) for m in d["files_missing"]} == missing
    assert d["reconcile"]["ok"] is True
    assert d["incoming_hashes"]["unchanged"] is True
    assert d["quarantine"] is False
