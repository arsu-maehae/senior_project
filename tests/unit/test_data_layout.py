"""Tester for T1 data_layout: behaviour tests via the CLI, using tiny real EVTX copied from data/incoming (read only)."""
from __future__ import annotations

import csv
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
INC = REPO / "data" / "incoming" / "dryrun" / "ep-02" / "dryrun_s04" / "evtx_export"
SYSTEM_SRC = INC / "ENDPOINT-02_System.evtx"
SYSMON_SRC = INC / "ENDPOINT-02_Microsoft-Windows-Sysmon_Operational.evtx"
EVTX_MAGIC = b"ElfFile\x00"


def _need(p: Path) -> Path:
    if not p.exists():
        pytest.skip(f"real fixture missing: {p}")
    return p


def cli(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    return subprocess.run([sys.executable, "-m", "data_layout.cli", *map(str, args)],
                          capture_output=True, text=True, env=env)


def put(src: Path, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(_need(src), dst)
    return dst


def rows(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def do_map(source: Path, out: Path, trial="t00", *extra) -> subprocess.CompletedProcess:
    return cli("map", "--source", source, "--trial", trial, "--out", out, *extra)


@pytest.fixture
def src(tmp_path) -> Path:
    s = tmp_path / "src"
    s.mkdir()
    return s


# ---------- mapping ----------

def test_basic_layout_and_channel_from_record_not_name(tmp_path, src):
    # File names deliberately lie: sysmon content named "Security.evtx".
    put(SYSMON_SRC, src / "ep-02" / "dryrun_s04" / "Security.evtx")
    put(SYSTEM_SRC, src / "ep-02" / "dryrun_s04" / "whatever.evtx")
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    by = {r["source_path"]: r for r in rows(out)}
    a = by["ep-02/dryrun_s04/Security.evtx"]
    b = by["ep-02/dryrun_s04/whatever.evtx"]
    assert (a["action"], a["dest_path"]) == ("copy", "s04/t00/ep-02/sysmon.evtx")
    assert (b["action"], b["dest_path"]) == ("copy", "s04/t00/ep-02/system.evtx")
    assert a["scenario"] == "s04" and a["trial"] == "t00" and a["host"] == "ep-02" and a["channel"] == "sysmon"


def test_scenario_case_insensitive_and_trial_arg(tmp_path, src):
    put(SYSTEM_SRC, src / "DC01" / "Dryrun_S03" / "x.evtx")
    out = tmp_path / "map.csv"
    assert do_map(src, out, "t07").returncode == 0
    r = rows(out)[0]
    assert r["dest_path"] == "s03/t07/dc01/system.evtx"


def test_evt_with_evtx_magic_is_copied_as_evtx(tmp_path, src):
    put(SYSTEM_SRC, src / "ep-01" / "Dryrun_S02" / "log.evt")
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    r = rows(out)[0]
    assert r["action"] == "copy"
    assert r["dest_path"] == "s02/t00/ep-01/system.evtx"
    assert "renamed" in r["reason"].lower()


def test_legacy_lfle_evt_ignored(tmp_path, src):
    f = src / "ep-01" / "Dryrun_S02" / "old.evt"
    f.parent.mkdir(parents=True)
    f.write_bytes(b"\x30\x00\x00\x00LfLe" + b"\x00" * 100)
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    r = rows(out)[0]
    assert r["action"] == "ignore" and r["dest_path"] == "" and r["reason"]


def test_text_log_ignored_with_reason(tmp_path, src):
    f = src / "ep-01" / "Dryrun_S02" / "vmware-1.log"
    f.parent.mkdir(parents=True)
    f.write_text("hello not an event log\n" * 5)
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    r = rows(out)[0]
    assert r["action"] == "ignore" and r["reason"].strip()


def test_text_file_with_evtx_extension_ignored(tmp_path, src):
    f = src / "ep-01" / "Dryrun_S02" / "fake.evtx"
    f.parent.mkdir(parents=True)
    f.write_text("not evtx at all")
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    r = rows(out)[0]
    assert r["action"] == "ignore" and r["reason"].strip()


def test_nested_ep02_folder_wins_over_first_folder(tmp_path, src):
    put(SYSTEM_SRC, src / "ep-01" / "Dryrun_S01" / "EP-02" / "ENDPOINT-02_System.evtx")
    put(SYSTEM_SRC, src / "ep-01" / "Dryrun_S01" / "EP-01" / "ENDPOINT-01_System.evtx")
    out = tmp_path / "map.csv"
    assert do_map(src, out).returncode == 0
    dests = {r["source_path"]: r["dest_path"] for r in rows(out)}
    assert dests["ep-01/Dryrun_S01/EP-02/ENDPOINT-02_System.evtx"] == "s01/t00/ep-02/system.evtx"
    assert dests["ep-01/Dryrun_S01/EP-01/ENDPOINT-01_System.evtx"] == "s01/t00/ep-01/system.evtx"


def test_override_replaces_action(tmp_path, src):
    put(SYSTEM_SRC, src / "ep-02" / "dryrun_s01" / "System.evtx")
    ov = tmp_path / "ov.csv"
    ov.write_text("source_path,action,reason\nep-02/dryrun_s01/System.evtx,ignore,superseded test\n")
    out = tmp_path / "map.csv"
    assert do_map(src, out, "t00", "--overrides", ov).returncode == 0
    r = rows(out)[0]
    assert r["action"] == "ignore" and "superseded test" in r["reason"] and r["dest_path"] == ""


def test_collision_is_error_and_override_resolves(tmp_path, src):
    put(SYSTEM_SRC, src / "ep-02" / "dryrun_s01" / "A.evtx")
    put(SYSTEM_SRC, src / "ep-02" / "dryrun_s01" / "B.evtx")
    out = tmp_path / "map.csv"
    r = do_map(src, out)
    assert r.returncode != 0
    assert "collision" in (r.stderr + r.stdout).lower()
    ov = tmp_path / "ov.csv"
    ov.write_text("source_path,action,reason\nep-02/dryrun_s01/B.evtx,ignore,dup\n")
    assert do_map(src, out, "t00", "--overrides", ov).returncode == 0


def test_map_is_read_only_on_source(tmp_path, src):
    f = put(SYSTEM_SRC, src / "ep-02" / "dryrun_s01" / "A.evtx")
    before = (sha(f), f.stat().st_mtime_ns)
    do_map(src, tmp_path / "map.csv")
    assert (sha(f), f.stat().st_mtime_ns) == before


def test_real_override_file_parses():
    p = REPO / "docs" / "data_overrides_t00.csv"
    if not p.exists():
        pytest.skip("overrides csv missing")
    rs = rows(p)
    assert rs and set(rs[0]) >= {"source_path", "action", "reason"}
    assert all(r["action"] in ("copy", "ignore") for r in rs)


# ---------- copy ----------

@pytest.fixture
def mapped(tmp_path, src):
    f = put(SYSTEM_SRC, src / "ep-02" / "dryrun_s04" / "System.evtx")
    # fix a known old mtime to test preservation
    old = 1_700_000_000
    os.utime(f, (old, old))
    mp = tmp_path / "map.csv"
    assert do_map(src, mp).returncode == 0
    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    return src, mp, raw, f


def test_copy_never_moves_verifies_and_preserves_mtime(mapped):
    src, mp, raw, f = mapped
    r = cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw)
    assert r.returncode == 0, r.stderr
    dest = raw / "s04" / "t00" / "ep-02" / "system.evtx"
    assert f.exists(), "source must remain"
    assert dest.read_bytes()[:8] == EVTX_MAGIC
    assert sha(dest) == sha(f)
    assert int(dest.stat().st_mtime) == int(f.stat().st_mtime) == 1_700_000_000
    assert not list(raw.rglob("*.part"))


def test_copy_refuses_overwrite_dest_unchanged(mapped):
    src, mp, raw, f = mapped
    dest = raw / "s04" / "t00" / "ep-02" / "system.evtx"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"PRECIOUS")
    r = cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw)
    assert r.returncode != 0
    assert dest.read_bytes() == b"PRECIOUS"
    assert f.exists()


def test_copy_twice_second_fails_without_change(mapped):
    src, mp, raw, f = mapped
    assert cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw).returncode == 0
    dest = raw / "s04" / "t00" / "ep-02" / "system.evtx"
    h = sha(dest)
    assert cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw).returncode != 0
    assert sha(dest) == h


def test_copy_ignores_ignore_rows(tmp_path, src):
    f = src / "ep-01" / "Dryrun_S02" / "vmware-1.log"
    f.parent.mkdir(parents=True)
    f.write_text("x")
    mp = tmp_path / "map.csv"
    assert do_map(src, mp).returncode == 0
    raw = tmp_path / "raw"
    raw.mkdir()
    assert cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw).returncode == 0
    assert not [p for p in raw.rglob("*") if p.is_file()]


def _write_map(path: Path, dest: str, srcrel: str):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source_path", "scenario", "trial", "host", "channel", "dest_path", "action", "reason"])
        w.writerow([srcrel, "s04", "t00", "ep-02", "system", dest, "copy", "ok"])


@pytest.mark.parametrize("dest", ["../evil.evtx", "s04/../../evil.evtx", "../../../evil.evtx"])
def test_path_traversal_dest_rejected(tmp_path, src, dest):
    put(SYSTEM_SRC, src / "a.evtx")
    mp = tmp_path / "m.csv"
    _write_map(mp, dest, "a.evtx")
    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    r = cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw)
    assert r.returncode != 0
    assert not (tmp_path / "data" / "evil.evtx").exists()
    assert not (tmp_path / "evil.evtx").exists()
    assert not (tmp_path.parent / "evil.evtx").exists()


def test_absolute_dest_rejected(tmp_path, src):
    put(SYSTEM_SRC, src / "a.evtx")
    target = tmp_path / "outside" / "x.evtx"
    mp = tmp_path / "m.csv"
    _write_map(mp, str(target), "a.evtx")
    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    r = cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw)
    assert r.returncode != 0
    assert not target.exists()


def test_dest_through_data_incoming_rejected(tmp_path, src):
    put(SYSTEM_SRC, src / "a.evtx")
    mp = tmp_path / "m.csv"
    _write_map(mp, "s04/t00/ep-02/system.evtx", "a.evtx")
    raw = tmp_path / "data" / "incoming" / "raw"
    raw.mkdir(parents=True)
    r = cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw)
    assert r.returncode != 0
    assert not [p for p in raw.rglob("*") if p.is_file()]


# ---------- manifest ----------

MANIFEST_COLS = ["path", "sha256", "size", "scenario", "trial", "host", "channel",
                 "source_path", "date", "records", "first_event_utc", "last_event_utc"]


def test_manifest_columns_values_and_idempotent(mapped, tmp_path):
    src, mp, raw, f = mapped
    assert cli("copy", "--source", src, "--mapping", mp, "--raw-root", raw).returncode == 0
    man = tmp_path / "manifest.csv"
    r = cli("manifest", "--raw-root", raw, "--mapping", mp, "--out", man)
    assert r.returncode == 0, r.stderr
    rs = rows(man)
    assert list(rs[0].keys()) == MANIFEST_COLS
    assert len(rs) == 1
    m = rs[0]
    dest = raw / "s04" / "t00" / "ep-02" / "system.evtx"
    assert m["path"] == "s04/t00/ep-02/system.evtx"
    assert m["sha256"] == sha(dest)
    assert int(m["size"]) == dest.stat().st_size
    assert (m["scenario"], m["trial"], m["host"], m["channel"]) == ("s04", "t00", "ep-02", "system")
    assert m["source_path"] == "ep-02/dryrun_s04/System.evtx"
    assert m["date"] == "2023-11-14T22:13:20Z"  # 1_700_000_000 UTC
    assert int(m["records"]) > 0
    assert m["first_event_utc"].endswith("Z") and m["last_event_utc"].endswith("Z")
    assert m["first_event_utc"] <= m["last_event_utc"]

    before = man.read_bytes()
    r2 = cli("manifest", "--raw-root", raw, "--mapping", mp, "--out", man)
    assert r2.returncode == 0
    assert "added=0" in r2.stdout
    assert man.read_bytes() == before


def test_manifest_appends_only_new_rows(tmp_path, src):
    put(SYSTEM_SRC, src / "ep-02" / "dryrun_s04" / "System.evtx")
    mp1 = tmp_path / "m1.csv"
    assert do_map(src, mp1).returncode == 0
    raw = tmp_path / "raw"
    raw.mkdir()
    assert cli("copy", "--source", src, "--mapping", mp1, "--raw-root", raw).returncode == 0
    man = tmp_path / "man.csv"
    assert cli("manifest", "--raw-root", raw, "--mapping", mp1, "--out", man).returncode == 0
    first = man.read_bytes()
    # add a second file, new mapping covering both
    put(SYSMON_SRC, src / "ep-02" / "dryrun_s04" / "Sysmon.evtx")
    mp2 = tmp_path / "m2.csv"
    assert do_map(src, mp2).returncode == 0
    # copy would refuse the existing one (non-zero) but still copies the new one
    cli("copy", "--source", src, "--mapping", mp2, "--raw-root", raw)
    r = cli("manifest", "--raw-root", raw, "--mapping", mp2, "--out", man)
    assert r.returncode == 0 and "added=1" in r.stdout
    assert man.read_bytes().startswith(first), "existing rows must not be rewritten"
    assert len(rows(man)) == 2
