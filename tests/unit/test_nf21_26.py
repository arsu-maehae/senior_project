"""Tests for spec rules NF-21..NF-26 (docs/specs/01_normalise_fixes.md section 4c, decision 010).

Written from the spec and the answer rows named in it; skipped with a reason when data is missing.
"""
from __future__ import annotations

import copy
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src" / "parsing_normalization"))
sys.path.insert(0, str(REPO / "tests" / "unit"))

from evtx_pipeline.trial_normalize import normalize_trial_event  # noqa: E402
import test_trial_import as ti  # noqa: E402  (fixture helpers)

JSONL = REPO / "data" / "processed" / "jsonl"
PROCESSED = REPO / "data" / "processed"


def read_line(rel: str, line_no: int) -> dict:
    path = JSONL / rel
    if not path.exists():
        pytest.skip(f"missing development JSONL: {path}")
    with open(path, encoding="utf-8", newline="") as fh:
        return json.loads(fh.read().split("\n")[line_no - 1])


def norm(event: dict, scenario="s05", line=1) -> dict:
    return normalize_trial_event(event, scenario_id=scenario, trial_id="t00", line_number=line)


def real(rel: str, line_no: int, scenario: str) -> dict:
    return norm(read_line(rel, line_no), scenario=scenario, line=line_no)


# ---------------------------------------------------------------- NF-21
WINRM = "s05_t00/per_file/ep-02/winrm.jsonl"


def test_nf21_real_winrm91():
    r = real(WINRM, 1525, "s05")
    assert r["event_id"] == 91
    assert r["account_name"] == "admin_it"
    assert r["domain"] == "LAB"
    assert r["domain_short"] == "lab"
    assert r["source_ip"] == "192.168.50.23"


def test_nf21_original_string_kept_in_field_values():
    r = real(WINRM, 1525, "s05")
    assert "clientIP: 192.168.50.23" in r["field_values_json"]
    assert "admin_it" in r["field_values_json"]


def test_nf21_no_pattern_unchanged():
    ev = copy.deepcopy(read_line(WINRM, 1525))
    for item in ev["event_data"]:
        if item["name"] == "resourceUri":
            item["value"] = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
    r = norm(ev, line=1525)
    assert r["source_ip"] is None
    assert r["account_name"] is None
    assert r["domain_short"] is None


# ---------------------------------------------------------------- NF-22
def test_nf22_real_5145():
    r = real("s04_t00/per_file/ep-02/security.jsonl", 5839, "s04")
    assert r["event_id"] == 5145
    assert r["relative_target_name"] == "\\"
    assert r["share_path"] == "\\??\\C:\\Shared"


def test_nf22_non_5145_has_null_relative_target_name():
    r = real("s02_t00/per_file/ep-02/security.jsonl", 8, "s02")
    assert r["relative_target_name"] is None


# ---------------------------------------------------------------- NF-23
def test_nf23_sysmon_event_utc_differs_from_record_time_s02():
    r = real("s02_t00/per_file/ep-02/sysmon.jsonl", 214, "s02")
    assert r["timestamp_utc"] == "2026-09-24T05:38:04.653545Z"
    assert r["event_utc"] == "2026-09-24T05:38:02.691000Z"


def test_nf23_sysmon_event_utc_s05():
    r = real("s05_t00/per_file/ep-02/sysmon.jsonl", 107, "s05")
    assert r["event_utc"] == "2026-10-12T07:03:37.508000Z"  # date from the file
    assert r["timestamp_utc"] > r["event_utc"]


def test_nf23_non_sysmon_event_utc_equals_timestamp():
    for rel, ln, sc in [("s02_t00/per_file/ep-02/security.jsonl", 8, "s02"), (WINRM, 1525, "s05")]:
        r = real(rel, ln, sc)
        assert r["event_utc"] == r["timestamp_utc"]


# ---------------------------------------------------------------- NF-24
def test_nf24_4688_new_and_parent_pid():
    r = real("s02_t00/per_file/ep-02/security.jsonl", 8, "s02")
    assert r["event_id"] == 4688
    assert r["process_id"] == 1792 == 0x700
    assert r["parent_process_id"] == 10200 == 0x27D8


def test_nf24_non_4688_keeps_old_meaning():
    ev = ti.logon4624("ep-02/security.evtx", 5)
    ev["event_data"].append({"name": "ProcessId", "value": "0x27d8"})
    r = norm(ev, scenario="s02")
    assert r["event_id"] == 4624
    assert r["process_id"] == 0x27D8      # the event's own ProcessId, as before NF-24
    assert r["parent_process_id"] is None


def test_nf24_sysmon1_unchanged():
    r = real("s05_t00/per_file/ep-02/sysmon.jsonl", 107, "s05")
    assert (r["process_id"], r["parent_process_id"]) == (3792, 820)


# ---------------------------------------------------------------- NF-25
def test_nf25_real_4779():
    r = real("s01_t00/per_file/ep-02/security.jsonl", 6483, "s01")
    assert r["event_id"] == 4779
    assert r["session_id"] == 0x6962F == 431663


@pytest.mark.parametrize("eid", [4778, 4779])
def test_nf25_synthetic(eid):
    ev = ti.make_event("Security", eid, {"AccountName": "svc_backup", "AccountDomain": "LAB",
                                          "LogonID": "0x6962f", "SessionName": "Console",
                                          "ClientName": "Unknown", "ClientAddress": "LOCAL"},
                       rel="ep-02/security.evtx", record_id=9)
    r = norm(ev, scenario="s01")
    assert r["session_id"] == 0x6962F


# ---------------------------------------------------------------- NF-26
def test_nf26_published_db(tmp_path):
    jdir = ti.build_trial(tmp_path)
    db, rep, result = ti.do_import(tmp_path, jdir)
    assert db.exists()
    conn = sqlite3.connect(db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
    assert conn.execute("select status from trial_run").fetchone()[0] == "complete"
    conn.close()
    assert not Path(str(db) + "-wal").exists() and not Path(str(db) + "-shm").exists()
    reports = list(rep.rglob("*.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["status"] == "PASS"
    assert result["status"] == "PASS"


def test_nf26_validation_failure_no_db_but_fail_report(tmp_path, monkeypatch):
    import evtx_pipeline.trial_import as mod
    real_checks = mod.run_checks

    def bad_checks(conn, acc):
        return real_checks(conn, acc) + [("forced_failure", False, 1, 0)]

    monkeypatch.setattr(mod, "run_checks", bad_checks)
    jdir = ti.build_trial(tmp_path)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    rep = tmp_path / "reports"
    with pytest.raises(Exception):
        mod.run_trial_import(jdir, "s02", "t00", db, rep)
    out = tmp_path / "out"
    assert not out.exists() or list(out.iterdir()) == []
    reports = list(rep.rglob("*.json"))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text(encoding="utf-8"))["status"] == "FAIL"


def test_nf26_accounting_mismatch_writes_no_report_known_gap(tmp_path):
    """Known gap: a manifest/accounting mismatch aborts before the report stage, so no FAIL report exists."""
    jdir = ti.build_trial(tmp_path, emitted_delta=1)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    rep = tmp_path / "reports"
    with pytest.raises(Exception):
        ti.run_trial_import(jdir, "s02", "t00", db, rep)
    assert not db.exists()
    assert not rep.exists() or not list(rep.rglob("*.json"))


def test_nf26_journal_mode_check_removes_wal_db(tmp_path):
    from evtx_pipeline.trial_import import verify_published_journal_mode
    db = tmp_path / "x.sqlite3"
    c = sqlite3.connect(db)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("create table t(a)")
    c.commit()
    c.close()
    with pytest.raises(Exception):
        verify_published_journal_mode(db)
    assert not db.exists()


# ---------------------------------------------------------------- real DBs
SCENARIOS = ["s01", "s02", "s03", "s04", "s05", "s06", "s07"]


def ro(sc: str) -> sqlite3.Connection:
    p = PROCESSED / f"{sc}_t00.sqlite3"
    if not p.exists():
        pytest.skip(f"missing {p}")
    return sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)


def sysmon_deltas(conn) -> list[float]:
    d = [r[0] for r in conn.execute(
        "select (julianday(timestamp_utc)-julianday(event_utc))*86400.0 from events where channel='Sysmon'")]
    return sorted(d)


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_event_utc_never_null(sc):
    conn = ro(sc)
    assert conn.execute("select count(*) from events where event_utc is null").fetchone()[0] == 0


def host_deltas(conn, hosts) -> list[float]:
    q = ",".join("'%s'" % h for h in hosts)
    return [r[0] for r in conn.execute(
        "select (julianday(timestamp_utc)-julianday(event_utc))*86400.0 from events "
        f"where channel='Sysmon' and host in ({q})")]


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_sysmon_gap_bounded_on_dc01_ep01(sc):
    d = host_deltas(ro(sc), ["dc01", "ep-01"])
    if not d:
        pytest.skip("no Sysmon rows on dc01/ep-01")
    assert min(d) >= -0.001 and max(d) <= 60, f"min {min(d):.3f}s max {max(d):.3f}s"


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_sysmon_gap_finite_on_ep02_ep03(sc):
    # Outliers (negative gaps, up to ~59,944 s) on ep-02/ep-03 are a documented data finding (spec NF-23):
    # clock steps. Only non-NULL event_utc and a finite gap are asserted.
    conn = ro(sc)
    assert conn.execute("select count(*) from events where channel='Sysmon' and host in ('ep-02','ep-03') "
                        "and event_utc is null").fetchone()[0] == 0
    import math
    assert all(math.isfinite(x) for x in host_deltas(conn, ["ep-02", "ep-03"]))


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_4688_has_both_pids(sc):
    bad = ro(sc).execute("select event_uid from events where channel='Security' and event_id=4688 and "
                         "(process_id is null or parent_process_id is null) limit 10").fetchall()
    assert not bad, f"4688 rows missing a pid: {bad}"


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_winrm91_clientip_parsed(sc):
    conn = ro(sc)
    bad = [r[0] for r in conn.execute(
        "select event_uid from events where event_id=91 and channel='WinRM' and "
        "field_values_json like '%clientIP%' and (source_ip is null or account_name is null)")]
    assert not bad, f"{len(bad)} WinRM 91 rows with clientIP but NULL source_ip/account_name, e.g. {bad[:5]}"


@pytest.mark.parametrize("sc", SCENARIOS)
def test_db_winrm91_ipv4_clientip_parsed(sc):
    """Spec NF-21 names only the IPv4 form a.b.c.d."""
    pat = re.compile(r"clientIP: \d+\.\d+\.\d+\.\d+\)")
    rows = ro(sc).execute("select event_uid, field_values_json, source_ip, account_name from events "
                          "where event_id=91 and channel='WinRM' and field_values_json like '%clientIP%'").fetchall()
    bad = [r[0] for r in rows if pat.search(r[1]) and (r[2] is None or r[3] is None)]
    assert not bad, bad[:5]
