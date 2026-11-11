"""Tests for the read-only package src/x10_validate (x10 trial design validator).

Written from decision 029 (criteria a-i, severities, verdict rule) and decision 030 (quarantine
identity). The code was read only to learn the input shape (events_dedup columns, function names);
synthetic trials are built from the implementation notes N1-N15, but every assertion is a 029 severity.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import itertools
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
PKG = SRC / "x10_validate"
sys.path.insert(0, str(SRC))

from x10_validate import cli, cross, db  # noqa: E402
from x10_validate.design import design_for  # noqa: E402
from x10_validate.validate import validate_trial  # noqa: E402

FORBIDDEN = ("answer_key", "log_check", "data_layout", "evtx_pipeline", "parsing_normalization")


def _forbidden(name: str) -> bool:
    return any(p in FORBIDDEN or "stitch" in p for p in name.split("."))


# ============================================================================ 1. import independence

def _imports(path: Path) -> list[tuple[int, str]]:
    """(relative level, dotted module) of every import, including 'from . import x' names."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out += [(0, a.name) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            out.append((node.level, mod))
            out += [(node.level, f"{mod}.{a.name}".strip(".")) for a in node.names]
    return out


def test_no_forbidden_imports_ast():
    files = sorted(PKG.glob("*.py"))
    assert files
    for f in files:
        for level, mod in _imports(f):
            assert not _forbidden(mod), f"{f.name} imports {mod}"


def test_stdlib_only():
    for f in sorted(PKG.glob("*.py")):
        for level, mod in _imports(f):
            if level > 0:
                continue                       # relative import inside the package
            top = mod.split(".")[0]
            assert top in sys.stdlib_module_names or top == "x10_validate", f"{f.name} imports non-stdlib {mod}"


def test_no_forbidden_modules_loaded_in_subprocess():
    code = (
        "import sys, importlib, pkgutil\n"
        f"sys.path.insert(0, {str(SRC)!r})\n"
        "import x10_validate\n"
        "for m in pkgutil.iter_modules(x10_validate.__path__):\n"
        "    if m.name != '__main__': importlib.import_module('x10_validate.' + m.name)\n"
        f"bad = [n for n in sys.modules if any(p in {FORBIDDEN!r} or 'stitch' in p for p in n.split('.'))]\n"
        "print('BAD', bad)\n"
    )
    cp = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    assert cp.returncode == 0, cp.stderr
    assert "BAD []" in cp.stdout, cp.stdout


def test_no_ground_truth_or_log_check_path_in_sources():
    for f in sorted(PKG.glob("*.py")):
        text = f.read_text(encoding="utf-8")
        assert "ground_truth" not in text, f.name
        assert "out/log_check" not in text and "out\\log_check" not in text and "out\\\\log_check" not in text, f.name


# ============================================================================ synthetic trial builder

T0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
IP = {"ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23"}
HOSTS = ("ep-01", "ep-02", "ep-03", "dc01")
CHANNELS = ("security", "system", "sysmon", "powershell", "winrm")
AGENT = r"C:\Users\Public\splunkd.exe"
_uid = itertools.count(1)


def _iso(t0: datetime, off: float) -> str:
    return (t0 + timedelta(seconds=off)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def row(t0: datetime, off: float, host: str, channel: str, eid: int, **kw) -> dict:
    r = {c: None for c in db.COLUMNS}
    r.update(event_uid=f"u{next(_uid)}", host=host, channel=channel, event_id=eid, event_utc=_iso(t0, off), **kw)
    r["ts"] = db.parse_ts(r["event_utc"])
    return r


def full_counts() -> dict:
    return {h: {c: 1 for c in CHANNELS} for h in HOSTS}


def agent_cmd(t0, off, host, cmd, guid, acct="svc_backup", sess=3):
    return row(t0, off, host, "Sysmon", 1, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
               parent_image=AGENT, process_guid=guid, parent_process_guid="splunkd-" + host, command_line=cmd,
               account_name=acct, session_id=sess, process_id=1000 + next(_uid))


def dump(t0, off, host="ep-01", acct="svc_backup", guid=None):
    return row(t0, off, host, "Sysmon", 10, source_image=r"C:\Windows\System32\rundll32.exe",
               target_image=r"C:\Windows\System32\lsass.exe", account_name=acct, process_guid=guid or f"dg{next(_uid)}",
               granted_access="0x1fffff")


def beacon(t0, off, host="ep-01"):
    return row(t0, off, host, "Sysmon", 3, image=AGENT, destination_ip="192.168.50.50", destination_port=8888,
               account_name="svc_backup", source_ip=IP.get(host))


def logon(t0, off, host, src, acct, lid, guid=None):
    return row(t0, off, host, "Security", 4624, logon_type=3, source_ip=IP[src], account_name=acct,
               target_logon_id=lid, logon_guid=guid, authentication_package="NTLM")


def smb_write(t0, off, host, src, acct, lid, fname):
    return row(t0, off, host, "Security", 5145, share_name=r"\\*\ADMIN$", relative_target_name=fname, source_ip=IP[src],
               account_name=acct, subject_logon_id=lid, field_values_json=json.dumps({"accessmask": ["0x2"]}))


def service(t0, off, host, name, image):
    return row(t0, off, host, "System", 7045, service_name=name, service_image_path=image)


def s02_rows(t0: datetime = T0, *, acct: str = "svc_backup", with_service: bool = True, with_beacon: bool = True,
             with_dc: bool = True, dc_shift: float = 0.0, svc: str = "x") -> list[dict]:
    """Passing minimal S02: beacon, dump, agent command naming ep-02, ep-02 4624, ADMIN$ write, service."""
    guid = "aaaaaaaa-0000-0000-0000-000000000001"
    rows = [dump(t0, 0),
            agent_cmd(t0, 5, "ep-01", r'powershell.exe -c "copy C:\x.exe \\ep-02\ADMIN$\x.exe; sc \\ep-02 create x '
                      r'binPath= C:\Windows\x.exe"', "g-b1"),
            logon(t0, 10, "ep-02", "ep-01", acct, 5000, guid),
            smb_write(t0, 11, "ep-02", "ep-01", acct, 5000, "x.exe")]
    if with_service:
        rows.append(service(t0, 12, "ep-02", svc, rf"C:\Windows\{svc}.exe"))
    if with_beacon:
        rows.append(beacon(t0, -30))
    if with_dc:
        rows.append(row(t0, 10 + dc_shift, "dc01", "Security", 4769, logon_guid=guid))
    return rows


def span_of(t0: datetime = T0) -> tuple[str, str]:
    return _iso(t0, -100), _iso(t0, 1000)


def run_trial(rows, scenario="s02", counts=None, trial_id=None, t0=T0, quarantine=False) -> dict:
    return validate_trial(trial_id or f"{scenario}_t01", scenario, quarantine, design_for(scenario), rows,
                          counts if counts is not None else full_counts(), span_of(t0), None)


def st(res: dict, c: str) -> str:
    return res["criteria"][c]["status"]


# ---- S04 and S06 builders

def s04_rows(t0: datetime = T0, *, track_a_write: bool = True, extra_dump_by_admin: bool = False) -> list[dict]:
    rows = s02_rows(t0)
    rows += [row(t0, 200, "ep-01", "Sysmon", 1, image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                 parent_image=r"C:\Windows\explorer.exe", process_guid="gA", parent_process_guid="pg-explorer",
                 command_line=r'powershell.exe -c "copy C:\a.exe \\ep-02\ADMIN$\a.exe; sc \\ep-02 create a '
                              r'binPath= C:\Windows\a.exe"', account_name="admin_it", session_id=7, process_id=4242),
             logon(t0, 210, "ep-02", "ep-01", "admin_it", 6000),
             service(t0, 212, "ep-02", "a", r"C:\Windows\a.exe")]
    if track_a_write:
        rows.append(smb_write(t0, 211, "ep-02", "ep-01", "admin_it", 6000, "a.exe"))
    if extra_dump_by_admin:
        rows.append(dump(t0, 220, "ep-01", "admin_it"))
    return rows


def s06_rows(t0: datetime = T0, *, acct: str = "admin_it", with_dump: bool = False) -> list[dict]:
    ps = r'powershell.exe -c "Invoke-Command -ComputerName {t} -ScriptBlock {{hostname}}"'
    rows = [agent_cmd(t0, 0, "ep-01", ps.format(t="ep-02"), "g6a", acct),
            agent_cmd(t0, 30, "ep-01", ps.format(t="ep-03"), "g6b", acct),
            agent_cmd(t0, 60, "ep-01", r"sc \\ep-02 create y binPath= C:\Windows\y.exe", "g6c", acct),
            logon(t0, 5, "ep-02", "ep-01", acct, 5001), logon(t0, 35, "ep-03", "ep-01", acct, 5002),
            logon(t0, 65, "ep-02", "ep-01", acct, 5003),
            service(t0, 66, "ep-02", "y", r"C:\Windows\y.exe"), beacon(t0, -30)]
    for off, host in ((6, "ep-02"), (36, "ep-03")):
        rows.append(row(t0, off, host, "WinRM", 91, field_values_json=json.dumps(
            {"resourceuri": [f"http://schemas (LAB\\{acct} clientIP: 192.168.50.21)"]})))
    if with_dump:
        rows.append(dump(t0, 90, "ep-01", acct))
    return rows


# ============================================================================ baselines

def test_baseline_s02_passes_every_local_criterion():
    res = run_trial(s02_rows())
    got = {c: st(res, c) for c in "abcdefgh"}
    assert got == {"a": "PASS", "b": "PASS", "c": "PASS", "d": "n/a", "e": "PASS", "f": "PASS", "g": "PASS",
                   "h": "PASS"}, res["criteria"]


def test_baseline_s04_and_s06_pass_their_own_criteria():
    r4 = run_trial(s04_rows(), "s04")
    assert st(r4, "b") == "PASS", r4["criteria"]["b"]
    assert st(r4, "c") == "PASS" and st(r4, "d") == "PASS" and st(r4, "e") == "PASS", r4["criteria"]
    r6 = run_trial(s06_rows(), "s06")
    assert st(r6, "c") == "PASS" and st(r6, "d") == "PASS", r6["criteria"]


# ============================================================================ 2. read-only

def _write_db(path: Path, rows: list[dict], scenario: str = "s02", trial: str = "t01") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    cols = list(db.COLUMNS) + ["scenario_id", "trial_id"]
    con.execute(f"CREATE TABLE events_dedup ({', '.join(cols)})")
    for r in rows:
        con.execute(f"INSERT INTO events_dedup VALUES ({', '.join('?' * len(cols))})",
                    [r[c] for c in db.COLUMNS] + [scenario, trial])
    con.commit()
    con.close()


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_db_opened_read_only_and_file_unchanged(tmp_path):
    repo = tmp_path
    path = repo / "data" / "processed" / "s02_t01.sqlite3"
    _write_db(path, s02_rows())
    before, mtime = _sha(path), path.stat().st_mtime_ns
    res = cli.validate_one(repo, "s02_t01", None)
    assert res["trial_id"] == "s02_t01"
    assert _sha(path) == before and path.stat().st_mtime_ns == mtime
    assert sorted(p.name for p in path.parent.iterdir()) == ["s02_t01.sqlite3"]   # no -wal / -journal
    con = db.open_ro(path)
    with pytest.raises(sqlite3.OperationalError):
        con.execute("CREATE TABLE x (a)")
    with pytest.raises(sqlite3.OperationalError):
        con.execute("DELETE FROM events_dedup")
    con.close()


def test_open_ro_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        db.open_ro(tmp_path / "nope.sqlite3")


def test_db_roundtrip_equals_in_memory(tmp_path):
    rows = s02_rows()
    path = tmp_path / "data" / "processed" / "s02_t01.sqlite3"
    _write_db(path, rows)
    res_db = cli.validate_one(tmp_path, "s02_t01", None)
    res_mem = run_trial(rows, t0=T0)
    for c in "bcdefgh":          # a differs: the DB holds only the few rows of this fixture, not 20 logs
        assert st(res_db, c) == st(res_mem, c), c


# ============================================================================ 3a criterion a

def test_a_pass_when_all_files():
    assert st(run_trial(s02_rows()), "a") == "PASS"


def test_a_path_host_missing_fails():
    counts = full_counts()
    counts.pop("ep-02")
    assert st(run_trial(s02_rows(), counts=counts), "a") == "FAIL"


def test_a_off_path_host_missing_warns():
    counts = full_counts()
    counts.pop("dc01")
    assert st(run_trial(s02_rows(), counts=counts), "a") == "WARN"


def test_a_single_log_missing_on_path_host_warns():
    counts = full_counts()
    counts["ep-02"]["winrm"] = 0
    assert st(run_trial(s02_rows(), counts=counts), "a") == "WARN"


def test_a_off_path_for_s03_is_ep02():
    """029: S03 path hosts are ep-01, ep-03; ep-02 absent is off the path -> WARN."""
    counts = full_counts()
    counts.pop("ep-02")
    res = validate_trial("s03_t01", "s03", False, design_for("s03"), s02_rows(), counts, span_of(), None)
    assert st(res, "a") == "WARN"


# ============================================================================ b

def test_b_missing_service_fails():
    res = run_trial(s02_rows(with_service=False))
    assert st(res, "b") == "FAIL"


def test_b_missing_binary_write_fails():
    rows = [r for r in s02_rows() if r["event_id"] != 5145]
    assert st(run_trial(rows), "b") == "FAIL"


def test_b_missing_target_logon_fails():
    rows = [r for r in s02_rows() if r["event_id"] != 4624]
    assert st(run_trial(rows), "b") == "FAIL"


def test_b_missing_dump_fails():
    rows = [r for r in s02_rows() if r["event_id"] != 10]
    assert st(run_trial(rows), "b") == "FAIL"


def test_b_missing_command_fails():
    rows = [r for r in s02_rows() if r["event_id"] != 1]
    assert st(run_trial(rows), "b") == "FAIL"


def test_b_command_not_naming_target_fails():
    rows = s02_rows()
    for r in rows:
        if r["event_id"] == 1:
            r["command_line"] = "powershell.exe -c hostname"
    assert st(run_trial(rows), "b") == "FAIL"


def test_b_no_anchor_at_all_fails():
    assert st(run_trial([beacon(T0, 0)]), "b") == "FAIL"


# ============================================================================ c

def test_c_other_account_fails():
    assert st(run_trial(s02_rows(acct="svc_sql")), "c") == "FAIL"


def test_c_other_account_s06_is_warn_not_fail():
    res = run_trial(s06_rows(acct="svc_sql"), "s06")
    assert st(res, "c") == "WARN"


def test_c_s07_y_intended_svc_sql_is_reported():
    """029: S07 path Y intended svc_sql; with only svc_backup observed, c is FAIL for Y and the observed account is reported."""
    rows = s02_rows()          # X only: svc_backup logon, svc_sql never appears
    res = validate_trial("s07_t01", "s07", False, design_for("s07"), rows, full_counts(), span_of(), None)
    assert st(res, "c") == "FAIL"
    hops = {h["hop_id"]: h for h in res["criteria"]["c"]["evidence"]["hops"]}
    assert hops["s07-Y"]["intended"] == "svc_sql" and "observed_in_window" in hops["s07-Y"]


# ============================================================================ d

def test_d_s04_track_a_without_admin_write_fails():
    assert st(run_trial(s04_rows(track_a_write=False), "s04"), "d") == "FAIL"


def test_d_s04_track_a_with_credential_access_fails():
    assert st(run_trial(s04_rows(extra_dump_by_admin=True), "s04"), "d") == "FAIL"


def test_d_s06_with_lsass_dump_fails():
    assert st(run_trial(s06_rows(with_dump=True), "s06"), "d") == "FAIL"


def test_d_is_not_applied_to_s02():
    assert st(run_trial(s02_rows()), "d") == "n/a"


# ============================================================================ e

def test_e_missing_beacon_fails():
    assert st(run_trial(s02_rows(with_beacon=False)), "e") == "FAIL"


def test_e_beacon_by_other_splunkd_path_does_not_count():
    rows = s02_rows(with_beacon=False)
    b = beacon(T0, -30)
    b["image"] = r"C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe"
    assert st(run_trial(rows + [b]), "e") == "FAIL"


def test_e_beacon_to_wrong_port_fails():
    rows = s02_rows(with_beacon=False)
    b = beacon(T0, -30)
    b["destination_port"] = 8089
    assert st(run_trial(rows + [b]), "e") == "FAIL"


def test_e_not_required_for_s04_track_a_manual():
    """029: e is not required for manual tracks; Track A has no beacon of its own, Track B's beacon suffices."""
    assert st(run_trial(s04_rows(), "s04"), "e") == "PASS"


# ============================================================================ f

def test_f_overlapping_windows_fail_across_trials():
    a = run_trial(s02_rows(T0), trial_id="s02_t01")
    b = run_trial(s02_rows(T0 + timedelta(seconds=100)), trial_id="s02_t02", t0=T0 + timedelta(seconds=100))
    out = {r["trial_id"]: r for r in cross.apply_cross([a, b])}
    assert st(out["s02_t01"], "f") == "FAIL" and st(out["s02_t02"], "f") == "FAIL"


def test_f_overlap_across_scenarios_fails():
    a = run_trial(s02_rows(T0), trial_id="s02_t01")
    b = run_trial(s02_rows(T0), "s03", trial_id="s03_t01")
    out = {r["trial_id"]: r for r in cross.apply_cross([a, b])}
    assert st(out["s02_t01"], "f") == "FAIL"


def test_f_separate_windows_pass():
    a = run_trial(s02_rows(T0), trial_id="s02_t01")
    t2 = T0 + timedelta(hours=3)
    b = run_trial(s02_rows(t2), trial_id="s02_t02", t0=t2)
    out = {r["trial_id"]: r for r in cross.apply_cross([a, b])}
    assert st(out["s02_t01"], "f") == "PASS" and st(out["s02_t02"], "f") == "PASS"


def test_f_older_cluster_over_30_min_warns():
    old = T0 - timedelta(minutes=40)
    rows = s02_rows() + [dump(old, 0), agent_cmd(old, 5, "ep-01", r"cmd /c dir \\ep-02\c$", "g-old")]
    res = run_trial(rows)
    assert st(res, "f") == "WARN"
    assert st(res, "b") == "PASS", "the older cluster must not pollute the design chain of the last run"
    out = cross.apply_cross([res])[0]
    assert st(out, "f") == "WARN"


def test_f_gap_just_under_30_min_is_same_cluster():
    """Anchors <= 30 min apart belong to one trial (decision 026, N1): no older cluster, so no WARN."""
    near = T0 - timedelta(minutes=20)
    rows = s02_rows() + [dump(near, 0)]
    assert st(run_trial(rows), "f") == "PASS"


# ============================================================================ g

def test_g_baseline_pass_with_dc01_security():
    assert st(run_trial(s02_rows()), "g") == "PASS"


def test_g_no_dc01_security_is_na_never_pass():
    counts = full_counts()
    counts["dc01"]["security"] = 0
    res = run_trial(s02_rows(with_dc=False), counts=counts)
    assert st(res, "g") == "n/a"
    assert res["criteria"]["g"]["evidence"].get("reason")


def test_g_offset_over_5s_warns():
    assert st(run_trial(s02_rows(dc_shift=-10.0)), "g") == "WARN"


def test_g_offset_under_5s_passes():
    assert st(run_trial(s02_rows(dc_shift=-2.0)), "g") == "PASS"


def test_g_lower_bound_over_5s_warns_without_dc01():
    """029: no dc01 Security -> n/a, but a lower bound > 5 s still gives WARN."""
    counts = full_counts()
    counts["dc01"]["security"] = 0
    rows = s02_rows(with_dc=False)
    for r in rows:                      # target 4624/5145/7045 logged 8 s BEFORE the source command
        if r["host"] == "ep-02":
            r["ts"] -= 13
            r["event_utc"] = db.iso(r["ts"])
    for r in rows:
        if r["event_id"] == 1:
            r["ts"] += 0
    res = run_trial(rows, counts=counts)
    assert st(res, "g") == "WARN"


# ============================================================================ h

def _extra_run(off, host, cmd, acct, guid):
    return agent_cmd(T0, off, host, cmd, guid, acct)


def test_h_single_run_passes():
    assert st(run_trial(s02_rows()), "h") == "PASS"


def test_h_indistinguishable_duplicate_fails():
    rows = s02_rows() + [_extra_run(40, "ep-01", r'powershell.exe -c "dir \\ep-02\ADMIN$"', "svc_backup", "g-dup")]
    assert st(run_trial(rows), "h") == "FAIL"


def test_h_duplicate_by_system_token_warns():
    rows = s02_rows() + [_extra_run(40, "ep-01", r'powershell.exe -c "dir \\ep-02\ADMIN$"', "SYSTEM", "g-sys")]
    assert st(run_trial(rows), "h") == "WARN"


def test_h_self_target_duplicate_warns():
    rows = s02_rows() + [_extra_run(20, "ep-02", r'powershell.exe -c "dir \\ep-02\ADMIN$"', "svc_backup", "g-self")]
    assert st(run_trial(rows), "h") == "WARN"


def test_h_duplicate_by_other_user_warns():
    rows = s02_rows() + [_extra_run(40, "ep-01", r'powershell.exe -c "dir \\ep-02\ADMIN$"', "admin_it", "g-other")]
    assert st(run_trial(rows), "h") == "WARN"


def test_h_processes_of_one_link_count_once():
    """Two child processes under one splunkd child (powershell -> net.exe) are one execution, not a duplicate."""
    rows = s02_rows()
    rows.append(row(T0, 6, "ep-01", "Sysmon", 1, image=r"C:\Windows\System32\net.exe", parent_image=r"C:\Windows\powershell.exe",
                    process_guid="g-child", parent_process_guid="g-b1", command_line=r"net use \\ep-02\ADMIN$",
                    account_name="svc_backup", session_id=3))
    assert st(run_trial(rows), "h") == "PASS"


def test_h_two_dumps_in_s02_same_user_fails():
    rows = s02_rows() + [dump(T0, 30, "ep-01", "svc_backup")]
    assert st(run_trial(rows), "h") == "FAIL"


# ============================================================================ i

def test_i_odd_shape_warns_majority_passes():
    results = []
    for n in range(5):
        t = T0 + timedelta(hours=3 * n)
        svc = "z" if n == 3 else "x"
        rows = s02_rows(t, svc=svc)
        if n == 3:
            for r in rows:
                if r["event_id"] == 1:
                    r["command_line"] = r["command_line"].replace("x.exe", "z.exe")
                if r["event_id"] == 5145:
                    r["relative_target_name"] = "z.exe"
        results.append(run_trial(rows, trial_id=f"s02_t0{n + 1}", t0=t))
    out = {r["trial_id"]: r for r in cross.apply_cross(results)}
    assert st(out["s02_t04"], "i") == "WARN"
    for tid in ("s02_t01", "s02_t02", "s02_t03", "s02_t05"):
        assert st(out[tid], "i") == "PASS"


def test_i_no_majority_is_na():
    results = []
    for n in range(2):
        t = T0 + timedelta(hours=3 * n)
        res = run_trial(s02_rows(t, svc="x" if n == 0 else "w"), trial_id=f"s02_t0{n + 1}", t0=t)
        results.append(res)
    out = cross.apply_cross(results)
    assert all(st(r, "i") in ("n/a", "WARN") for r in out)
    assert not any(st(r, "i") == "FAIL" for r in out)


def test_i_never_fails():
    results = [run_trial(s02_rows(T0 + timedelta(hours=3 * n), svc="x" if n else "q"), trial_id=f"s02_t0{n + 1}",
                         t0=T0 + timedelta(hours=3 * n)) for n in range(4)]
    assert all(st(r, "i") != "FAIL" for r in cross.apply_cross(results))


# ============================================================================ verdict (Decision 3)

def _fake(tid: str, fails=(), warns=(), scenario="s02") -> dict:
    crit = {c: {"status": "PASS"} for c in "abcdefghi"}
    for c in warns:
        crit[c] = {"status": "WARN"}
    for c in fails:
        crit[c] = {"status": "FAIL"}
    return {"trial_id": tid, "scenario": scenario, "criteria": crit}


def _ten(bad: dict[int, tuple], warn_all=False):
    return [_fake(f"s02_t{n:02d}", bad.get(n, ()), "acdfgh" if warn_all else ()) for n in range(1, 11)]


def test_verdict_pass_with_zero_failing():
    assert cross.verdict(_ten({}))["verdict"] == "pass"


def test_verdict_replace_two():
    assert cross.verdict(_ten({2: ("c",), 5: ("e",)}))["verdict"] == "replace 2"


def test_verdict_full_rerun_six_of_ten():
    assert cross.verdict(_ten({n: ("c",) for n in range(1, 7)}))["verdict"] == "full rerun"


def test_verdict_six_failing_on_different_criteria_still_full_rerun():
    bad = {1: ("a",), 2: ("c",), 3: ("d",), 4: ("e",), 5: ("f",), 6: ("h",)}
    assert cross.verdict(_ten(bad))["verdict"] == "full rerun"


def test_verdict_five_failing_is_replace_five():
    assert cross.verdict(_ten({n: ("e",) for n in range(1, 6)}))["verdict"] == "replace 5"


def test_verdict_all_ten_fail_full_rerun():
    assert cross.verdict(_ten({n: ("b",) for n in range(1, 11)}))["verdict"] == "full rerun"


def test_verdict_warns_never_change_verdict():
    assert cross.verdict(_ten({}, warn_all=True))["verdict"] == "pass"
    assert cross.verdict(_ten({2: ("c",)}, warn_all=True))["verdict"] == "replace 1"


def test_verdict_counts_trial_once_even_with_two_failing_criteria():
    assert cross.verdict(_ten({1: ("b", "c")}))["verdict"] == "replace 1"


# ============================================================================ quarantine identity (030)

def test_quarantine_identity_from_file_name(tmp_path):
    path = tmp_path / "data" / "processed" / "quarantine" / "s05q_t03.sqlite3"
    _write_db(path, s02_rows(), scenario="s05", trial="t03")       # rows say s05 / t03
    res = cli.validate_one(tmp_path, "s05q_t03", None)
    assert res["trial_id"] == "s05q_t03"
    assert res["quarantine"] is True and res["scenario"] == "s05"
    assert res["db_path"].endswith("quarantine/s05q_t03.sqlite3")


def test_quarantine_parse_and_paths(tmp_path):
    assert cli.parse_trial("s05q_t03") == ("s05", True, "t03")
    assert cli.parse_trial("s02_t10") == ("s02", False, "t10")
    with pytest.raises(ValueError):
        cli.parse_trial("s05_q03")
    assert cli.db_path(tmp_path, "s05q_t03") == tmp_path / "data" / "processed" / "quarantine" / "s05q_t03.sqlite3"


def test_quarantine_is_its_own_group_for_i_and_verdict():
    q = [_fake(f"s05q_t0{n}", scenario="s05") for n in range(1, 4)]
    for r in q:
        r["quarantine"] = True
    s = _fake("s05_t00", scenario="s05")
    assert cross.group_of(q[0]) == "s05q" and cross.group_of(s) == "s05"


def test_quarantine_cmd_run_writes_json_named_by_file(tmp_path):
    path = tmp_path / "data" / "processed" / "quarantine" / "s05q_t03.sqlite3"
    _write_db(path, s02_rows(), scenario="s05", trial="t03")
    ing = tmp_path / "out" / "ingest" / "x10" / "s05q_t03" / "ingest.json"
    ing.parent.mkdir(parents=True)
    ing.write_text(json.dumps({"status": "ok", "files_missing": [],
                               "files_copied": [{"host": h, "channel": c} for h in HOSTS for c in CHANNELS]}))
    assert cli.main(["run", "--trials", "s05q_t03"], repo=tmp_path) == 0
    out = tmp_path / "out" / "x10_validate" / "s05q_t03.json"
    assert out.is_file()
    assert json.loads(out.read_text(encoding="utf-8"))["trial_id"] == "s05q_t03"
    assert not (tmp_path / "out" / "x10_validate" / "s05_t03.json").exists()


def test_cli_writes_only_under_out_x10_validate(tmp_path):
    path = tmp_path / "data" / "processed" / "s02_t01.sqlite3"
    _write_db(path, s02_rows())
    ing = tmp_path / "out" / "ingest" / "x10" / "s02_t01" / "ingest.json"
    ing.parent.mkdir(parents=True)
    ing.write_text(json.dumps({"status": "ok", "files_missing": [],
                               "files_copied": [{"host": h, "channel": c} for h in HOSTS for c in CHANNELS]}))
    before = {p for p in tmp_path.rglob("*") if p.is_file()}
    cli.main(["run", "--trials", "s02_t01"], repo=tmp_path)
    cli.main(["report"], repo=tmp_path)
    new = {p for p in tmp_path.rglob("*") if p.is_file()} - before
    assert new and all("x10_validate" in p.parts for p in new), new


def test_no_ingest_check_refused_for_x10_trial(tmp_path):
    path = tmp_path / "data" / "processed" / "s02_t01.sqlite3"
    _write_db(path, s02_rows())
    with pytest.raises(SystemExit):
        cli.main(["run", "--trials", "s02_t01", "--no-ingest-check"], repo=tmp_path)


# ============================================================================ contract

def test_result_contract_columns():
    res = run_trial(s02_rows())
    assert set(res["criteria"]) == set("abcdefghi")
    assert all(v["status"] in ("PASS", "WARN", "FAIL", "n/a") and "evidence" in v for v in res["criteria"].values())
    assert res["trial_id"] == "s02_t01" and res["scenario"] == "s02" and res["quarantine"] is False
    assert st(res, "i") == "n/a"          # filled only across trials
    json.dumps(res)                       # serialisable


def test_apply_cross_does_not_mutate_input_and_keeps_all_rows():
    a = run_trial(s02_rows(T0), trial_id="s02_t01")
    b = run_trial(s02_rows(T0), trial_id="s02_t02")
    snap = copy.deepcopy([a, b])
    out = cross.apply_cross([a, b])
    assert [a, b] == snap and len(out) == 2 and [r["trial_id"] for r in out] == ["s02_t01", "s02_t02"]


def test_design_for_s01_matches_035_and_s08_still_rejected():
    d = design_for("s01")
    assert tuple(d.path_hosts) == ("ep-01", "ep-02")
    assert tuple(d.dumps) == ()
    assert len(d.hops) == 1
    h = d.hops[0]
    assert (h.hop_id, h.protocol, h.source, h.target, h.lane, h.intended_account) ==         ("s01-h1", "RDP", "ep-01", "ep-02", "manual", "svc_backup")
    assert tuple(h.steps) == ("rdp_source", "logon")
    assert d.benign is None
    assert tuple(d.caldera_hosts) == ()
    with pytest.raises(KeyError):
        design_for("s08")


def test_path_hosts_match_029():
    want = {"s02": ("ep-01", "ep-02"), "s03": ("ep-01", "ep-03"), "s04": ("ep-01", "ep-02"),
            "s06": ("ep-01", "ep-02", "ep-03"), "s07": ("ep-01", "ep-02"), "s05": ("ep-01", "ep-02", "ep-03")}
    for s, hosts in want.items():
        assert tuple(design_for(s).path_hosts) == hosts
    assert design_for("s06").c_severity == "WARN"
    assert all(design_for(s).c_severity == "FAIL" for s in ("s02", "s03", "s04", "s07", "s05"))


# ============================================================================ 4. real data

def _real(trial: str):
    p = REPO / "data" / "processed" / f"{trial}.sqlite3"
    if not p.is_file():
        pytest.skip(f"{p} missing")
    ingest, _ = cli.read_ingest(REPO, trial)
    return cli.validate_one(REPO, trial, ingest)


def test_real_s02_t01_has_no_fail():
    res = _real("s02_t01")
    fails = [c for c in "abcdefgh" if st(res, c) == "FAIL"]
    assert not fails, {c: res["criteria"][c]["evidence"].get("reason") for c in fails}


def test_real_s02_t03_a_warn_and_g_na():
    res = _real("s02_t03")
    assert st(res, "a") == "WARN", res["criteria"]["a"]
    assert st(res, "g") == "n/a", res["criteria"]["g"]


# ============================================================================ S01 (decision 035): manual RDP ep-01 -> ep-02

MSTSC = r"C:\Windows\System32\mstsc.exe"


def mstsc(t0, off, *, dst=None, port=3389, image=MSTSC):
    """Sysmon 3 on ep-01: the RDP client connecting to the target (the source-side anchor)."""
    return row(t0, off, "ep-01", "Sysmon", 3, image=image, destination_ip=dst or IP["ep-02"], destination_port=port,
               source_ip=IP["ep-01"], account_name="svc_backup")


def rdp_logon(t0, off, ltype=10, acct="svc_backup", lid=7000, src="ep-01"):
    """4624 on ep-02 from the source's IP."""
    return row(t0, off, "ep-02", "Security", 4624, logon_type=ltype, source_ip=IP[src], account_name=acct,
               target_logon_id=lid, authentication_package="Negotiate")


def rdp_inbound(t0, off, port=3389):
    """Sysmon 3 on ep-02: the inbound RDP connection (svchost, Initiated = false)."""
    return row(t0, off, "ep-02", "Sysmon", 3, image=r"C:\Windows\System32\svchost.exe", source_ip=IP["ep-01"],
               destination_ip=IP["ep-02"], destination_port=port, account_name="NETWORK SERVICE")


def s01_rows(t0: datetime = T0, **kw) -> list[dict]:
    """Passing minimal S01: mstsc on ep-01, then a type 10 logon by svc_backup on ep-02."""
    return [mstsc(t0, 0), rdp_logon(t0, 5, **kw)]


def s01_run(rows, trial_id="s01_t01"):
    return run_trial(rows, "s01", trial_id=trial_id)


def test_s01_baseline_statuses():
    res = s01_run(s01_rows())
    assert st(res, "b") == "PASS", res["criteria"]["b"]
    assert st(res, "c") == "PASS", res["criteria"]["c"]
    assert st(res, "d") == "n/a"
    assert st(res, "e") == "n/a"
    assert res["criteria"]["e"]["evidence"].get("reason"), "e is n/a with a reason (manual, no agent)"
    assert st(res, "h") == "PASS", res["criteria"]["h"]
    assert res["scenario"] == "s01" and res["quarantine"] is False


def test_s01_no_mstsc_fails_b():
    res = s01_run([rdp_logon(T0, 5)])
    assert st(res, "b") == "FAIL"


@pytest.mark.parametrize("kw", [
    {"dst": IP["ep-03"]},                       # wrong destination IP
    {"port": 445},                              # wrong port
    {"image": r"C:\Windows\System32\cmd.exe"},  # not mstsc
], ids=["wrong_ip", "wrong_port", "not_mstsc"])
def test_s01_bad_source_connection_fails_b(kw):
    res = s01_run([mstsc(T0, 0, **kw), rdp_logon(T0, 5)])
    assert st(res, "b") == "FAIL", res["criteria"]["b"]


def test_s01_no_logon_fails_b_and_c():
    res = s01_run([mstsc(T0, 0)])
    assert st(res, "b") == "FAIL"
    assert st(res, "c") == "FAIL"


@pytest.mark.parametrize("ltype", [7, 11])
def test_s01_reconnect_or_cached_logon_type_does_not_count(ltype):
    res = s01_run([mstsc(T0, 0), rdp_logon(T0, 5, ltype=ltype)])
    assert st(res, "b") == "FAIL", res["criteria"]["b"]


def test_s01_type10_by_other_account_fails_c_and_reports_observed():
    res = s01_run(s01_rows(acct="admin_it"))
    assert st(res, "c") == "FAIL"
    assert "admin_it" in json.dumps(res["criteria"]["c"]["evidence"]), res["criteria"]["c"]


def test_s01_type3_with_inbound_3389_counts_as_rdp():
    res = s01_run([mstsc(T0, 0), rdp_logon(T0, 5, ltype=3), rdp_inbound(T0, 6)])
    assert st(res, "b") == "PASS", res["criteria"]["b"]
    assert st(res, "c") == "PASS", res["criteria"]["c"]


def test_s01_type3_inbound_before_logon_within_seconds_counts():
    res = s01_run([mstsc(T0, 0), rdp_inbound(T0, 3), rdp_logon(T0, 5, ltype=3)])
    assert st(res, "b") == "PASS", res["criteria"]["b"]


def test_s01_type3_without_inbound_fails_b():
    res = s01_run([mstsc(T0, 0), rdp_logon(T0, 5, ltype=3)])
    assert st(res, "b") == "FAIL", res["criteria"]["b"]


def test_s01_type3_with_inbound_on_other_port_fails_b():
    res = s01_run([mstsc(T0, 0), rdp_logon(T0, 5, ltype=3), rdp_inbound(T0, 6, port=445)])
    assert st(res, "b") == "FAIL", res["criteria"]["b"]


def test_s01_type3_with_inbound_far_in_time_fails_b():
    res = s01_run([mstsc(T0, 0), rdp_logon(T0, 5, ltype=3), rdp_inbound(T0, 65)])
    assert st(res, "b") == "FAIL", res["criteria"]["b"]


def test_s01_two_sessions_same_account_far_apart_fails_h():
    rows = s01_rows() + [mstsc(T0, 495), rdp_logon(T0, 500, lid=7001)]
    res = s01_run(rows)
    assert st(res, "h") == "FAIL", res["criteria"]["h"]


def test_s01_two_sessions_different_accounts_warns_h():
    rows = s01_rows() + [mstsc(T0, 495), rdp_logon(T0, 500, acct="admin_it", lid=7001)]
    res = s01_run(rows)
    assert st(res, "h") == "WARN", res["criteria"]["h"]


def test_s01_rundll32_lsass_dump_changes_no_status():
    base = s01_run(s01_rows())
    with_dump = s01_run(s01_rows() + [dump(T0, 3, "ep-01", "svc_backup")])
    assert {c: st(with_dump, c) for c in "abcdefgh"} == {c: st(base, c) for c in "abcdefgh"}


def test_s01_validate_via_db_and_discover(tmp_path):
    path = tmp_path / "data" / "processed" / "s01_t01.sqlite3"
    _write_db(path, s01_rows(), scenario="s01")
    assert "s01_t01" in cli.discover(tmp_path)
    res = cli.validate_one(tmp_path, "s01_t01", None)
    assert res["scenario"] == "s01" and st(res, "b") == "PASS" and st(res, "c") == "PASS"


def _ten_s01(bad: dict[int, tuple]):
    return [_fake(f"s01_t{n:02d}", bad.get(n, ()), scenario="s01") for n in range(1, 11)]


def test_s01_groups_as_s01_with_expected_ten():
    ts = _ten_s01({})
    assert all(cross.group_of(t) == "s01" for t in ts)
    v = cross.verdict(ts)
    assert v["expected"] == 10 and v["verdict"] == "pass"


def test_s01_verdict_replace_two_and_full_rerun_six():
    assert cross.verdict(_ten_s01({3: ("b",), 7: ("c",)}))["verdict"] == "replace 2"
    assert cross.verdict(_ten_s01({n: ("b",) for n in range(1, 7)}))["verdict"] == "full rerun"
