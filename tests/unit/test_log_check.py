"""Tests for the T4 stage `src/log_check` (spec docs/specs/00_log_check.md).

Written from the spec (WN-01..WN-05, LC-01..LC-13 incl. LC-04e/f/g, edge cases LCT-01..LCT-14, section 7);
the code was read only for module/function names and the output format.

Synthetic trial DBs are built in tmp_path with the same events / events_dedup DDL as the real DBs (copied
read-only from data/processed). Real-data checks use data/sample and write only to tmp_path.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from log_check.matching import (decode_powershell_b64, mask_command_line, names_target,  # noqa: E402
                                target_name_forms)
from log_check.runner import LogCheckError, run_log_check  # noqa: E402
from log_check.__main__ import main as cli_main  # noqa: E402

PROCESSED = REPO / "data" / "processed"
SAMPLE = REPO / "data" / "sample"
DDL_SOURCES = [PROCESSED / "s04_t00.sqlite3", SAMPLE / "s04_t00.sqlite3"]

CSV_SPEC_COLUMNS = [
    "trial_id", "protocol", "hop_id", "target_host", "target_event_uids", "target_time_utc", "account_name",
    "source_ip", "source_port", "source_host", "method", "candidate_count_sessions_before_account",
    "candidate_count_sessions_after_account", "candidate_count_rows", "time_delta_ms", "confidence_tier",
    "candidate_session_id", "candidate_account", "candidate_logon_type", "zero_reason", "supporting_event_uids",
    "candidate_count_sessions_after_4648_bridge",
]
DAY = "2026-09-24"
CMD_EXE = r"C:\Windows\System32\cmd.exe"
RUNDLL = r"C:\Windows\System32\rundll32.exe"
LSASS = r"C:\Windows\System32\lsass.exe"


# --------------------------------------------------------------------------------------------------
# synthetic DB builder
# --------------------------------------------------------------------------------------------------

def _ddl() -> list[str]:
    for src in DDL_SOURCES:
        if src.exists():
            conn = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
            try:
                rows = conn.execute("select name, sql from sqlite_master where name in ('events','events_dedup')").fetchall()
            finally:
                conn.close()
            by = dict(rows)
            return [by["events"], by["events_dedup"]]
    pytest.skip("no real DB available to copy the events DDL from")


def fmt(value: datetime | str, day: str = DAY) -> str:
    """'10:57:36.855' or datetime -> DB format with 6 fractional digits and Z."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    text = value if "T" in value else f"{day}T{value}"
    if "." not in text:
        text += ".000000"
    head, frac = text.split(".")
    return f"{head}.{(frac + '000000')[:6]}Z"


def pdt(value: str, day: str = DAY) -> datetime:
    return datetime.strptime(fmt(value, day), "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


class Builder:
    """Collects hand-made event rows and writes them to a SQLite DB with the real schema."""

    def __init__(self, scenario: str = "s04", trial: str = "t00") -> None:
        self.scenario, self.trial = scenario, trial
        self.rows: list[dict] = []

    def add(self, ts, host: str, channel: str, event_id: int, day: str = DAY, **kw) -> str:
        n = len(self.rows) + 1
        uid = hashlib.sha256(f"synthetic-{n}".encode()).hexdigest()
        t = fmt(ts, day)
        row = {"scenario_id": self.scenario, "trial_id": self.trial, "event_uid": uid, "timestamp_utc": t,
               "event_utc": t, "host": host, "channel": channel, "event_id": event_id, "field_values_json": "{}",
               "raw_event_sha256": uid, "duplicate_content_sha256": uid, "source_relative_path": "synthetic.jsonl",
               "source_line": n}
        row.update(kw)
        self.rows.append(row)
        return uid

    # -- event shortcuts ---------------------------------------------------------------------
    def logon(self, ts, host, acct, lid, ltype, ip=None, port=None, pkg="NTLM", guid=None, linked=None, day=DAY):
        return self.add(ts, host, "Security", 4624, day=day, account_name=acct, target_logon_id=lid,
                        logon_type=ltype, source_ip=ip, source_port=port, authentication_package=pkg,
                        logon_guid=guid, target_linked_logon_id=linked)

    def logoff(self, ts, host, lid, eid=4634):
        return self.add(ts, host, "Security", eid, session_id=lid)

    def sysmon1(self, ts, host, session, cmd, acct="svc_backup", pid=None, image=CMD_EXE, guid=None, **kw):
        return self.add(ts, host, "Sysmon", 1, session_id=session, command_line=cmd, account_name=acct,
                        process_id=pid, image=image, process_guid=guid, **kw)

    def sec4688(self, ts, host, session, cmd, pid=None, image=CMD_EXE, acct=None):
        return self.add(ts, host, "Security", 4688, session_id=session, command_line=cmd, process_id=pid,
                        image=image, subject_account=acct)

    def dump(self, ts, host, access="0x1fffff", acct="system", day=DAY):
        return self.add(ts, host, "Sysmon", 10, day=day, source_image=RUNDLL, target_image=LSASS, granted_access=access,
                        account_name=acct)

    def service(self, ts, host, name, path, eid=7045, subject=None, day=DAY):
        chan = "System" if eid == 7045 else "Security"
        return self.add(ts, host, chan, eid, day=day, service_name=name, service_image_path=path, subject_logon_id=subject)

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
        for stmt in _ddl():
            conn.execute(stmt)
        for row in self.rows:
            cols = ", ".join(f'"{c}"' for c in row)
            conn.execute(f"insert into events ({cols}) values ({', '.join('?' for _ in row)})", list(row.values()))
        conn.commit()
        conn.close()
        return path


def run(b: Builder, tmp_path: Path, name: str, windows=None, keys=None):
    """Save the builder to tmp_path/name/db.sqlite3 and run the log check with outputs in tmp_path/name/out."""
    db = b.save(tmp_path / name / "db.sqlite3")
    trial = f"{b.scenario}_{b.trial}"
    out = run_log_check(db, trial, tmp_path / name / "out", windows, keys)
    return out, db


def lc04_hops(out) -> list[dict]:
    return out.report["checks"]["LC-04"]["result"]["hops"]


def hop_of(out, acct: str, target: str = "ep-02") -> dict:
    found = [h for h in lc04_hops(out) if h["account_name"] == acct and h["target_host"] == target]
    assert found, f"no hop for {acct}@{target}: {[ (h['account_name'], h['target_host']) for h in lc04_hops(out)]}"
    return found[0]


def csv_rows(out) -> list[dict]:
    return list(csv.DictReader(io.StringIO(out.csv_text)))


# ---- the hop-test base: one target 4624 on ep-02 at 10:57:36.000, source ep-01 -------------------

T0 = pdt("10:57:36.000")


def hop_builder(target_acct="svc_backup", sessions=((0x100, "svc_backup"),)) -> Builder:
    b = Builder()
    for sid, acct in sessions:
        b.logon("10:00:00", "ep-01", acct, sid, 4)
    b.logon("10:57:36.000", "ep-02", target_acct, 0xE0010, 3, ip="192.168.50.21", port=49734)
    return b


def cmd_at(b: Builder, offset_s: float, text: str, session=0x100, acct="svc_backup", **kw) -> str:
    return b.sysmon1(T0 + timedelta(seconds=offset_s), "ep-01", session, text, acct=acct, **kw)


@pytest.fixture(scope="module")
def tmp_mod(tmp_path_factory):
    return tmp_path_factory.mktemp("log_check")


# ---- the main synthetic trial (S04-like) ----------------------------------------------------------

def build_main() -> tuple[Builder, dict]:
    b = Builder("s04")
    u: dict[str, str] = {}
    # noise on ep-01: first record of the host, Sysmon record gap of 70 s (LC-09), and an exact duplicate (LC-01)
    u["noise"] = b.sysmon1("06:00:00", "ep-01", 0x77, "notepad.exe", acct="svc_sql", pid=7,
                           image=r"C:\Windows\notepad.exe", timestamp_utc=fmt("06:01:10"))
    b.add("06:00:00", "ep-01", "Sysmon", 1, session_id=0x77, command_line="notepad.exe", account_name="svc_sql",
          process_id=7, image=r"C:\Windows\notepad.exe", timestamp_utc=fmt("06:01:10"),
          duplicate_content_sha256=u["noise"])
    # sessions on ep-01 (LC-08, LCT-08, LCT-13, LCT-14)
    for hms in ("05:00:00", "05:10:00", "05:20:00"):
        b.logon(hms, "ep-01", "system", 0x3E7, 5)
    u["admin_agent"] = b.logon("10:00:00", "ep-01", "admin_it", 0xD6398, 4)
    u["svc_agent"] = b.logon("10:01:00", "ep-01", "svc_backup", 0x17C46, 4)
    b.logon("10:05:00", "ep-01", "svc_sql", 0x1001, 2)
    b.logoff("10:30:00", "ep-01", 0x1001)                                   # closed
    b.logon("10:06:00", "ep-01", "svc_backup", 0x1002, 2, linked=0x1003)
    b.logoff("10:31:00", "ep-01", 0x1003, eid=4647)                         # closed through the linked id
    b.logon("09:00:00", "ep-01", "admin_it", 0x1004, 3)
    b.logoff("09:10:00", "ep-01", 0x1004)                                   # first use closed
    u["reused"] = b.logon("10:20:00", "ep-01", "svc_sql", 0x1004, 3)        # id reused, open
    b.logon("08:00:00", "ep-01", "admin_it", 0x1005, 2)
    b.add("08:30:00", "ep-01", "System", 6005)                              # boot between 0x1005 and the dump
    b.logoff("09:00:00", "ep-01", 0x1007)                                   # stale logoff BEFORE the 4624
    u["stale"] = b.logon("10:10:00", "ep-01", "admin_it", 0x1007, 10)       # open
    b.logon("07:30:00", "ep-01", "svc_backup", 0x1008, 2)
    b.logoff("10:00:00", "ep-01", 0x1008)                                   # logoff after a boot: not honoured
    b.logon("10:00:00", "ep-01", "admin_it", 0x1006, 2, day="2026-09-23")   # previous day
    b.sysmon1("10:30:00", "ep-01", 0x2000, "whoami", acct="svc_sql")        # process only, no 4624
    b.sysmon1("10:58:00", "ep-01", 0xD6398, "whoami", acct="admin_it")      # ran a command after the dump
    # credential dumps: pair 0x1410 + 0x1fffff on ep-01 (one dump, run as SYSTEM), single on ep-02
    u["dump_a"] = b.dump("10:56:56.000", "ep-01", "0x1410")
    u["dump_b"] = b.dump("10:56:56.400", "ep-01", "0x1fffff")
    u["dump_ep02"] = b.dump("10:58:20.000", "ep-02", "0x1fffff", acct="svc_sql")
    # two tracks 3 s apart, both naming \\192.168.50.22 (LCT-02)
    u["cmd_admin"] = b.sysmon1("10:57:34.000", "ep-01", 0xD6398,
                               r"cmd.exe /c net use \\192.168.50.22\ADMIN$ /user:LAB\admin_it FakePw-0001",
                               acct="admin_it", pid=100)
    u["cmd_admin_4688"] = b.sec4688("10:57:34.100", "ep-01", 0xD6398,
                                    r"cmd.exe /c net use \\192.168.50.22\ADMIN$ /user:LAB\admin_it FakePw-0001", pid=100)
    u["tool_admin"] = b.sysmon1("10:57:34.300", "ep-01", 0xD6398,
                                r"net.exe use \\192.168.50.22\ADMIN$ /user:LAB\admin_it FakePw-0001", acct="admin_it",
                                pid=101, image=r"C:\Windows\System32\net.exe")
    u["cmd_svc"] = b.sysmon1("10:57:38.355", "ep-01", 0x17C46,
                             r"net.exe use \\ep-02.lab.local\ADMIN$ /user:LAB\svc_backup FakePw-0001",
                             acct="svc_backup", pid=102, image=r"C:\Windows\System32\net.exe")
    # target 4624s on ep-02
    for hms, port, lid in (("10:57:35.000", 49700, 0xE0001), ("10:57:35.400", 49701, 0xE0002), ("10:57:36.000", 0, 0xE0003)):
        u[f"admin_{lid:x}"] = b.logon(hms, "ep-02", "admin_it", lid, 3, ip="192.168.50.21", port=port)
    u["svc_4624"] = b.logon("10:57:36.855", "ep-02", "svc_backup", 0xE0010, 3, ip="192.168.50.21", port=49734)
    u["svc_krb"] = b.logon("10:57:37.200", "ep-02", "svc_backup", 0xE0011, 3, ip="192.168.50.21", port=0,
                           pkg="Kerberos", guid="11111111-2222-3333-4444-555555555555")
    b.logon("10:57:00", "ep-02", "svc_backup", 0xE0020, 3, ip="::1", port=0)
    b.logon("10:57:01", "ep-02", "svc_backup", 0xE0021, 3, ip="fe80::1", port=0)
    b.add("10:57:34.700", "dc01", "Security", 4769, logon_guid="11111111-2222-3333-4444-555555555555",
          service_name="endpoint-02$")
    # 4688 vs Sysmon 1 for pid 100 gives +100 ms; target-side share + service evidence (LCT-07)
    b.add("10:57:37.900", "ep-02", "Security", 5140, session_id=0xE0001, share_name=r"\\*\ADMIN$")
    b.add("10:57:38.000", "ep-02", "Security", 5145, session_id=0xE0001, share_name=r"\\*\ADMIN$",
          relative_target_name="HealthAgent.exe")
    b.add("10:57:39.000", "ep-02", "Security", 5145, session_id=0xE0010, share_name=r"\\*\ADMIN$",
          relative_target_name="Updater.exe")
    u["svc7045_a"] = b.service("10:57:40", "ep-02", "HealthAgentSvc", r"C:\Windows\HealthAgent.exe")
    u["svc4697_a"] = b.service("10:57:41", "ep-02", "HealthAgentSvc", r"C:\Windows\HealthAgent.exe", eid=4697,
                               subject=0xE0001)
    u["svc7045_b"] = b.service("10:57:43", "ep-02", "UpdaterService", r"C:\Windows\Updater.exe")
    b.sysmon1("10:57:50", "ep-02", 0xE0002, "whoami", acct="admin_it")
    return b, u


@pytest.fixture(scope="module")
def main_run(tmp_mod):
    b, u = build_main()
    out, db = run(b, tmp_mod, "main")
    return out, db, u, b


# --------------------------------------------------------------------------------------------------
# contract: files, JSON structure, CSV columns, DB unchanged, outputs only in out dir
# --------------------------------------------------------------------------------------------------

def test_outputs_exist_and_only_in_out_dir(tmp_path):
    b, _ = build_main()
    db = b.save(tmp_path / "db" / "db.sqlite3")
    before_db_dir = sorted(os.listdir(tmp_path / "db"))
    sha_before = hashlib.sha256(db.read_bytes()).hexdigest()
    out = run_log_check(db, "s04_t00", tmp_path / "out", None, None)
    assert hashlib.sha256(db.read_bytes()).hexdigest() == sha_before          # LC-11: DB unchanged
    assert sorted(os.listdir(tmp_path / "db")) == before_db_dir                # no -journal / -wal / extra files
    assert sorted(p.name for p in (tmp_path / "out").iterdir()) == ["s04_t00"]
    assert sorted(p.name for p in (tmp_path / "out" / "s04_t00").iterdir()) == [
        "hop_candidates.csv", "report.json", "report.md"]
    assert out.report["db_sha256"] == sha_before
    assert out.report["checks"]["LC-11"]["result"]["unchanged"] is True


def test_report_json_contract(main_run):
    out, db, _, _ = main_run
    rep = out.report
    for key in ("trial_id", "db_path", "db_sha256", "window", "checks"):
        assert key in rep
    assert rep["trial_id"] == "s04_t00"
    for key in ("start_utc", "end_utc", "status", "flags", "clusters", "anchors"):
        assert key in rep["window"]
    expected = {"LC-01", "LC-02", "LC-03", "LC-04", "LC-04b", "LC-04c", "LC-04d", "LC-05", "LC-06", "LC-07",
                "LC-08", "LC-08b", "LC-09", "LC-10", "LC-11"}
    assert expected <= set(rep["checks"])
    for cid, chk in rep["checks"].items():
        assert chk["status"] in {"OK", "PROBLEM", "INFO", "NOT_MEASURABLE"}, cid
        for key in ("result", "effect", "sql"):
            assert key in chk, (cid, key)
        assert isinstance(chk["sql"], list)
    # the JSON file on disk equals the returned report
    on_disk = json.loads((Path(out.files[0]).parent / "report.json").read_text(encoding="utf-8"))
    assert on_disk["trial_id"] == "s04_t00" and set(on_disk["checks"]) == set(rep["checks"])


def test_lc11_every_check_stores_sql(main_run):
    out, *_ = main_run
    for cid in ("LC-01", "LC-02", "LC-03", "LC-04", "LC-04b", "LC-04c", "LC-04d", "LC-05", "LC-06", "LC-07",
                "LC-08", "LC-08b", "LC-09"):
        assert out.report["checks"][cid]["sql"], f"{cid} stores no SQL"
        assert all(isinstance(s, str) and "select" in s.lower() for s in out.report["checks"][cid]["sql"])


def test_csv_columns_exact_order(main_run):
    out, *_ = main_run
    header = out.csv_text.splitlines()[0].split(",")
    assert header == CSV_SPEC_COLUMNS
    assert header[-1] == "candidate_count_sessions_after_4648_bridge"


def test_report_md_has_table_and_wn03b_warning(main_run):
    out, *_ = main_run
    md = out.markdown
    assert "anchor-derived window" in md
    assert "must NOT be used for evaluation" in md
    assert "T7.6/T10 use T5 answer-key windows" in md
    # the check table (check . result . status . effect) comes before the warning and per-check detail
    assert md.index("| check |") < md.index("must NOT be used for evaluation")
    for cid in ("LC-01", "LC-04", "LC-08", "LC-10"):
        assert cid in md
    assert (Path(out.files[0]).parent / "report.md").read_text(encoding="utf-8") == md or \
        "must NOT be used" in (Path(out.files[0]).parent / "report.md").read_text(encoding="utf-8")


def test_cli_runs_and_writes_only_to_out(tmp_path):
    b, _ = build_main()
    db = b.save(tmp_path / "db" / "db.sqlite3")
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    res = subprocess.run([sys.executable, "-m", "log_check", "--db", str(db), "--trial", "s04_t00", "--out",
                          str(tmp_path / "out"), "--windows", str(tmp_path / "none.csv"), "--keys",
                          str(tmp_path / "nokeys")], cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "out" / "s04_t00" / "report.json").exists()
    assert "LC-04" in res.stdout


def test_cli_rejects_wrong_trial_and_bad_id(tmp_path, capsys):
    b, _ = build_main()
    db = b.save(tmp_path / "db" / "db.sqlite3")
    assert cli_main(["--db", str(db), "--trial", "s02_t00", "--out", str(tmp_path / "o")]) == 2
    assert cli_main(["--db", str(db), "--trial", "nonsense", "--out", str(tmp_path / "o")]) == 2
    assert cli_main(["--db", str(tmp_path / "missing.sqlite3"), "--trial", "s04_t00", "--out", str(tmp_path / "o")]) == 2
    assert not (tmp_path / "o").exists()           # nothing written on an input error


# --------------------------------------------------------------------------------------------------
# windows: WN-01 .. WN-05, LCT-10, LCT-11
# --------------------------------------------------------------------------------------------------

def test_wn03_main_window_from_dump_cluster(main_run):
    out, _, u, _ = main_run
    w = out.report["window"]
    assert w["status"] == "PROVISIONAL"
    assert w["start_utc"] == "2026-09-24T10:46:56.000Z"        # first anchor 10:56:56 - 600 s
    assert w["end_utc"] == "2026-09-24T11:08:20.000Z"          # last anchor 10:58:20 + 600 s
    assert "no_dump" not in w["flags"]
    types = {a["type"] for a in w["anchors"]}
    assert {"a", "b"} <= types
    assert all({"event_uid", "host", "time", "type"} <= set(a) for a in w["anchors"])
    uids = {a["event_uid"] for a in w["anchors"]}
    assert u["dump_a"] in uids and u["svc7045_a"] in uids


def _anchor_day_db(scenario: str, day: str, trial="t00") -> Builder:
    b = Builder(scenario, trial)
    b.logon("00:10:00", "ep-01", "svc_backup", 0x500, 4, day=day)     # something so the DB is not empty
    return b


def test_wn01_run_day_per_scenario(tmp_path):
    """A dump on the run day anchors the window, the same dump on the neighbouring day does not."""
    for scenario, day, other in (("s02", "2026-09-24", "2026-09-25"), ("s05", "2026-10-12", "2026-10-11"),
                                 ("s07", "2026-10-12", "2026-10-13")):
        b = _anchor_day_db(scenario, day)
        b.dump("08:00:00", "ep-01", day=other)
        b.dump("09:00:00", "ep-01", day=day)
        out, _ = run(b, tmp_path, scenario)
        starts = [a["time"] for a in out.report["window"]["anchors"]]
        assert starts == [f"{day}T09:00:00.000Z"], (scenario, starts)


def test_wn02_anchor_rules(tmp_path):
    b = _anchor_day_db("s04", DAY)
    ok_dump = b.dump("07:00:00", "ep-01")
    # a Sysmon 10 that is not rundll32 -> lsass is not an anchor
    b.add("07:00:05", "ep-01", "Sysmon", 10, source_image=r"C:\Windows\System32\svchost.exe", target_image=LSASS)
    b.add("07:00:06", "ep-01", "Sysmon", 10, source_image=RUNDLL, target_image=r"C:\Windows\System32\notepad.exe")
    ok_svc = b.service("07:01:00", "ep-02", "Odd", r"C:\Windows\Odd.exe")
    ok_4697 = b.service("07:01:30", "ep-02", "Odd2", r"C:\Windows\Odd2.exe", eid=4697)
    b.service("07:01:40", "ep-02", "Sys32", r"C:\Windows\System32\svc.exe")
    b.service("07:01:41", "ep-02", "Drv", r"C:\Windows\System32\drivers\x.sys")
    b.service("07:01:42", "ep-02", "PF", r"C:\Program Files\A\a.exe")
    ok_w = b.add("07:02:00", "ep-02", "WinRM", 91, account_name="svc_sql")
    b.add("07:02:10", "ep-02", "WinRM", 91, account_name="bob")
    out, _ = run(b, tmp_path, "anch")
    got = {a["event_uid"]: a["type"] for a in out.report["window"]["anchors"]}
    assert got == {ok_dump: "a", ok_svc: "b", ok_4697: "b", ok_w: "c"}


def test_lct11_clusters_reported_window_from_latest_dump_cluster(tmp_path):
    b = _anchor_day_db("s05", "2026-10-12")
    d = "2026-10-12"
    b.dump("06:00:00", "ep-01", day=d)                              # cluster 0 (dump)
    b.service("06:02:00", "ep-02", "Early", r"C:\Windows\Early.exe", day=d)
    b.dump("07:09:43", "ep-01", day=d)                              # cluster 1 (dump)  <- expected window
    b.dump("07:11:49", "ep-02", day=d)
    b.dump("07:00:00", "ep-01", day="2026-10-11")                   # other day: never an anchor
    for hms in ("14:00:00", "14:02:00", "14:04:00"):                # cluster 2: biggest, but no dump
        b.service(hms, "ep-02", "Late" + hms[3:5], r"C:\Windows\Late.exe", day=d)
    out, _ = run(b, tmp_path, "clus")
    w = out.report["window"]
    assert len(w["clusters"]) == 3
    assert w["start_utc"] == "2026-10-12T06:59:43.000Z"             # 07:09:43 - 600 s
    assert w["end_utc"] == "2026-10-12T07:21:49.000Z"
    assert [a["type"] for a in w["anchors"]] == ["a", "a"]
    assert "no_dump" not in w["flags"]


def test_lct10_benign_anchors_only_flag_no_dump_and_lc08_info(tmp_path):
    b = _anchor_day_db("s06", "2026-10-12")
    d = "2026-10-12"
    b.service("12:00:00", "ep-02", "Benign1", r"C:\Windows\Benign1.exe", day=d)
    b.service("12:05:00", "ep-02", "Benign2", r"C:\Windows\Benign2.exe", day=d)
    b.add("12:03:00", "ep-02", "WinRM", 91, account_name="svc_sql", day=d)
    out, _ = run(b, tmp_path, "benign")
    w = out.report["window"]
    assert "no_dump" in w["flags"]
    assert w["status"] == "PROVISIONAL"
    assert w["start_utc"] == "2026-10-12T11:50:00.000Z" and w["end_utc"] == "2026-10-12T12:15:00.000Z"
    assert out.report["checks"]["LC-08"]["status"] == "INFO"             # S06: no dump expected
    assert out.report["checks"]["LC-08"]["result"]["dumps"] == []


def test_wn04_no_anchor_is_run_day_only(tmp_path):
    out, _ = run(_anchor_day_db("s03", DAY), tmp_path, "noanchor")
    w = out.report["window"]
    assert w["status"] == "RUN_DAY_ONLY"
    assert w["start_utc"] == "2026-09-24T00:00:00.000Z"
    assert w["end_utc"] in ("2026-09-25T00:00:00.000Z", "2026-09-24T23:59:59.999Z")
    assert "no_dump" in w["flags"]


def test_wn04_override_csv_row_wins(tmp_path):
    b, _ = build_main()
    win = tmp_path / "w.csv"
    win.write_text("trial_id,start_utc,end_utc,status,anchors,note\n"
                   "s04_t00,2026-09-24T10:00:00Z,2026-09-24T11:00:00Z,PROVISIONAL,manual,from test\n"
                   "s02_t00,2026-09-24T01:00:00Z,2026-09-24T02:00:00Z,PROVISIONAL,x,other trial\n", encoding="utf-8")
    out, _ = run(b, tmp_path, "ovr", windows=win)
    w = out.report["window"]
    assert w["start_utc"] == "2026-09-24T10:00:00.000Z" and w["end_utc"] == "2026-09-24T11:00:00.000Z"
    assert w["status"] == "PROVISIONAL"
    assert "override" in json.dumps(w).lower()


def test_wn05_answer_key_window_replaces_provisional_and_lc10(tmp_path):
    b, u = build_main()
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "s04_t00.yaml").write_text(
        "trial_id: s04_t00\nstart_utc: 2026-09-24T10:50:00Z\nend_utc: 2026-09-24T11:00:00Z\n"
        f"events:\n  - {u['dump_a']}\n  - {u['cmd_admin']}\n", encoding="utf-8")
    win = tmp_path / "w.csv"
    win.write_text("trial_id,start_utc,end_utc,status,anchors,note\n"
                   "s04_t00,2026-09-24T10:00:00Z,2026-09-24T11:00:00Z,PROVISIONAL,manual,x\n", encoding="utf-8")
    out, _ = run(b, tmp_path, "key", windows=win, keys=keys)
    w = out.report["window"]
    assert w["start_utc"] == "2026-09-24T10:50:00.000Z" and w["end_utc"] == "2026-09-24T11:00:00.000Z"
    assert w["status"] == "ANSWER_KEY"
    assert "answer_key" in out.markdown.lower() or "answer key" in out.markdown.lower()
    assert out.report["checks"]["LC-10"]["status"] == "OK"
    assert out.report["checks"]["LC-10"]["sql"]


def test_lc10_missing_key_event_is_problem_and_no_key_is_not_measurable(tmp_path):
    b, u = build_main()
    out, _ = run(b, tmp_path, "nokey", keys=tmp_path / "nokeys")
    assert out.report["checks"]["LC-10"]["status"] == "NOT_MEASURABLE"
    assert "no key" in json.dumps(out.report["checks"]["LC-10"]).lower()
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "s04_t00.yaml").write_text(f"events:\n  - {u['dump_a']}\n  - {'ab' * 32}\n", encoding="utf-8")
    out2, _ = run(b, tmp_path, "badkey", keys=keys)
    assert out2.report["checks"]["LC-10"]["status"] == "PROBLEM"
    assert "ab" * 32 in json.dumps(out2.report["checks"]["LC-10"]["result"])


# --------------------------------------------------------------------------------------------------
# LC-01, LC-02, LC-03, LC-07, LC-09
# --------------------------------------------------------------------------------------------------

def test_lc01_counts_and_dedup(main_run):
    out, db, _, _ = main_run
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    n_events = conn.execute("select count(*) from events").fetchone()[0]
    n_dedup = conn.execute("select count(*) from events_dedup").fetchone()[0]
    w = out.report["window"]
    n_win = conn.execute("select count(*) from events_dedup where event_utc >= ? and event_utc <= ?",
                         (fmt(w["start_utc"].replace("Z", "")), fmt(w["end_utc"].replace("Z", "")))).fetchone()[0]
    conn.close()
    r = out.report["checks"]["LC-01"]["result"]
    assert n_events == n_dedup + 1
    assert (r["events_rows"], r["events_dedup_rows"]) == (n_events, n_dedup)
    assert r["whole_db_total"] == n_dedup
    assert r["in_window_total"] == n_win
    by = {(x["channel"], x["event_id"]): x["n"] for x in r["whole_db"]}
    assert by[("Sysmon", 10)] == 3 and by[("Security", 4688)] == 1 and by[("Security", 5145)] == 2


def test_lc02_remote_4624_categories_and_ports(main_run):
    r = main_run[0].report["checks"]["LC-02"]["result"]
    assert r["totals"] == {"lab_ipv4": 5, "link_local": 1, "loopback": 1}
    lab = r["by_category_package"]["lab_ipv4"]
    assert lab["NTLM"]["count"] == 4 and lab["NTLM"]["port_gt_0"] == 3 and lab["NTLM"]["port_0"] == 1
    assert lab["Kerberos"]["count"] == 1 and lab["Kerberos"]["valid_logon_guid"] == 1
    assert main_run[0].report["checks"]["LC-02"]["status"] == "OK"


def test_lc03_kerberos_confirmation(main_run):
    r = main_run[0].report["checks"]["LC-03"]["result"]
    assert r["lab_ipv4_4624"] == 5 and r["with_valid_guid"] == 1 and r["confirmed"] == 1


def test_lc07_session_process_share(main_run):
    r = main_run[0].report["checks"]["LC-07"]["result"]
    assert r["total"] == 5 and r["with_process"] == 1 and r["share"] == 0.2


def test_lc09_clock_checks(main_run):
    r = main_run[0].report["checks"]["LC-09"]["result"]
    ep02 = r["kerberos_vs_dc01_ms"]["ep-02"]
    assert ep02["n"] == 1 and ep02["p50"] == 2500 and ep02["min"] == 2500 and ep02["max"] == 2500
    assert set(ep02) >= {"n", "p5", "p50", "p95", "min", "max"}
    x = r["security4688_minus_sysmon1_ms"]["ep-01"]
    assert x["n"] == 1 and x["p50"] == 100
    gap = r["sysmon_record_gap_s"]["ep-01"]
    assert gap["max"] == 70 and gap["rows_over_flag"] == 1
    assert r["flags"] == []


def test_lc09_skew_flag_rule():
    from log_check.checks_clock import skew_flag
    from log_check.params import DEFAULT_PARAMS
    agree = {"ep-01": {"n": 3, "p50": 2600.0}, "ep-02": {"n": 3, "p50": 2400.0}}
    assert skew_flag(agree, DEFAULT_PARAMS) is True
    near_zero = {"ep-01": {"n": 3, "p50": 200.0}, "ep-02": {"n": 3, "p50": 100.0}}
    assert skew_flag(near_zero, DEFAULT_PARAMS) is False
    disagree = {"ep-01": {"n": 3, "p50": 2600.0}, "ep-02": {"n": 3, "p50": 100.0}}
    assert skew_flag(disagree, DEFAULT_PARAMS) is False


# --------------------------------------------------------------------------------------------------
# LC-04: LCT-01, LCT-02, LCT-03, LCT-14 on the main trial
# --------------------------------------------------------------------------------------------------

def test_lct02_two_tracks_two_sessions_before_one_after(main_run):
    out = main_run[0]
    for acct in ("admin_it", "svc_backup"):
        h = hop_of(out, acct)
        assert h["candidate_count_sessions_before_account"] == 2, acct
        assert h["candidate_count_sessions_after_account"] == 1, acct
        assert h["mismatch_table"] == [], acct
        assert h["zero_reason"] is None
    assert hop_of(out, "admin_it")["n_4624"] == 3 and hop_of(out, "svc_backup")["n_4624"] == 2
    assert hop_of(out, "admin_it")["t_first_4624"] == "2026-09-24T10:57:35.000Z"      # t = first 4624 of the burst


def test_lct01_sysmon1_4688_collapse_one_session_rows_exceed_sessions(main_run):
    out, _, u, _ = main_run
    h = hop_of(out, "admin_it")
    admin = [c for c in h["candidates"] if c["account"] == "admin_it"][0]
    # Sysmon 1 + 4688 of one command = ONE process; the net.exe tool row is a second process
    assert admin["processes"] == 2
    assert h["candidate_count_rows"] == 3                      # collapsed processes over both sessions
    assert h["candidate_count_rows_raw"] == 4                  # raw rows (4688 twin counted)
    assert h["candidate_count_rows"] > h["candidate_count_sessions_before_account"]
    assert u["cmd_admin"] in admin["event_uids"] and u["cmd_admin_4688"] in admin["event_uids"]


def test_lct03_command_after_target_4624_is_candidate(main_run):
    out = main_run[0]
    h = hop_of(out, "svc_backup")
    svc = [c for c in h["candidates"] if c["account"] == "svc_backup"][0]
    assert svc["time_delta_ms"] == 1500                         # command 38.355 - 4624 36.855
    rows = [r for r in csv_rows(out) if r["account_name"] == "svc_backup" and r["candidate_account"] == "svc_backup"]
    assert len(rows) == 1 and rows[0]["time_delta_ms"] == "1500"


def test_lct03_window_edges_cmd_after_10_s(tmp_path):
    b = hop_builder()
    cmd_at(b, 9.5, r"net use \\192.168.50.22\c$")
    out, _ = run(b, tmp_path, "after_in")
    assert hop_of(out, "svc_backup")["candidate_count_sessions_before_account"] == 1
    b2 = hop_builder()
    cmd_at(b2, 10.8, r"net use \\192.168.50.22\c$")
    out2, _ = run(b2, tmp_path, "after_out")
    h = hop_of(out2, "svc_backup")
    assert h["candidate_count_sessions_before_account"] == 0 and h["zero_reason"] == "a_no_command_in_range"
    b3 = hop_builder()
    cmd_at(b3, -119, r"net use \\192.168.50.22\c$")
    out3, _ = run(b3, tmp_path, "before_in")
    assert hop_of(out3, "svc_backup")["candidate_count_sessions_before_account"] == 1
    b4 = hop_builder()
    cmd_at(b4, -121, r"net use \\192.168.50.22\c$")
    out4, _ = run(b4, tmp_path, "before_out")
    assert hop_of(out4, "svc_backup")["candidate_count_sessions_before_account"] == 0


def test_lct14_agent_session_type_reported(main_run):
    out = main_run[0]
    rows = [r for r in csv_rows(out) if r["candidate_account"] in ("admin_it", "svc_backup")]
    assert rows and all(r["candidate_logon_type"] == "4" for r in rows)
    for h in lc04_hops(out):
        for c in h["candidates"]:
            assert c["logon_type"] == 4 and c["logon_event_uid"]


def test_csv_contents_main(main_run):
    out, _, u, _ = main_run
    rows = csv_rows(out)
    assert len(rows) == 4                                       # 2 hops x 2 candidate sessions
    assert {r["hop_id"] for r in rows} == {"s04-h1", "s04-h2"}
    for r in rows:
        assert r["trial_id"] == "s04_t00" and r["target_host"] == "ep-02" and r["source_host"] == "ep-01"
        assert r["source_ip"] == "192.168.50.21" and r["method"] == "cmdline_target"
        assert r["candidate_count_sessions_before_account"] == "2"
        assert r["candidate_count_sessions_after_account"] == "1"
        assert r["candidate_count_sessions_after_4648_bridge"] == "1"
        assert r["supporting_event_uids"] and r["target_event_uids"]
        assert r["target_time_utc"].endswith("Z")
    consistent = [r for r in rows if r["candidate_account"] == r["account_name"]]
    assert len(consistent) == 2 and all(r["confidence_tier"] == "B" for r in consistent)   # LC-04g
    h1 = [r for r in rows if r["hop_id"] == "s04-h1"][0]
    assert len(h1["target_event_uids"].split(";")) == 3
    assert u["admin_e0001"] in h1["target_event_uids"]
    admin = [r for r in rows if r["hop_id"] == "s04-h1" and r["candidate_account"] == "admin_it"][0]
    assert admin["time_delta_ms"] == "-700" and admin["candidate_session_id"] == "0xd6398"
    assert u["cmd_admin"] in admin["supporting_event_uids"]


def test_lc04_status_ok_and_linked(main_run):
    chk = main_run[0].report["checks"]["LC-04"]
    assert chk["status"] == "OK"
    assert chk["result"]["smb_scenario_hops"] == 2 and chk["result"]["smb_scenario_hops_linked"] == 2
    assert all(h["protocol"] == "SMB" for h in chk["result"]["hops"])


def test_lc04f_protocol_label_and_self_ip_excluded(tmp_path):
    b = hop_builder()
    b.logon("10:57:20", "ep-02", "svc_backup", 0xE0030, 3, ip="192.168.50.22", port=50000)   # target's own IP
    out, _ = run(b, tmp_path, "selfip")
    r = out.report["checks"]["LC-04"]["result"]
    assert r["excluded_4624"]["self_ip"] == 1
    assert [h["target_event_uids"] for h in r["hops"]] == [h["target_event_uids"] for h in r["hops"]]
    assert len(r["hops"]) == 1                                  # the self-IP logon is not a hop


def test_hop_group_s_splits_hop_instances(tmp_path):
    b = hop_builder()
    b.logon("10:57:45", "ep-02", "svc_backup", 0xE0031, 3, ip="192.168.50.21", port=49735)   # +9 s: same hop
    b.logon("10:58:10", "ep-02", "svc_backup", 0xE0032, 3, ip="192.168.50.21", port=49736)   # +34 s: new hop
    out, _ = run(b, tmp_path, "grp")
    hops = [h for h in lc04_hops(out) if h["account_name"] == "svc_backup"]
    assert sorted(h["n_4624"] for h in hops) == [1, 2]


# --------------------------------------------------------------------------------------------------
# LC-04 name matching and zero reasons: LCT-04, LCT-05, LCT-06
# --------------------------------------------------------------------------------------------------

FORMS = target_name_forms("ep-02", "192.168.50.22")


@pytest.mark.parametrize("text,expected", [
    (r"net use \\192.168.50.22\c$", True),
    (r"net use \\192.168.50.2\c$", False),            # prefix of .22
    (r"net use \\192.168.50.220\c$", False),
    (r"net use \\192.168.50.222\c$", False),
    (r"net use \\1192.168.50.22\c$", False),
    (r"net use \\EP-02\c$", True),
    (r"net use \\ep-02.lab.local\c$", True),
    (r"net use \\Endpoint-02\c$", True),
    (r"net use \\ENDPOINT-02.lab.local\c$", True),
    (r"net use \\ep-020\c$", False),
    (r"net use \\xep-02\c$", False),
    (r"net use \\ep-01\c$", False),
    (None, False), ("", False),
])
def test_lct04_names_target_boundaries(text, expected):
    assert names_target(text, FORMS) is expected


def test_lct04_db_prefix_ip_no_match_reason_b(tmp_path):
    b = hop_builder()
    cmd_at(b, 1, r"net use \\192.168.50.2\c$")
    cmd_at(b, 2, r"net use \\192.168.50.220\c$", session=0x101)
    out, _ = run(b, tmp_path, "prefix")
    h = hop_of(out, "svc_backup")
    assert h["candidate_count_sessions_before_account"] == 0
    assert h["zero_reason"] == "b_no_command_names_target"


def _ps_enc(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode()


def test_lct05_decode_helper():
    assert decode_powershell_b64(_ps_enc(r"Copy-Item a \\192.168.50.22\ADMIN$")) == r"Copy-Item a \\192.168.50.22\ADMIN$"
    assert decode_powershell_b64("not_base64!!") is None


def test_lct05_encoded_command_matched_after_decoding(tmp_path):
    payload = _ps_enc(r"Copy-Item a.txt \\192.168.50.22\ADMIN$\a.txt")
    b = hop_builder(sessions=((0x100, "svc_backup"), (0x101, "svc_backup"), (0x102, "svc_backup")))
    cmd_at(b, 1, f"powershell.exe -NoProfile -enc {payload}", session=0x100)
    cmd_at(b, 1.5, f"powershell.exe -EncodedCommand {payload}", session=0x101)
    cmd_at(b, 2, f"powershell.exe -ec {payload}", session=0x102)
    out, _ = run(b, tmp_path, "enc")
    h = hop_of(out, "svc_backup")
    assert h["candidate_count_sessions_before_account"] == 3
    assert all(c["matched_via"] == ["decoded"] for c in h["candidates"])
    # decoded text is for matching only: it is never written to the outputs
    assert "Copy-Item a.txt" not in out.markdown and "Copy-Item a.txt" not in out.csv_text
    assert "Copy-Item a.txt" not in json.dumps(out.report)


def test_lct05_encoded_naming_other_host_is_reason_b_and_undecodable_is_reason_c(tmp_path):
    other = _ps_enc(r"Copy-Item a.txt \\192.168.50.23\ADMIN$")
    b = hop_builder()
    cmd_at(b, 1, f"powershell.exe -enc {other}")
    out, _ = run(b, tmp_path, "enc_other")
    assert hop_of(out, "svc_backup")["zero_reason"] == "b_no_command_names_target"
    b2 = hop_builder()
    cmd_at(b2, 1, "powershell.exe -enc not_base64!!")
    out2, _ = run(b2, tmp_path, "enc_bad")
    h = hop_of(out2, "svc_backup")
    assert h["candidate_count_sessions_before_account"] == 0 and h["zero_reason"] == "c_encoded_undecodable"
    rows = csv_rows(out2)
    assert len(rows) == 1 and rows[0]["zero_reason"] == "c_encoded_undecodable" and rows[0]["candidate_session_id"] == ""


def test_lct06_zero_reasons_a_and_b_and_empty_csv_row(tmp_path):
    b = hop_builder()                                           # no command at all -> a
    out, _ = run(b, tmp_path, "zero_a")
    h = hop_of(out, "svc_backup")
    assert h["zero_reason"] == "a_no_command_in_range" and h["candidate_count_rows"] == 0
    rows = csv_rows(out)
    assert len(rows) == 1 and rows[0]["zero_reason"] == "a_no_command_in_range"
    assert rows[0]["candidate_count_sessions_before_account"] == "0" and rows[0]["candidate_count_rows"] == "0"
    b2 = hop_builder()                                          # commands exist, none names the target -> b
    cmd_at(b2, 1, "whoami /all")
    cmd_at(b2, 2, r"net use \\192.168.50.23\c$")
    out2, _ = run(b2, tmp_path, "zero_b")
    h2 = hop_of(out2, "svc_backup")
    assert h2["zero_reason"] == "b_no_command_names_target" and h2["rows_in_range"] == 2
    b3 = hop_builder()                                          # a 4688 with NULL command_line is no evidence -> a
    b3.add(T0 + timedelta(seconds=1), "ep-01", "Security", 4688, session_id=0x100, command_line=None, process_id=5,
           image=CMD_EXE)
    out3, _ = run(b3, tmp_path, "zero_null")
    assert hop_of(out3, "svc_backup")["zero_reason"] == "a_no_command_in_range"


def test_lc04_sysmon1_and_4688_collapse_needs_same_session_and_same_cmdline(tmp_path):
    cmdline = r"cmd.exe /c net use \\192.168.50.22\c$"
    b = hop_builder(sessions=((0x100, "svc_backup"),))
    cmd_at(b, 1.0, cmdline, pid=9)
    b.sec4688(T0 + timedelta(seconds=1.1), "ep-01", 0x100, cmdline, pid=9)                   # twin: collapses
    cmd_at(b, 1.2, r"cmd.exe /c net use \\192.168.50.22\d$")                               # other cmd, same session
    b.sec4688(T0 + timedelta(seconds=1.25), "ep-01", 0x100, r"cmd.exe /c net use \\192.168.50.22\d$")
    out, _ = run(b, tmp_path, "collapse")
    h = hop_of(out, "svc_backup")
    assert h["candidate_count_sessions_before_account"] == 1
    assert h["candidate_count_rows"] == 2 and h["candidate_count_rows_raw"] == 4


# --------------------------------------------------------------------------------------------------
# LC-04e bridge, LC-04g tiers
# --------------------------------------------------------------------------------------------------

def _bridge_builder(with_4648=True, bridge_account="admin_it", bridge_target="ep-02") -> Builder:
    b = hop_builder(target_acct="admin_it", sessions=((0x500, "svc_backup"),))
    cmd_at(b, 1.0, r"net use \\192.168.50.22\c$", session=0x500, acct="svc_backup")
    if with_4648:
        b.add(T0 + timedelta(seconds=0.5), "ep-01", "Security", 4648, session_id=0x500, subject_logon_id=0x500,
              account_name=bridge_account, destination_host=bridge_target)
    return b


def test_lc04e_4648_bridge_passes_svc_backup_session_for_admin_it(tmp_path):
    out, _ = run(_bridge_builder(), tmp_path, "bridge")
    h = hop_of(out, "admin_it")
    assert h["candidate_count_sessions_before_account"] == 1
    assert h["candidate_count_sessions_after_account"] == 0            # plain filter drops it
    assert h["candidate_count_sessions_after_4648_bridge"] == 1        # with the bridge it passes
    assert h["mismatch_table"] != [] and h["mismatch_after_bridge"] == []
    rows = csv_rows(out)
    assert len(rows) == 1
    r = rows[0]
    assert (r["candidate_count_sessions_before_account"], r["candidate_count_sessions_after_account"],
            r["candidate_count_sessions_after_4648_bridge"]) == ("1", "0", "1")
    assert r["candidate_account"] == "svc_backup" and r["account_name"] == "admin_it"
    assert r["confidence_tier"] == "B"
    assert out.report["checks"]["LC-04"]["result"]["hops_changed_by_4648_bridge"] == [h["hop_id"]]


@pytest.mark.parametrize("kwargs", [
    {"with_4648": False},                                       # no 4648
    {"bridge_account": "svc_sql"},                              # credentials of another account
    {"bridge_target": "ep-03"},                                 # names another host
])
def test_lc04e_no_bridge_without_matching_4648(tmp_path, kwargs):
    out, _ = run(_bridge_builder(**kwargs), tmp_path, "nobridge")
    h = hop_of(out, "admin_it")
    assert (h["candidate_count_sessions_before_account"], h["candidate_count_sessions_after_account"],
            h["candidate_count_sessions_after_4648_bridge"]) == (1, 0, 0)
    assert csv_rows(out)[0]["confidence_tier"] == "D"                   # LC-04g: candidates, none consistent


def test_lc04e_4648_outside_time_range_does_not_bridge(tmp_path):
    b = hop_builder(target_acct="admin_it", sessions=((0x500, "svc_backup"),))
    cmd_at(b, 1.0, r"net use \\192.168.50.22\c$", session=0x500, acct="svc_backup")
    b.add(T0 - timedelta(seconds=300), "ep-01", "Security", 4648, session_id=0x500, account_name="admin_it",
          destination_host="ep-02")
    out, _ = run(b, tmp_path, "bridge_late")
    assert hop_of(out, "admin_it")["candidate_count_sessions_after_4648_bridge"] == 0


def test_lc04g_tier_c_for_several_account_consistent_sessions(tmp_path):
    b = hop_builder(sessions=((0x100, "svc_backup"), (0x101, "svc_backup")))
    cmd_at(b, 1, r"net use \\192.168.50.22\c$", session=0x100)
    cmd_at(b, 2, r"net use \\192.168.50.22\d$", session=0x101)
    out, _ = run(b, tmp_path, "tierc")
    rows = csv_rows(out)
    assert len(rows) == 2 and {r["confidence_tier"] for r in rows} == {"C"}
    assert hop_of(out, "svc_backup")["candidate_count_sessions_after_account"] == 2


def test_lc04d_sensitivity_grid(tmp_path):
    b = hop_builder()
    cmd_at(b, -100, r"net use \\192.168.50.22\a$", session=0x100)          # only in range for before >= 120
    b.logon("10:00:00", "ep-01", "svc_backup", 0x101, 4)
    cmd_at(b, 20, r"net use \\192.168.50.22\b$", session=0x101)             # only in range for after >= 30
    out, _ = run(b, tmp_path, "grid")
    r = out.report["checks"]["LC-04d"]["result"]
    cells = [x for x in r["hops"] if x["account_name"] == "svc_backup"][0]["sessions_after_account"]
    assert len(cells) == 9
    assert cells["before30_after10"] == 0
    assert cells["before120_after10"] == 1
    assert cells["before30_after30"] == 1
    assert cells["before300_after300"] == 2
    assert r["grid_after"] == [10, 30, 300] and r["grid_before"] == [30, 120, 300]


# --------------------------------------------------------------------------------------------------
# LC-04b, LC-04c, LCT-07
# --------------------------------------------------------------------------------------------------

def test_lc04b_zero_on_synthetic_main(main_run):
    r = main_run[0].report["checks"]["LC-04b"]["result"]
    assert r["joined"] == [] and r["sysmon3_rows"] == 0


def test_lc04b_legacy_join_works_when_system_445_rows_exist(tmp_path):
    b = hop_builder()
    b.add(T0 + timedelta(seconds=0.2), "ep-01", "Sysmon", 3, image="System", source_ip="192.168.50.21",
          source_port=49734, destination_ip="192.168.50.22", destination_port=445, initiated=1)
    out, _ = run(b, tmp_path, "legacy")
    r = out.report["checks"]["LC-04b"]["result"]
    assert r["sysmon3_rows"] == 1 and len(r["joined"]) == 1 and r["joined"][0]["time_delta_ms"] == 200


def test_lct07_services_tied_to_one_session_each(main_run):
    out, _, u, _ = main_run
    r = out.report["checks"]["LC-04c"]["result"]
    svcs = {s["service_name"]: s for s in r["services"]}
    assert set(svcs) == {"HealthAgentSvc", "UpdaterService"}                   # 4697 + 7045 count once
    assert svcs["HealthAgentSvc"]["match"] == "one" and svcs["HealthAgentSvc"]["admin_write_sessions"] == ["0xe0001"]
    assert svcs["UpdaterService"]["match"] == "one" and svcs["UpdaterService"]["admin_write_sessions"] == ["0xe0010"]
    assert sorted(svcs["HealthAgentSvc"]["event_uids"]) == sorted([u["svc7045_a"], u["svc4697_a"]])
    assert r["service_match_counts"] == {"non_system_one": 2}
    assert r["smb_hops"] == 2 and r["smb_hops_port0"] == 0
    per = {h["account_name"]: h for h in r["hops"]}
    assert per["admin_it"]["n_5140"] == 1 and per["admin_it"]["n_5145"] == 1
    assert per["svc_backup"]["n_5145"] == 1


def test_lc04c_service_with_several_or_no_sessions(tmp_path):
    b = hop_builder()
    for lid in (0xE0010, 0xE0011):
        b.add(T0 + timedelta(seconds=2), "ep-02", "Security", 5145, session_id=lid, share_name=r"\\*\ADMIN$",
              relative_target_name="Dup.exe")
    b.add(T0 + timedelta(seconds=2), "ep-02", "Security", 5145, session_id=0xE0010, share_name=r"\\*\ADMIN$",
          relative_target_name="Other.exe")
    b.service(T0 + timedelta(seconds=4), "ep-02", "DupSvc", r"C:\Windows\Dup.exe")
    b.service(T0 + timedelta(seconds=6), "ep-02", "NoneSvc", r"C:\Windows\NoSuchFile.exe")
    out, _ = run(b, tmp_path, "svcmatch")
    svcs = {s["service_name"]: s for s in out.report["checks"]["LC-04c"]["result"]["services"]}
    assert svcs["DupSvc"]["match"] == "several" and svcs["NoneSvc"]["match"] == "none"


def test_lc04c_port0_share_of_smb_hops(tmp_path):
    b = Builder()
    b.logon("10:00:00", "ep-01", "svc_backup", 0x100, 4)
    b.logon("10:57:36.000", "ep-02", "svc_backup", 0xE0010, 3, ip="192.168.50.21", port=0)
    b.add("10:57:38", "ep-02", "Security", 5145, session_id=0xE0010, share_name=r"\\*\ADMIN$", relative_target_name="a.exe")
    out, _ = run(b, tmp_path, "port0")
    r = out.report["checks"]["LC-04c"]["result"]
    assert r["smb_hops"] == 1 and r["smb_hops_port0"] == 1


# --------------------------------------------------------------------------------------------------
# LC-05 / LC-06
# --------------------------------------------------------------------------------------------------

PS_EXE = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _winrm_builder(port_offset_s=0.2) -> Builder:
    b = hop_builder(sessions=((0x100, "svc_backup"),))
    b.sysmon1("10:56:00", "ep-01", 0x100, "powershell.exe", pid=11, image=PS_EXE, guid="{G-PS-1}")
    b.add(T0 + timedelta(seconds=port_offset_s), "ep-01", "Sysmon", 3, image=PS_EXE, source_ip="192.168.50.21",
          source_port=49734, destination_ip="192.168.50.22", destination_port=5985, initiated=1,
          process_guid="{G-PS-1}")
    b.add(T0 + timedelta(seconds=0.3), "ep-02", "WinRM", 91, account_name="svc_backup", source_ip="192.168.50.21")
    b.sysmon1("10:57:37", "ep-02", 0xE0010, "wsmprovhost.exe", acct="svc_backup",
              image=r"C:\Windows\System32\wsmprovhost.exe")
    return b


def test_lc06_winrm_port_join_91_wsmprovhost_and_source_session(tmp_path):
    out, _ = run(_winrm_builder(), tmp_path, "winrm")
    chk = out.report["checks"]["LC-06"]
    h = chk["result"]["winrm_hops"][0]
    assert h["protocol"] == "WinRM"
    assert len(h["port_joins"]) == 1 and len(h["winrm91"]) == 1 and len(h["wsmprovhost"]) == 1
    assert h["source_sessions"][0]["session_id"] == "0x100" and h["source_sessions"][0]["account"] == "svc_backup"
    rows = [r for r in csv_rows(out) if r["protocol"] == "WinRM" and r["method"] == "sysmon3_port"]
    assert len(rows) == 1
    r = rows[0]
    assert r["method"] == "sysmon3_port" and r["candidate_session_id"] == "0x100" and r["confidence_tier"] == "A"
    assert r["candidate_count_sessions_before_account"] == r["candidate_count_sessions_after_account"] == "1"
    assert r["time_delta_ms"] == "200"
    assert chk["status"] in {"OK", "INFO"}


def test_lc06_join_needs_port_gt_0_and_5_s(tmp_path):
    out, _ = run(_winrm_builder(port_offset_s=6.0), tmp_path, "winrm_late")        # 6 s apart: no join
    assert out.report["checks"]["LC-06"]["result"]["joined_pairs"] == 0
    b = hop_builder()
    b.add(T0, "ep-02", "Security", 4624, account_name="svc_backup", target_logon_id=0xE0040, logon_type=3,
          source_ip="192.168.50.21", source_port=0)
    b.add(T0, "ep-01", "Sysmon", 3, image=PS_EXE, source_ip="192.168.50.21", source_port=0,
          destination_ip="192.168.50.22", destination_port=5985, initiated=1)
    out2, _ = run(b, tmp_path, "winrm_port0")                                      # port 0 is never a join key
    assert out2.report["checks"]["LC-06"]["result"]["joined_pairs"] == 0


def test_lc05_not_measurable_without_rdp_source_rows(tmp_path):
    b = hop_builder()
    b.add(T0 + timedelta(seconds=-1), "ep-02", "Sysmon", 3, image=r"C:\Windows\System32\svchost.exe",
          source_ip="192.168.50.21", source_port=50500, destination_ip="192.168.50.22", destination_port=3389,
          initiated=0)
    b.logon(T0 + timedelta(seconds=1), "ep-02", "svc_backup", 0xE0050, 10, ip="192.168.50.21", port=0)
    out, _ = run(b, tmp_path, "rdp")
    chk = out.report["checks"]["LC-05"]
    assert chk["status"] == "NOT_MEASURABLE"
    assert "S01 t01" in json.dumps(chk)
    assert chk["result"]["inbound_with_4624"] == 2      # the type 3 hop 4624 (+1 s) and the type 10 one (+1 s)
    assert any(h["protocol"] == "RDP" for h in lc04_hops(out))


# --------------------------------------------------------------------------------------------------
# LC-08 / LC-08b: LCT-08, LCT-09, LCT-13
# --------------------------------------------------------------------------------------------------

def _dump_sessions(out, host="ep-01") -> tuple[dict, dict[str, list[dict]]]:
    dumps = [d for d in out.report["checks"]["LC-08"]["result"]["dumps"] if d["host"] == host]
    assert len(dumps) == 1
    by: dict[str, list[dict]] = {}
    for s in dumps[0]["sessions"]:
        by.setdefault(s["session_hex"], []).append(s)
    return dumps[0], by


def test_lct09_dump_pair_is_one_dump(main_run):
    out, _, u, _ = main_run
    dumps = out.report["checks"]["LC-08"]["result"]["dumps"]
    assert len(dumps) == 2                                       # ep-01 pair + ep-02 single
    d, _ = _dump_sessions(out)
    assert d["time"] == "2026-09-24T10:56:56.000Z"
    assert sorted(d["granted_access"]) == ["0x1410", "0x1fffff"]
    assert sorted(d["event_uids"]) == sorted([u["dump_a"], u["dump_b"]])
    assert d["source_image"].lower().endswith("rundll32.exe")


def test_lct08_open_closed_reused_linked_boot_and_previous_day(main_run):
    out, *_ = main_run
    _, by = _dump_sessions(out)
    state = lambda sid: [s["state"] for s in by.get(sid, [])]              # noqa: E731
    assert state("0xd6398") == ["open"] and state("0x17c46") == ["open"]    # agent sessions
    assert "0x1001" not in by                                               # logoff on the logon id: closed, not listed
    assert "0x1002" not in by and "0x1003" not in by                        # logoff on the LINKED id: closed
    assert state("0x1004") == ["open"]                                      # id reused: only the new session, open
    assert by["0x1004"][0]["account_name"] == "svc_sql"
    assert state("0x1007") == ["open"]                                      # a logoff BEFORE the 4624 does not close it
    assert state("0x1005") == ["end_unknown"]                               # boot event between start and dump
    assert state("0x1008") == ["end_unknown"]                               # logoff after a boot is not trusted
    assert "open" not in state("0x1006")                                    # previous-day session is never "open"
    assert state("0x2000") == ["end_unknown"]                               # process-only session, no 4624
    assert by["0x2000"][0]["category"] == "unknown"


def test_lc08_split_by_logon_type_and_predefined_once(main_run):
    out, *_ = main_run
    _, by = _dump_sessions(out)
    assert by["0xd6398"][0]["category"] == "batch_service" and by["0xd6398"][0]["logon_type"] == 4
    assert by["0x1007"][0]["category"] == "interactive"
    assert by["0x1004"][0]["category"] == "network"
    assert len(by["0x3e7"]) == 1 and by["0x3e7"][0]["category"] == "predefined"      # three 4624s, listed once


def test_lct13_dump_as_system_sessions_listed_by_host(main_run):
    out, *_ = main_run
    d, by = _dump_sessions(out)
    assert d["account_name"] == "system"                        # the dumper is SYSTEM ...
    open_accounts = {s["account_name"] for s in d["sessions"] if s["state"] == "open"}
    assert {"admin_it", "svc_backup", "svc_sql"} <= open_accounts   # ... but every account with a session is listed


def test_lc08b_scenario_accounts_and_s04a_answer(main_run):
    out, *_ = main_run
    r = out.report["checks"]["LC-08b"]["result"]
    d = [x for x in r["dumps"] if x["host"] == "ep-01"][0]
    by = {(e["account_name"], e["session_id"]): e for e in d["sessions"]}
    assert by[("admin_it", "0xd6398")]["state"] == "open" and by[("admin_it", "0xd6398")]["ran_command_within_10min"] is True
    assert by[("svc_backup", "0x17c46")]["ran_command_within_10min"] is True
    assert by[("svc_sql", "0x1004")]["ran_command_within_10min"] is False
    assert r["s04_a"]["answer"].lower().startswith("yes") and "0xd6398" in r["s04_a"]["answer"]
    assert out.report["checks"]["LC-08"]["status"] == "OK"
    assert "S04-A" in out.markdown


def test_lc08_hours_lookback_limits_listing(tmp_path):
    b = Builder("s02")
    b.sysmon1("03:00:00", "ep-01", 0x9, "whoami")
    b.logon("04:00:00", "ep-01", "admin_it", 0x600, 2)                # 1 h 40 before the dump: listed
    b.logon("2026-09-24T09:00:00", "ep-01", "svc_sql", 0x601, 2, day=DAY)
    b.dump("05:42:00", "ep-01")
    out, _ = run(b, tmp_path, "lookback")
    _, by = _dump_sessions(out)
    assert by["0x600"][0]["state"] == "open"
    b2 = Builder("s02")
    b2.sysmon1("00:00:00", "ep-01", 0x9, "whoami")
    b2.logon("00:10:00", "ep-01", "admin_it", 0x700, 2)               # 5.5 h < 6 h lookback ... listed
    b2.logon("00:10:00", "ep-01", "svc_sql", 0x701, 2, day="2026-09-23")   # 29.5 h before: > lookback
    b2.dump("05:42:00", "ep-01")
    out2, _ = run(b2, tmp_path, "lookback2")
    _, by2 = _dump_sessions(out2)
    assert by2["0x700"][0]["state"] == "open"
    assert [s["state"] for s in by2["0x701"]] == ["end_unknown"]      # older than the lookback: listed, not dropped


def test_s01_t00_reference_only_is_not_measurable_not_problem(tmp_path):
    b = Builder("s01")
    b.logon("10:00:00", "ep-01", "svc_backup", 0x100, 4)
    out, _ = run(b, tmp_path, "s01")
    ck = out.report["checks"]
    assert ck["LC-08"]["status"] == "NOT_MEASURABLE"
    assert ck["LC-08b"]["status"] == "NOT_MEASURABLE"
    assert ck["LC-05"]["status"] != "PROBLEM"
    assert all(c["status"] != "PROBLEM" for c in ck.values() if c is not ck["LC-02"])


def test_lc12_problem_when_expected_evidence_missing(tmp_path):
    b = Builder("s04")
    b.logon("10:00:00", "ep-01", "svc_backup", 0x100, 4)
    out, _ = run(b, tmp_path, "empty_s04")
    ck = out.report["checks"]
    assert ck["LC-02"]["status"] == "PROBLEM"          # S04 expects remote lab 4624s
    assert ck["LC-04"]["status"] == "PROBLEM"          # S04 expects 2 SMB hops
    assert ck["LC-08"]["status"] == "PROBLEM"          # S04 expects a dump
    assert ck["LC-01"]["status"] == "INFO" and ck["LC-04d"]["status"] == "INFO"
    assert out.csv_text.strip().splitlines() == [",".join(CSV_SPEC_COLUMNS)]     # header only, no rows invented


# --------------------------------------------------------------------------------------------------
# LCT-12 masking (LC-13)
# --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("cmd,secret", [
    (r"net use \\192.168.50.22\c$ /user:LAB\x FakePw-0001", "FakePw-0001"),
    (r"powershell -Command New-PSCredential -User x -Password hunter2pass", "hunter2pass"),
    (r"tool.exe /p:Pa55word77 /s:srv", "Pa55word77"),
])
def test_lct12_mask_command_line_rules(cmd, secret):
    masked = mask_command_line(cmd)
    assert secret not in masked and "***" in masked


def test_lct12_passwords_masked_in_every_output(tmp_path):
    b = hop_builder(sessions=((0x100, "svc_backup"), (0x101, "svc_backup"), (0x102, "svc_backup"), (0x103, "svc_backup")))
    cmd_at(b, 1, r"net use \\192.168.50.22\IPC$ /user:LAB\svc_backup FakePw-0001", session=0x100)
    cmd_at(b, 2, r"powershell -Command Copy-Item x \\192.168.50.22\c$ -Password S3cr3tPW9", session=0x101)
    cmd_at(b, 3, r"cmd /c copy x \\192.168.50.22\c$ /p:Pa55word77", session=0x102)
    cmd_at(b, 4, r"cmd /c echo FakePw-0001 \\192.168.50.22\c$", session=0x103)       # secret appears literally elsewhere
    out, db = run(b, tmp_path, "mask")
    texts = {"json": (Path(out.files[0]).parent / "report.json").read_text(encoding="utf-8"),
             "md": (Path(out.files[0]).parent / "report.md").read_text(encoding="utf-8"),
             "csv": (Path(out.files[0]).parent / "hop_candidates.csv").read_text(encoding="utf-8"),
             "in_memory": out.markdown + out.csv_text + json.dumps(out.report)}
    for name, text in texts.items():
        for secret in ("FakePw-0001", "S3cr3tPW9", "Pa55word77"):
            assert secret not in text, f"{secret} leaked into {name}"
    assert "***" in texts["json"]


# --------------------------------------------------------------------------------------------------
# real data (data/sample): acceptance section 7, answer-key events for S02 t01 / S04 t01 / S05 t01 pending
# --------------------------------------------------------------------------------------------------

def _sample(name: str):
    db = SAMPLE / f"{name}_t00.sqlite3"
    if not db.exists():
        pytest.skip(f"missing {db}")
    return db


@pytest.fixture(scope="module")
def real_runs(tmp_path_factory):
    root = tmp_path_factory.mktemp("log_check_real")
    runs = {}
    for name in ("s02", "s04", "s05"):
        db = _sample(name)
        sha = hashlib.sha256(db.read_bytes()).hexdigest()
        out = run_log_check(db, f"{name}_t00", root / "out", None, root / "nokeys")
        assert hashlib.sha256(db.read_bytes()).hexdigest() == sha          # sample DB untouched
        runs[name] = (out, db)
    return runs


def _dump_times(out) -> set[tuple[str, datetime]]:
    return {(d["host"], datetime.strptime(d["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc))
            for d in out.report["checks"]["LC-08"]["result"]["dumps"]}


def _has_dump(out, host: str, when: str, day: str) -> bool:
    target = pdt(when, day)
    return any(h == host and abs((t - target).total_seconds()) <= 1.5 for h, t in _dump_times(out))


@pytest.mark.parametrize("name", ["s02", "s04", "s05"])
def test_real_reports_exist_lc01_totals_and_lc04b_zero(real_runs, name):
    out, db = real_runs[name]
    conn = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
    n_ev = conn.execute("select count(*) from events").fetchone()[0]
    n_dd = conn.execute("select count(*) from events_dedup").fetchone()[0]
    conn.close()
    r = out.report["checks"]["LC-01"]["result"]
    assert r["events_rows"] == n_ev and r["events_dedup_rows"] == n_dd and r["whole_db_total"] == n_dd
    assert out.report["checks"]["LC-04b"]["result"]["joined"] == []
    assert {Path(p).name for p in out.files} == {"report.json", "report.md", "hop_candidates.csv"}
    assert out.csv_text.splitlines()[0].split(",") == CSV_SPEC_COLUMNS
    assert out.report["checks"]["LC-10"]["status"] == "NOT_MEASURABLE"
    assert out.report["checks"]["LC-05"]["status"] == "NOT_MEASURABLE" or name == "s04"


def test_real_lc08_dumps_at_spec_times(real_runs):
    assert _has_dump(real_runs["s02"][0], "ep-01", "05:42:00", "2026-09-24")
    assert _has_dump(real_runs["s04"][0], "ep-01", "10:56:56", "2026-09-24")
    assert _has_dump(real_runs["s05"][0], "ep-01", "07:09:43", "2026-10-12")
    assert _has_dump(real_runs["s05"][0], "ep-02", "07:11:49", "2026-10-12")


def test_real_lct13_s02_ep02_dump_as_system(real_runs):
    out = real_runs["s02"][0]
    assert _has_dump(out, "ep-02", "05:41:32", "2026-09-24")
    d = [x for x in out.report["checks"]["LC-08"]["result"]["dumps"] if x["host"] == "ep-02"][0]
    assert d["sessions"], "sessions must be listed by host even if the dumper is SYSTEM"


def test_real_s04_two_tracks_two_before_one_after(real_runs):
    out = real_runs["s04"][0]
    track = [h for h in lc04_hops(out) if h["target_host"] == "ep-02" and h["source_ip"] == "192.168.50.21"
             and h["account_name"] in ("admin_it", "svc_backup") and h["t_first_4624"].startswith("2026-09-24T10:57:3")]
    assert {h["account_name"] for h in track} == {"admin_it", "svc_backup"}, [(h["account_name"], h["t_first_4624"]) for h in lc04_hops(out)]
    for h in track:
        assert h["candidate_count_sessions_before_account"] == 2, h["hop_id"]
        assert h["candidate_count_sessions_after_account"] == 1, h["hop_id"]
        assert h["mismatch_table"] == []
    assert out.report["checks"]["LC-04"]["status"] == "OK"
    svc = [h for h in track if h["account_name"] == "svc_backup"][0]
    assert any(c["session_id"] == "0x17c46" for c in svc["candidates"])
    adm = [h for h in track if h["account_name"] == "admin_it"][0]
    assert any(c["session_id"] == "0xd6398" for c in adm["candidates"])


def test_real_s04a_admin_it_open_at_dump(real_runs):
    out = real_runs["s04"][0]
    dump = [d for d in out.report["checks"]["LC-08"]["result"]["dumps"]
            if d["host"] == "ep-01" and d["time"].startswith("2026-09-24T10:56:56")][0]
    admin = [s for s in dump["sessions"] if s["account_name"] == "admin_it" and s["state"] == "open"]
    assert admin, "admin_it must have an open session at the S04 dump"
    ans = out.report["checks"]["LC-08b"]["result"]["s04_a"]["answer"]
    assert ans.lower().startswith("yes")


def test_real_s02_svc_backup_hop_candidate_0x25cac3(real_runs):
    out = real_runs["s02"][0]
    hits = [r for r in csv_rows(out) if r["account_name"] == "svc_backup" and r["candidate_session_id"] == "0x25cac3"]
    assert hits, [(r["hop_id"], r["account_name"], r["candidate_session_id"]) for r in csv_rows(out)]
    assert all(r["candidate_count_sessions_after_account"] != "0" for r in hits)


def test_real_s05_has_smb_and_winrm_hops_and_no_password_leak(real_runs):
    out = real_runs["s05"][0]
    protos = {h["protocol"] for h in lc04_hops(out) if h["account_name"] in ("svc_backup", "admin_it", "svc_sql")}
    assert "SMB" in protos
    for name in ("s04", "s05", "s02"):
        o = real_runs[name][0]
        assert "FakePw-0001" not in o.markdown and "FakePw-0001" not in o.csv_text
        assert "FakePw-0001" not in json.dumps(o.report)


# --------------------------------------------------------------------------------------------------
# LC-04h: 4648 coverage (method source_4648)
# --------------------------------------------------------------------------------------------------

def _smb_hop_builder(target_acct="svc_backup") -> Builder:
    """hop_builder plus an ADMIN$ 5145 in the target 4624 session so the hop is labelled SMB."""
    b = hop_builder(target_acct=target_acct, sessions=((0x100, "svc_backup"), (0x300, "svc_backup")))
    b.add(T0 + timedelta(seconds=2), "ep-02", "Security", 5145, session_id=0xE0010, share_name=r"\*\ADMIN$",
          relative_target_name="a.exe")
    return b


def _add4648(b, offset, server, sid=0x300, cred="svc_backup", host="ep-01"):
    return b.add(T0 + timedelta(seconds=offset), host, "Security", 4648, session_id=sid, subject_logon_id=sid,
                 account_name=cred, subject_account=r"lab\svc_backup", destination_host=server)


def _src4648(out):
    return [r for r in csv_rows(out) if r["method"] == "source_4648"]


@pytest.mark.parametrize("server", ["ep-02", "EP-02", "ep-02.lab.local", "endpoint-02", "192.168.50.22"])
@pytest.mark.parametrize("cred,hop_acct,match,tier", [
    ("svc_backup", "svc_backup", "direct", "B"),     # subject account == 4624 account
    ("admin_it", "svc_backup", "direct", "B"),       # subject account == 4624 account (credentials differ)
    ("admin_it", "admin_it", "4648", "B"),           # credentials account == 4624 account
    ("svc_sql", "admin_it", "none", "D"),            # neither
])
def test_lc04h_naming_4648_gives_source_4648_row(tmp_path, server, cred, hop_acct, match, tier):
    b = _smb_hop_builder(target_acct=hop_acct)
    _add4648(b, 0.5, server, cred=cred)
    out, _ = run(b, tmp_path, "h4648")
    rows = _src4648(out)
    assert len(rows) == 1, rows
    r = rows[0]
    assert r["candidate_session_id"] == "0x300" and r["confidence_tier"] == tier
    assert r["protocol"] == "SMB" and r["hop_id"] == hop_of(out, hop_acct)["hop_id"]
    assert r["time_delta_ms"] == "500" and r["supporting_event_uids"] and r["target_event_uids"]
    assert r["candidate_count_rows"] == "1"
    hop = [x for x in out.report["checks"]["LC-04h"]["result"]["hops"] if x["hop_id"] == r["hop_id"]][0]
    assert [x["account_match"] for x in hop["sessions"]] == [match]


@pytest.mark.parametrize("server,offset", [
    ("192.168.50.2", 1), ("192.168.50.220", 1), ("ep-020", 1),      # boundary-aware: other names
    ("ep-03", 1),                                                   # another host
    ("ep-02", -121), ("ep-02", 10.5),                               # outside [t-120, t+10]
])
def test_lc04h_no_row_for_other_host_boundary_or_out_of_range(tmp_path, server, offset):
    b = _smb_hop_builder()
    _add4648(b, offset, server)
    out, _ = run(b, tmp_path, "h4648_no")
    assert _src4648(out) == []
    h = [x for x in out.report["checks"]["LC-04h"]["result"]["hops"] if x["account_name"] == "svc_backup"][0]
    assert h["n_4648"] == 0


def test_lc04h_range_edges_inside(tmp_path):
    b = _smb_hop_builder()
    _add4648(b, -119, "ep-02", sid=0x300)
    _add4648(b, 9.5, "ep-02", sid=0x301)
    out, _ = run(b, tmp_path, "h4648_edge")
    assert sorted(r["candidate_session_id"] for r in _src4648(out)) == ["0x300", "0x301"]


def test_lc04h_report_counts_and_status_info(tmp_path):
    b = _smb_hop_builder()
    _add4648(b, 0.5, "ep-02")
    b.logon("11:05:30", "ep-02", "admin_it", 0xE0060, 3, ip="192.168.50.21", port=49800)   # second hop, no 4648
    b.add("11:05:32", "ep-02", "Security", 5145, session_id=0xE0060, share_name=r"\*\ADMIN$",
          relative_target_name="b.exe")
    out, _ = run(b, tmp_path, "h4648_cnt")
    chk = out.report["checks"]["LC-04h"]
    assert chk["status"] == "INFO" and chk["sql"]
    s = chk["result"]["summary"]["all"]
    assert s["hops"] == 2 and len(s["with_naming_4648"]) == 1 and len(s["without_naming_4648"]) == 1
    assert "session_differs_from_cmdline" in s


def test_lc04h_not_measurable_for_reference_trial(tmp_path):
    b = Builder("s01")
    b.logon("10:00:00", "ep-01", "svc_backup", 0x100, 4)
    out, _ = run(b, tmp_path, "h4648_s01")
    assert out.report["checks"]["LC-04h"]["status"] == "NOT_MEASURABLE"


def test_real_lc04h_s05_winrm_hop_has_source_4648_0x1c63d2(real_runs):
    out = real_runs["s05"][0]
    rows = [r for r in _src4648(out) if r["protocol"] == "WinRM"]
    assert any(r["candidate_session_id"] == "0x1c63d2" for r in rows), [
        (r["hop_id"], r["protocol"], r["candidate_session_id"]) for r in _src4648(out)]
    assert out.report["checks"]["LC-04h"]["status"] == "INFO"


def test_real_lc04h_s04_smb_hops_have_no_source_4648(real_runs):
    out = real_runs["s04"][0]
    assert [r for r in _src4648(out) if r["protocol"] == "SMB"] == []


def test_lc08_session_older_than_lookback_is_end_unknown_not_dropped(tmp_path):
    b = Builder("s02")
    b.sysmon1("03:00:00", "ep-01", 0x9, "whoami")
    b.logon("2026-09-23T10:00:00", "ep-01", "admin_it", 0x800, 2)     # ~19 h before the dump, no logoff, no boot
    b.dump("05:42:00", "ep-01")
    out, _ = run(b, tmp_path, "old_session")
    _, by = _dump_sessions(out)
    assert [s["state"] for s in by["0x800"]] == ["end_unknown"]
