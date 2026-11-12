"""Tests for evtx_pipeline.trial_import and the `import-trial` CLI (T3 pass B).

Written from docs/specs/01_normalise_fixes.md (NF-02, NF-07..NF-09, NF-15..NF-20, sections 6-7)
and decisions 004-008.  Synthetic Phase 1 trials are built in tmp_path from a few real JSONL
lines (skipped with a reason when the real data is missing) plus synthetic events.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src" / "parsing_normalization"
sys.path.insert(0, str(SRC))

from evtx_pipeline.trial_import import run_trial_import  # noqa: E402

JSONL = REPO / "data" / "processed" / "jsonl"
PROCESSED = REPO / "data" / "processed"
LOGON_ID_COLUMNS = ("session_id", "subject_logon_id", "target_logon_id", "target_linked_logon_id")


# ---------------------------------------------------------------- helpers
def real_line(rel: str, line_no: int) -> str:
    path = JSONL / rel
    if not path.exists():
        pytest.skip(f"missing development JSONL: {path}")
    return path.read_bytes().split(b"\n")[line_no - 1].decode("utf-8")


def make_event(channel: str, event_id, data: dict, *, rel: str, record_id: int,
               computer: str = "Endpoint-02.lab.local", ts="2026-09-24T05:00:00.1234567Z") -> dict:
    return {
        "schema_version": "1.0",
        "source": {"relative_path": rel, "filename": rel.split("/")[-1], "sha256": "ab" * 32,
                   "size_bytes": 1, "record_index": record_id},
        "hints": {"claimed_scenario": None, "host_from_path": None},
        "system": {"provider": "p", "event_id": str(event_id), "event_record_id": str(record_id),
                   "channel": channel, "computer": computer, "timestamp_raw": ts},
        "event_data": [{"name": k, "value": v} for k, v in data.items()],
        "user_data": None,
        "raw_xml": "<Event><System><Execution ProcessID=\"772\" ThreadID=\"1\"/></System></Event>",
    }


def logon4624(rel: str, record_id: int, user="svc_backup", **kw) -> dict:
    data = {"SubjectUserSid": "S-1-0-0", "SubjectUserName": "-", "SubjectDomainName": "-",
            "SubjectLogonId": "0x0", "TargetUserName": user, "TargetDomainName": "LAB",
            "TargetLogonId": "0x11a5b15", "LogonType": "3", "TargetLinkedLogonId": "0x0",
            "IpAddress": "192.168.50.22", "IpPort": "49761"}
    return make_event("Security", 4624, data, rel=rel, record_id=record_id, **kw)


def dump(event: dict) -> str:
    return json.dumps(event, ensure_ascii=False)


def base_files() -> dict[str, list[tuple[str, str]]]:
    """relative_path (<host>/<channel>.evtx) -> [(tag, line)], tag in kept/nr/bad/blank."""
    sec = "dc01/security.evtx"
    return {
        sec: [
            ("kept", real_line("s01_t00/per_file/dc01/security.jsonl", 1)),     # 1102 log cleared
            ("kept", dump(logon4624(sec, 7001, user="u\u2028x"))),               # U+2028 inside a string
            ("kept", real_line("s01_t00/per_file/dc01/security.jsonl", 2)),     # 4688, session 0x5f3f3
            ("blank", ""),
            ("nr", dump(make_event("Security", 4663, {"ObjectName": "x"}, rel=sec, record_id=7002))),
            ("bad", dump(make_event("Security", "abc", {"x": "y"}, rel=sec, record_id=7003))),
            ("kept", real_line("s01_t00/per_file/dc01/security.jsonl", 29)),    # 4769
            ("kept", real_line("s01_t00/per_file/dc01/security.jsonl", 33)),    # 4624
        ],
        "dc01/sysmon.evtx": [("kept", real_line("s01_t00/per_file/dc01/sysmon.jsonl", 21))],      # Sysmon 1
        "dc01/system.evtx": [("kept", real_line("s01_t00/per_file/dc01/system.jsonl", 3))],       # 6005
        "ep-01/security.evtx": [("kept", real_line("s01_t00/per_file/ep-01/security.jsonl", 121))],  # 4647
        "ep-01/sysmon.evtx": [
            ("kept", real_line("s01_t00/per_file/ep-01/sysmon.jsonl", 4)),      # Sysmon 10
            ("kept", real_line("s01_t00/per_file/ep-01/sysmon.jsonl", 272)),    # Sysmon 3
        ],
    }


def build_trial(root: Path, files: dict[str, list[tuple[str, str]]] | None = None, *, scenario="s02",
                trial="t00", folder: str | None = None, input_root: str | None = None,
                emitted_delta: int = 0, parse_errors: str = "", status: str = "ok",
                reverse_manifest: bool = False) -> Path:
    files = base_files() if files is None else files
    folder = folder or f"{scenario}_{trial}"
    jdir = root / folder
    items = []
    for rel, lines in files.items():
        out_rel = "per_file/" + rel.rsplit(".", 1)[0] + ".jsonl"
        path = jdir / out_rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes("".join(text + "\n" for _, text in lines).encode("utf-8"))
        emitted = sum(1 for tag, _ in lines if tag != "blank")
        items.append({"relative_path": rel, "size_bytes": 1, "pre_run_sha256": "00" * 32,
                      "post_run_sha256": "00" * 32, "evtx_signature": True, "status": status,
                      "attempted_record_count": emitted, "emitted_event_count": emitted + emitted_delta,
                      "parse_error_count": 0, "unaccounted_records_reason": None,
                      "output_relative_path": out_rel})
        emitted_delta = 0  # only the first file is perturbed
    if reverse_manifest:
        items.reverse()
    manifest = {"schema_version": "1.0", "run_mode": "full",
                "input_root": input_root or f"D:\\raw\\{scenario}\\{trial}",
                "selected_inputs": items, "failures": [], "warnings": [],
                "totals": {"files": len(items)}}
    (jdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (jdir / "parse_errors.jsonl").write_text(parse_errors, encoding="utf-8")
    return jdir


def do_import(tmp_path: Path, jdir: Path, scenario="s02", trial="t00"):
    db = tmp_path / "out" / f"{scenario}_{trial}.sqlite3"
    rep = tmp_path / "reports"
    result = run_trial_import(jdir, scenario, trial, db, rep)
    return db, rep, result


def connect(db: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


def assert_nothing_left(tmp_path: Path, rep: Path | None = None) -> None:
    out = tmp_path / "out"
    leftovers = sorted(p.name for p in out.iterdir()) if out.exists() else []
    assert leftovers == [], f"files left after failed import: {leftovers}"
    if rep is not None and rep.exists():
        assert not list(rep.rglob("*.json")), "report written for a failed import"


@pytest.fixture()
def imported(tmp_path):
    jdir = build_trial(tmp_path)
    db, rep, result = do_import(tmp_path, jdir)
    return {"jdir": jdir, "db": db, "rep": rep, "result": result, "tmp": tmp_path}


def row_where(conn, sql, *args):
    r = conn.execute(sql, args).fetchall()
    assert len(r) == 1, f"expected exactly 1 row for {sql} {args}, got {len(r)}"
    return r[0]


# ---------------------------------------------------------------- contract
def test_tables_views_and_counts(imported):
    conn = connect(imported["db"])
    names = {r[0] for r in conn.execute("select name from sqlite_master where type in ('table','view')")}
    assert {"events", "events_dedup", "events_display", "source_files", "duplicate_events"} <= names
    n_kept = sum(1 for lines in base_files().values() for t, _ in lines if t == "kept")
    assert conn.execute("select count(*) from events").fetchone()[0] == n_kept
    assert conn.execute("select count(*) from events_display").fetchone()[0] == n_kept


def test_integrity_check_ok(imported):
    assert [r[0] for r in connect(imported["db"]).execute("pragma integrity_check")] == ["ok"]


def test_accounting_counted_independently(imported):
    """NF-17: per-file kept/excluded/blank counts equal the construction and the manifest."""
    conn = connect(imported["db"])
    manifest = json.loads((imported["jdir"] / "manifest.json").read_text())
    emitted = {i["relative_path"]: i["emitted_event_count"] for i in manifest["selected_inputs"]}
    expect = {}
    for rel, lines in base_files().items():
        c = {t: sum(1 for tag, _ in lines if tag == t) for t in ("kept", "nr", "bad", "blank")}
        expect[rel] = c
    rows = {r["relative_path"]: r for r in conn.execute("select * from source_files")}
    assert set(rows) == set(expect)
    for rel, c in expect.items():
        r = rows[rel]
        assert (r["kept"], r["excluded_not_relevant"], r["excluded_bad_event_id"], r["blank_lines"]) == \
            (c["kept"], c["nr"], c["bad"], c["blank"]), rel
        assert r["kept"] + r["excluded_not_relevant"] + r["excluded_bad_event_id"] == emitted[rel]
        assert r["emitted_event_count"] == emitted[rel]
        assert r["lines_read"] == sum(c.values())
    # rows in events per file equal kept
    for rel, c in expect.items():
        n = conn.execute("select count(*) from events where source_relative_path in (?,?)",
                         (rel, "per_file/" + rel.rsplit('.', 1)[0] + ".jsonl")).fetchone()[0]
        assert n == c["kept"], rel


def test_source_files_store_jsonl_sha256(imported):
    conn = connect(imported["db"])
    for r in conn.execute("select * from source_files"):
        p = Path(r["jsonl_path"])
        if not p.is_absolute():
            p = imported["jdir"] / p
        assert hashlib.sha256(p.read_bytes()).hexdigest() == r["jsonl_sha256"]


def test_scenario_trial_columns(imported):
    conn = connect(imported["db"])
    assert {tuple(r) for r in conn.execute("select distinct scenario_id, trial_id from events")} == {("s02", "t00")}


def test_hosts_from_folder_and_export_host(imported):
    conn = connect(imported["db"])
    assert {r[0] for r in conn.execute("select distinct host from events")} == {"dc01", "ep-01"}
    r = row_where(conn, "select host, export_host from events where event_id=1102")
    assert r["host"] == "dc01" and r["export_host"].lower().startswith("dc-01")


def test_log_state_events_kept(imported):
    conn = connect(imported["db"])
    assert conn.execute("select count(*) from events where event_id=1102 and channel='Security'").fetchone()[0] == 1
    assert conn.execute("select count(*) from events where event_id=6005").fetchone()[0] == 1


def test_logoff_and_4688_kept(imported):
    conn = connect(imported["db"])
    r = row_where(conn, "select session_id from events where event_id=4647")
    assert r["session_id"] == 0x62f43
    assert conn.execute("select count(*) from events where event_id=4688").fetchone()[0] == 1


def test_irrelevant_and_bad_ids_not_in_events(imported):
    conn = connect(imported["db"])
    assert conn.execute("select count(*) from events where event_id=4663").fetchone()[0] == 0
    assert conn.execute("select count(*) from events where record_id in ('7002','7003') or record_id in (7002,7003)").fetchone()[0] == 0


def test_raw_event_null_everywhere(imported):
    conn = connect(imported["db"])
    assert conn.execute("select count(*) from events where raw_event is not null").fetchone()[0] == 0
    assert conn.execute("select count(*) from events where raw_event_sha256 is null").fetchone()[0] == 0
    assert conn.execute("select count(*) from events where source_line is null").fetchone()[0] == 0


def test_raw_event_sha256_is_canonical_json_of_line(imported):
    conn = connect(imported["db"])
    r = row_where(conn, "select raw_event_sha256 from events where event_id=1102")
    ev = json.loads(real_line("s01_t00/per_file/dc01/security.jsonl", 1))
    canon = json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    candidates = {hashlib.sha256(json.dumps(ev, sort_keys=True, separators=(",", ":"), ensure_ascii=a).encode()).hexdigest()
                  for a in (True, False)}
    assert r["raw_event_sha256"] in candidates, canon[:80]


def test_source_line_round_trip_u2028(imported):
    """NF-16/NF-20: source_line is the physical line split on \\n only."""
    conn = connect(imported["db"])
    src = {r["relative_path"]: r["jsonl_path"] for r in conn.execute("select relative_path, jsonl_path from source_files")}
    cache: dict[str, list[bytes]] = {}
    checked = 0
    for r in conn.execute("select source_relative_path, source_line, record_id, event_id from events"):
        rel = r["source_relative_path"]
        path = Path(src[rel]) if rel in src else imported["jdir"] / rel
        if not path.is_absolute():
            path = imported["jdir"] / path
        lines = cache.setdefault(str(path), path.read_bytes().split(b"\n"))
        ev = json.loads(lines[r["source_line"] - 1].decode("utf-8"))
        assert str(ev["system"]["event_record_id"]) == str(r["record_id"])
        assert int(ev["system"]["event_id"]) == r["event_id"]
        checked += 1
    assert checked > 0
    # the U+2028 line is line 2, the 4688 after it is line 3 (physical), not shifted
    r = row_where(conn, "select source_line from events where event_id=4688")
    assert r["source_line"] == 3
    assert row_where(conn, "select source_line from events where record_id in ('7001', 7001)")["source_line"] == 2


def test_no_zero_logon_ids(imported):
    conn = connect(imported["db"])
    for c in LOGON_ID_COLUMNS:
        assert conn.execute(f"select count(*) from events where {c} = 0").fetchone()[0] == 0, c


def test_indexes_exist(imported):
    conn = connect(imported["db"])
    cols = set()
    for (name,) in conn.execute("select name from sqlite_master where type='index' and tbl_name='events'").fetchall():
        cols |= {r[2] for r in conn.execute(f"pragma index_info('{name}')")}
    assert {"session_id", "process_guid", "timestamp_utc", "source_port"} <= cols


def test_import_report_per_file_accounting(imported):
    reports = list(imported["rep"].rglob("*.json"))
    assert reports, "no import report JSON in the report dir"
    rep = json.loads(reports[0].read_text(encoding="utf-8"))
    per_file = rep["per_file"]
    assert {p["relative_path"] for p in per_file} == set(base_files())
    for p in per_file:
        for k in ("lines_read", "kept", "excluded_not_relevant", "excluded_bad_event_id", "blank_lines"):
            assert k in p
    assert sum(p["kept"] for p in per_file) == connect(imported["db"]).execute("select count(*) from events").fetchone()[0]


def test_no_tmp_left_after_success(imported):
    assert sorted(p.name for p in imported["db"].parent.iterdir()) == [imported["db"].name]


# ---------------------------------------------------------------- display view
def test_events_display_hex_and_null(imported):
    conn = connect(imported["db"])
    r = row_where(conn, "select session_id, session_id_hex from events_display where event_id=4688")
    assert r["session_id"] == 390131 and r["session_id_hex"] == "0x5f3f3"
    r = row_where(conn, "select * from events_display where record_id in ('7001', 7001)")
    assert r["subject_logon_id"] is None and r["subject_logon_id_hex"] is None
    for c in ("session_id_hex", "subject_logon_id_hex", "target_logon_id_hex"):
        assert conn.execute(f"select count(*) from events_display where {c}='0x0'").fetchone()[0] == 0


# ---------------------------------------------------------------- dedup (NF-08, NF-19)
def dup_files(copy_first: bool = True):
    sec = "dc01/security.evtx"
    exact = dump(logon4624(sec, 9001))
    near_a = dump(logon4624(sec, 9002))
    near_b = dump(logon4624(sec, 9002, user="someoneelse"))
    # a duplicate export file is a different EVTX: different source path and sha256, same content
    other = json.loads(exact)
    other["source"]["relative_path"] = "dc01/security_copy.evtx"
    other["source"]["sha256"] = "cd" * 32
    return {
        "dc01/security.evtx": [("kept", exact), ("kept", near_a), ("kept", near_b), ("kept", exact)],
        "dc01/security_copy.evtx": [("kept", dump(other))],
    }


def test_dedup_survivor_lowest_path_line_and_ledger(tmp_path):
    jdir = build_trial(tmp_path, dup_files())
    db, _, _ = do_import(tmp_path, jdir)
    conn = connect(db)
    assert conn.execute("select count(*) from events_dedup").fetchone()[0] <= conn.execute("select count(*) from events").fetchone()[0]
    rows = conn.execute("select event_uid, source_relative_path, source_line from events where record_id in ('9001', 9001)").fetchall()
    assert len(rows) == 3
    expected = min(rows, key=lambda r: (r["source_relative_path"], r["source_line"]))
    surv = conn.execute("select event_uid, source_relative_path, source_line from events_dedup where record_id in ('9001', 9001)").fetchall()
    assert len(surv) == 1
    assert (surv[0]["source_relative_path"], surv[0]["source_line"]) == (expected["source_relative_path"], expected["source_line"])
    # ledger: the two non-survivors recorded as exact duplicates of the survivor
    ledger = conn.execute("select * from duplicate_events").fetchall()
    exact_rows = [r for r in ledger if "exact" in r["duplicate_kind"]]
    hidden = {r["event_uid"] for r in rows} - {expected["event_uid"]}
    assert {r["event_uid"] for r in exact_rows if r["event_uid"] in hidden} == hidden
    assert all(r["duplicate_of_event_uid"] == expected["event_uid"] for r in exact_rows if r["event_uid"] in hidden)


def test_near_duplicates_listed_but_kept(tmp_path):
    jdir = build_trial(tmp_path, dup_files())
    db, _, _ = do_import(tmp_path, jdir)
    conn = connect(db)
    uids = {r[0] for r in conn.execute("select event_uid from events where record_id in ('9002', 9002)")}
    assert len(uids) == 2
    assert {r[0] for r in conn.execute("select event_uid from events_dedup where record_id in ('9002', 9002)")} == uids
    near = [r for r in conn.execute("select * from duplicate_events") if "near" in r["duplicate_kind"]]
    assert near and all(r["event_uid"] in uids or r["duplicate_of_event_uid"] in uids for r in near)
    assert any(r["event_uid"] in uids for r in near)


def test_dedup_survivor_deterministic_across_manifest_order(tmp_path):
    out = []
    for i, rev in enumerate((False, True)):
        root = tmp_path / f"r{i}"
        root.mkdir()
        jdir = build_trial(root, dup_files(), reverse_manifest=rev)
        db, _, _ = do_import(root, jdir)
        conn = connect(db)
        out.append(sorted((r["source_relative_path"], r["source_line"]) for r in conn.execute("select * from events_dedup")))
    assert out[0] == out[1]


@pytest.mark.parametrize("same_computer", [
    pytest.param(True, marks=pytest.mark.xfail(strict=True, reason="FINDING: duplicate_content_sha256 ignores the host folder; "
                                               "identical payload incl. Computer on two hosts collapses (spec silent, NF-08/NF-19)")),
    False])
def test_dedup_keeps_same_payload_on_different_hosts(tmp_path, same_computer):
    a = dump(logon4624("dc01/security.evtx", 9100, computer="HOST-A.lab.local"))
    b = dump(logon4624("ep-01/security.evtx", 9100, computer="HOST-A.lab.local" if same_computer else "HOST-B.lab.local"))
    jdir = build_trial(tmp_path, {"dc01/security.evtx": [("kept", a)], "ep-01/security.evtx": [("kept", b)]})
    db, _, _ = do_import(tmp_path, jdir)
    conn = connect(db)
    assert conn.execute("select count(*) from events_dedup").fetchone()[0] == 2
    assert {r[0] for r in conn.execute("select host from events_dedup")} == {"dc01", "ep-01"}


# ---------------------------------------------------------------- aborts (NF-02, NF-15, NF-17)
def fail_case(tmp_path, jdir, scenario="s02", trial="t00"):
    db = tmp_path / "out" / f"{scenario}_{trial}.sqlite3"
    rep = tmp_path / "reports"
    with pytest.raises(Exception):
        run_trial_import(jdir, scenario, trial, db, rep)
    assert_nothing_left(tmp_path, rep)


def test_abort_counter_mismatch(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path, emitted_delta=1))


def test_abort_counter_mismatch_negative(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path, emitted_delta=-1))


def test_abort_non_empty_parse_errors(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path, parse_errors='{"error":"x"}\n'))


def test_abort_input_status_not_ok(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path, status="failed"))


def test_abort_cli_scenario_disagrees_with_folder(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path), scenario="s03")


def test_abort_cli_trial_disagrees_with_folder(tmp_path):
    fail_case(tmp_path, build_trial(tmp_path), trial="t05")


def test_abort_manifest_input_root_disagrees(tmp_path):
    jdir = build_trial(tmp_path, scenario="s03", trial="t00", input_root="D:\\raw\\s02\\t00")
    fail_case(tmp_path, jdir, scenario="s03", trial="t00")


def test_abort_host_not_in_hosts(tmp_path):
    f = {"ep-09/security.evtx": [("kept", dump(logon4624("ep-09/security.evtx", 5)))]}
    fail_case(tmp_path, build_trial(tmp_path, f))


def test_abort_null_timestamp(tmp_path):
    f = {"dc01/security.evtx": [("kept", dump(logon4624("dc01/security.evtx", 5, ts=None)))]}
    fail_case(tmp_path, build_trial(tmp_path, f))


def test_abort_invalid_json_line(tmp_path):
    f = {"dc01/security.evtx": [("kept", dump(logon4624("dc01/security.evtx", 5))), ("kept", "{not json")]}
    fail_case(tmp_path, build_trial(tmp_path, f))


def test_refuses_to_overwrite_existing_db(tmp_path):
    jdir = build_trial(tmp_path)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    db.parent.mkdir()
    db.write_bytes(b"precious bytes")
    with pytest.raises(Exception):
        run_trial_import(jdir, "s02", "t00", db, tmp_path / "reports")
    assert db.read_bytes() == b"precious bytes"
    assert sorted(p.name for p in db.parent.iterdir()) == [db.name]


# ---------------------------------------------------------------- CLI
def cli(tmp_path, jdir, scenario, trial, db, *extra):
    env = {**os.environ, "PYTHONPATH": str(SRC)}
    return subprocess.run(
        [sys.executable, "-m", "evtx_pipeline.cli", "import-trial", "--jsonl", str(jdir), "--scenario", scenario,
         "--trial", trial, "--database", str(db), "--report-dir", str(tmp_path / "reports"), *extra],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=300)


def test_cli_success(tmp_path):
    jdir = build_trial(tmp_path)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    p = cli(tmp_path, jdir, "s02", "t00", db)
    assert p.returncode == 0, p.stdout + p.stderr
    assert db.exists()
    assert list((tmp_path / "reports").rglob("*.json"))


def test_cli_mismatch_exit_nonzero_no_db(tmp_path):
    jdir = build_trial(tmp_path, emitted_delta=1)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    p = cli(tmp_path, jdir, "s02", "t00", db)
    assert p.returncode != 0
    assert_nothing_left(tmp_path, tmp_path / "reports")


def test_cli_wrong_scenario_exit_nonzero(tmp_path):
    jdir = build_trial(tmp_path)
    db = tmp_path / "out" / "s03_t00.sqlite3"
    assert cli(tmp_path, jdir, "s03", "t00", db).returncode != 0
    assert_nothing_left(tmp_path)


def test_cli_existing_db_not_overwritten(tmp_path):
    jdir = build_trial(tmp_path)
    db = tmp_path / "out" / "s02_t00.sqlite3"
    db.parent.mkdir()
    db.write_bytes(b"keep me")
    assert cli(tmp_path, jdir, "s02", "t00", db).returncode != 0
    assert db.read_bytes() == b"keep me"


# ---------------------------------------------------------------- real acceptance (section 7)
@pytest.mark.parametrize("n", ["s01", "s02", "s03", "s04", "s05", "s06", "s07"])
def test_real_t00_accounting_matches_manifest(n):
    db = PROCESSED / f"{n}_t00.sqlite3"
    manifest_path = JSONL / f"{n}_t00" / "manifest.json"
    if not db.exists() or not manifest_path.exists():
        pytest.skip(f"missing {db} or {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    conn = sqlite3.connect(f"{db.as_uri()}?mode=ro", uri=True)
    cols = [r[1] for r in conn.execute("pragma table_info(source_files)")]
    if "kept" not in cols:
        pytest.skip(f"{db.name} is not a trial-import database")
    rows = {r[0]: r for r in conn.execute(
        "select relative_path, kept, excluded_not_relevant, excluded_bad_event_id, blank_lines, lines_read from source_files")}
    items = manifest["selected_inputs"]
    assert len(rows) == len(items)
    for item in items:
        r = rows[item["relative_path"]]
        assert r[1] + r[2] + r[3] == item["emitted_event_count"], item["relative_path"]
        assert r[5] == r[1] + r[2] + r[3] + r[4]
    assert conn.execute("select count(*) from events").fetchone()[0] == sum(r[1] for r in rows.values())
    assert conn.execute("select count(*) from events where raw_event is not null").fetchone()[0] == 0
    assert conn.execute("select count(*) from events_dedup").fetchone()[0] <= \
        conn.execute("select count(*) from events").fetchone()[0]
    conn.close()


# ---------------------------------------------------------------- CO-18: clock-change events (NF-09 amended, decision 043)
KG = "Microsoft-Windows-Kernel-General"


def clock_event(channel: str, event_id: int, provider, *, rel: str, record_id: int, data: dict) -> dict:
    ev = make_event(channel, event_id, data, rel=rel, record_id=record_id,
                    ts=f"2026-09-24T05:00:{record_id % 60:02d}.5000000Z")
    if provider is None:
        ev["system"].pop("provider", None)
    else:
        ev["system"]["provider"] = provider
    return ev


def clock_files() -> dict[str, list[tuple[str, str]]]:
    sec, sysc = "ep-02/security.evtx", "ep-02/system.evtx"
    t4616 = {"SubjectUserSid": "S-1-5-18", "SubjectUserName": "ENDPOINT-02$", "SubjectDomainName": "LAB",
             "SubjectLogonId": "0x3e7", "PreviousTime": "2026-09-24T05:00:01.0000000Z",
             "NewTime": "2026-09-24T05:00:09.4800000Z", "ProcessId": "0x4",
             "ProcessName": "C:\\Windows\\System32\\svchost.exe"}
    time_change = {"NewTime": "2026-09-24T05:00:09.4800000Z", "OldTime": "2026-09-24T05:00:01.0000000Z"}
    return {
        sec: [("kept", dump(logon4624(sec, 8001))),
              ("kept", dump(clock_event("Security", 4616, "Microsoft-Windows-Security-Auditing", rel=sec,
                                        record_id=8002, data=t4616)))],
        sysc: [("kept", dump(clock_event("System", 1, KG, rel=sysc, record_id=8101, data=time_change))),
               ("kept", dump(clock_event("System", 1, KG.lower() + " ", rel=sysc, record_id=8102, data=time_change))),
               ("nr", dump(clock_event("System", 1, "Microsoft-Windows-Power-Troubleshooter", rel=sysc,
                                       record_id=8103, data={"TargetState": "4"}))),
               ("nr", dump(clock_event("System", 1, "Microsoft-Windows-FilterManager", rel=sysc, record_id=8104,
                                       data={"Reason": "x"}))),
               ("nr", dump(clock_event("System", 1, None, rel=sysc, record_id=8105, data=time_change))),
               ("kept", dump(clock_event("System", 6005, "EventLog", rel=sysc, record_id=8106,
                                         data={"param1": "x"})))],
    }


@pytest.fixture()
def clock_imported(tmp_path):
    jdir = build_trial(tmp_path, clock_files())
    db, rep, result = do_import(tmp_path, jdir)
    return {"jdir": jdir, "db": db, "rep": rep, "tmp": tmp_path}


def test_co18_kernel_general_system1_and_4616_are_in_events(clock_imported):
    """CO-18 / NF-09: a Kernel-General System 1 (also lower case with padding) and a Security 4616 end up in `events`,
    each with a valid event_utc, its source_relative_path and its physical source_line."""
    conn = connect(clock_imported["db"])
    sys1 = conn.execute("select * from events where channel='System' and event_id=1 order by source_line").fetchall()
    sec = conn.execute("select * from events where channel='Security' and event_id=4616").fetchall()
    assert [r["source_line"] for r in sys1] == [1, 2]                    # physical lines of the two Kernel-General rows
    assert [r["source_line"] for r in sec] == [2]
    for r in sys1 + sec:
        assert r["event_utc"] and r["event_utc"].endswith("Z")
        assert r["event_utc"].startswith("2026-09-24T05:00:")
        assert r["source_relative_path"] and r["source_relative_path"].endswith(".evtx")
        assert r["host"] == "ep-02"
    assert {r["source_relative_path"] for r in sys1} == {"ep-02/system.evtx"}
    assert {r["source_relative_path"] for r in sec} == {"ep-02/security.evtx"}
    assert {str(r["record_id"]) for r in sys1} == {"8101", "8102"}
    for r in sys1 + sec:                          # the pointer round-trips: that line of that file is this record
        path = clock_imported["jdir"] / "per_file" / Path(r["source_relative_path"]).with_suffix(".jsonl")
        line = json.loads(path.read_bytes().split(b"\n")[r["source_line"] - 1].decode("utf-8"))
        assert line["system"]["event_id"] == str(r["event_id"])


def test_co18_other_provider_and_no_provider_system1_not_in_events_and_counted(clock_imported):
    """CO-18: System 1 from Power-Troubleshooter, FilterManager and with no provider are not in `events`; each is
    counted in excluded_not_relevant (3 of them) and the accounting still adds up."""
    conn = connect(clock_imported["db"])
    ids = {str(r[0]) for r in conn.execute("select record_id from events")}
    assert not ids & {"8103", "8104", "8105"}
    assert conn.execute("select count(*) from events where channel='System' and event_id=1").fetchone()[0] == 2
    row = conn.execute("select * from source_files where relative_path='ep-02/system.evtx'").fetchone()
    assert (row["kept"], row["excluded_not_relevant"], row["excluded_bad_event_id"], row["blank_lines"]) == (3, 3, 0, 0)
    assert row["lines_read"] == 6 and row["emitted_event_count"] == 6
    sec = conn.execute("select * from source_files where relative_path='ep-02/security.evtx'").fetchone()
    assert (sec["kept"], sec["excluded_not_relevant"]) == (2, 0)
    rep = json.loads(next(clock_imported["rep"].rglob("*.json")).read_text(encoding="utf-8"))
    pf = {p["relative_path"]: p for p in rep["per_file"]}
    assert pf["ep-02/system.evtx"]["excluded_not_relevant"] == 3 and pf["ep-02/system.evtx"]["kept"] == 3


def test_co18_system1_with_non_string_provider_is_not_kept(tmp_path):
    """CO-18: a System 1 whose `system.provider` is not a string (null, number, list) is not kept."""
    sysc = "ep-02/system.evtx"
    odd = []
    for i, prov in enumerate([None, 5, ["Microsoft-Windows-Kernel-General"]]):
        ev = clock_event("System", 1, "x", rel=sysc, record_id=8200 + i,
                         data={"NewTime": "2026-09-24T05:00:09.0000000Z"})
        ev["system"]["provider"] = prov
        odd.append(("nr", dump(ev)))
    jdir = build_trial(tmp_path, {sysc: odd})
    db, _, _ = do_import(tmp_path, jdir)
    conn = connect(db)
    assert conn.execute("select count(*) from events").fetchone()[0] == 0
    assert conn.execute("select excluded_not_relevant from source_files").fetchone()[0] == 3


def test_co18_sysmon_1_is_not_system_1(tmp_path):
    """CO-18: a Sysmon event id 1 is kept as before whatever its provider; the provider filter is for System 1 only."""
    sysm = "ep-02/sysmon.evtx"
    ev = make_event("Sysmon", 1, {"ProcessGuid": "{aaaa}", "Image": "C:\\x.exe", "UtcTime": "2026-09-24 05:00:00.123"},
                    rel=sysm, record_id=8300)
    ev["system"]["provider"] = "Microsoft-Windows-Sysmon"
    jdir = build_trial(tmp_path, {sysm: [("kept", dump(ev))]})
    db, _, _ = do_import(tmp_path, jdir)
    assert connect(db).execute("select count(*) from events where channel='Sysmon' and event_id=1").fetchone()[0] == 1


def test_co18_existing_trial_dbs_untouched_and_have_no_new_events(tmp_path):
    """CO-18 / spec 08: existing DBs are not re-ingested. A synthetic import in tmp_path leaves the real s02_t00 DB's
    hash unchanged (compared read-only), and that DB holds no 4616 and no System 1 (ingested before CO-18)."""
    real_db = PROCESSED / "s02_t00.sqlite3"
    if not real_db.exists():
        pytest.skip(f"missing {real_db}")
    before = hashlib.sha256(real_db.read_bytes()).hexdigest()
    jdir = build_trial(tmp_path, clock_files())
    do_import(tmp_path, jdir)
    assert hashlib.sha256(real_db.read_bytes()).hexdigest() == before
    con = sqlite3.connect(f"{real_db.resolve().as_uri()}?mode=ro", uri=True)
    try:
        n = con.execute("select count(*) from events where (channel='Security' and event_id=4616) "
                        "or (channel='System' and event_id=1)").fetchone()[0]
    finally:
        con.close()
    assert n == 0
