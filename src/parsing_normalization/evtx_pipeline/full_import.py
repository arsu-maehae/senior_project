"""Safe bounded full import of immutable Phase 1 JSONL into SQLite."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import insert_parse_error, insert_scenario_run, insert_source_file, record_normalization_error, transaction
from .normalize import (RELEVANT_EVENT_IDS, canonical_channel, canonical_host, exact_duplicate_digest_from_event,
                        normalize_event, normalization_issues, scenario_from_path)
from .schema import EVENT_COLUMNS, INDEX_DDL, SCHEMA_VERSION, create_schema
from .validation import REQUIRED_INDEXES, REQUIRED_TABLES, schema_check

EXPECTED_SCENARIOS = {f"s{i:02d}" for i in range(1, 8)}
EXPECTED_HOSTS = {"ep-01", "ep-02", "ep-03", "DC01"}
EXPECTED_CHANNELS = {"Security", "Sysmon", "System", "PowerShell", "WinRM"}
FULL_INPUT_EVENT_COUNT = 2_981_147
FULL_INPUT_FILE_COUNT = 85
INSERT_BATCH_SIZE = 1000


class FullImportFailure(RuntimeError):
    def __init__(self, message: str, *, source_file: str | None = None, record_number: int | None = None,
                 temp_database: str | None = None):
        super().__init__(message)
        self.source_file = source_file
        self.record_number = record_number
        self.temp_database = temp_database


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_id(relative_path: str, sha256: str) -> str:
    return hashlib.sha256((relative_path + "\0" + sha256).encode("utf-8")).hexdigest()


def validate_publication_paths(input_root: Path, final_database: Path, workspace: Path) -> tuple[Path, Path, Path]:
    workspace = workspace.resolve(strict=True)
    input_root = input_root.resolve(strict=True)
    final_database = final_database.resolve()
    temp_database = final_database.with_name(final_database.name + ".tmp")
    expected_input = (workspace / "data" / "staging" / "evtx_jsonl_full").resolve(strict=True)
    expected_final = workspace / "data" / "processed" / "attack_path.sqlite3"
    if input_root != expected_input or final_database != expected_final.resolve():
        raise ValueError("Full import paths must use the immutable Phase 1 input and approved workspace database paths.")
    if final_database.exists():
        raise FileExistsError(f"Final database already exists; refusing overwrite: {final_database}")
    if temp_database.exists():
        raise FileExistsError(f"Temporary publication database already exists; refusing overwrite: {temp_database}")
    if final_database.is_relative_to(input_root) or input_root.is_relative_to(final_database.parent):
        raise ValueError("Input and database paths overlap.")
    return input_root, final_database, temp_database


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tree_hashes(root: Path) -> dict[str, str]:
    resolved_root = root.resolve(strict=True)
    hashes = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(resolved_root):
            raise ValueError(f"Phase 1 tree contains a file path escaping its root: {path}")
        hashes[path.relative_to(root).as_posix()] = _hash_file(resolved)
    return hashes


def preflight(input_root: Path, final_database: Path, workspace: Path) -> dict[str, Any]:
    input_root, final_database, temp_database = validate_publication_paths(input_root, final_database, workspace)
    manifest_path = input_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = manifest.get("selected_inputs", [])
    totals = manifest.get("totals", {})
    if manifest.get("run_mode") != "full" or len(rows) != FULL_INPUT_FILE_COUNT:
        raise ValueError(f"Expected a full 85-file Phase 1 manifest; found {len(rows)} entries.")
    if int(totals.get("emitted_events", -1)) != FULL_INPUT_EVENT_COUNT or int(totals.get("parse_errors", -1)) != 0:
        raise ValueError(f"Manifest totals do not match expected preflight: {totals!r}")
    if int(totals.get("files", -1)) != FULL_INPUT_FILE_COUNT or int(totals.get("attempted_records", -1)) != FULL_INPUT_EVENT_COUNT:
        raise ValueError(f"Manifest file/attempted row counts do not match expected preflight: {totals!r}")
    profile_path = workspace / "data" / "profiles" / "full_normalization_profile.json"
    if not profile_path.is_file():
        raise ValueError("A current Phase 2B full normalization profile is required before full import.")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    audit = profile.get("security_4624_guid_field_audit", {})
    security_4624_count = int(profile.get("groups", {}).get("channel_event_id", {}).get("Security:4624", -1))
    target_coverage = profile.get("applicable_field_coverage", {}).get("target_logon_guid", {})
    if (int(profile.get("counts", {}).get("events", -1)) != int(totals["emitted_events"])
            or int(audit.get("event_count", -1)) != security_4624_count
            or int(target_coverage.get("applicable_event_count", -1)) != security_4624_count
            or int(audit.get("events_with_parseable_nonzero_guid", 0)) <= 0):
        raise ValueError("Phase 2B profile is stale or lacks the completed 4624 GUID alias audit; rerun profile-normalization.")
    if any(row.get("status") != "ok" or int(row.get("parse_error_count", -1)) != 0 for row in rows):
        raise ValueError("Manifest contains a non-ok source file or parse error.")
    for row in rows:
        output_path = (input_root / row["output_relative_path"]).resolve(strict=True)
        if not output_path.is_relative_to(input_root) or not output_path.is_file():
            raise ValueError(f"Manifest output path is missing or escapes input root: {row.get('output_relative_path')}")
    parse_path = input_root / "parse_errors.jsonl"
    if not parse_path.is_file() or parse_path.stat().st_size:
        raise ValueError("Expected empty Phase 1 parse_errors.jsonl for zero-parse-error full import.")
    source_bytes = sum(int(row["size_bytes"]) for row in rows)
    jsonl_bytes = sum((input_root / row["output_relative_path"]).stat().st_size for row in rows)
    disk_path = final_database.parent
    while not disk_path.exists() and disk_path.parent != disk_path:
        disk_path = disk_path.parent
    free_bytes = shutil.disk_usage(disk_path).free
    estimated_db_bytes = int(jsonl_bytes * 2.0 + 1_073_741_824)
    if free_bytes < estimated_db_bytes:
        raise OSError(f"Insufficient free disk space: {free_bytes} available, estimated {estimated_db_bytes} required.")
    source_hashes = _tree_hashes(input_root)
    return {"input_root":input_root,"manifest": manifest, "manifest_path": manifest_path,
            "profile_path":profile_path,"profile":profile,"files": rows,
            "input_rows": FULL_INPUT_EVENT_COUNT, "source_evtx_bytes": source_bytes,
            "phase1_jsonl_bytes": jsonl_bytes, "estimated_database_bytes": estimated_db_bytes,
            "free_bytes_before": free_bytes, "phase1_tree_hashes_before": source_hashes,
            "temp_database": temp_database, "final_database": final_database}


def _row_values(event: dict[str, Any], digest: str) -> tuple[Any, ...]:
    row = dict(event)
    row["duplicate_content_sha256"] = digest
    return tuple(row.get(column) for column in EVENT_COLUMNS)


def _insert_batch(connection: sqlite3.Connection, batch: list[tuple[Any, ...]]) -> int:
    if not batch:
        return 0
    columns = list(EVENT_COLUMNS)
    sql = f"INSERT INTO events({','.join(columns)}) VALUES({','.join('?' for _ in columns)})"
    with transaction(connection):
        connection.executemany(sql, batch)
    return len(batch)


def row_accounting(input_rows: int, event_rows: int, excluded_rows: int) -> dict[str, Any]:
    return {"input_rows":input_rows,"events_table_rows":event_rows,"excluded_rows":excluded_rows,
            "accounting_balanced":input_rows == event_rows + excluded_rows}


def publish_database(temp_database: Path, final_database: Path) -> None:
    if final_database.exists():
        raise FileExistsError(f"Final database already exists; refusing overwrite: {final_database}")
    os.rename(temp_database, final_database)


def _build_duplicate_ledger(connection: sqlite3.Connection, run_id: str) -> tuple[int, int]:
    # Helper indexes make ledger construction bounded and fast; final required indexes follow afterward.
    connection.execute("CREATE INDEX idx_tmp_full_digest ON events(duplicate_content_sha256,event_uid)")
    connection.execute("""INSERT INTO duplicate_events(scenario_run_id,event_uid,duplicate_of_event_uid,duplicate_kind,duplicate_digest,decision)
      SELECT ?,e.event_uid,first.event_uid,'exact_content_candidate',e.duplicate_content_sha256,
             'retain_both_pending_final_cross_export_review'
      FROM events e JOIN (SELECT duplicate_content_sha256,MIN(event_uid) AS event_uid FROM events
                          GROUP BY duplicate_content_sha256 HAVING COUNT(*)>1) first
        ON first.duplicate_content_sha256=e.duplicate_content_sha256
      WHERE e.event_uid<>first.event_uid""", (run_id,))
    exact_count = int(connection.execute("SELECT COUNT(*) FROM duplicate_events WHERE scenario_run_id=? AND duplicate_kind='exact_content_candidate'", (run_id,)).fetchone()[0])
    connection.execute("CREATE INDEX idx_tmp_full_identity ON events(scenario_id,host,channel,event_id,record_id,duplicate_content_sha256,event_uid)")
    connection.execute("""INSERT OR IGNORE INTO duplicate_events(scenario_run_id,event_uid,duplicate_of_event_uid,duplicate_kind,duplicate_digest,decision)
      SELECT ?,e.event_uid,other.event_uid,'near_duplicate_conflict',e.duplicate_content_sha256,
             'retain_both_identity_conflict_review'
      FROM events e JOIN events other ON other.scenario_id=e.scenario_id AND other.host=e.host
        AND other.channel=e.channel AND other.event_id=e.event_id AND other.record_id=e.record_id
        AND other.duplicate_content_sha256<>e.duplicate_content_sha256 AND other.event_uid<e.event_uid
      WHERE e.scenario_id IS NOT NULL AND e.host IS NOT NULL AND e.channel IS NOT NULL AND e.event_id IS NOT NULL AND e.record_id IS NOT NULL""", (run_id,))
    near_count = int(connection.execute("SELECT COUNT(*) FROM duplicate_events WHERE scenario_run_id=? AND duplicate_kind='near_duplicate_conflict'", (run_id,)).fetchone()[0])
    connection.execute("DROP INDEX idx_tmp_full_identity")
    connection.execute("DROP INDEX idx_tmp_full_digest")
    return exact_count, near_count


def validate_full_database(connection: sqlite3.Connection, *, manifest: dict[str, Any], run_id: str) -> dict[str, Any]:
    schema = schema_check(connection)
    integrity = [row[0] for row in connection.execute("PRAGMA integrity_check")]
    fk_issues = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
    q = lambda sql, args=(): int(connection.execute(sql, args).fetchone()[0] or 0)
    events = q("SELECT COUNT(*) FROM events")
    source_count = q("SELECT COUNT(*) FROM source_files WHERE scenario_run_id=?", (run_id,))
    input_rows = int(manifest["totals"]["emitted_events"])
    invalid_raw = q("SELECT COUNT(*) FROM events WHERE json_valid(raw_event)=0")
    uid_mismatch = q("SELECT COUNT(*)-COUNT(DISTINCT event_uid) FROM events")
    parse_errors = q("SELECT COUNT(*) FROM parse_errors WHERE scenario_run_id=?", (run_id,))
    normalization_error_rows = q("SELECT COUNT(*) FROM normalization_errors WHERE scenario_run_id=?", (run_id,))
    events_with_norm_errors = q("SELECT COUNT(DISTINCT event_uid) FROM normalization_errors WHERE scenario_run_id=? AND event_uid IS NOT NULL", (run_id,))
    duplicate_exact = q("SELECT COUNT(*) FROM duplicate_events WHERE scenario_run_id=? AND duplicate_kind='exact_content_candidate'", (run_id,))
    duplicate_near = q("SELECT COUNT(*) FROM duplicate_events WHERE scenario_run_id=? AND duplicate_kind='near_duplicate_conflict'", (run_id,))
    host_counts = {r[0]: r[1] for r in connection.execute("SELECT host,COUNT(*) FROM events GROUP BY host ORDER BY host")}
    scenario_counts = {r[0]: r[1] for r in connection.execute("SELECT scenario_id,COUNT(*) FROM events GROUP BY scenario_id ORDER BY scenario_id")}
    channel_counts = {r[0]: r[1] for r in connection.execute("SELECT channel,COUNT(*) FROM events GROUP BY channel ORDER BY channel")}
    event_counts: dict[str, int] = {}
    for channel, event_ids in RELEVANT_EVENT_IDS.items():
        ids = sorted(event_ids)
        placeholders = ",".join("?" for _ in ids)
        event_counts.update({f"{channel}:{r[0]}":r[1] for r in connection.execute(
            f"SELECT event_id,COUNT(*) FROM events WHERE channel=? AND event_id IN ({placeholders}) GROUP BY event_id ORDER BY event_id",
            (channel,*ids))})
    per_file_mismatches = [tuple(r) for r in connection.execute("""SELECT f.relative_path,f.phase1_event_count,f.imported_event_count,
      COUNT(e.event_uid) AS actual FROM source_files f LEFT JOIN events e USING(source_file_id)
      WHERE f.scenario_run_id=? GROUP BY f.source_file_id
      HAVING f.phase1_event_count<>f.imported_event_count OR f.imported_event_count<>actual""", (run_id,))]
    missing_required = sorted({"schema_version", "scenario_runs", "source_files", "events", "parse_errors", "normalization_errors", "duplicate_events", "validation_results"} - set(schema["tables"]))
    index_names = {r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    missing_indexes = sorted(REQUIRED_INDEXES - index_names)
    expected_presence = {"scenarios": set(scenario_counts) == EXPECTED_SCENARIOS,
                         "hosts": set(host_counts) == EXPECTED_HOSTS,
                         "channels": set(channel_counts) == EXPECTED_CHANNELS}
    accounting = row_accounting(input_rows, events, max(input_rows - events, 0))
    accounting.update({
                  "normalization_error_rows": normalization_error_rows, "events_with_normalization_errors": events_with_norm_errors,
                  "parse_error_rows": parse_errors})
    checks = {
        "integrity_check": integrity == ["ok"], "foreign_key_check": not fk_issues,
        "schema": schema["passed"] and not missing_required and not missing_indexes,
        "source_file_count": source_count == FULL_INPUT_FILE_COUNT,
        "event_row_count": events == input_rows, "raw_event_json": invalid_raw == 0,
        "event_uid_uniqueness": uid_mismatch == 0, "per_source_file_reconciliation": not per_file_mismatches,
        "expected_scenarios_hosts_channels": all(expected_presence.values()), "row_accounting": accounting["accounting_balanced"],
    }
    return {"passed": all(checks.values()), "checks": checks, "integrity_check": integrity,
            "foreign_key_issues": fk_issues, "schema": schema, "missing_tables": missing_required,
            "missing_indexes": missing_indexes, "source_file_count": source_count,
            "event_rows": events, "input_rows": input_rows, "invalid_raw_event_json_count": invalid_raw,
            "event_uid_uniqueness_mismatch": uid_mismatch, "per_source_file_mismatches": per_file_mismatches,
            "expected_presence": expected_presence, "row_accounting": accounting,
            "duplicate_exact_candidates": duplicate_exact, "duplicate_near_conflicts": duplicate_near,
            "parse_error_rows": parse_errors, "normalization_error_rows": normalization_error_rows,
            "events_with_normalization_errors": events_with_norm_errors,
            "counts_by_host": host_counts, "counts_by_scenario": scenario_counts,
            "counts_by_channel": channel_counts, "counts_by_relevant_event_id": event_counts}


def _report(details: dict[str, Any], *, success: bool, error: str | None = None) -> str:
    p = details["preflight"]
    lines = ["# Phase 2C Full SQLite Import Report", "", "## Status", "",
             f"- Result: **{'PASS' if success else 'FAIL'}**.",
             f"- Tests: **{details.get('test_summary', 'Not recorded')}**.",
             f"- Schema: **{SCHEMA_VERSION}**.", "- Correlation, nodes/edges, attack labels, scoring, and diagrams: **not performed**.", ""]
    if error:
        lines += [f"- Failure: {error}", f"- Partial database retained for diagnosis: `{p['temp_database']}`", ""]
        if details.get("failed_source"):
            lines += [f"- Failed source file: `{details['failed_source']}`", f"- Failed source record/line: {details.get('failed_record')}", ""]
        return "\n".join(lines)
    v = details["validation"]
    lines += ["## Import totals", "",
              f"- Input events: {v['input_rows']:,}.", f"- Successfully normalized / inserted: {v['event_rows']:,}.",
              f"- Events-table rows: {v['event_rows']:,}.", f"- Normalization-error rows: {v['normalization_error_rows']:,} across {v['events_with_normalization_errors']:,} events.",
              f"- Duplicate ledger rows: {v['duplicate_exact_candidates'] + v['duplicate_near_conflicts']:,}.",
              f"- Exact duplicate candidates: {v['duplicate_exact_candidates']:,}; near-duplicate conflicts: {v['duplicate_near_conflicts']:,}.",
              f"- Source files registered: {v['source_file_count']}.", f"- Database size: {details['database_bytes']:,} bytes.",
              f"- Import duration: {details['duration_seconds']:.2f} seconds; throughput: {details['events_per_second']:.1f} events/second.",
              f"- Available disk space after import: {details['free_bytes_after']:,} bytes.", "",
              "## Row accounting", "",
              f"`{v['input_rows']:,} input = {v['event_rows']:,} events-table rows + {v['row_accounting']['excluded_rows']:,} excluded rows`.",
              f"Normalization errors are annotations on retained event rows ({v['normalization_error_rows']:,} error records across {v['events_with_normalization_errors']:,} events); duplicates remain in events and have ledger references.", "",
              "## Counts by scenario, host, and channel", "", "```json",
              json.dumps({"scenario":v["counts_by_scenario"],"host":v["counts_by_host"],"channel":v["counts_by_channel"]},indent=2), "```", "",
              "### Relevant event IDs", "", "```json", json.dumps(v["counts_by_relevant_event_id"],indent=2), "```", "",
              "## Validation", "", "| Check | Result |", "|---|---|"]
    for key, passed in v["checks"].items():
        lines.append(f"| {key} | {'PASS' if passed else 'FAIL'} |")
    lines += [f"| SQLite integrity_check | {', '.join(v['integrity_check'])} |",
              f"| Foreign key violations | {len(v['foreign_key_issues'])} |",
              f"| Phase 1 file hashes unchanged | {'PASS' if details['source_hashes_unchanged'] else 'FAIL'} |",
              f"| Required indexes | {len(REQUIRED_INDEXES)} present |", "",
              "## GUID audit and remaining correlation warnings", "",
              f"The Phase 2B raw-key audit counted {p['profile']['security_4624_guid_field_audit']['event_count']:,} Security 4624 records and found field occurrences `{json.dumps(p['profile']['security_4624_guid_field_audit']['guid_named_field_occurrences'],sort_keys=True)}`. Parseable nonzero GUIDs occurred in {p['profile']['security_4624_guid_field_audit']['events_with_parseable_nonzero_guid']:,} records. Normalization maps Security 4624 `LogonGuid` to `target_logon_guid`; zero GUIDs remain NULL with `zero` state. Rows without usable GUIDs must use the documented bounded fallback; this import did not run that join.",
              "Fallback design: same scenario; normalized account; normalized source IP; destination host inferred from the 4624 export host and the 4769 SPN; compatible logon type/protocol; bounded timestamp difference. Future correlation outputs must record `correlation_method`, `candidate_count`, `time_delta_ms`, confidence tier, and supporting event UIDs.", "",
              "## Paths", "", f"- Final database: `{details['final_database']}`.",
              f"- Phase 1 JSONL input: `{p['input_root']}`.", f"- Phase 1 manifest: `{p['manifest_path']}`.",
              f"- Phase 2B profile: `{p['profile_path']}`.",
              f"- Temporary publication path (removed after success): `{p['temp_database']}`.",
              f"- Report: `{details['report_path']}`.", "", "## Final result", "",
              "FULL_IMPORT_PASS_CORRELATION_REQUIRES_FALLBACK"]
    return "\n".join(lines) + "\n"


def run_full_import(input_root: Path, final_database: Path, report_path: Path, *, workspace: Path,
                    test_summary: str) -> dict[str, Any]:
    pre = preflight(input_root, final_database, workspace)
    if report_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing Phase 2C report: {report_path}")
    manifest, rows = pre["manifest"], pre["files"]
    temp_path: Path = pre["temp_database"]
    started = time.perf_counter()
    run_id = str(uuid.uuid4())
    current_source: str | None = None
    current_record: int | None = None
    maximum_batch_rows = 0
    connection: sqlite3.Connection | None = None
    details: dict[str, Any] = {"preflight": pre, "test_summary": test_summary,
                               "final_database": str(pre["final_database"]), "report_path": str(report_path)}
    try:
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(temp_path)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("PRAGMA cache_size=-65536")
        connection.execute("PRAGMA mmap_size=0")
        create_schema(connection, create_indexes=False)
        run_row = {"run_id":run_id,"schema_version":SCHEMA_VERSION,"started_utc":_utc_now(),"completed_utc":None,
                   "input_root":str(pre["input_root"]),"phase1_manifest_path":str(pre["manifest_path"]),
                   "sampling_rule":"Complete manifest order, streamed per source JSONL, batches of 1000; no sampling or deduplication.",
                   "input_file_count":len(rows),"input_event_count":pre["input_rows"],"inserted_event_count":0,
                   "run_status":"loading","notes":"Phase 2C full normalized import; duplicate candidates retained; no graph outputs."}
        insert_scenario_run(connection, run_row)
        file_map: dict[str, dict[str, Any]] = {}
        for row in rows:
            rel = row["relative_path"]
            host_hint = Path(rel.replace("\\", "/")).parts[0] if rel else None
            source_id = _source_id(rel, row["pre_run_sha256"])
            file_map[rel] = {"source_file_id":source_id,"row":row,"events":0,"errors":0}
            insert_source_file(connection, {"source_file_id":source_id,"scenario_run_id":run_id,"relative_path":rel,
                "source_sha256":row["pre_run_sha256"],"source_size_bytes":row["size_bytes"],
                "channel":canonical_channel(None,rel),"host_hint":host_hint,"scenario_id":scenario_from_path(rel),
                "phase1_status":row["status"],"selected_for_smoke":0,"phase1_event_count":row["emitted_event_count"],
                "imported_event_count":0,"normalization_error_count":0})
        connection.commit()
        total_inserted = 0
        columns = list(EVENT_COLUMNS)
        insert_sql = f"INSERT INTO events({','.join(columns)}) VALUES({','.join('?' for _ in columns)})"
        for row in rows:
            current_source = row["relative_path"]
            current_record = 0
            output_path = (pre["input_root"] / row["output_relative_path"]).resolve(strict=True)
            batch: list[tuple[Any, ...]] = []
            error_batch: list[tuple[Any, ...]] = []
            file_error_count = 0
            with output_path.open("r", encoding="utf-8") as stream:
                for current_record, line in enumerate(stream, 1):
                    if not line.strip():
                        continue
                    try:
                        original = json.loads(line)
                        if not isinstance(original, dict):
                            raise ValueError("JSONL record is not an object")
                        source = original.get("source") if isinstance(original.get("source"), dict) else {}
                        if source.get("relative_path") != current_source or source.get("sha256") != row["pre_run_sha256"]:
                            raise ValueError("Event source provenance does not match Phase 1 manifest")
                        normalized = normalize_event(original, line_number=current_record)
                        digest = exact_duplicate_digest_from_event(original)
                        batch.append(_row_values(normalized, digest))
                        issues = normalization_issues(original, normalized)
                        for field_name, error_type, message in issues:
                            error_batch.append((run_id,file_map[current_source]["source_file_id"],normalized["event_uid"],
                                                "warning",field_name,error_type,message))
                        file_error_count += len(issues)
                    except Exception as exc:
                        raise FullImportFailure(f"Import failed: {type(exc).__name__}: {str(exc)[:300]}",
                                                source_file=current_source,record_number=current_record,
                                                temp_database=str(temp_path)) from exc
                    if len(batch) >= INSERT_BATCH_SIZE:
                        maximum_batch_rows = max(maximum_batch_rows,len(batch))
                        with transaction(connection):
                            connection.executemany(insert_sql,batch)
                            if error_batch:
                                connection.executemany("""INSERT INTO normalization_errors(scenario_run_id,source_file_id,event_uid,severity,field_name,error_type,message)
                                  VALUES(?,?,?,?,?,?,?)""",error_batch)
                        file_map[current_source]["events"] += len(batch)
                        file_map[current_source]["errors"] += len(error_batch)
                        total_inserted += len(batch)
                        batch.clear(); error_batch.clear()
                if batch or error_batch:
                    maximum_batch_rows = max(maximum_batch_rows,len(batch))
                    with transaction(connection):
                        if batch:
                            connection.executemany(insert_sql,batch)
                        if error_batch:
                            connection.executemany("""INSERT INTO normalization_errors(scenario_run_id,source_file_id,event_uid,severity,field_name,error_type,message)
                              VALUES(?,?,?,?,?,?,?)""",error_batch)
                    file_map[current_source]["events"] += len(batch)
                    file_map[current_source]["errors"] += len(error_batch)
                    total_inserted += len(batch)
            counts = file_map[current_source]
            if counts["events"] != int(row["emitted_event_count"]):
                raise FullImportFailure(f"Per-file row count mismatch: expected {row['emitted_event_count']}, imported {counts['events']}",
                                        source_file=current_source,record_number=current_record,temp_database=str(temp_path))
            connection.execute("UPDATE source_files SET imported_event_count=?,normalization_error_count=? WHERE source_file_id=?",
                               (counts["events"],counts["errors"],counts["source_file_id"]))
            connection.commit()
        parse_path = pre["input_root"] / "parse_errors.jsonl"
        for line in parse_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                insert_parse_error(connection,run_id,json.loads(line))
        exact_count, near_count = _build_duplicate_ledger(connection,run_id)
        connection.executescript(INDEX_DDL)
        connection.execute("UPDATE scenario_runs SET inserted_event_count=?,completed_utc=?,run_status='complete' WHERE run_id=?",
                           (total_inserted,_utc_now(),run_id))
        connection.commit()
        validation = validate_full_database(connection,manifest=manifest,run_id=run_id)
        validation["duplicate_exact_candidates"] = exact_count
        validation["duplicate_near_conflicts"] = near_count
        if not validation["passed"]:
            raise FullImportFailure("Full database validation failed; temporary database retained for diagnosis.",
                                    source_file=current_source,record_number=current_record,temp_database=str(temp_path))
        # Record validation results within the temporary database before publication.
        for check_name, passed in validation["checks"].items():
            connection.execute("INSERT INTO validation_results(scenario_run_id,check_name,result_status,details_json,created_utc) VALUES(?,?,?,?,?)",
                               (run_id,check_name,"PASS" if passed else "FAIL",json.dumps({"passed":passed},separators=(",",":")),_utc_now()))
        connection.commit()
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.close(); connection = None
        sidecars = [Path(str(temp_path)+suffix) for suffix in ("-wal","-shm")]
        if any(path.exists() for path in sidecars):
            raise FullImportFailure(f"SQLite sidecars remain before publication: {[p.name for p in sidecars if p.exists()]}",temp_database=str(temp_path))
        if pre["final_database"].exists():
            raise FileExistsError(f"Final database appeared during import; refusing publication: {pre['final_database']}")
        source_hashes_after = _tree_hashes(pre["input_root"])
        details["source_hashes_unchanged"] = source_hashes_after==pre["phase1_tree_hashes_before"]
        if not details["source_hashes_unchanged"]:
            raise FullImportFailure("Phase 1 input hashes changed during import; temporary database retained.",
                                    temp_database=str(temp_path))
        publish_database(temp_path,pre["final_database"])
        duration = time.perf_counter()-started
        details.update({"validation":validation,"duration_seconds":duration,
                        "events_per_second":total_inserted/max(duration,1e-9),"maximum_batch_rows":maximum_batch_rows,
                        "database_bytes":pre["final_database"].stat().st_size,
                        "free_bytes_after":shutil.disk_usage(pre["final_database"].parent).free,
                        "run_id":run_id})
        report_path.parent.mkdir(parents=True,exist_ok=True)
        report_path.write_text(_report(details,success=True),encoding="utf-8")
        return details
    except BaseException as exc:
        if connection is not None:
            try:
                connection.close()
            except sqlite3.Error:
                pass
        details["failed_source"] = getattr(exc,"source_file",None)
        details["failed_record"] = getattr(exc,"record_number",None)
        details["temp_database"] = str(temp_path)
        report_path.parent.mkdir(parents=True,exist_ok=True)
        if not report_path.exists():
            report_path.write_text(_report(details,success=False,error=f"{type(exc).__name__}: {str(exc)[:500]}"),encoding="utf-8")
        raise

