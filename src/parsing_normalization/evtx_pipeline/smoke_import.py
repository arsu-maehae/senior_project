"""Bounded, deterministic Phase 2A smoke import from immutable Phase 1 JSONL."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .database import (insert_event, insert_parse_error, insert_scenario_run,
                       insert_source_file, record_normalization_error, transaction)
from .normalize import (RELEVANT_EVENT_IDS, canonical_channel, canonical_host, normalize_event,
                        normalization_issues, scenario_from_path, to_int)
from .schema import SCHEMA_VERSION, create_schema
from .validation import store_validation_results, validate_database

SAMPLE_RULE = (
    "Deterministic first-seen stratified sample from manifest-sorted Phase 1 JSONL: one row for each relevant "
    "(canonical channel,event ID), each available channel, host, and scenario; first rows demonstrating each "
    "available correlation-field class; and the first row from both members of every duplicate source-file SHA-256 pair. "
    "Input JSONL is streamed in manifest order and line order; no random sampling. The full collection is scanned only "
    "to discover event IDs and select these bounded rows; only selected rows are inserted."
)

FIELD_EXAMPLE_ALIASES = {
    "session_id": {"sessionid", "session", "targetlogonid", "subjectlogonid", "logonid"},
    "guid": {"logonguid", "targetlogonguid", "processguid", "parentprocessguid", "activityid"},
    "account": {"subjectusername", "targetusername", "username", "accountname", "user"},
    "source_ip": {"ipaddress", "sourceaddress", "sourceip", "clientaddress"},
    "destination_ip": {"destaddress", "destinationaddress", "destinationip"},
    "process_guid": {"processguid", "sourceprocessguid"},
    "service": {"servicename", "servicefilename", "imagepath", "param1", "param2"},
    "share": {"sharename", "share", "sharelocalpath", "relativetargetname"},
    "network_ports": {"sourceport", "srcport", "destport", "destinationport", "dstport"},
    "spn": {"spn", "serviceprincipalname"},
    "winrm_activity_id": {"activityid", "activityidentifier"},
    "powershell_host_application": {"hostapplication"},
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_id(relative_path: str, sha256: str) -> str:
    return hashlib.sha256((relative_path + "\0" + sha256).encode("utf-8")).hexdigest()


def render_report(details: dict[str, Any], test_summary: str = "Not recorded") -> str:
    test_summary = test_summary.rstrip().rstrip(".")
    sample = details["sample"]
    counts = details["counts"]
    validation = details["validation"]
    readiness = validation["diagram_readiness"]
    lines = [
        "# Phase 2A Normalization and SQLite Smoke Report", "",
        "## Summary", "",
        f"- Schema version: **{SCHEMA_VERSION}**.",
        f"- Readiness: **{validation['readiness_status']}**.",
        f"- Tests: {test_summary}.",
        f"- Database: {details['database_path']}.",
        f"- Phase 1 manifest: {details['manifest_path']}.",
        f"- Files registered: {counts['source_files']}.",
        f"- JSONL records scanned for deterministic selection: {sample['scanned_jsonl_records']:,}.",
        f"- Sample records inserted: {counts['events']:,}; parse errors imported: {counts['parse_errors']:,}; normalization errors: {counts['normalization_errors']:,}; exact duplicate candidates: {counts['duplicate_candidates']:,}.",
        f"- Duplicate source-file pairs were retained as separate provenance; {sample['duplicate_source_file_count']} source files belonged to repeated SHA-256 groups.",
        "- No complete dataset import, graph nodes/edges, attack labels, ATT&CK techniques, scores, or confidence values were generated.", "",
        "## Sampling", "", sample["sample_rule"], "",
        f"Selected channels: {', '.join(sample['channels_selected']) or 'none'}.",
        f"Selected hosts: {', '.join(sample['hosts_selected']) or 'none'}.",
        f"Selected scenarios: {', '.join(sample['scenarios_selected']) or 'none'}.",
        f"Available field-example classes: {', '.join(sample['field_examples_available']) or 'none'}.",
        "", "| Relevant channel/event ID found in complete Phase 1 output | Total records found | Sample rows inserted |", "|---|---:|---:|",
    ]
    imported_type_counts = {(row["channel"], row["event_id"]): row["sample_events"] for row in details["field_coverage_by_type"]}
    for key, amount in sorted(sample["relevant_event_types_found"].items()):
        channel, event_id = key.rsplit(":", 1)
        lines.append(f"| {channel} / {event_id} | {amount:,} | {imported_type_counts.get((channel, int(event_id)), 0):,} |")
    lines += ["", "## Field coverage by channel and event ID (smoke database)", "",
              "Counts show usable normalized values within inserted sample rows for that channel/event ID.", "",
              "| Channel | Event ID | Sample | UTC time | Host | Account | Session | Non-zero logon GUID | Process GUID | Source IP | Destination IP | Port | Share | Service |",
              "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in details["field_coverage_by_type"]:
        lines.append("| " + " | ".join(str(row.get(key) or 0) for key in (
            "channel", "event_id", "sample_events", "timestamps", "hosts", "accounts", "sessions",
            "logon_guids", "process_guids", "source_ips", "destination_ips", "ports", "shares", "services")) + " |")
    lines += ["", "## diagram_readiness", "",
              f"Relevant sample events: {readiness['relevant_event_count']:,}.", "",
              "| Readiness measure | Usable | Relevant events | Percent |", "|---|---:|---:|---:|"]
    for name, row in readiness["coverage"].items():
        lines.append(f"| {name} | {row['usable']:,} | {row['relevant_events']:,} | {row['percent']:.2f}% |")
    lines += ["", "Planned join counts (these are sample-level candidate or match counts; no edges were created):", "",
              "| Planned join | Count details |", "|---|---|"]
    for name, row in readiness["planned_join_counts"].items():
        lines.append(f"| {name} | " + ", ".join(f"{key}={value:,}" for key, value in row.items()) + " |")
    lines += ["", "Relevant event types with missing required join fields (sample only):", ""]
    if readiness["event_types_with_missing_required_join_fields"]:
        lines += ["| Channel:event ID | Missing-field occurrences |", "|---|---|"]
        for key, missing in readiness["event_types_with_missing_required_join_fields"].items():
            lines.append(f"| {key} | " + ", ".join(f"{field}={count}" for field, count in sorted(missing.items())) + " |")
    else:
        lines.append("None in the imported sample.")
    lines += ["", "## SQLite schema", "",
              "Tables: schema_version, scenario_runs, source_files, events, parse_errors, normalization_errors, duplicate_events, validation_results.",
              "Required correlation indexes and all graph-ready normalized event fields are present. Every event retains a valid JSON serialization of the complete Phase 1 event object, plus source-file ID and source-relative path.", "",
              "## Files changed", "",
              "- evtx_pipeline/normalize.py", "- evtx_pipeline/schema.py", "- evtx_pipeline/database.py", "- evtx_pipeline/validation.py", "- evtx_pipeline/smoke_import.py", "- evtx_pipeline/cli.py",
              "- data/processed/attack_path_smoke.sqlite3", "- data/reports/phase2a_normalization_report.md", "",
              "## Example SQL queries", "",
              "Queries below return counts or normalized keys only; they do not dump raw events.", "",
              "```sql\n-- Security 4769 LogonGuid to 4624 TargetLogonGuid candidates\nSELECT COUNT(*)\nFROM events tgs JOIN events logon\n  ON tgs.scenario_id=logon.scenario_id AND tgs.logon_guid=logon.target_logon_guid\nWHERE tgs.channel='Security' AND tgs.event_id=4769\n  AND logon.channel='Security' AND logon.event_id=4624;\n```", "",
              "```sql\n-- Sysmon process parent candidates within host and scenario\nSELECT COUNT(*)\nFROM events child JOIN events parent\n  ON child.scenario_id=parent.scenario_id AND child.host=parent.host\n AND child.parent_process_guid=parent.process_guid\nWHERE child.channel='Sysmon' AND parent.channel='Sysmon';\n```", "",
              "```sql\n-- Sample coverage by channel and event ID\nSELECT channel,event_id,COUNT(*) AS events,\n       SUM(timestamp_utc IS NOT NULL) AS timestamped,\n       SUM(account IS NOT NULL) AS with_account\nFROM events GROUP BY channel,event_id ORDER BY channel,event_id;\n```", "",
              "## Tests and results", "", test_summary, "",
              "## Limitations and mappings requiring review", "",
              "- The smoke database contains only deterministic representative records; join counts and readiness coverage describe the smoke sample, not the full event population.",
              "- The complete Phase 1 JSONL was streamed to discover event IDs and choose sample rows; no complete event set was inserted into SQLite.",
              "- Channel names and host aliases are canonicalized from Windows System metadata, then file paths where metadata is absent. Confirm endpoint/domain naming aliases before a full import.",
              "- EventData duplicate field names are preserved as ordered value arrays in field_values_json; normalized columns use the first non-empty alias match. Review alias precedence for Security account/domain and network fields.",
              "- Unzoned timestamps are left NULL; they are not assumed to be UTC. Zero GUIDs are canonicalized but excluded from non-zero GUID coverage.",
              "- WinRM ActivityID may be absent from Phase 1 EventData for some providers; process/session/time joins therefore remain conditional. Service and share path field names vary by event version and require review against representative raw events in a separate review workflow.",
              "- Exact duplicate candidates are retained. Final cross-export deduplication is intentionally not performed.",
              "- No maliciousness labels, ATT&CK mappings, scores, confidence, correlation edges, or diagram output were created.", "",
              "## Proposed future full-import command", "",
              "NOT EXECUTED — proposed only after approval and a separate capacity check:", "",
              "```powershell\npython -m evtx_pipeline.cli normalize --input \".\\data\\staging\\evtx_jsonl_full\" --database \".\\data\\processed\\attack_path.sqlite3\" --mode full\n```", "",
              "The current Phase 2A CLI intentionally rejects --mode full; that future mode requires a separate reviewed implementation and approval.", "",
              "Report output: " + str(details["report_path"]), ""]
    return "\n".join(lines)


def _event_data_names(event: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    system = event.get("system")
    if isinstance(system, dict):
        names.update(re.sub(r"[^a-z0-9]", "", str(k).casefold()) for k in system)
    data = event.get("event_data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("name"):
                names.add(re.sub(r"[^a-z0-9]", "", str(item["name"]).casefold()))
    return names


def _smoke_sample(input_root: Path, manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    candidates: dict[str, dict[str, Any]] = {}
    found_types: Counter[tuple[str, int]] = Counter()
    scanned_lines = 0
    first_channels: set[str] = set()
    first_hosts: set[str] = set()
    first_scenarios: set[str] = set()
    field_examples: set[str] = set()
    duplicate_hash_paths: set[str] = set()
    hash_paths: dict[str, list[str]] = defaultdict(list)
    for row in manifest["selected_inputs"]:
        if row.get("pre_run_sha256"):
            hash_paths[row["pre_run_sha256"]].append(row["relative_path"])
    for rels in hash_paths.values():
        if len(rels) > 1:
            duplicate_hash_paths.update(rels)

    def save(key: str, event: dict[str, Any], line_number: int) -> dict[str, Any]:
        if key not in candidates:
            normalized = normalize_event(event, line_number=line_number)
            candidates[key] = {"normalized": normalized, "event": event}
        return candidates[key]

    rows = sorted(manifest["selected_inputs"], key=lambda r: r["relative_path"].casefold())
    for source_row in rows:
        output_path = input_root / Path(source_row["output_relative_path"])
        if not output_path.is_file():
            raise FileNotFoundError(f"Phase 1 per-file JSONL is missing: {source_row['output_relative_path']}")
        rel = source_row["relative_path"]
        source_duplicate = rel in duplicate_hash_paths
        with output_path.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                scanned_lines += 1
                if not line.strip():
                    continue
                event = json.loads(line)
                system = event.get("system") if isinstance(event.get("system"), dict) else {}
                source = event.get("source") if isinstance(event.get("source"), dict) else {}
                actual_rel = str(source.get("relative_path") or rel)
                channel = canonical_channel(system.get("channel"), actual_rel)
                event_id = to_int(system.get("event_id"))
                scenario = scenario_from_path(actual_rel, event.get("hints") if isinstance(event.get("hints"), dict) else {})
                path_host = Path(actual_rel.replace("\\", "/")).parts[0] if actual_rel else None
                host = canonical_host(system.get("computer")) or canonical_host(path_host)
                if channel in RELEVANT_EVENT_IDS and event_id in RELEVANT_EVENT_IDS[channel]:
                    found_types[(channel, event_id)] += 1
                    key = f"type:{channel}:{event_id}"
                    if key not in candidates:
                        save(key, event, line_number)
                if channel and channel not in first_channels:
                    first_channels.add(channel)
                    save(f"channel:{channel}", event, line_number)
                if host and host not in first_hosts:
                    first_hosts.add(host)
                    save(f"host:{host}", event, line_number)
                if scenario and scenario not in first_scenarios:
                    first_scenarios.add(scenario)
                    save(f"scenario:{scenario}", event, line_number)
                if source_duplicate:
                    key = f"duplicate_source:{rel}"
                    if key not in candidates:
                        save(key, event, line_number)
                names = _event_data_names(event)
                for category, aliases in FIELD_EXAMPLE_ALIASES.items():
                    if category not in field_examples and names.intersection(aliases):
                        field_examples.add(category)
                        save(f"field:{category}", event, line_number)

    for item in candidates.values():
        normalized = item["normalized"]
        selected[normalized["event_uid"]] = item
    output_rows = [selected[uid] for uid in sorted(selected)]
    stats = {
        "scanned_jsonl_records": scanned_lines,
        "sample_records": len(output_rows),
        "sample_rule": SAMPLE_RULE,
        "relevant_event_types_found": {f"{ch}:{eid}": count for (ch, eid), count in sorted(found_types.items())},
        "relevant_event_type_count": len(found_types),
        "channels_selected": sorted({item["normalized"]["channel"] for item in output_rows if item["normalized"]["channel"]}),
        "hosts_selected": sorted({item["normalized"]["host"] for item in output_rows if item["normalized"]["host"]}),
        "scenarios_selected": sorted({item["normalized"]["scenario_id"] for item in output_rows if item["normalized"]["scenario_id"]}),
        "field_examples_available": sorted(field_examples),
        "duplicate_source_file_count": len(duplicate_hash_paths),
    }
    return output_rows, stats


def run_smoke(input_root: Path, database_path: Path, test_summary: str = "Not recorded") -> dict[str, Any]:
    input_root = input_root.resolve(strict=True)
    database_path = database_path.resolve()
    if database_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing Phase 2A database: {database_path}")
    report_path = Path(__file__).resolve().parent.parent / "data" / "reports" / "phase2a_normalization_report.md"
    if report_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing Phase 2A report: {report_path}")
    manifest_path = input_root / "manifest.json"
    errors_path = input_root / "parse_errors.jsonl"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("run_mode") != "full" or len(manifest.get("selected_inputs", [])) != 85:
        raise ValueError("Smoke import expects the validated 85-file Phase 1 full-conversion manifest.")
    sample, sampling = _smoke_sample(input_root, manifest)
    if not sample:
        raise ValueError("Deterministic sample selection produced no rows.")

    file_by_rel = {row["relative_path"]: row for row in manifest["selected_inputs"]}
    selected_relatives = {item["normalized"]["source_relative_path"] for item in sample}
    now = _utc_now()
    run_id = hashlib.sha256((SCHEMA_VERSION + "\0" + str(manifest_path) + "\0" + SAMPLE_RULE).encode()).hexdigest()
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    try:
        create_schema(connection)
        parse_errors = [json.loads(line) for line in errors_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        with transaction(connection):
            insert_scenario_run(connection, {
                "run_id": run_id, "schema_version": SCHEMA_VERSION, "started_utc": now,
                "completed_utc": None, "input_root": str(manifest.get("input_root", "")),
                "phase1_manifest_path": str(manifest_path), "sampling_rule": SAMPLE_RULE,
                "input_file_count": len(file_by_rel),
                "input_event_count": int(manifest.get("totals", {}).get("emitted_events", 0)),
                "inserted_event_count": 0, "run_status": "loading", "notes": "Phase 2A bounded smoke only; no graph outputs.",
            })
            for rel, row in file_by_rel.items():
                host_hint = Path(rel.replace("\\", "/")).parts[0] if rel else None
                insert_source_file(connection, {
                    "source_file_id": _source_id(rel, row["pre_run_sha256"]), "scenario_run_id": run_id,
                    "relative_path": rel, "source_sha256": row["pre_run_sha256"],
                    "source_size_bytes": row["size_bytes"], "channel": canonical_channel(None, rel),
                    "host_hint": host_hint, "scenario_id": scenario_from_path(rel),
                    "phase1_status": row["status"], "selected_for_smoke": int(rel in selected_relatives),
                })
            for error in parse_errors:
                source_rel = error.get("source")
                error["source_file_id"] = _source_id(source_rel, file_by_rel[source_rel]["pre_run_sha256"]) if source_rel in file_by_rel else None
                insert_parse_error(connection, run_id, error)
            for item in sample:
                event = item["normalized"]
                insert_event(connection, run_id, event)
                for field_name, error_type, message in normalization_issues(item["event"], event):
                    record_normalization_error(connection, run_id, severity="warning", field_name=field_name,
                                               error_type=error_type, message=message,
                                               source_file_id=event["source_file_id"], event_uid=event["event_uid"])
            connection.execute("""UPDATE scenario_runs SET completed_utc=?, inserted_event_count=?, run_status='complete'
                                  WHERE run_id=?""", (now, len(sample), run_id))
        validation = validate_database(connection)
        store_validation_results(connection, run_id, validation, _utc_now())
        if not validation["schema"]["passed"] or validation["foreign_key_issues"] or validation["invalid_raw_event_json_count"]:
            raise RuntimeError("Phase 2A SQLite smoke validation failed; inspect the workspace database and report state.")
        counts = {
            "source_files": connection.execute("SELECT COUNT(*) FROM source_files WHERE scenario_run_id=?", (run_id,)).fetchone()[0],
            "events": connection.execute("SELECT COUNT(*) FROM events WHERE source_file_id IN (SELECT source_file_id FROM source_files WHERE scenario_run_id=?)", (run_id,)).fetchone()[0],
            "parse_errors": connection.execute("SELECT COUNT(*) FROM parse_errors WHERE scenario_run_id=?", (run_id,)).fetchone()[0],
            "normalization_errors": connection.execute("SELECT COUNT(*) FROM normalization_errors WHERE scenario_run_id=?", (run_id,)).fetchone()[0],
            "duplicate_candidates": connection.execute("SELECT COUNT(*) FROM duplicate_events WHERE scenario_run_id=?", (run_id,)).fetchone()[0],
        }
        field_rows = [dict(row) for row in connection.execute("""SELECT channel,event_id,COUNT(*) AS sample_events,
          SUM(timestamp_utc IS NOT NULL) AS timestamps,SUM(host IS NOT NULL) AS hosts,SUM(account IS NOT NULL) AS accounts,
          SUM(session_id IS NOT NULL) AS sessions,SUM((logon_guid IS NOT NULL AND logon_guid<>'00000000-0000-0000-0000-000000000000') OR
              (target_logon_guid IS NOT NULL AND target_logon_guid<>'00000000-0000-0000-0000-000000000000')) AS logon_guids,
          SUM(process_guid IS NOT NULL AND process_guid<>'00000000-0000-0000-0000-000000000000') AS process_guids,
          SUM(source_ip IS NOT NULL) AS source_ips,SUM(destination_ip IS NOT NULL) AS destination_ips,
          SUM(source_port IS NOT NULL OR destination_port IS NOT NULL) AS ports,SUM(share_name IS NOT NULL) AS shares,
          SUM(service_name IS NOT NULL) AS services FROM events GROUP BY channel,event_id ORDER BY channel,event_id""")]
        details = {"run_id": run_id, "database_path": str(database_path), "manifest_path": str(manifest_path),
                   "parse_errors_path": str(errors_path), "sample": sampling, "counts": counts,
                   "validation": validation, "field_coverage_by_type": field_rows,
                   "report_path": str(report_path)}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_report(details, test_summary), encoding="utf-8")
        return details
    finally:
        connection.close()


