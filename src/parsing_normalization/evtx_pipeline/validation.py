"""SQLite integrity and future diagram-readiness validation."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from .normalize import RELEVANT_EVENT_IDS, ZERO_GUID
from .schema import EVENT_COLUMNS, SCHEMA_VERSION

REQUIRED_TABLES = {"schema_version", "scenario_runs", "source_files", "events", "parse_errors",
                   "normalization_errors", "duplicate_events", "validation_results"}
REQUIRED_INDEXES = {
    "idx_events_scenario_timestamp", "idx_events_scenario_host_timestamp", "idx_events_scenario_host_session",
    "idx_events_scenario_logon_guid", "idx_events_scenario_process_guid", "idx_events_scenario_parent_process_guid",
    "idx_events_scenario_account_timestamp", "idx_events_scenario_source_destination_ip",
    "idx_events_scenario_channel_event_id", "idx_events_source_file_record_id",
    "idx_events_scenario_target_logon_guid",
}


def schema_check(connection: sqlite3.Connection) -> dict[str, Any]:
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
    missing_tables = sorted(REQUIRED_TABLES - tables)
    missing_indexes = sorted(REQUIRED_INDEXES - indexes)
    missing_columns = sorted(set(EVENT_COLUMNS) - columns)
    version = connection.execute("SELECT version FROM schema_version ORDER BY applied_utc DESC LIMIT 1").fetchone()
    return {"schema_version": version[0] if version else None, "tables": sorted(tables),
            "indexes": sorted(indexes), "missing_tables": missing_tables,
            "missing_indexes": missing_indexes, "missing_event_columns": missing_columns,
            "passed": not (missing_tables or missing_indexes or missing_columns or not version or version[0] != SCHEMA_VERSION)}


def _scalar(connection: sqlite3.Connection, sql: str, args: tuple[Any, ...] = ()) -> int:
    return int(connection.execute(sql, args).fetchone()[0] or 0)


def _join_counts(connection: sqlite3.Connection) -> dict[str, dict[str, int]]:
    pairs = {
        "security_4769_logonguid_to_4624_targetlogonguid": """SELECT COUNT(*) FROM events a JOIN events b
          ON a.scenario_id=b.scenario_id AND a.logon_guid=b.target_logon_guid
          WHERE a.channel='Security' AND a.event_id=4769 AND b.channel='Security' AND b.event_id=4624
          AND a.logon_guid IS NOT NULL AND a.logon_guid<>?""",
        "security_4624_targetlogonid_to_sysmon_logonid_same_host_scenario": """SELECT COUNT(*) FROM events a JOIN events b
          ON a.scenario_id=b.scenario_id AND a.host=b.host AND a.target_logon_id=b.session_id
          WHERE a.channel='Security' AND a.event_id=4624 AND b.channel='Sysmon'
          AND a.target_logon_id IS NOT NULL AND b.session_id IS NOT NULL""",
        "sysmon_processguid_to_parentprocessguid_same_host_scenario": """SELECT COUNT(*) FROM events child JOIN events parent
          ON child.scenario_id=parent.scenario_id AND child.host=parent.host AND child.parent_process_guid=parent.process_guid
          WHERE child.channel='Sysmon' AND parent.channel='Sysmon'
          AND child.parent_process_guid IS NOT NULL AND parent.process_guid IS NOT NULL""",
        "sysmon_event3_process_and_network_tuple_eligible": """SELECT COUNT(*) FROM events e WHERE e.channel='Sysmon' AND e.event_id=3
          AND e.process_guid IS NOT NULL AND e.source_ip IS NOT NULL AND e.destination_ip IS NOT NULL
          AND e.source_port IS NOT NULL AND e.destination_port IS NOT NULL
          AND EXISTS(SELECT 1 FROM events p WHERE p.channel='Sysmon' AND p.event_id=1 AND p.scenario_id=e.scenario_id
                     AND p.host=e.host AND p.process_guid=e.process_guid)""",
        "security_5140_5145_account_session_host_share_complete": """SELECT COUNT(*) FROM events e WHERE e.channel='Security'
          AND e.event_id IN (5140,5145) AND e.account IS NOT NULL AND e.session_id IS NOT NULL
          AND e.host IS NOT NULL AND e.share_name IS NOT NULL""",
        "security_4697_to_system_7045_service_image_within_5m": """SELECT COUNT(*) FROM events a JOIN events b
          ON a.scenario_id=b.scenario_id AND a.host=b.host AND lower(a.service_name)=lower(b.service_name)
          AND lower(a.service_image_path)=lower(b.service_image_path)
          AND abs(a.epoch_ms-b.epoch_ms)<=300000
          WHERE a.channel='Security' AND a.event_id=4697 AND b.channel='System' AND b.event_id=7045
          AND a.service_name IS NOT NULL AND a.service_image_path IS NOT NULL AND a.epoch_ms IS NOT NULL AND b.epoch_ms IS NOT NULL""",
        "winrm_to_powershell_activity_or_process_session_within_5m": """SELECT COUNT(*) FROM events w JOIN events p
          ON w.scenario_id=p.scenario_id AND w.host=p.host AND abs(w.epoch_ms-p.epoch_ms)<=300000
          AND ((w.winrm_activity_id IS NOT NULL AND w.winrm_activity_id=p.winrm_activity_id)
            OR (w.process_id IS NOT NULL AND w.process_id=p.process_id)
            OR (w.session_id IS NOT NULL AND w.session_id=p.session_id))
          WHERE w.channel='WinRM' AND w.event_id IN (6,91,193) AND p.channel='PowerShell' AND p.event_id IN (4103,4104)
          AND w.epoch_ms IS NOT NULL AND p.epoch_ms IS NOT NULL""",
        "account_host_ip_spn_identity_rows": """SELECT COUNT(*) FROM events WHERE account IS NOT NULL AND host IS NOT NULL
          AND (source_ip IS NOT NULL OR destination_ip IS NOT NULL) AND spn IS NOT NULL""",
    }
    result: dict[str, dict[str, int]] = {}
    for name, sql in pairs.items():
        args = (ZERO_GUID,) if name.startswith("security_4769") else ()
        result[name] = {"matched_or_eligible_rows": _scalar(connection, sql, args)}
    result["security_4697_to_system_7045_service_image_within_5m"]["candidate_4697"] = _scalar(
        connection, "SELECT COUNT(*) FROM events WHERE channel='Security' AND event_id=4697")
    result["security_4697_to_system_7045_service_image_within_5m"]["candidate_7045"] = _scalar(
        connection, "SELECT COUNT(*) FROM events WHERE channel='System' AND event_id=7045")
    return result


def diagram_readiness(connection: sqlite3.Connection) -> dict[str, Any]:
    relevant_predicate = " OR ".join(
        f"(channel='{channel}' AND event_id IN ({','.join(str(i) for i in sorted(ids))}))"
        for channel, ids in RELEVANT_EVENT_IDS.items())
    total = _scalar(connection, f"SELECT COUNT(*) FROM events WHERE {relevant_predicate}")
    coverage_fields = {
        "timestamp_utc": "timestamp_utc IS NOT NULL", "host": "host IS NOT NULL",
        "account": "account IS NOT NULL", "session_id": "session_id IS NOT NULL",
        "nonzero_logon_guid": f"(logon_guid IS NOT NULL AND logon_guid<>'{ZERO_GUID}') OR (target_logon_guid IS NOT NULL AND target_logon_guid<>'{ZERO_GUID}')",
        "process_guid": f"process_guid IS NOT NULL AND process_guid<>'{ZERO_GUID}'",
        "source_or_destination_ip": "source_ip IS NOT NULL OR destination_ip IS NOT NULL",
    }
    coverage = {}
    for name, where in coverage_fields.items():
        count = _scalar(connection, f"SELECT COUNT(*) FROM events WHERE ({relevant_predicate}) AND ({where})")
        coverage[name] = {"usable": count, "relevant_events": total,
                          "percent": round(100.0 * count / total, 2) if total else 0.0}

    required_by_type = {
        ("Security", 4769): ["logon_guid", "timestamp_utc", "host"],
        ("Security", 4624): ["target_logon_guid", "target_logon_id", "timestamp_utc", "host"],
        ("Sysmon", 1): ["process_guid", "timestamp_utc", "host"],
        ("Sysmon", 3): ["process_guid", "source_ip", "destination_ip", "source_port", "destination_port", "timestamp_utc", "host"],
        ("Security", 5140): ["account", "session_id", "host", "share_name"],
        ("Security", 5145): ["account", "session_id", "host", "share_name"],
        ("Security", 4697): ["host", "service_name", "service_image_path", "timestamp_utc"],
        ("System", 7045): ["host", "service_name", "service_image_path", "timestamp_utc"],
        ("WinRM", 6): ["host", "timestamp_utc"], ("WinRM", 91): ["host", "timestamp_utc"],
        ("WinRM", 193): ["host", "timestamp_utc"],
        ("PowerShell", 4103): ["host", "timestamp_utc"], ("PowerShell", 4104): ["host", "timestamp_utc"],
    }
    missing: list[dict[str, Any]] = []
    for (channel, event_id), fields in required_by_type.items():
        rows = connection.execute(f"SELECT {','.join(fields)} FROM events WHERE channel=? AND event_id=?",
                                  (channel, event_id)).fetchall()
        for row in rows:
            absent = [field for field in fields if row[field] is None]
            for field in ("target_logon_guid", "logon_guid", "process_guid"):
                if field in fields and row[field] == ZERO_GUID and field not in absent:
                    absent.append(field)
            if (channel, event_id) in {("WinRM", 6), ("WinRM", 91), ("WinRM", 193),
                                       ("PowerShell", 4103), ("PowerShell", 4104)}:
                correlation_keys = connection.execute("SELECT winrm_activity_id,process_id,session_id FROM events WHERE channel=? AND event_id=?",
                                                      (channel, event_id)).fetchall()
                if correlation_keys and all(not any(key) for key in correlation_keys):
                    absent.append("activity_id_or_process_or_session")
            if absent:
                missing.append({"channel": channel, "event_id": event_id, "missing_fields": absent})
    missing_summary: dict[str, dict[str, int]] = {}
    for item in missing:
        key = f"{item['channel']}:{item['event_id']}"
        counts = missing_summary.setdefault(key, {})
        for field in item["missing_fields"]:
            counts[field] = counts.get(field, 0) + 1
    return {"relevant_event_count": total, "coverage": coverage, "planned_join_counts": _join_counts(connection),
            "event_types_with_missing_required_join_fields": missing_summary,
            "events_missing_required_field_count": len(missing)}


def validate_database(connection: sqlite3.Connection) -> dict[str, Any]:
    schema = schema_check(connection)
    foreign_key_issues = [tuple(row) for row in connection.execute("PRAGMA foreign_key_check")]
    invalid_raw_count = _scalar(connection, "SELECT COUNT(*) FROM events WHERE json_valid(raw_event)=0")
    count_mismatch = _scalar(connection, """SELECT COUNT(*) FROM scenario_runs r WHERE r.run_status='complete'
      AND r.inserted_event_count<>(SELECT COUNT(*) FROM events e JOIN source_files f USING(source_file_id)
                                   WHERE f.scenario_run_id=r.run_id)""")
    readiness = diagram_readiness(connection)
    warnings = []
    if readiness["events_missing_required_field_count"]:
        warnings.append("Relevant sample events are missing one or more join fields.")
    if _scalar(connection, "SELECT COUNT(*) FROM normalization_errors WHERE severity='warning'"):
        warnings.append("One or more ambiguous record identities were retained as warnings.")
    status = "NOT_READY" if not schema["passed"] or foreign_key_issues or invalid_raw_count or count_mismatch else (
        "READY_WITH_WARNINGS" if warnings or not readiness["relevant_event_count"] else "READY_FOR_CORRELATION")
    return {"schema": schema, "foreign_key_issues": foreign_key_issues, "invalid_raw_event_json_count": invalid_raw_count,
            "run_count_mismatch_count": count_mismatch, "diagram_readiness": readiness,
            "warnings": warnings, "readiness_status": status}


def store_validation_results(connection: sqlite3.Connection, run_id: str,
                             result: dict[str, Any], created_utc: str) -> None:
    rows = [
        ("schema_integrity", "PASS" if result["schema"]["passed"] else "FAIL", None, None, None, result["schema"]),
        ("sqlite_foreign_keys", "PASS" if not result["foreign_key_issues"] else "FAIL", None, None, None,
         {"issues": result["foreign_key_issues"]}),
        ("raw_event_json", "PASS" if result["invalid_raw_event_json_count"] == 0 else "FAIL", None, None, None,
         {"invalid_count": result["invalid_raw_event_json_count"]}),
        ("diagram_readiness", result["readiness_status"], None, None, None, result["diagram_readiness"]),
    ]
    for name, status, numerator, denominator, value, details in rows:
        connection.execute("""INSERT INTO validation_results(scenario_run_id,check_name,result_status,numerator,denominator,
          result_value,details_json,created_utc) VALUES(?,?,?,?,?,?,?,?)""",
          (run_id, name, status, numerator, denominator, value,
           json.dumps(details, ensure_ascii=False, separators=(",", ":")), created_utc))
    connection.commit()

