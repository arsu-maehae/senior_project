"""Bounded-memory normalization profiling for immutable Phase 1 JSONL exports."""
from __future__ import annotations

import ipaddress
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Iterator

from .normalize import (_account, _first, _raw_first, _values, canonical_channel,
                        canonical_host, classify_guid, normalize_guid,
                        normalize_ip, normalize_timestamp, scenario_from_path, to_int)

PROFILE_RULE = "Stream manifest-listed JSONL files in manifest and line order; aggregate counters only."
_SEC_AUTH = {4624, 4625, 4648, 4768, 4769, 4778, 4779, 5140, 5145}
_SYSMON = {1, 3, 10, 11}

# Applicability is explicit: these are event types where a field is expected or useful.
APPLICABILITY: dict[str, dict[str, set[int]]] = {
    "timestamp_utc": {"*": set()},
    "host": {"*": set()},
    "account": {"Security": {4624,4625,4648,4672,4697,4768,4769,4776,4778,4779,5140,5145},
                "Sysmon": _SYSMON, "PowerShell": {4103,4104}},
    "session_id": {"Security": {4624,4625,4648,4672,4778,4779,5140,5145}, "Sysmon": _SYSMON},
    "logon_guid": {"Security": {4769}},
    "target_logon_guid": {"Security": {4624}},
    "process_guid": {"Sysmon": _SYSMON},
    "parent_process_guid": {"Sysmon": {1}},
    "source_ip": {"Security": _SEC_AUTH, "Sysmon": {3}},
    "destination_ip": {"Sysmon": {3}},
    "service_name": {"Security": {4697}, "System": {7045}},
    "share_name": {"Security": {5140,5145}},
}
ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp_utc": ("timestamp_raw", "UtcTime", "TimeCreated", "timestamp"),
    "host": ("computer", "host_from_path"),
    "account": ("TargetUserName", "AccountName", "UserName", "User", "SubjectUserName", "SubjectUser", "CallerUserName"),
    "session_id": ("SessionId", "SessionID", "TargetLogonId", "TargetLogonID", "SubjectLogonId", "SubjectLogonID", "LogonId", "LogonID"),
    "logon_guid": ("LogonGuid", "LogonGUID"), "target_logon_guid": ("TargetLogonGuid", "TargetLogonGUID"),
    "process_guid": ("ProcessGuid", "ProcessGUID", "SourceProcessGUID"),
    "parent_process_guid": ("ParentProcessGuid", "ParentProcessGUID"),
    "source_ip": ("IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "RemoteAddress"),
    "destination_ip": ("DestAddress", "DestinationAddress", "DestinationIp", "TargetAddress"),
    "service_name": ("ServiceName", "param1"), "share_name": ("ShareName", "Share"),
}


def _field_state(field: str, event: dict[str, Any], normalized: dict[str, Any], values: dict[str, list[Any]] | None = None) -> str:
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    aliases = ALIASES[field]
    if field == "timestamp_utc":
        present = "timestamp_raw" in system and system.get("timestamp_raw") is not None
        raw = system.get("timestamp_raw")
    elif field == "host":
        raw = system.get("computer") or (event.get("hints") or {}).get("host_from_path")
        present = bool(raw)
    else:
        lookup_aliases = aliases
        if field == "target_logon_guid" and normalized.get("channel") == "Security" and normalized.get("event_id") == 4624:
            lookup_aliases += ("LogonGuid", "LogonGUID")
        present, raw = _raw_first(values if values is not None else _values(event), *lookup_aliases)
    if not present:
        return "missing"
    if raw is None or not str(raw).strip():
        return "empty"
    text = str(raw).strip()
    if text.casefold() in {"-", "null", "none", "n/a"}:
        return "placeholder"
    if field in {"logon_guid", "target_logon_guid", "process_guid", "parent_process_guid"}:
        return classify_guid((True, raw))
    if field in {"source_ip", "destination_ip"}:
        try:
            ipaddress.ip_address(text)
            return "usable"
        except ValueError:
            return "malformed"
    if field == "session_id":
        return "usable" if to_int(raw) is not None else "malformed"
    if field == "timestamp_utc":
        return "usable" if normalize_timestamp(raw)[0] is not None else "malformed"
    value = normalized.get(field)
    return "usable" if value is not None else "malformed"


def _expected(channel: str | None, event_id: int | None, field: str) -> bool:
    rules = APPLICABILITY[field]
    if "*" in rules:
        return True
    return channel in rules and event_id in rules[channel]


def _path_host_scenario(relative_path: str, event: dict[str, Any]) -> tuple[str | None, str | None]:
    parts = Path(relative_path.replace("\\", "/")).parts
    hints = event.get("hints") if isinstance(event.get("hints"), dict) else {}
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    known = {"ep-01", "ep-02", "ep-03", "DC01"}
    h1, h2 = canonical_host(system.get("computer")), canonical_host(parts[0]) if parts else None
    host = h1 if h1 in known else h2 if h2 in known else h1 or h2
    return host, scenario_from_path(relative_path, hints)


def _profile_values(event: dict[str, Any], relative_path: str) -> tuple[dict[str, Any], dict[str, list[Any]]]:
    """Compute only profile keys; avoid raw-event serialization and unrelated XML parsing."""
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    hints = event.get("hints") if isinstance(event.get("hints"), dict) else {}
    values = _values(event)
    channel = canonical_channel(system.get("channel"), relative_path)
    event_id = to_int(system.get("event_id")) or to_int(_first(values, "event_id", "id"))
    host, scenario = _path_host_scenario(relative_path, event)
    timestamp_raw = system.get("timestamp_raw") or _first(values, "UtcTime", "TimeCreated", "timestamp")
    timestamp_utc, epoch = normalize_timestamp(timestamp_raw)
    target = _account(_first(values, "TargetUserName", "AccountName", "UserName", "User"),
                      _first(values, "TargetDomainName", "AccountDomain", "Domain"))
    subject = _account(_first(values, "SubjectUserName", "SubjectUser", "CallerUserName"),
                       _first(values, "SubjectDomainName", "SubjectDomain"))
    account = target or subject or _account(_first(values, "User", "UserName", "AccountName"),
                                            _first(values, "TargetDomainName", "SubjectDomainName", "Domain"))
    session_id = to_int(_first(values, "SessionId", "SessionID", "TargetLogonId", "TargetLogonID", "SubjectLogonId", "SubjectLogonID", "LogonId", "LogonID"))
    source_ip = normalize_ip(_first(values, *ALIASES["source_ip"]))
    destination_ip = normalize_ip(_first(values, *ALIASES["destination_ip"]))
    guid = lambda *names: normalize_guid(_first(values, *names))
    normalized = {"channel": channel, "event_id": event_id, "host": host, "scenario_id": scenario,
            "host_hint_raw": hints.get("host_from_path"), "scenario_hint_raw": hints.get("claimed_scenario"),
            "timestamp_utc": timestamp_utc, "epoch_ms": epoch, "account": account,
            "session_id": session_id, "target_logon_id": to_int(_first(values, "TargetLogonId", "TargetLogonID")),
            "logon_guid": guid("LogonGuid", "LogonGUID"),
            "target_logon_guid": guid("TargetLogonGuid", "TargetLogonGUID"),
            "process_guid": guid("ProcessGuid", "ProcessGUID", "SourceProcessGUID"),
            "parent_process_guid": guid("ParentProcessGuid", "ParentProcessGUID"),
            "source_ip": source_ip, "destination_ip": destination_ip,
            "source_port": to_int(_first(values, "SourcePort", "SrcPort")),
            "destination_port": to_int(_first(values, "DestPort", "DestinationPort", "DstPort")),
            "service_name": _first(values, "ServiceName", "param1"),
            "service_image_path": _first(values, "ImagePath", "ServiceFileName", "param2"),
            "share_name": _first(values, "ShareName", "Share"),
            "winrm_activity_id": guid("ActivityID", "ActivityId", "ActivityIdentifier"),
            "process_id": to_int(_first(values, "ProcessId", "ProcessID"))}
    if channel == "Security" and event_id == 4624:
        normalized["target_logon_guid"] = normalize_guid(_first(values, "TargetLogonGuid", "TargetLogonGUID", "LogonGuid", "LogonGUID"))
    return normalized, values


def iter_events(input_root: Path, manifest: dict[str, Any]) -> Iterator[tuple[str, int, dict[str, Any]]]:
    """Yield a single decoded JSON object at a time; never materialize the corpus."""
    for row in manifest["selected_inputs"]:
        out = input_root / row["output_relative_path"]
        with out.open("r", encoding="utf-8") as stream:
            for line_no, line in enumerate(stream, 1):
                if line.strip():
                    yield row["relative_path"], line_no, json.loads(line)


def profile_events(records: Iterable[tuple[str, int, dict[str, Any]]], manifest: dict[str, Any]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    by_scenario: Counter[str] = Counter(); by_host: Counter[str] = Counter()
    by_channel: Counter[str] = Counter(); by_event: Counter[str] = Counter()
    fields: dict[str, Counter[str]] = {name: Counter() for name in APPLICABILITY}
    field_types: dict[str, dict[str, Counter[str]]] = {name: {} for name in APPLICABILITY}
    errors: Counter[str] = Counter(); guid_states: Counter[str] = Counter()
    ip_categories: Counter[str] = Counter(); session_failures: Counter[str] = Counter()
    unknown_host: Counter[str] = Counter(); unknown_scenario: Counter[str] = Counter()
    join: Counter[str] = Counter(); account_fields: Counter[str] = Counter()
    duplicate_hashes: Counter[str] = Counter()
    audit_names: Counter[str] = Counter()
    audit_usable: Counter[str] = Counter()
    audit_events_with_guid_name = 0
    audit_events_with_usable_guid = 0
    for item in manifest.get("selected_inputs", []):
        duplicate_hashes[item.get("pre_run_sha256", "")] += 1
    duplicates = {h: n for h, n in duplicate_hashes.items() if h and n > 1}
    duplicate_source_files = sum(n for n in duplicates.values())
    duplicate_source_extras = sum(n - 1 for n in duplicates.values())
    file_events: Counter[str] = Counter()
    last_count = 0
    for relative_path, line_no, event in records:
        counts["events"] += 1
        file_events[relative_path] += 1
        normalized, values = _profile_values(event, relative_path)
        channel, eid, scenario = normalized["channel"], normalized["event_id"], normalized["scenario_id"]
        host, _ = _path_host_scenario(relative_path, event)
        by_scenario[scenario or "<unknown>"] += 1
        by_host[host or "<unknown>"] += 1
        by_channel[channel or "<unknown>"] += 1
        by_event[f"{channel or '<unknown>'}:{eid if eid is not None else '<unknown>'}"] += 1
        if channel == "Security" and eid == 4624:
            event_has_guid_name = False
            event_has_usable_guid = False
            for item in event.get("event_data", []) if isinstance(event.get("event_data"), list) else []:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    continue
                raw_name = item["name"]
                local_name = raw_name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
                if "guid" not in local_name.casefold():
                    continue
                audit_names[raw_name] += 1
                event_has_guid_name = True
                if classify_guid((True, item.get("value"))) == "valid":
                    audit_usable[raw_name] += 1
                    event_has_usable_guid = True
            audit_events_with_guid_name += int(event_has_guid_name)
            audit_events_with_usable_guid += int(event_has_usable_guid)
        if channel is None: counts["unknown_channels"] += 1
        if host is None: unknown_host[str(normalized.get("host_hint_raw") or "<missing>")] += 1
        if scenario is None: unknown_scenario[str(normalized.get("scenario_hint_raw") or "<missing>")] += 1
        hints = event.get("hints") if isinstance(event.get("hints"), dict) else {}
        raw_hint_host = hints.get("host_from_path")
        raw_hint_scenario = hints.get("claimed_scenario")
        known_hosts = {"ep-01", "ep-02", "ep-03", "DC01"}
        if raw_hint_host and canonical_host(raw_hint_host) not in known_hosts:
            unknown_host[str(raw_hint_host)] += 1
        if raw_hint_scenario and scenario_from_path("", {"claimed_scenario": raw_hint_scenario}) is None:
            unknown_scenario[str(raw_hint_scenario)] += 1
        if normalized["timestamp_utc"] is None:
            counts["timestamp_failures"] += 1
            errors["timestamp_utc:missing_or_invalid"] += 1
        for field in APPLICABILITY:
            if not _expected(channel, eid, field):
                continue
            state = _field_state(field, event, normalized, values)
            bucket = fields[field]
            bucket["applicable"] += 1; bucket[state] += 1
            if state == "valid":
                bucket["usable"] += 1
            key = f"{channel}:{eid}"
            field_types[field].setdefault(key, Counter())[state] += 1
            if state in {"malformed"}:
                errors[f"{field}:malformed"] += 1
            if state == "placeholder":
                errors[f"{field}:placeholder"] += 1
            if field.endswith("guid") or field in {"logon_guid", "target_logon_guid"}:
                guid_states[f"{field}:{state}"] += 1
            if field.endswith("_ip"):
                ip_categories[f"{field}:{state}"] += 1
                if state == "usable":
                    present_ip, raw_ip = _raw_first(values, *ALIASES[field])
                    try:
                        parsed_ip = ipaddress.ip_address(str(raw_ip).strip()) if present_ip else None
                        if parsed_ip is not None:
                            kind = ("ipv4_mapped_ipv6" if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.ipv4_mapped else
                                    "loopback" if parsed_ip.is_loopback else "unspecified" if parsed_ip.is_unspecified else
                                    "ipv4" if parsed_ip.version == 4 else "ipv6")
                            ip_categories[f"{field}:{kind}"] += 1
                    except ValueError:
                        pass
            if field == "session_id" and state == "malformed":
                session_failures["invalid_integer"] += 1
        # Account-specific field coverage helps review alias precedence.
        if channel == "Security" and eid is not None:
            for key, aliases in {"target_account": ("TargetUserName",), "subject_account": ("SubjectUserName",),
                                 "caller_account": ("CallerUserName",), "domain": ("TargetDomainName", "SubjectDomainName")}.items():
                present, raw = _raw_first(values, *aliases)
                if present and raw is not None and str(raw).strip() and str(raw).strip() != "-":
                    account_fields[f"{channel}:{eid}:{key}:present"] += 1
                else:
                    account_fields[f"{channel}:{eid}:{key}:missing_or_placeholder"] += 1
        # Join readiness counts are usable endpoint/key records only; no pairwise joins are attempted.
        if channel == "Security" and eid == 4769 and normalized.get("logon_guid"):
            join["4769_usable_logon_guid"] += 1
        if channel == "Security" and eid == 4624:
            if normalized.get("target_logon_guid"): join["4624_usable_target_logon_guid"] += 1
            if normalized.get("target_logon_id") is not None: join["4624_usable_target_logon_id"] += 1
        if channel == "Sysmon" and eid in _SYSMON:
            if normalized.get("session_id") is not None: join["sysmon_usable_logon_id"] += 1
            if normalized.get("process_guid"): join["sysmon_process_guid"] += 1
            if normalized.get("parent_process_guid"): join["sysmon_parent_process_guid"] += 1
        if channel == "Sysmon" and eid == 3 and normalized.get("process_guid") and normalized.get("source_ip") and normalized.get("destination_ip") and normalized.get("source_port") is not None and normalized.get("destination_port") is not None:
            join["sysmon_event3_process_network_tuple"] += 1
        if channel == "Security" and eid in {5140,5145}:
            if normalized.get("account") and normalized.get("session_id") is not None and host and normalized.get("share_name"):
                join["security_share_complete"] += 1
            join[f"security_{eid}_share_records"] += 1
        if channel == "Security" and eid == 4697 and normalized.get("service_name") and normalized.get("service_image_path"):
            join["security_4697_service_image"] += 1
        if channel == "System" and eid == 7045 and normalized.get("service_name") and normalized.get("service_image_path"):
            join["system_7045_service_image"] += 1
        if channel == "WinRM" and eid in {6,91,193}:
            join["winrm_records"] += 1
            if normalized.get("winrm_activity_id") or normalized.get("session_id") or normalized.get("process_id"):
                join["winrm_with_activity_process_or_session"] += 1
        if channel == "PowerShell" and eid in {4103,4104}:
            join["powershell_records"] += 1
            if normalized.get("winrm_activity_id") or normalized.get("session_id") or normalized.get("process_id"):
                join["powershell_with_activity_process_or_session"] += 1
        if counts["events"] % 100000 == 0:
            last_count = counts["events"]
    # Explicit exact duplicate candidates from byte-identical source exports; do not remove rows.
    extra_duplicate_events = 0
    if duplicates:
        copies_left = {h: n - 1 for h, n in duplicates.items()}
        for row in manifest["selected_inputs"]:
            h = row.get("pre_run_sha256", "")
            if copies_left.get(h, 0) > 0:
                extra_duplicate_events += int(row.get("emitted_event_count", file_events.get(row["relative_path"], 0)))
                copies_left[h] -= 1
    coverage = {}
    for field, counter in fields.items():
        applicable = counter["applicable"]
        usable = counter["usable"]
        coverage[field] = {"applicable_event_count": applicable, "usable_count": usable,
                           "missing_count": counter["missing"],
                           "zero_or_placeholder_count": counter["zero"] + counter["placeholder"],
                           "empty_count": counter["empty"], "malformed_count": counter["malformed"],
                           "usable_percent": round(100 * usable / applicable, 4) if applicable else None,
                           "by_channel_event_id": {k: dict(v) for k,v in sorted(field_types[field].items())}}
    return {
        "sampling_rule": PROFILE_RULE, "counts": dict(counts),
        "groups": {"scenario": dict(sorted(by_scenario.items())), "host": dict(sorted(by_host.items())),
                   "channel": dict(sorted(by_channel.items())), "channel_event_id": dict(sorted(by_event.items()))},
        "normalization_errors_by_field_reason": dict(sorted(errors.items())),
        "timestamp_failures": counts["timestamp_failures"], "unknown_channels": counts["unknown_channels"],
        "unknown_host_hints": dict(sorted(unknown_host.items())), "unknown_scenario_hints": dict(sorted(unknown_scenario.items())),
        "guid_categories": dict(sorted(guid_states.items())), "session_id_conversion_failures": dict(session_failures),
        "ip_categories": dict(sorted(ip_categories.items())), "relevant_account_field_counts": dict(sorted(account_fields.items())),
        "applicable_field_coverage": coverage,
        "duplicate_candidates": {"duplicate_source_hash_groups": len(duplicates), "files_in_groups": duplicate_source_files,
                                  "duplicate_source_files_beyond_first": duplicate_source_extras,
                                  "candidate_event_rows_from_duplicate_exports": extra_duplicate_events,
                                  "method": "SHA-256-identical complete source exports; counts only, retained in outputs"},
        "join_readiness": dict(sorted(join.items())),
        "security_4624_guid_field_audit": {
            "event_count": by_event.get("Security:4624", 0),
            "guid_named_field_occurrences": dict(sorted(audit_names.items())),
            "events_with_guid_named_field": audit_events_with_guid_name,
            "parseable_nonzero_guid_values_by_field": dict(sorted(audit_usable.items())),
            "events_with_parseable_nonzero_guid": audit_events_with_usable_guid,
        },
        "joins_created": False,
    }


def run_profile(input_root: Path) -> dict[str, Any]:
    input_root = input_root.resolve(strict=True)
    manifest_path = input_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("run_mode") != "full" or len(manifest.get("selected_inputs", [])) != 85:
        raise ValueError("Profiling requires the immutable validated 85-file Phase 1 full manifest.")
    result = profile_events(iter_events(input_root, manifest), manifest)
    expected = int(manifest.get("totals", {}).get("emitted_events", 0))
    if result["counts"].get("events", 0) != expected:
        raise ValueError(f"Profiled event count {result['counts'].get('events', 0)} does not match manifest {expected}.")
    result["manifest_expected_events"] = expected
    result["source_file_count"] = len(manifest["selected_inputs"])
    return result


def render_report(profile: dict[str, Any], *, test_result: str) -> str:
    counts = profile["counts"]
    guid_audit = profile.get("security_4624_guid_field_audit", {})
    guid_occurrences = guid_audit.get("guid_named_field_occurrences", {})
    guid_usable = guid_audit.get("parseable_nonzero_guid_values_by_field", {})
    usable_4624_guids = guid_audit.get("events_with_parseable_nonzero_guid", 0)
    total_4624 = guid_audit.get("event_count", 0)
    lines = ["# Phase 2B Full Normalization Profile", "", "## Summary", "",
             f"- Events profiled: **{counts.get('events', 0):,}** across **{profile.get('source_file_count', 0)}** Phase 1 JSONL files.",
             f"- Tests: **{test_result}**.", "- Full SQLite import: **not run**; no correlation or graph outputs were created.",
             f"- Stream rule: {profile['sampling_rule']}", "", "## Aggregate distribution", "",
             "| Dimension | Values |", "|---|---:|"]
    for key, title in (("scenario","Scenario"),("host","Host"),("channel","Channel"),("channel_event_id","Channel / event ID")):
        lines.append(f"| {title} | {len(profile['groups'][key])} |")
    lines += ["", "### Event counts", "", "```json", json.dumps(profile["groups"], indent=2, ensure_ascii=False), "```", "",
              "## Applicable field coverage", "",
              "Coverage uses only explicitly applicable channel/event types listed in the profile JSON. Zero GUIDs and placeholders are unavailable values; they are not counted usable.", "",
              "| Field | Applicable | Usable | Missing | Zero / placeholder | Empty | Malformed | Usable % |",
              "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for field, d in profile["applicable_field_coverage"].items():
        pct = "n/a" if d["usable_percent"] is None else f"{d['usable_percent']:.2f}%"
        lines.append(f"| {field} | {d['applicable_event_count']:,} | {d['usable_count']:,} | {d['missing_count']:,} | {d['zero_or_placeholder_count']:,} | {d['empty_count']:,} | {d['malformed_count']:,} | {pct} |")
    lines += ["", "### Coverage by applicable channel and event ID", "",
              "| Field | Channel / event ID | Applicable | Usable | Missing | Zero / placeholder | Empty | Malformed | Usable % |",
              "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for field, d in profile["applicable_field_coverage"].items():
        for event_type, states in d["by_channel_event_id"].items():
            applicable = sum(states.values())
            usable = states.get("usable", 0) + states.get("valid", 0)
            missing = states.get("missing", 0)
            zero_placeholder = states.get("zero", 0) + states.get("placeholder", 0)
            empty = states.get("empty", 0)
            malformed = states.get("malformed", 0)
            pct = 100 * usable / applicable if applicable else 0
            lines.append(f"| {field} | {event_type} | {applicable:,} | {usable:,} | {missing:,} | {zero_placeholder:,} | {empty:,} | {malformed:,} | {pct:.2f}% |")
    lines += ["", "## Normalization diagnostics", "", "```json",
              json.dumps({k: profile[k] for k in ("normalization_errors_by_field_reason","timestamp_failures","unknown_channels","unknown_host_hints","unknown_scenario_hints","guid_categories","session_id_conversion_failures","ip_categories","relevant_account_field_counts","duplicate_candidates")}, indent=2, ensure_ascii=False),
              "```", "", "## Warning investigation", "",
              f"- Security 4624 `TargetLogonGuid`: the sampled event at `DC01/dryrun_s01/evtxexportDC-01_Security.evtx`, record ID 300903, lacks that exact EventData name. The complete raw-key audit found {guid_audit.get('events_with_guid_named_field', 0):,}/{total_4624:,} Security 4624 records with GUID-named fields; names/counts: `{json.dumps(guid_occurrences, sort_keys=True)}`. Parseable nonzero values: `{json.dumps(guid_usable, sort_keys=True)}` across {usable_4624_guids:,} records. Security 4624 `LogonGuid` is now mapped as the target GUID fallback; zero/missing values remain NULL with explicit state, and raw Phase 1 JSON is retained. For records without a usable GUID, a future fallback may use scenario + host + account + source IP + logon type + a bounded time window. Do not fabricate a GUID.",
              "- Malformed IP warning: Security 4779, event ID 4779, field `ClientAddress` / normalized `source_ip`; value category is nonempty malformed/non-IP text (literal redacted). Python `ipaddress.ip_address` rejects it. The full profile found 3 malformed source IP values total: one Security 4778 and two Security 4779. Raw values remain in Phase 1 JSON; normalized values are NULL and counted as malformed.",
              "- Blank and `-` are treated as placeholders; IPv4, IPv6, IPv4-mapped IPv6, loopback, `::`, and `0.0.0.0` follow Python standard-library parsing. Mapped IPv6 is emitted in IPv4 form.",
              "", "## Join readiness counts", "",
              "These are usable record/key counts per side or event family, not matched joins. No correlation was run.", "", "```json",
              json.dumps(profile["join_readiness"], indent=2), "```", "",
              "## Warnings and blockers", "",
              f"- Timestamp failures: {profile['timestamp_failures']:,}.",
              f"- Unknown channels: {profile['unknown_channels']:,}.",
              f"- Exact duplicate candidates are estimated from SHA-256-identical complete source exports; {profile['duplicate_candidates']['candidate_event_rows_from_duplicate_exports']:,} event rows belong to repeated source copies and remain retained.",
              "- Missing and malformed field values are source-quality limitations; Phase 2B leaves unavailable normalized values NULL and retains originals.",
              f"- TargetLogonGuid coverage is {usable_4624_guids:,}/{total_4624:,} for Security 4624. The direct GUID join is available only for records with a usable GUID; use the documented bounded fallback for the remainder and review collisions before relying on it.",
              "", "## Files changed", "",
              "- `evtx_pipeline/normalize.py` — zero GUIDs normalize to NULL with explicit state classification; Security 4624 `LogonGuid` maps to `target_logon_guid`; standard `ipaddress` behavior handles valid special IPs.",
              "- `evtx_pipeline/schema.py` — schema 2.3.0 includes GUID-state columns and per-file import accounting.",
              "- `evtx_pipeline/cli.py` — adds constrained `profile-normalization` command; full SQLite mode remains rejected.",
              "- `evtx_pipeline/profile.py` — bounded streaming profile and report generation.",
              "- `tests/test_phase2a.py`, `tests/test_phase2b.py` — normalization, denominator, and streaming regressions.",
              "- `data/processed/attack_path_smoke.sqlite3` — existing 47-row smoke database upgraded with GUID-state flags; no full events were inserted.",
              "- `data/profiles/full_normalization_profile.json`, `data/reports/phase2b_full_profile_report.md` — Phase 2B outputs.",
              "", "## Future full-import command", "", "NOT EXECUTED — full SQLite import remains disabled:", "",
              "```powershell", 'python -m evtx_pipeline.cli normalize --input ".\\data\\staging\\evtx_jsonl_full" --database ".\\data\\processed\\attack_path.sqlite3" --mode full', "```", "",
              "## Final decision", ""]
    decision = "READY_WITH_ACTIONABLE_WARNINGS" if profile["timestamp_failures"] == 0 and profile["unknown_channels"] == 0 else "NOT_READY_FOR_FULL_IMPORT"
    lines.append(decision)
    return "\n".join(lines) + "\n"

