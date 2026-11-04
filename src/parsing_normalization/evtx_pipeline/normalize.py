"""Loss-aware normalization helpers for Phase 1 JSON event objects."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable

SCHEMA_VERSION = "2.3.0"
ZERO_GUID = "00000000-0000-0000-0000-000000000000"
RELEVANT_EVENT_IDS = {
    "Security": {4624, 4625, 4648, 4672, 4768, 4769, 4776, 4778, 4779, 5140, 5145, 4697},
    "Sysmon": {1, 3, 10, 11},
    "System": {7045},
    "PowerShell": {4103, 4104},
    "WinRM": {6, 91, 193},
}


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text and text.casefold() not in {"null", "none", "-", "n/a"} else None


def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _values(event: dict[str, Any]) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = {}

    def add(name: Any, value: Any) -> None:
        if name is not None:
            result.setdefault(_key(name), []).append(value)

    system = event.get("system")
    if isinstance(system, dict):
        for k, v in system.items():
            add(k, v)
    data = event.get("event_data")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                add(item.get("name"), item.get("value"))

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            tag = node.get("tag")
            if tag:
                add(tag, node.get("text"))
            for child in node.get("children", []) if isinstance(node.get("children"), list) else []:
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(event.get("user_data"))
    return result


def _raw_xml_metadata(event: dict[str, Any]) -> dict[str, Any]:
    """Read selected System metadata from Phase 1 raw XML without reopening EVTX."""
    xml_text = event.get("raw_xml")
    if not isinstance(xml_text, str) or not xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}
    found: dict[str, Any] = {}
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1].casefold()
        attrs = {str(k).casefold(): v for k, v in node.attrib.items()}
        if tag == "correlation" and attrs.get("activityid"):
            found["activity_id"] = attrs["activityid"]
        elif tag == "execution" and attrs.get("processid"):
            found["process_id"] = attrs["processid"]
    return found


def _first(values: dict[str, list[Any]], *aliases: str) -> Any:
    for alias in aliases:
        for value in values.get(_key(alias), []):
            if _clean(value) is not None:
                return value
    return None


def _raw_first(values: dict[str, list[Any]], *aliases: str) -> tuple[bool, Any]:
    for alias in aliases:
        items = values.get(_key(alias), [])
        if items:
            return True, items[0]
    return False, None


def classify_guid(raw: tuple[bool, Any]) -> str:
    """Classify a GUID field without conflating absent, blank, zero, or malformed values."""
    present, value = raw
    if not present:
        return "missing"
    if value is None or not str(value).strip():
        return "empty"
    text = str(value).strip()
    if text.casefold() in {"-", "null", "none", "n/a"}:
        return "placeholder"
    try:
        return "zero" if uuid.UUID(text.strip("{}() ")).int == 0 else "valid"
    except (ValueError, AttributeError, TypeError):
        return "malformed"


def to_int(value: Any) -> int | None:
    text = _clean(value)
    if text is None:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except (ValueError, TypeError):
        return None


def normalize_guid(value: Any) -> str | None:
    text = _clean(value)
    if text is None:
        return None
    text = text.strip("{}() ")
    try:
        parsed = uuid.UUID(text)
        return None if parsed.int == 0 else str(parsed).lower()
    except (ValueError, AttributeError, TypeError):
        return None


def normalize_ip(value: Any) -> str | None:
    text = _clean(value)
    if text is None:
        return None
    try:
        address = ipaddress.ip_address(text)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    except ValueError:
        return None


def normalize_timestamp(value: Any) -> tuple[str | None, int | None]:
    text = _clean(value)
    if text is None:
        return None, None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None, None
        utc = parsed.astimezone(timezone.utc)
        iso = utc.isoformat(timespec="microseconds").replace("+00:00", "Z")
        return iso, int(utc.timestamp() * 1000)
    except (ValueError, OverflowError):
        return None, None


def canonical_channel(value: Any, relative_path: str = "") -> str | None:
    text = str(value or "").casefold()
    path = relative_path.casefold()
    if "sysmon" in text:
        return "Sysmon"
    if "winrm" in text:
        return "WinRM"
    if "powershell" in text:
        return "PowerShell"
    if text == "security":
        return "Security"
    if text == "system":
        return "System"
    if "sysmon" in path:
        return "Sysmon"
    if "winrm" in path:
        return "WinRM"
    if "powershell" in path or "psoperational" in path or "psclassic" in path:
        return "PowerShell"
    if "security" in path:
        return "Security"
    if re.search(r"(?:^|[/_ ])system(?:$|[./_ ])", path):
        return "System"
    return None


def canonical_host(value: Any) -> str | None:
    text = _clean(value)
    if text is None:
        return None
    short = text.split(".", 1)[0].strip().casefold().replace("_", "-")
    match = re.search(r"(?:endpoint|ep)-?0?(\d+)", short)
    if match:
        return f"ep-{int(match.group(1)):02d}"
    if short.replace("-", "") in {"dc01", "dc1"}:
        return "DC01"
    return short


def scenario_from_path(relative_path: str, hints: dict[str, Any] | None = None) -> str | None:
    path = str(relative_path).replace("\\", "/")
    match = re.search(r"(?i)(?:^|[/_-])s(0?[1-7])(?:[/_.-]|$)", path)
    if match:
        return f"s{int(match.group(1)):02d}"
    claimed = _clean((hints or {}).get("claimed_scenario"))
    if claimed and re.fullmatch(r"(?i)s0?[1-7]", claimed):
        return f"s{int(claimed[1:]):02d}"
    return None


def _account(name: Any, domain: Any = None) -> str | None:
    value = _clean(name)
    dom = _clean(domain)
    if value is None:
        return None
    if "\\" in value or "@" in value or dom is None:
        return value.casefold()
    return f"{dom}\\{value}".casefold()


def _event_id(system: dict[str, Any], fields: dict[str, list[Any]]) -> int | None:
    return to_int(system.get("event_id") if isinstance(system, dict) else None) or to_int(_first(fields, "event_id", "id"))


def normalize_event(event: dict[str, Any], *, line_number: int = 1) -> dict[str, Any]:
    """Return normalized columns plus the untouched Phase 1 object as JSON text."""
    if not isinstance(event, dict):
        raise TypeError("Phase 1 JSONL event must be an object")
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    hints = event.get("hints") if isinstance(event.get("hints"), dict) else {}
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    relative_path = str(source.get("relative_path") or "")
    fields = _values(event)
    xml_metadata = _raw_xml_metadata(event)
    channel_raw = system.get("channel")
    channel = canonical_channel(channel_raw, relative_path)
    event_id = _event_id(system, fields)
    record_id = to_int(system.get("event_record_id") or _first(fields, "event_record_id", "record_id"))
    timestamp_raw = system.get("timestamp_raw") or _first(fields, "UtcTime", "TimeCreated", "timestamp")
    timestamp_utc, epoch_ms = normalize_timestamp(timestamp_raw)
    scenario_id = scenario_from_path(relative_path, hints)
    host_raw = system.get("computer") or hints.get("host_from_path")
    path_parts = PurePosixPath(relative_path.replace("\\", "/")).parts
    system_host = canonical_host(host_raw)
    path_host = canonical_host(path_parts[0]) if path_parts else None
    known_dataset_hosts = {"ep-01", "ep-02", "ep-03", "DC01"}
    host = (system_host if system_host in known_dataset_hosts else
            path_host if path_host in known_dataset_hosts else system_host or path_host)

    domain = _clean(_first(fields, "TargetDomainName", "SubjectDomainName", "AccountDomain", "Domain"))
    target_account = _account(_first(fields, "TargetUserName", "AccountName", "UserName", "User"),
                              _first(fields, "TargetDomainName", "AccountDomain", "Domain"))
    subject_account = _account(_first(fields, "SubjectUserName", "SubjectUser", "CallerUserName"),
                               _first(fields, "SubjectDomainName", "SubjectDomain"))
    account = target_account or subject_account or _account(_first(fields, "User", "UserName", "AccountName"), domain)
    source_ip = normalize_ip(_first(fields, "IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "RemoteAddress"))
    destination_ip = normalize_ip(_first(fields, "DestAddress", "DestinationAddress", "DestinationIp", "TargetAddress"))
    source_host = canonical_host(_first(fields, "WorkstationName", "SourceHostname", "SourceHost", "ClientName"))
    destination_host = canonical_host(_first(fields, "TargetServerName", "DestinationHostname", "DestinationHost", "ServerName"))
    logon_guid = normalize_guid(_first(fields, "LogonGuid", "LogonGUID"))
    target_guid_aliases = ("TargetLogonGuid", "TargetLogonGUID")
    if channel == "Security" and event_id == 4624:
        target_guid_aliases += ("LogonGuid", "LogonGUID")
    target_logon_guid = normalize_guid(_first(fields, *target_guid_aliases))
    target_guid_raw = _raw_first(fields, *target_guid_aliases)
    process_guid = normalize_guid(_first(fields, "ProcessGuid", "ProcessGUID", "SourceProcessGUID"))
    parent_process_guid = normalize_guid(_first(fields, "ParentProcessGuid", "ParentProcessGUID"))
    source_file = source.get("relative_path")
    source_file_id = hashlib.sha256((str(source_file or "") + "\0" + str(source.get("sha256") or "")).encode()).hexdigest()
    raw_event = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    raw_digest = hashlib.sha256(raw_event.encode("utf-8")).hexdigest()
    uid_material = "\0".join((scenario_id or "", source_file_id, str(line_number), raw_digest))
    event_uid = hashlib.sha256(uid_material.encode("utf-8")).hexdigest()
    raw_channel_fields = {k: vals for k, vals in fields.items() if vals}

    subject_logon_id = to_int(_first(fields, "SubjectLogonId", "SubjectLogonID"))
    target_logon_id = to_int(_first(fields, "TargetLogonId", "TargetLogonID"))
    session_id = to_int(_first(fields, "SessionId", "SessionID", "TargetLogonId", "SubjectLogonId", "LogonId"))
    account_for_flag = (account or "").casefold()
    predefined = account_for_flag in {"system", "nt authority\\system", "local service", "nt authority\\local service",
                                        "network service", "nt authority\\network service", "anonymous logon"} or session_id in {996, 997, 998, 999}
    service_name = _clean(_first(fields, "ServiceName"))
    service_image_path = _clean(_first(fields, "ImagePath", "ServiceFileName"))
    if channel == "Security" and event_id == 4697 or channel == "System" and event_id == 7045:
        service_name = service_name or _clean(_first(fields, "param1"))
        service_image_path = service_image_path or _clean(_first(fields, "param2"))
    spn = _clean(_first(fields, "ServicePrincipalName", "SPN"))
    if spn is None and channel == "Security" and event_id in {4768, 4769}:
        spn = _clean(_first(fields, "ServiceName"))
    return {
        "scenario_id": scenario_id, "scenario_hint_raw": _clean(hints.get("claimed_scenario")),
        "event_uid": event_uid, "timestamp_utc": timestamp_utc,
        "epoch_ms": epoch_ms, "host": host, "host_hint_raw": _clean(hints.get("host_from_path")),
        "export_host": _clean(system.get("computer")),
        "source_host": source_host, "destination_host": destination_host, "channel": channel,
        "channel_raw": _clean(channel_raw), "event_id": event_id, "record_id": record_id,
        "account": account, "subject_account": subject_account, "target_account": target_account,
        "domain": domain, "session_id": session_id, "subject_logon_id": subject_logon_id,
        "target_logon_id": target_logon_id, "logon_guid": logon_guid,
        "target_logon_guid": target_logon_guid,
        "logon_guid_state": classify_guid(_raw_first(fields, "LogonGuid", "LogonGUID")),
        "target_logon_guid_state": classify_guid(target_guid_raw),
        "logon_type": to_int(_first(fields, "LogonType")),
        "authentication_package": _clean(_first(fields, "AuthenticationPackageName", "AuthenticationPackage")),
        "source_ip": source_ip, "source_port": to_int(_first(fields, "SourcePort", "SrcPort")),
        "destination_ip": destination_ip, "destination_port": to_int(_first(fields, "DestPort", "DestinationPort", "DstPort")),
        "workstation_name": _clean(_first(fields, "WorkstationName")),
        "client_name": _clean(_first(fields, "ClientName", "ClientHostname")),
        "session_name": _clean(_first(fields, "SessionName", "ShellName")),
        "process_guid": process_guid, "parent_process_guid": parent_process_guid,
        "process_id": to_int(_first(fields, "ProcessId", "ProcessID", "NewProcessId", "SourceProcessId") or xml_metadata.get("process_id")),
        "parent_process_id": to_int(_first(fields, "ParentProcessId", "ParentProcessID")),
        "image": _clean(_first(fields, "Image", "NewProcessName", "ProcessName", "Application")),
        "parent_image": _clean(_first(fields, "ParentImage", "ParentProcessName")),
        "command_line": _clean(_first(fields, "CommandLine", "ProcessCommandLine")),
        "target_image": _clean(_first(fields, "TargetImage", "ServiceFileName")),
        "target_filename": _clean(_first(fields, "TargetFilename", "ObjectName", "FileName")),
        "share_name": _clean(_first(fields, "ShareName", "Share")),
        "share_path": _clean(_first(fields, "ShareLocalPath", "RelativeTargetName", "SharePath")),
        "service_name": service_name,
        "service_image_path": service_image_path,
        "spn": spn,
        "winrm_activity_id": normalize_guid(_first(fields, "ActivityID", "ActivityId", "ActivityIdentifier") or xml_metadata.get("activity_id")),
        "powershell_host_application": _clean(_first(fields, "HostApplication")),
        "source_file_id": source_file_id, "source_relative_path": relative_path,
        "source_sha256": _clean(source.get("sha256")), "machine_account": int(bool(account and account.endswith("$"))),
        "predefined_session": int(predefined), "field_values_json": json.dumps(raw_channel_fields, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
        "raw_event": raw_event, "raw_event_sha256": raw_digest,
    }


def event_field_presence(normalized: dict[str, Any]) -> set[str]:
    return {key for key in (
        "account", "session_id", "logon_guid", "target_logon_guid", "process_guid", "parent_process_guid",
        "source_ip", "destination_ip", "source_port", "destination_port", "service_name", "share_name",
        "share_path", "spn", "winrm_activity_id", "powershell_host_application", "image", "timestamp_utc", "host",
    ) if normalized.get(key) is not None}


def normalization_issues(event: dict[str, Any], normalized: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Return genuine parse/conversion failures; absent fields are not errors."""
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    values = _values(event)
    issues: list[tuple[str, str, str]] = []

    def supplied(raw: Any) -> bool:
        return _clean(raw) is not None

    event_id_raw = system.get("event_id") or _first(values, "event_id", "id")
    if supplied(event_id_raw) and normalized["event_id"] is None:
        issues.append(("event_id", "invalid_integer", "Event ID was present but could not be parsed as an integer."))
    record_raw = system.get("event_record_id") or _first(values, "event_record_id", "record_id")
    if supplied(record_raw) and normalized["record_id"] is None:
        issues.append(("record_id", "invalid_integer", "Record ID was present but could not be parsed as an integer."))
    timestamp_raw = system.get("timestamp_raw") or _first(values, "UtcTime", "TimeCreated", "timestamp")
    if supplied(timestamp_raw) and normalized["timestamp_utc"] is None:
        issues.append(("timestamp_utc", "invalid_or_timezone_missing", "Timestamp was preserved in raw_event but could not be normalized to UTC."))
    numeric_fields = {
        "session_id": ("SessionId", "SessionID", "TargetLogonId", "SubjectLogonId", "LogonId"),
        "logon_type": ("LogonType",), "source_port": ("SourcePort", "SrcPort"),
        "destination_port": ("DestPort", "DestinationPort", "DstPort"),
        "process_id": ("ProcessId", "ProcessID", "NewProcessId", "SourceProcessId"),
        "parent_process_id": ("ParentProcessId", "ParentProcessID"),
    }
    for field_name, aliases in numeric_fields.items():
        raw = _first(values, *aliases)
        if supplied(raw) and normalized.get(field_name) is None:
            issues.append((field_name, "invalid_integer", f"{field_name} was present but was not a valid integer."))
    guid_fields = {
        "logon_guid": ("LogonGuid", "LogonGUID"), "target_logon_guid": ("TargetLogonGuid", "TargetLogonGUID"),
        "process_guid": ("ProcessGuid", "ProcessGUID", "SourceProcessGUID"),
        "parent_process_guid": ("ParentProcessGuid", "ParentProcessGUID"),
        "winrm_activity_id": ("ActivityID", "ActivityId", "ActivityIdentifier"),
    }
    if normalized.get("channel") == "Security" and normalized.get("event_id") == 4624:
        guid_fields["target_logon_guid"] = ("TargetLogonGuid", "TargetLogonGUID", "LogonGuid", "LogonGUID")
    for field_name, aliases in guid_fields.items():
        raw = _first(values, *aliases)
        if supplied(raw) and normalized.get(field_name) is None and classify_guid((True, raw)) not in {"zero", "placeholder"}:
            issues.append((field_name, "invalid_guid", f"{field_name} was present but was not a valid GUID."))
    ip_fields = {
        "source_ip": ("IpAddress", "SourceAddress", "SourceIp", "ClientAddress", "RemoteAddress"),
        "destination_ip": ("DestAddress", "DestinationAddress", "DestinationIp", "TargetAddress"),
    }
    for field_name, aliases in ip_fields.items():
        raw = _first(values, *aliases)
        if supplied(raw) and normalized.get(field_name) is None and _clean(raw) != "-":
            issues.append((field_name, "invalid_ip", f"{field_name} was present but was not a valid IP address."))
    return issues


def exact_duplicate_digest(normalized: dict[str, Any]) -> str:
    """Hash event content without Phase 1 source provenance for duplicate candidates."""
    try:
        obj = json.loads(normalized["raw_event"])
        payload = _duplicate_payload(obj)
    except (ValueError, TypeError):
        payload = normalized["raw_event"]
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def exact_duplicate_digest_from_event(event: dict[str, Any]) -> str:
    """Compute the content-only digest while the original object is already in hand."""
    return hashlib.sha256(_duplicate_payload(event).encode("utf-8")).hexdigest()


def _duplicate_payload(obj: dict[str, Any]) -> str:
    content = (obj.get("system", {}) if isinstance(obj.get("system"), dict) else {}) | {
        "event_data": obj.get("event_data"), "user_data": obj.get("user_data")}
    return json.dumps(content, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

