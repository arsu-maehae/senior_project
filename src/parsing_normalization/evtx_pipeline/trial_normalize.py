"""Per-trial field-level normalisation (spec 01_normalise_fixes, pass A).

This module wraps the reviewed ``normalize_event`` and overrides only the
fields the spec changes.  The old function, ``full_import.py`` and their tests
stay untouched (decision 006).  Everything here is pure: no DB, no file I/O.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

from .normalize import (
    RELEVANT_EVENT_IDS,
    _clean,
    _first,
    _values,
    canonical_host,
    exact_duplicate_digest_from_event,
    normalize_event,
    normalize_guid,
    normalize_ip,
    normalize_timestamp,
    to_int,
)

# NF-10: the one place where the host set lives (lowercase).
HOSTS: tuple[str, ...] = ("dc01", "ep-01", "ep-02", "ep-03")

# NF-09 / decision 004: old relevant set plus logoffs, 4688 and log-state events.
TRIAL_RELEVANT_EVENT_IDS: dict[str, set[int]] = {
    channel: set(ids) for channel, ids in RELEVANT_EVENT_IDS.items()
}
TRIAL_RELEVANT_EVENT_IDS["Security"] |= {1102, 4634, 4647, 4688}
TRIAL_RELEVANT_EVENT_IDS["System"] |= {104, 6005, 6006, 6008, 41, 1074}
# NF-09 amended / decision 043 / spec 08 CO-18 (new ingests only): clock-change
# events, so a clock step inside a trial is visible to clock_offset (CO-15).
# Security 4616 = system time changed; System 1 = Kernel-General time change,
# restricted by provider below because other System providers reuse id 1.
TRIAL_RELEVANT_EVENT_IDS["Security"] |= {4616}
TRIAL_RELEVANT_EVENT_IDS["System"] |= {1}

# CO-18: (channel, event id) pairs kept only for one provider.  The DB has no
# provider column, so this check must happen at ingest time.
PROVIDER_RESTRICTED: dict[tuple[str, int], str] = {("System", 1): "Microsoft-Windows-Kernel-General"}

# NF-11: which logon-id column is "the session" for each Security event.
_SESSION_TARGET_EVENTS = {4624, 4634}
_SESSION_TARGET_THEN_SUBJECT_EVENTS = {4647}  # real 4647 rows carry only TargetLogonId
_SESSION_SUBJECT_EVENTS = {4648, 4672, 4688, 5140, 5145}
# NF-13: events for which a "predefined session" flag has any meaning.
_PREDEFINED_EVENTS = {4624, 4634, 4647, 4648, 4672}
_PREDEFINED_LOGON_IDS = {996, 997, 998, 999}
_WINRM_RESOURCE_RE = re.compile(r"\(\s*([^\\\s()]+)\\([^\s()]+)\s+clientIP:\s*([0-9a-fA-F:.]+(?:%[^\s()]+)?)\s*\)")
_PREDEFINED_NAMES = {"system", "local service", "network service", "anonymous logon"}


def is_relevant(channel: str | None, event_id: int | None, provider: str | None = None) -> bool:
    """NF-09: True if (channel, event id) belongs in the analysis DB.

    WHY: the DB keeps only events the stitcher or the log-state checks need,
    which keeps the per-trial SQLite file small.  For a pair listed in
    ``PROVIDER_RESTRICTED`` (CO-18: System 1) the provider must match too,
    because the same id from another provider (e.g. resume from sleep) is not
    a clock change and the DB could not tell them apart later.  A missing
    provider is not kept.  Every other pair ignores ``provider``.
    """
    if (channel is None or event_id is None or channel not in TRIAL_RELEVANT_EVENT_IDS
            or event_id not in TRIAL_RELEVANT_EVENT_IDS[channel]):
        return False
    required = PROVIDER_RESTRICTED.get((channel, event_id))
    if required is None:
        return True
    return isinstance(provider, str) and provider.strip().casefold() == required.casefold()


def host_lower(value: Any) -> str | None:
    """NF-10/NF-15: one lowercase host style for host, source_host, destination_host.

    WHY: ``canonical_host`` returns 'DC01' but 'ep-01'; mixed case breaks joins.
    """
    host = canonical_host(value)
    return host.lower() if host else None


def host_from_relative_path(relative_path: str) -> str:
    """NF-15: host = first folder of source.relative_path; must be in HOSTS.

    WHY: the export 'Computer' field is unreliable (default WIN-... names);
    the folder is set by the lab layout. Unknown folder fails the import.
    """
    parts = PurePosixPath(str(relative_path).replace("\\", "/")).parts
    host = parts[0].lower() if len(parts) > 1 else ""
    if host not in HOSTS:
        raise ValueError(f"host folder {parts[0] if parts else ''!r} of {relative_path!r} not in HOSTS {HOSTS}")
    return host


def split_domain_user(value: Any) -> tuple[str | None, str | None]:
    """NF-18: split 'DOMAIN\\user' into (domain, user); no prefix gives (None, user).

    WHY: Sysmon User/SourceUser carry the domain inside the string.
    """
    text = _clean(value)
    if text is None:
        return None, None
    if "\\" in text:
        dom, _, user = text.partition("\\")
        return _clean(dom), _clean(user)
    return None, text


def bare_account_name(value: Any) -> str | None:
    """NF-04: bare lowercase user name; strips DOMAIN\\ and @REALM, keeps trailing '$'.

    WHY: 4769 gives 'svc@LAB.LOCAL', 4624 gives 'svc' + 'LAB'; both must match.
    """
    text = _clean(value)
    if text is None:
        return None
    if "\\" in text:
        text = text.rsplit("\\", 1)[1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.strip().casefold() or None


def domain_short(domain: Any) -> str | None:
    """NF-18: first label before '.', lowercase ('LAB.LOCAL' -> 'lab')."""
    text = _clean(domain)
    return text.split(".", 1)[0].strip().casefold() if text else None


def logon_id_or_none(value: Any) -> int | None:
    """NF-11/decision 005: integer logon id, with 0 (no session) stored as NULL.

    WHY: a join on 0 would glue unrelated events together.
    """
    number = to_int(value)
    return None if number in (None, 0) else number


def _guid_text(value: Any) -> str | None:
    return normalize_guid(value)


def _pick_session_id(channel: str | None, event_id: int | None, fields: dict[str, list[Any]]) -> int | None:
    """NF-11: choose the logon-id column by event id (not a fallback chain)."""
    if channel == "Security":
        if event_id in _SESSION_TARGET_EVENTS:
            return logon_id_or_none(_first(fields, "TargetLogonId", "TargetLogonID"))
        if event_id in _SESSION_TARGET_THEN_SUBJECT_EVENTS:
            return (logon_id_or_none(_first(fields, "TargetLogonId", "TargetLogonID"))
                    or logon_id_or_none(_first(fields, "SubjectLogonId", "SubjectLogonID")))
        if event_id in _SESSION_SUBJECT_EVENTS:
            return logon_id_or_none(_first(fields, "SubjectLogonId", "SubjectLogonID"))
        if event_id in {4778, 4779}:  # NF-25: reconnect/disconnect carry LogonID
            return logon_id_or_none(_first(fields, "LogonID", "LogonId"))
    elif channel == "Sysmon" and event_id == 1:
        return logon_id_or_none(_first(fields, "LogonId", "LogonID"))
    return None


def _predefined_session(channel: str | None, event_id: int | None, session_id: int | None,
                        owner_name: str | None) -> int:
    """NF-13: 1 only for Security 4624/4634/4647/4648/4672 with a predefined id or name.

    WHY: the process owner of a Sysmon row (e.g. SYSTEM on an SMB connection)
    says nothing about a logon session, so Sysmon never sets this flag.
    """
    if channel != "Security" or event_id not in _PREDEFINED_EVENTS:
        return 0
    return int(session_id in _PREDEFINED_LOGON_IDS or owner_name in _PREDEFINED_NAMES)


def parse_winrm_resource_uri(value: Any) -> tuple[str, str, str | None] | None:
    """NF-21: (domain, user, client_ip) from a resourceUri ending in "(DOMAIN-slash-user clientIP: a.b.c.d)", else None.

    WHY: WinRM 91 carries the remote account and client address only inside
    this one string; without parsing, those rows cannot join to 4624.
    """
    text = _clean(value)
    match = _WINRM_RESOURCE_RE.search(text) if text else None
    if not match:
        return None
    # Strip an IPv6 zone id ('%4'); an address that still fails to parse gives None, account kept.
    return match.group(1), match.group(2), normalize_ip(match.group(3).split("%", 1)[0])


def parse_sysmon_utc_time(value: Any) -> str | None:
    """NF-23: Sysmon UtcTime ('2026-09-24 05:38:02.691', no zone) as UTC ISO text.

    WHY: Sysmon's UtcTime is UTC by definition; normalize_timestamp rejects
    zone-less text, so the zone is added here.
    """
    text = _clean(value)
    if text is None:
        return None
    if not re.search(r"(Z|[+-]\d\d:?\d\d)$", text):
        text = text.replace(" ", "T") + "+00:00"
    return normalize_timestamp(text)[0]


def _sysmon_identity(event_id: int | None, fields: dict[str, list[Any]]) -> dict[str, Any]:
    """NF-05/NF-14/NF-18: Sysmon account columns from User / SourceUser / TargetUser."""
    out: dict[str, Any] = {}
    if event_id == 10:
        s_dom, s_user = split_domain_user(_first(fields, "SourceUser"))
        _, t_user = split_domain_user(_first(fields, "TargetUser"))
        raw_s, raw_t = _clean(_first(fields, "SourceUser")), _clean(_first(fields, "TargetUser"))
        out.update(subject_account=raw_s.casefold() if raw_s else None,
                   target_account=raw_t.casefold() if raw_t else None,
                   _dom=s_dom, _name=s_user)
    else:
        raw = _clean(_first(fields, "User"))
        dom, user = split_domain_user(raw)
        out.update(subject_account=raw.casefold() if raw else None, target_account=None,
                   _dom=dom, _name=user)
    return out


def normalize_trial_event(event: dict[str, Any], *, scenario_id: str, trial_id: str,
                          line_number: int) -> dict[str, Any]:
    """Return one normalised trial row (NF-01 .. NF-18); raises ValueError on bad input.

    WHY a wrapper: ``normalize_event`` stays byte-for-byte the same for the old
    importer; this function overrides only what the spec changes, so every
    other column keeps its reviewed behaviour.
    """
    row = normalize_event(event, line_number=line_number)
    source = event.get("source") if isinstance(event.get("source"), dict) else {}
    system = event.get("system") if isinstance(event.get("system"), dict) else {}
    fields = _values(event)
    channel, event_id = row["channel"], row["event_id"]

    # NF-01 / NF-16: scenario and trial come from arguments; uid includes both.
    row["scenario_id"], row["trial_id"] = scenario_id, trial_id
    row["event_uid"] = hashlib.sha256("\0".join((
        scenario_id, trial_id, row["source_file_id"], str(line_number), row["raw_event_sha256"],
    )).encode("utf-8")).hexdigest()
    row["raw_event"] = None
    row["source_line"] = line_number
    row["duplicate_content_sha256"] = exact_duplicate_digest_from_event(event)

    # NF-15: host from folder; Computer to export_host; same lowercase function for the rest.
    row["host"] = host_from_relative_path(str(source.get("relative_path") or ""))
    row["export_host"] = _clean(system.get("computer"))
    row["source_host"] = host_lower(_first(fields, "WorkstationName", "SourceHostname", "SourceHost", "ClientName"))
    row["destination_host"] = host_lower(_first(fields, "TargetServerName", "DestinationHostname",
                                                "DestinationHost", "ServerName"))

    # NF-17: no row without a timestamp.
    if row["timestamp_utc"] is None:
        raise ValueError(f"NULL timestamp_utc at line {line_number} ({channel} {event_id})")

    # NF-03: IpPort is a source-port alias; 0 stays 0.
    row["source_port"] = to_int(_first(fields, "SourcePort", "SrcPort", "IpPort"))

    # NF-06: no XML Execution ProcessID fallback outside Sysmon/PowerShell.
    if channel in {"Security", "System", "WinRM"}:
        row["process_id"] = to_int(_first(fields, "ProcessId", "ProcessID", "NewProcessId", "SourceProcessId"))

    # NF-05/NF-14/NF-18: Sysmon identity and typed columns; LogonGuid moves out of logon_guid.
    row.update(source_image=None, granted_access=None, target_process_guid=None,
               initiated=None, sysmon_logon_guid=None)
    sysmon_dom = None
    name_source: Any = row["account"]
    if channel == "Sysmon":
        ident = _sysmon_identity(event_id, fields)
        row["subject_account"], row["target_account"] = ident["subject_account"], ident["target_account"]
        sysmon_dom, name_source = ident["_dom"], ident["_name"]
        row["sysmon_logon_guid"] = _guid_text(_first(fields, "LogonGuid", "LogonGUID"))
        row["logon_guid"] = None
        row["logon_guid_state"] = row["target_logon_guid_state"] = "not_applicable"
        if event_id == 10:
            row["source_image"] = _clean(_first(fields, "SourceImage"))
            row["granted_access"] = _clean(_first(fields, "GrantedAccess"))
            row["target_process_guid"] = _guid_text(_first(fields, "TargetProcessGUID", "TargetProcessGuid"))
        elif event_id == 3:
            flag = (_clean(_first(fields, "Initiated")) or "").casefold()
            row["initiated"] = 1 if flag == "true" else 0 if flag == "false" else None

    # NF-21: WinRM 91 account and client IP from resourceUri.
    if channel == "WinRM" and event_id == 91:
        parsed = parse_winrm_resource_uri(_first(fields, "resourceUri"))
        if parsed:
            dom, user, ip = parsed
            sysmon_dom, name_source = dom, user
            row["domain"] = dom
            row["account"] = row["account"] or (dom + "\\" + user).casefold()
            row["source_ip"] = row["source_ip"] or ip

    # NF-22: 5145 relative target name (share_path unchanged).
    row["relative_target_name"] = (_clean(_first(fields, "RelativeTargetName"))
                                   if channel == "Security" and event_id == 5145 else None)

    # NF-23: event_utc = Sysmon UtcTime, else the record time.
    row["event_utc"] = (parse_sysmon_utc_time(_first(fields, "UtcTime")) if channel == "Sysmon" else None)         or row["timestamp_utc"]

    # NF-24: 4688 process ids (new process / creator).
    if channel == "Security" and event_id == 4688:
        row["process_id"] = to_int(_first(fields, "NewProcessId"))
        row["parent_process_id"] = to_int(_first(fields, "ProcessId"))

    # NF-04/NF-18: bare name, domain, short domain, machine flag.
    if sysmon_dom is not None:
        row["domain"] = sysmon_dom
    row["account_name"] = bare_account_name(name_source)
    row["domain_short"] = domain_short(row["domain"])
    row["machine_account"] = int(bool(row["account_name"] and row["account_name"].endswith("$")))

    # NF-11/NF-12: session by event id; logon id 0 becomes NULL.
    row["session_id"] = _pick_session_id(channel, event_id, fields)
    row["subject_logon_id"] = logon_id_or_none(_first(fields, "SubjectLogonId", "SubjectLogonID"))
    row["target_logon_id"] = logon_id_or_none(_first(fields, "TargetLogonId", "TargetLogonID"))
    row["target_linked_logon_id"] = logon_id_or_none(_first(fields, "TargetLinkedLogonId"))

    # NF-13: predefined session, judged on the session owner (target for 4624/4634, else subject).
    owner = row["target_account"] if event_id in _SESSION_TARGET_EVENTS else row["subject_account"]
    row["predefined_session"] = _predefined_session(channel, event_id, row["session_id"],
                                                    bare_account_name(owner))
    return row
