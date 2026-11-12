"""Parameters and output column lists of the gate (spec 02_gate sections 3 and 5; decisions 037-041).

WHY one frozen dataclass: every tunable value of a run is visible in one place, written into
stats.json, and a sensitivity run derives a copy with ``dataclasses.replace`` instead of mutating
module state. The clock constants are imported from the trial window step, never redefined, so
the window and the gate can never disagree on which trials are allowed (spec 2.2, decision 039).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from types import MappingProxyType
from typing import Mapping

from trial_window.params import (CLOCK_CHANGES_SUFFIX, CLOCK_CORRECTION_AVAILABLE, CLOCK_ONLY_TRIALS, OFFSETS_SUFFIX,
                                 PROCESSED_REL, QUARANTINE_DIR, QUARANTINE_PREFIX, RAW_TIME_CUTOFF_DATE, TIME_BASIS,
                                 WINDOWS_REL)

# 0.2.0 (T6b.2, decision 043): clock-corrected times, clock refusals, event_utc_corrected and clock columns.
TOOL_VERSION = "gate 0.2.0"

# Re-exported so callers import the gate's whole configuration from one module.
__all__ = ["GateParams", "TOOL_VERSION", "CLOCK_CORRECTION_AVAILABLE", "RAW_TIME_CUTOFF_DATE", "TIME_BASIS",
           "CLOCK_ONLY_TRIALS", "OFFSETS_SUFFIX", "CLOCK_CHANGES_SUFFIX",
           "QUARANTINE_PREFIX", "QUARANTINE_DIR", "WINDOWS_REL", "PROCESSED_REL", "DB_COLUMNS",
           "TRIGGER_COLUMNS", "UNMATCHED_COLUMNS", "DISPOSITION_COLUMNS", "SUPPORTING_COLUMNS",
           "DISPOSITIONS", "RULES", "SUPPORTING_RULES", "METHODS", "TIERS", "OUTPUT_FILES", "VIEW"]

VIEW = "events_dedup"

# Spec section 2: exactly these columns are read (no command_line; the gate never rebuilds what was typed).
DB_COLUMNS: tuple[str, ...] = (
    "event_uid", "host", "channel", "event_id", "record_id", "event_utc", "logon_type", "source_ip",
    "source_port", "destination_port", "initiated", "account_name", "domain_short", "target_logon_id",
    "target_linked_logon_id", "subject_logon_id", "session_id", "machine_account", "authentication_package",
    "image", "parent_image", "share_name", "relative_target_name", "service_name", "service_image_path",
    "target_image", "granted_access",
    # Decision 041: the remote end of an outbound Sysmon 3 (GT-02(c), GT-05).
    "destination_ip",
    # Decision 042: the host's own machine account (subject of its SYSTEM-opened 4624s), for evidence E2.
    "subject_account",
)

# Clock columns appended to every output row (spec 3 as amended in T6b.2, decision 043): the trial-level flags
# copied from the window row and the row-level clock_unreliable (spec 08 CO-09, CO-15).
CLOCK_COLUMNS: tuple[str, ...] = ("clock_flag", "clock_change_in_window", "clock_unreliable")

# Spec section 3, in the order listed there. T6b.2 (decision 043): event_utc is the ORIGINAL logged time and
# event_utc_corrected (= event_utc - offset_ms(host), CO-09) takes the place of the removed event_utc_raw.
TRIGGER_COLUMNS: tuple[str, ...] = (
    "trigger_id", "rule", "host", "event_utc", "event_utc_corrected", "trigger_event_uid", "anchor_logon_uid",
    "target_logon_id", "target_logon_id_hex", "logon_type", "source_ip", "ip_kind", "account_name",
    "domain_short", "authentication_package", "machine_account", "supporting_event_uids", "method",
    "candidate_count", "time_delta_ms", "gate_tier", "near_duplicate", "window_source", "time_basis",
) + CLOCK_COLUMNS
# "Same columns as triggers.csv minus rule" (spec 3); trigger_id kept, numbered <trial_id>-u<NNNN>.
UNMATCHED_COLUMNS: tuple[str, ...] = tuple(c for c in TRIGGER_COLUMNS if c != "rule")
DISPOSITION_COLUMNS: tuple[str, ...] = (
    "event_uid", "host", "event_id", "event_utc", "disposition", "reason_detail", "anchor_logon_uid",
    "event_utc_corrected",
) + CLOCK_COLUMNS
SUPPORTING_COLUMNS: tuple[str, ...] = (
    "rule", "event_uid", "host", "event_utc", "account_name", "session_id", "event_utc_corrected",
) + CLOCK_COLUMNS

# Precedence order, first match wins (spec 3).
DISPOSITIONS: tuple[str, ...] = (
    "excluded_source_ip", "excluded_source_ip_session", "interactive_logon", "system_logon_id",
    "loopback_or_self", "paired_excluded", "trigger", "supporting", "unmatched_remote", "no_rule",
)
RULES: tuple[str, ...] = ("R4_smb", "R5_rdp", "R6_service", "R8_winrm")
SUPPORTING_RULES: tuple[str, ...] = ("R1_lsass", "R3_explicit", "R8_parent")
# Decision 041 (re-amended): method/gate_tier describe the anchor tie only; service_name_time removed.
METHODS: tuple[str, ...] = ("logon_id", "ip_port_time", "ip_time", "none")
TIERS: tuple[str, ...] = ("A", "B", "D")

OUTPUT_FILES: tuple[str, ...] = ("triggers.csv", "unmatched_remote.csv", "dispositions.csv", "supporting.csv",
                                 "stats.json", "report.md", "run_info.json")


def _ro(mapping: dict) -> Mapping:
    """Read-only view so the frozen dataclass cannot be changed through a mapping field."""
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class GateParams:
    """Spec section 5 values. Times in seconds unless the name says otherwise."""

    # Decisions 032, 037: non-lab workstations; excluded by IP only, never by account.
    excluded_source_ips: frozenset[str] = frozenset({"192.168.50.97", "192.168.50.98", "192.168.50.99"})
    # Same values as src/log_check/params.py host_ip; used for the self check (GT-05).
    lab_host_ips: Mapping[str, str] = field(default_factory=lambda: _ro({
        "dc01": "192.168.50.10", "ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23",
    }))
    # Caldera is listed for display only: it is not a gated lab host, so it plays no part in the self check.
    display_host_ips: Mapping[str, str] = field(default_factory=lambda: _ro({"caldera": "192.168.50.50"}))
    system_logon_ids: frozenset[int] = frozenset({996, 997, 999})
    loopback: frozenset[str] = frozenset({"127.0.0.1", "::1", "::ffff:127.0.0.1"})
    rdp_pair_s: float = 5.0
    service_pair_s: float = 5.0
    winrm_pair_s: float = 5.0
    # Stored as ints so "0x1410" and "0x00001410" compare equal (hex case and leading zeros ignored).
    r1_access_masks: frozenset[int] = frozenset({0x1010, 0x1410, 0x143A, 0x1FFFFF})
    near_window_s: float = 300.0
    sensitivity_s: tuple[float, ...] = (2.0, 10.0)
    # Clock rule (spec 2.2 and 5 as amended in T6b.2, decision 043), taken from the window step so both refuse
    # the same trials: corrected times required; raw_time_cutoff_date is now only the CO-17 date.
    clock_correction_available: bool = CLOCK_CORRECTION_AVAILABLE
    raw_time_cutoff_date: date = RAW_TIME_CUTOFF_DATE
    time_basis: str = TIME_BASIS
    # Decision 034, spec 08 COA-04: measured for the clock offset method only, never gated.
    clock_only_trials: tuple[str, ...] = CLOCK_ONLY_TRIALS
