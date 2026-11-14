"""Parameters and constants of the stitcher (spec 03_stitch sections 2 and 5; decisions 044, 046, 047).

WHY one frozen dataclass: every tunable value is visible in one place, can be written into a stats file,
and a sensitivity run derives a copy with ``dataclasses.replace`` instead of mutating module state. Values
another stage already defines (the development allowlist, lab host IPs, system logon IDs) are imported,
never copied, so the stitcher cannot disagree with the clock step or the gate (spec 5: "one definition").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from clock_offset.params import BOOT_EVENT_IDS, DEVELOPMENT_TRIALS
from gate.params import GateParams

TOOL_VERSION = "stitch 0.1.0"
VIEW = "events_dedup"

# Spec section 2, in spec order. Checked for PRESENCE only: a DB lacking any of them is refused (ST-00) even
# if T7.2 does not select it yet, so a later step (T7.3+) never meets a missing column mid-run.
SPEC_DB_COLUMNS: tuple[str, ...] = (
    "event_uid", "host", "channel", "event_id", "record_id", "event_utc", "logon_type", "source_ip",
    "source_port", "destination_ip", "destination_port", "destination_host", "initiated", "account_name",
    "subject_account", "target_logon_id", "target_linked_logon_id", "subject_logon_id", "session_id",
    "logon_guid", "authentication_package", "image", "parent_image", "command_line", "process_guid",
    "parent_process_guid", "process_id", "share_name", "relative_target_name", "service_name",
    "service_image_path", "source_image", "target_image", "granted_access", "machine_account",
    "field_values_json",
)

# What the scan selects. WHY no command text columns: the scan is event level only, so no command text can
# reach the index, tests, outputs or reports (plan T7.2 limits; spec 00 LC-13). Command text and the 4648
# JSON fields are read by uid in ``cmdtext.py`` only (decision 048 item 1). The last seven columns are the
# non-command fields of the T7.3 link kinds (048 item 2): GUID (ST-47), share / service artefacts (ST-30..33),
# 4648 target and subject (ST-42).
SCAN_COLUMNS: tuple[str, ...] = (
    "event_uid", "host", "channel", "event_id", "record_id", "event_utc", "logon_type", "account_name",
    "target_logon_id", "target_linked_logon_id", "subject_logon_id", "session_id", "process_guid",
    "parent_process_guid", "process_id", "image", "parent_image", "source_image", "target_image",
    "machine_account", "authentication_package", "source_ip", "source_port", "destination_ip",
    "destination_port", "initiated",
    "logon_guid", "share_name", "relative_target_name", "service_name", "service_image_path",
    "destination_host", "subject_account",
)

_FORBIDDEN_SCAN = {"command_line", "field_values_json"}
if _FORBIDDEN_SCAN & set(SCAN_COLUMNS):  # WHY at import: a later edit must never select command text silently
    raise ImportError(f"SCAN_COLUMNS must not contain {sorted(_FORBIDDEN_SCAN & set(SCAN_COLUMNS))}")
if not set(SCAN_COLUMNS) <= set(SPEC_DB_COLUMNS):
    raise ImportError(f"SCAN_COLUMNS not in spec section 2: {sorted(set(SCAN_COLUMNS) - set(SPEC_DB_COLUMNS))}")

# T7.3 vocabularies (spec 03_stitch section 3, ST-30..ST-43; decision 048). WHY here: later modules and the
# check file must spell each value the same way, and a test can compare them with the spec.
METHODS: tuple[str, ...] = ("sysmon3_port", "source_4648", "cmdline_target", "target_only")
ARTEFACT_KINDS: tuple[str, ...] = ("share_burst", "service_install", "winrm_host", "winrm_91", "rdp_connection",
                                   "followup_logon")
TARGET_ONLY_REASONS: tuple[str, ...] = ("source_host_unknown", "source_host_no_logs", "no_evidence_in_range")

# Decision 046: the stitcher runs on the nine development trials only, until T10. Imported, never copied.
ALLOWED_TRIALS: tuple[str, ...] = DEVELOPMENT_TRIALS

# Decision 047 item 3 (ST-10 as amended): boot events grouped by kind, System channel only.
BOOT_CHANNEL = "System"
BOOT_STARTUP_IDS: frozenset[int] = frozenset({41, 6005, 6008})
BOOT_SHUTDOWN_IDS: frozenset[int] = frozenset({1074, 6006})
# WHY checked at import: the clock step (CO-15) and the stitcher must mean the same events by "boot".
if BOOT_STARTUP_IDS | BOOT_SHUTDOWN_IDS != BOOT_EVENT_IDS or BOOT_STARTUP_IDS & BOOT_SHUTDOWN_IDS:
    raise ImportError(f"stitch boot ids {sorted(BOOT_STARTUP_IDS | BOOT_SHUTDOWN_IDS)} disagree with "
                      f"clock_offset.params.BOOT_EVENT_IDS {sorted(BOOT_EVENT_IDS)}")

# ST-63 names Security 1102 only as a log clear (decision 047 item 7).
LOG_CLEAR_EVENTS: frozenset[tuple[str, int]] = frozenset({("Security", 1102)})

# Spec section 2: the gate outputs the stitcher reads; every one must exist (ST-00).
GATE_FILES: tuple[str, ...] = ("triggers.csv", "unmatched_remote.csv", "supporting.csv", "dispositions.csv",
                               "stats.json")
GATE_OUT_REL = "out/gate"

# T7.2 development check output (plan section 2): counts only, never a spec 3 file.
CHECK_OUT_REL = "out/stitch_check"

_GATE_DEFAULTS = GateParams()


@dataclass(frozen=True)
class StitchParams:
    """Spec section 5 values, in seconds. Frozen on the development trials (spec 5 "Freeze")."""

    group_gap_s: float = 2.0                              # ST-20, 044 (b)
    group_review_band_s: tuple[float, float] = (1.0, 3.0)  # ST-20 flags
    burst_gap_s: float = 5.0                              # ST-30
    copy_install_s: float = 10.0                          # ST-32
    port_join_s: float = 5.0                              # ST-41, decision 014
    link_lookback_s: float = 30.0                         # ST-42/43, 044 (b)
    link_after_s: float = 15.0                            # ST-42/43, 044 (b)
    order_tol_s: float = 5.0                              # ST-62, ST-72, decision 014
    order_unc_floor_s: float = 2.5                        # ST-62, 044 (c)
    followup_max_s: float = 30.0                          # ST-26, owner Q10
    process_collapse_s: float = 2.0                       # ST-11, spec 00 LC-04f
    boot_group_s: float = 120.0                           # ST-10, decision 047
    # Spec 5: "as src/gate/params.py", one definition.
    lab_host_ips: Mapping[str, str] = field(default_factory=lambda: _GATE_DEFAULTS.lab_host_ips)
    system_logon_ids: frozenset[int] = _GATE_DEFAULTS.system_logon_ids
