"""Parameters and output column lists of the clock offset step (spec 08_clock_offset sections 3 and 5; decision 043).

WHY a separate file with constants only: spec 08 section 5 freezes the parameters (ATK-10). The
SHA-256 of this file is recorded in decision 043 before the step-2 rerun check (COT-17), so it must
hold no timestamps or generated content, and every value the estimate depends on is visible here.
Values shared with the trial window step are imported from it, never redefined, so both steps agree
on which trials are quarantined or excluded and on the 2026-10-26 date.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from trial_window.params import (EXCLUDED_TRIALS, MARGIN_END_S, PROCESSED_REL, QUARANTINE_DIR, QUARANTINE_PREFIX,
                                 RAW_TIME_CUTOFF_DATE)

__all__ = ["PAIR_PAD_S", "DC_EDGE_S", "MIN_PAIRS", "MAX_LOO_SHIFT_S", "READING_AGREE_S", "CHECK_PORTS",
           "MAX_PAIR_DELTA_S", "CHECK_JOIN_S", "CHECK_REVIEW_S", "CHECK_KILL_S", "MIN_CLOCK_STEP_MS", "METHOD",
           "CHECK_METHOD",
           "TOOL_VERSION", "ENDPOINTS", "REFERENCE_HOST", "HOSTS", "LAB_HOST_IPS", "BOOT_EVENT_IDS",
           "CLOCK_CHANGE_EVENTS", "DEVELOPMENT_TRIALS", "CLOCK_ONLY_TRIALS", "DEFAULT_TRIALS",
           "EXCLUDED_TRIALS", "QUARANTINE_PREFIX", "QUARANTINE_DIR", "CO17_DATE", "MARGIN_END_S",
           "PROCESSED_REL", "OUT_REL", "OFFSETS_SUFFIX", "STATUSES", "STATUS_REFERENCE", "STATUS_OK",
           "STATUS_WIDE", "STATUS_STALE", "STATUS_NONE", "CORRECTED_STATUSES", "UNRELIABLE_STATUSES",
           "OFFSETS_COLUMNS", "PAIRS_COLUMNS", "CHECK_COLUMNS", "OUTPUT_FILES"]

# ---------------------------------------------------------------- spec 08 section 5

# Pad around the raw agent window for the pair search: 30 min >> the largest skew (27 s, decision 032).
PAIR_PAD_S: float = 1800.0
# dc01 4769s are searched this far beyond the span edges so an edge pair keeps its partner (CO-02).
DC_EDGE_S: float = 120.0
# Smallest sample with a median and a stability value; 1 pair is not corrected (owner Q3).
MIN_PAIRS: int = 2  # PROVISIONAL (spec 08 step 2, decision 043): confirmed on the rerun t01 trials
# Half the 5 s cross-host tolerance of decision 014; set from the tolerance, not fitted.
MAX_LOO_SHIFT_S: float = 2.5  # PROVISIONAL (spec 08 step 2, decision 043): confirmed on the rerun t01 trials
# Computed offset vs the lab clock reading (CO-12); proposal, half the tolerance.
READING_AGREE_S: float = 2.5  # PROVISIONAL (spec 08 step 2, decision 043): confirmed on the rerun t01 trials
# Ports whose target 4624 carries IpPort, so the CO-10 check can join by port.
CHECK_PORTS: tuple[int, ...] = (445, 3389, 5985, 5986)
# A single pair further apart than this is dropped (ATK-02: ticket cache, GUID reuse).
MAX_PAIR_DELTA_S: float = 60.0
# CO-10 join on raw time: wider than any raw offset (27 s), joined before correction (ATK-07).
CHECK_JOIN_S: float = 60.0
# CO-10 review level (ATK-07); reported to the owner, does not kill by itself.
CHECK_REVIEW_S: float = 2.5
# CO-10 kill level (decision 032 criterion; CO-11a).
CHECK_KILL_S: float = 5.0
# CO-15/CO-18 (owner D1, 2026-11-12): a Security 4616 / Kernel-General System 1 counts as a clock change only
# when |new - previous| >= this; a smaller one is routine (listed, changes nothing). Unknown shift counts.
MIN_CLOCK_STEP_MS: int = 1000  # PROVISIONAL (spec 08 step 2, decision 043)

# ---------------------------------------------------------------- method names and version

METHOD = "logonguid_4624_4769_mutual_nearest_median"
# The CO-10 join: source Sysmon 3 -> target 4624 by IpAddress + IpPort, nearest on raw time.
CHECK_METHOD = "sysmon3_ipport_raw_nearest"
TOOL_VERSION = "clock_offset 0.1.0"

# ---------------------------------------------------------------- lab hosts

ENDPOINTS: tuple[str, ...] = ("ep-01", "ep-02", "ep-03")
# dc01 is the reference clock (offset 0 by definition, unverified: there is no absolute time).
REFERENCE_HOST = "dc01"
HOSTS: tuple[str, ...] = (REFERENCE_HOST,) + ENDPOINTS
# Same values as gate.params.GateParams.lab_host_ips and src/log_check/params.py host_ip.
LAB_HOST_IPS: Mapping[str, str] = MappingProxyType({
    "dc01": "192.168.50.10", "ep-01": "192.168.50.21", "ep-02": "192.168.50.22", "ep-03": "192.168.50.23",
})

# CO-15: boot / shutdown events on the System channel (a restart may reset the clock).
BOOT_EVENT_IDS: frozenset[int] = frozenset({41, 1074, 6005, 6006, 6008})
# CO-18: clock-change events, present only in DBs ingested after the spec 01 amendment.
CLOCK_CHANGE_EVENTS: frozenset[tuple[str, int]] = frozenset({("Security", 4616), ("System", 1)})

# ---------------------------------------------------------------- trials (decisions 019, 034, 043)

DEVELOPMENT_TRIALS: tuple[str, ...] = ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00",
                                       "s02_t01", "s03_t01", "s06_t01")
# Owner A1: measured for the offset method only, never gated or scored (COA-04).
CLOCK_ONLY_TRIALS: tuple[str, ...] = ("s04_t01", "s07_t01")
DEFAULT_TRIALS: tuple[str, ...] = DEVELOPMENT_TRIALS + CLOCK_ONLY_TRIALS

# CO-17: a trial whose window starts on or after this date is refused with an uncorrected host.
CO17_DATE = RAW_TIME_CUTOFF_DATE

# ---------------------------------------------------------------- locations

OUT_REL = "out/clock_offset"
OFFSETS_SUFFIX = ".clock_offsets.csv"

# ---------------------------------------------------------------- statuses (spec 08 section 3)

STATUS_REFERENCE = "reference"
STATUS_OK = "ok"
STATUS_WIDE = "wide"
STATUS_STALE = "stale"
STATUS_NONE = "none"
STATUSES: tuple[str, ...] = (STATUS_REFERENCE, STATUS_OK, STATUS_WIDE, STATUS_STALE, STATUS_NONE)
# Statuses whose offset is applied (CO-06: wide is corrected, never left raw).
CORRECTED_STATUSES: frozenset[str] = frozenset({STATUS_REFERENCE, STATUS_OK, STATUS_WIDE})
# Statuses that flag the trial and mark cross-host rows clock_unreliable (CO-08, CO-09).
UNRELIABLE_STATUSES: frozenset[str] = frozenset({STATUS_NONE, STATUS_WIDE, STATUS_STALE})

# ---------------------------------------------------------------- output columns (spec 08 section 3)

OFFSETS_COLUMNS: tuple[str, ...] = (
    "trial_id", "host", "offset_ms", "offset_status", "offset_unc_ms", "n_pairs", "n_dropped_far",
    "n_pairs_lab_ip", "late_gap_s", "min_ms", "q1_ms", "median_ms", "q3_ms", "max_ms", "loo_shift_ms",
    "pair_span_s", "host_has_events", "method", "search_start_utc", "search_end_utc", "db_sha256",
    "tool_version", "clock_changes_sha256", "clock_scan",
)
PAIRS_COLUMNS: tuple[str, ...] = (
    "host", "event_uid_4624", "event_uid_4769", "logon_guid", "t_4624_utc", "t_4769_utc", "delta_ms",
    "logon_type", "account_name", "service_name", "method", "candidate_count", "time_delta_ms",
)
# CO-10 check rows (stats.json); not a spec 3 file, listed so the row layout is fixed in one place.
CHECK_COLUMNS: tuple[str, ...] = (
    "source_host", "target_host", "destination_port", "source_port", "event_uid_sysmon3", "event_uid_4624",
    "t_sysmon3_utc", "t_4624_utc", "method", "candidate_count", "ambiguous", "time_delta_ms", "raw_delta_ms",
    "corrected_delta_ms", "abs_raw_ms", "abs_corrected_ms", "net_effect", "clock_unreliable", "review", "kill",
)

OUTPUT_FILES: tuple[str, ...] = ("pairs.csv", "stats.json", "report.md", "run_info.json")
