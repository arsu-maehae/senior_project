"""Parameters of the trial window step (spec 02_gate sections 2.1, 2.2, 5; decisions 019, 026, 030, 032, 039, 040).

WHY a separate file: every value the window depends on is visible in one place. The 60 s / 300 s
margins come from the neutral module ``lab_common.margins``, the same source the key builder uses,
so the two can never drift apart and this step never imports the key builder (decision 041).
"""
from __future__ import annotations

from datetime import date

from answer_key import agent_tree as _agent_tree
from lab_common.margins import RUN_INTERVAL_AFTER_S, RUN_INTERVAL_BEFORE_S

# Margins already included in the window edges (decision 026): start - 60 s, end + 300 s.
MARGIN_START_S: float = RUN_INTERVAL_BEFORE_S
MARGIN_END_S: float = RUN_INTERVAL_AFTER_S

# Lab setup metadata. The agent binary is a renamed Sandcat (docs/handoff_18.md line 1439).
# Every non-mDNS splunkd Sysmon 3 goes to 192.168.50.50:8888 and the launch line reads
# ``-server http://192.168.50.50:8888`` (docs/research/agent_evidence.md lines 6-7).
# AGENT_SERVER is recorded in the rule text only; it is not used for matching.
AGENT_IMAGE = r"C:\Users\Public\splunkd.exe"
AGENT_SERVER = "192.168.50.50:8888"

# WHY checked at import: the roots rule (answer_key.agent_tree) and this metadata must name the
# same binary, otherwise the rule text written into the CSV would describe a different agent.
if AGENT_IMAGE.lower() != _agent_tree.AGENT_IMAGE:
    raise ImportError(f"AGENT_IMAGE {AGENT_IMAGE!r} disagrees with answer_key.agent_tree.AGENT_IMAGE "
                      f"{_agent_tree.AGENT_IMAGE!r}")

# Clock rule (spec 2.2 as amended in T6b.2, decision 043; spec 08 section 4.1 item 2): the per-host
# correction of decision 032 exists (src/clock_offset), so the flag now means "corrected times are
# required" and windows are computed on corrected times. The t00-only and the 2026-10-26 refusals
# are gone; RAW_TIME_CUTOFF_DATE (first day with ep-01 10-27 s behind dc01) is kept only as the CO-17
# date: on or after it, a host with events that is uncorrected (none/stale) refuses the trial.
CLOCK_CORRECTION_AVAILABLE = True
RAW_TIME_CUTOFF_DATE = date(2026, 10, 26)
TIME_BASIS_CORRECTED = "corrected"
# Raw basis: only for the GTA-06 test (spec 02_gate GTA-06, spec 08 section 4.1 item 6, owner Q7), because
# the answer keys are in raw time. It skips the offsets and leaves the clock columns empty.
TIME_BASIS_RAW = "raw"
TIME_BASES: tuple[str, ...] = (TIME_BASIS_CORRECTED, TIME_BASIS_RAW)
TIME_BASIS = TIME_BASIS_CORRECTED

# WHY a copy and not an import: clock_offset.params imports this module, so importing clock_offset here
# would be a cycle. This tuple mirrors clock_offset.params.CLOCK_ONLY_TRIALS (decision 034, spec 08
# COA-04: measured for the offset method only, never windowed or gated); a test checks they are equal.
CLOCK_ONLY_TRIALS: tuple[str, ...] = ("s04_t01", "s07_t01")

# Quarantined trial ids (decision 030).
QUARANTINE_PREFIX = "s05q_"
QUARANTINE_DIR = "quarantine"

# Decision 019: S01 t00 is excluded from the split (target side only; its source EP-01 and DC01
# files are S02 exports), so it never gets a window. Refused independently of the clock flag.
EXCLUDED_TRIALS: tuple[str, ...] = ("s01_t00",)

DEFAULT_TRIALS = ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00")

# Spec 2.1. The last six columns were appended in T6b.2 (decision 043): the hashes tie the window to the
# exact offsets / clock-changes files it was computed with, the flags carry the trial-level clock state to
# the gate, and the edge hosts say whose clock the GT-01 clip compares against.
COLUMNS = ("trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s",
           "rule", "db_sha256", "time_basis",
           "offsets_sha256", "clock_changes_sha256", "clock_flag", "clock_change_in_window", "start_host",
           "end_host")

SOURCE_COMPUTED = "computed_agent_run"
SOURCE_OPERATOR = "operator"

RULE_COMPUTED = (f"agent tree: first splunkd root of the run (30 min walk-back) - {MARGIN_START_S:g} s .. "
                 f"last Sysmon 1 descendant + {MARGIN_END_S:g} s, clipped to manifest export span (must overlap); "
                 f"agent {AGENT_IMAGE}, server {AGENT_SERVER}")
RULE_OPERATOR = (f"operator-recorded trial start - {MARGIN_START_S:g} s .. operator-recorded end + "
                 f"{MARGIN_END_S:g} s, clipped to manifest export span (must overlap)")

# Optional operator file (columns trial_id,start_utc,end_utc); used for trials without agent activity (S01).
OPERATOR_TIMES_REL = "data/operator_times.csv"
WINDOWS_REL = "data/trial_windows.csv"
PROCESSED_REL = "data/processed"
# Spec 08 section 3: data/processed/<trial>.clock_offsets.csv and <trial>.clock_changes.csv, next to the DB.
# Mirrors clock_offset.params.OFFSETS_SUFFIX and clock_offset.changes.CHANGES_SUFFIX (same import-cycle
# reason as CLOCK_ONLY_TRIALS); trial_window.window checks at import that they agree.
OFFSETS_SUFFIX = ".clock_offsets.csv"
CLOCK_CHANGES_SUFFIX = ".clock_changes.csv"
