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

# Clock rule (spec 2.2, decision 039): until decision 032's per-host correction exists, only t00
# trials collected before 2026-10-26 (first day with ep-01 10-27 s behind dc01) get a window.
CLOCK_CORRECTION_AVAILABLE = False
RAW_TIME_CUTOFF_DATE = date(2026, 10, 26)
TIME_BASIS = "raw"

# Quarantined trial ids (decision 030).
QUARANTINE_PREFIX = "s05q_"
QUARANTINE_DIR = "quarantine"

# Decision 019: S01 t00 is excluded from the split (target side only; its source EP-01 and DC01
# files are S02 exports), so it never gets a window. Refused independently of the clock flag.
EXCLUDED_TRIALS: tuple[str, ...] = ("s01_t00",)

DEFAULT_TRIALS = ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00")

COLUMNS = ("trial_id", "start_utc", "end_utc", "window_source", "margin_start_s", "margin_end_s",
           "rule", "db_sha256", "time_basis")

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
