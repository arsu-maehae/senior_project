"""Constants of the runner (spec 06_evaluate section 4 B).

WHY the output file names are imported from the stages and not written out here: the post-check (RT-09) must
expect exactly the files each stage documents; a hand-copied list could drift when a stage adds a file. The
development list is imported, never copied (RT-11).
"""
from __future__ import annotations

from pathlib import Path

from clock_offset.params import DEVELOPMENT_TRIALS
from evaluate.__main__ import LINK_SUMMARY_FILES, LINK_TRIAL_FILES
from evaluate.params import KEYED_DEVELOPMENT_TRIALS
from evaluate.rank_report import RANK_FILE, RANK_MD, RANK_SWEEP, RANK_TOTALS
from evaluate.results_report import RESULTS_FILES
from evaluate.writers import KEYED_FILE, LABEL_RECALL_FILE, LABEL_RECALL_MD
from gate.params import OUTPUT_FILES as GATE_FILES
from label.outputs import OUTPUT_FILES as LABEL_FILES
from score.outputs import OUTPUT_FILES as SCORE_FILES
from stitch.__main__ import OUTPUT_FILES as STITCH_FILES
from stitch.params import DISABLEABLE_METHODS

__all__ = ["TOOL_VERSION", "DEVELOPMENT_TRIALS", "KEYED_DEVELOPMENT_TRIALS", "REPO", "RUN_TRIAL_OUT_REL",
           "DEVELOPMENT_DIR_NAME", "RUN_LOG_JSON", "RUN_LOG_MD", "PROCESSED_REL", "WINDOWS_REL", "DB_SUFFIX",
           "OFFSETS_SUFFIX", "CHANGES_SUFFIX", "STAGE_OUT_REL", "GATE_FILES", "STITCH_FILES", "LABEL_FILES",
           "SCORE_FILES", "EVAL_LINK_FILES_UNKEYED", "EVAL_LINK_FILES_KEYED", "EVAL_SUMMARY_DIR", "LINK_SUMMARY_FILES",
           "LABEL_RECALL_FILE", "LABEL_RECALL_MD", "RANK_FILE", "RANK_SWEEP_SUMMARY_FILES", "RESULTS_FILES",
           "STDERR_TAIL_LINES", "MTIME_SLACK_S", "EXIT_REFUSED", "EXIT_FAILED", "STATUS_OK", "STATUS_REFUSED",
           "STATUS_FAILED", "RESULT_NOT_RUN", "NOT_RUN_NOTE", "PRESENCE_STEP", "ALLOWLIST_STEP", "REPO_STEP",
           "DISABLEABLE_METHODS", "DB_MB"]

TOOL_VERSION = "run_trial 0.1.0"

# The code location: subprocesses start here (so ``python -m <stage>`` imports this checkout), but every path they
# use comes from an explicit ``--repo`` (RT-08, ATK-EV-07).
REPO = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------- locations (repo-relative)
RUN_TRIAL_OUT_REL = Path("out/run_trial")
DEVELOPMENT_DIR_NAME = "development"
RUN_LOG_JSON, RUN_LOG_MD = "run_log.json", "run_log.md"
PROCESSED_REL = Path("data/processed")
WINDOWS_REL = Path("data/trial_windows.csv")
DB_SUFFIX = ".sqlite3"
OFFSETS_SUFFIX, CHANGES_SUFFIX = ".clock_offsets.csv", ".clock_changes.csv"
STAGE_OUT_REL: dict[str, Path] = {"gate": Path("out/gate"), "stitch": Path("out/stitch"),
                                  "label": Path("out/label"), "score": Path("out/score"),
                                  "evaluate": Path("out/evaluate")}
EVAL_SUMMARY_DIR = Path("out/evaluate/development")

# ---------------------------------------------------------------- documented outputs per step (RT-09)
# Link accuracy of one trial: link_accuracy_hops.csv only for a keyed trial (decision 051 item 8).
EVAL_LINK_FILES_KEYED: tuple[str, ...] = tuple(LINK_TRIAL_FILES)
EVAL_LINK_FILES_UNKEYED: tuple[str, ...] = tuple(n for n in LINK_TRIAL_FILES if n != KEYED_FILE)
# --rank-sweep --development writes rank.md, rank_totals.csv and rank_sweep.csv into the summary folder.
RANK_SWEEP_SUMMARY_FILES: tuple[str, ...] = (RANK_MD, RANK_TOTALS, RANK_SWEEP)

# ---------------------------------------------------------------- runner behaviour
STDERR_TAIL_LINES = 20
# WHY a slack on the freshness check: file times on some file systems have a 2 s resolution, so a file written in
# the first instant of a step can carry a time just before the runner's own clock reading. A stale file from an
# earlier run is minutes or days older, so 2 s cannot hide one.
MTIME_SLACK_S = 2.0
EXIT_REFUSED, EXIT_FAILED = 2, 1
STATUS_OK, STATUS_REFUSED, STATUS_FAILED = "ok", "refused", "failed"
RESULT_NOT_RUN = "not run"
NOT_RUN_NOTE = ("not run because an earlier step stopped the run; outputs from an earlier run remain in this "
                "step's folders (RT-10)")
# Pseudo-step names for the runner's own refusals (no subprocess).
ALLOWLIST_STEP, REPO_STEP, PRESENCE_STEP = "allowlist", "repo", "presence"
# PT-02: DB size in run_log.md in MB = 10^6 bytes (decimal; the unit is stated in run_log.md).
DB_MB = 1_000_000
