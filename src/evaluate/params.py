"""Constants of the link accuracy module (PLAN T7.6; decision 051).

WHY a file with constants only: the evaluation must read the stitch outputs exactly as written, so every
location, file name and vocabulary it relies on is visible in one place. Nothing here is imported from
``stitch`` (decision 051 item 1: the dependency points one way, and the accuracy code must not even share the
stitcher's parameters). The development list is imported from the clock step, never copied (decision 046).
"""
from __future__ import annotations

import math
from pathlib import Path

from clock_offset.params import DEVELOPMENT_TRIALS

__all__ = ["TOOL_VERSION", "EVAL_OUT_REL", "STITCH_OUT_REL", "LABEL_OUT_REL", "SCORE_OUT_REL", "APPROVED_KEYS_REL",
           "KEY_LOCK_REL",
           "DB_REL",
           "DB_SUFFIX", "SUMMARY_DIR_NAME", "STITCH_FILES", "STITCH_RUN_INFO", "ENDPOINTS", "SPLIT_DEVELOPMENT",
           "SPLIT_TEST", "split_of", "Q9_READS", "Q9_VARIANTS", "DEFAULT_VARIANT", "SYSTEM_ACCOUNTS",
           "BOOT_STARTUP_IDS", "BOOT_SHUTDOWN_IDS", "BOOT_CHANNEL", "KEY_LOCK_HEADER", "TRIAL_ID_PATTERN",
           "METHODS", "METHOD_PORT", "METHOD_4648", "METHOD_CMD", "METHOD_TARGET_ONLY", "PROTOCOL_GROUPS",
           "PROTOCOL_GROUP_ORDER", "TIER_ORDER", "DEVELOPMENT_TRIALS", "KEYED_DEVELOPMENT_TRIALS",
           "FROZEN_SCORE_PARAMETERS", "FROZEN_ORDER_TABLE_SHA256", "FROZEN_PARAM_TOLERANCE", "H1_TOP1_MIN",
           "H2_MRR_PER_KEY_MIN", "H3_MIN_DIFFERENCE", "H4_MIN_DIFFERENCE", "H5_MIN_MARGIN", "VERDICT_DECIMALS",
           "S06_TRIAL_PREFIX", "is_s06"]

TOOL_VERSION = "evaluate 0.1.0"

# ---------------------------------------------------------------- locations (repo-relative)
EVAL_OUT_REL = Path("out/evaluate")
# WHY an own constant and not stitch.params.STITCH_OUT_REL: decision 051 item 1 (no import from stitch).
STITCH_OUT_REL = Path("out/stitch")
# The label stage output read by the labelling recall (spec 04 §3.4; PLAN T8.3).
LABEL_OUT_REL = Path("out/label")
# The score stage output read by the development ranking check (spec 05 SCA-06; PLAN T9.5); read as files, never
# imported (T9.5 brief, decision 051 item 1 spirit).
SCORE_OUT_REL = Path("out/score")
APPROVED_KEYS_REL = Path("ground_truth/approved")
# Written by the owner only (decision 051 item 9); this package reads it for split = test and never writes it.
KEY_LOCK_REL = Path("ground_truth/key_lock.csv")
DB_REL = Path("data/processed")
DB_SUFFIX = ".sqlite3"
SUMMARY_DIR_NAME = "development"

# ---------------------------------------------------------------- stitch output (spec 03_stitch section 3)
STITCH_RUN_INFO = "run_info.json"
STITCH_FILES: tuple[str, ...] = ("hops.csv", "links.csv", "hop_artefacts.csv", "hop_identity.csv", "paths.csv",
                                 "path_edges.csv", "path_nodes.csv", "stats.json", "report.md", STITCH_RUN_INFO)

METHOD_PORT, METHOD_4648, METHOD_CMD, METHOD_TARGET_ONLY = ("sysmon3_port", "source_4648", "cmdline_target",
                                                            "target_only")
# Canonical order of the session methods (spec 03 links.csv `method`), used to spell method lists the same way.
METHODS: tuple[str, ...] = (METHOD_PORT, METHOD_4648, METHOD_CMD)

# Decision 051 item 8: smb = smb + smb_service; the stitch protocol vocabulary is ST-22.
PROTOCOL_GROUPS: dict[str, str] = {"smb": "smb", "smb_service": "smb", "winrm": "winrm", "rdp": "rdp",
                                   "none": "none"}
PROTOCOL_GROUP_ORDER: tuple[str, ...] = ("smb", "winrm", "rdp", "none")
# ST-48 tiers, then the label of a key hop that matched no single stitch hop.
TIER_ORDER: tuple[str, ...] = ("A", "B", "C", "D", "unmatched")

# ---------------------------------------------------------------- lab and split
ENDPOINTS: tuple[str, ...] = ("ep-01", "ep-02", "ep-03")
SPLIT_DEVELOPMENT, SPLIT_TEST = "development", "test"
TRIAL_ID_PATTERN = r"s\d\d_t\d\d"


def split_of(trial: str) -> str:
    """``development`` iff the trial is in ``DEVELOPMENT_TRIALS`` (decision 019 / 046), else ``test``.

    WHY derived from the one shared list: a second hand-written list could drift from the stitcher's allowlist.
    """
    return SPLIT_DEVELOPMENT if trial in DEVELOPMENT_TRIALS else SPLIT_TEST


# ---------------------------------------------------------------- identity (decision 051 item 7; Q9 open)
Q9_READS: tuple[str, ...] = ("all", "nonsystem", "key_rule")
# (reads, end_unknown_counted): the six readings while Q9 is open, in a fixed order.
Q9_VARIANTS: tuple[tuple[str, bool], ...] = tuple((r, c) for r in Q9_READS for c in (False, True))
# The variant whose deciding rows give the reported order flags and deciding dump uids.
DEFAULT_VARIANT: tuple[str, bool] = ("all", False)
SYSTEM_ACCOUNTS: frozenset[str] = frozenset({"system", "network service", "local service"})

# ---------------------------------------------------------------- boot epochs (decision 047 item 3)
BOOT_CHANNEL = "System"
BOOT_STARTUP_IDS: frozenset[int] = frozenset({41, 6005, 6008})
BOOT_SHUTDOWN_IDS: frozenset[int] = frozenset({1074, 6006})

# ---------------------------------------------------------------- key lock (decision 051 item 9)
KEY_LOCK_HEADER: tuple[str, ...] = ("trial_id", "key_path", "sha256")


# ---------------------------------------------------------------- ranking check pins (decision 069 items 6, 8)
# ATK-SC-25: the development trials whose approved key must exist (decision 019 split: t00 of S02-S07; S01 t00 is
# excluded). WHY a refusal and not "unkeyed": a missing key would silently move a keyed trial out of top-1 / MRR.
KEYED_DEVELOPMENT_TRIALS: tuple[str, ...] = ("s02_t00", "s03_t00", "s04_t00", "s05_t00", "s06_t00", "s07_t00")

# ATK-SC-18: a copy of the decision 066 freeze, so ``--rank`` can refuse a score run made with other values. WHY a
# copy and not ``score.params``: evaluate must not import score (decision 051 item 1 spirit, T9.5 brief); a test pins
# this copy to 066. Floats are compared with ``FROZEN_PARAM_TOLERANCE`` (absolute).
FROZEN_SCORE_PARAMETERS: dict[str, float] = {
    "lam": 1.0 / math.log(2.0), "w1": 1.0 / 3.0, "w2": 1.0 / 3.0, "w3": 1.0 / 3.0, "alpha": 0.5, "beta": 0.5,
    "a": 1.0, "b": 1.0, "eps": 0.01,
}
FROZEN_ORDER_TABLE_SHA256 = "6bfae08b869178c618cef9b42b341eb9c78441ef2aeeb4cf9aeaaf2cfa07d61e"
FROZEN_PARAM_TOLERANCE = 1e-12

# ---------------------------------------------------------------- T10 hypothesis thresholds (spec 06 section 5, RS-03..05)
# Frozen before any test trial is scored; read here by the results tables and pinned by a test. Never moved after
# seeing development numbers (070 item 3).
H1_TOP1_MIN = 0.80              # 065 H1: top-1 rate (expected ties), full, >= ; unchanged by 070 item 3
H2_MRR_PER_KEY_MIN = 0.85       # 065 H2 threshold; reading = per-key MRR (070 item 2); unchanged (070 item 3)
H3_MIN_DIFFERENCE = 0.0         # 065 H3 strict: per-key MRR(full) - per-key MRR(b1) > 0 (070 item 2); equal = not held
H4_MIN_DIFFERENCE = 0.0         # 065 H4 / 070 item 1 / 071: mean labelled recall full - b0 > 0, strict
H5_MIN_MARGIN = 0.0             # 065 H5: lowest key attack score - highest S06 score > 0 in every keyed S06 trial
VERDICT_DECIMALS = 12           # RS-09 (ATK-EV-02): verdicts compare fsum values rounded to 12 decimals, as SC-41

# ATK-EV-15: the benign scenario S06 (decision 024, no attack) is named by its scenario id, never inferred from a key
# that happens to name no attack path; ``rank_run`` refuses a key that disagrees with its scenario.
S06_TRIAL_PREFIX = "s06_"


def is_s06(trial: str) -> bool:
    """True for a trial of scenario S06 (trial id prefix ``s06_``). WHY by id: H5 is decided per S06 trial, and a
    keyed attack trial whose key lost its attack paths must not silently become an S06 trial (ATK-EV-15)."""
    return trial.startswith(S06_TRIAL_PREFIX)
