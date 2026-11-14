"""Constants of the link accuracy module (PLAN T7.6; decision 051).

WHY a file with constants only: the evaluation must read the stitch outputs exactly as written, so every
location, file name and vocabulary it relies on is visible in one place. Nothing here is imported from
``stitch`` (decision 051 item 1: the dependency points one way, and the accuracy code must not even share the
stitcher's parameters). The development list is imported from the clock step, never copied (decision 046).
"""
from __future__ import annotations

from pathlib import Path

from clock_offset.params import DEVELOPMENT_TRIALS

__all__ = ["TOOL_VERSION", "EVAL_OUT_REL", "STITCH_OUT_REL", "APPROVED_KEYS_REL", "KEY_LOCK_REL", "DB_REL",
           "DB_SUFFIX", "SUMMARY_DIR_NAME", "STITCH_FILES", "STITCH_RUN_INFO", "ENDPOINTS", "SPLIT_DEVELOPMENT",
           "SPLIT_TEST", "split_of", "Q9_READS", "Q9_VARIANTS", "DEFAULT_VARIANT", "SYSTEM_ACCOUNTS",
           "BOOT_STARTUP_IDS", "BOOT_SHUTDOWN_IDS", "BOOT_CHANNEL", "KEY_LOCK_HEADER", "TRIAL_ID_PATTERN",
           "METHODS", "METHOD_PORT", "METHOD_4648", "METHOD_CMD", "METHOD_TARGET_ONLY", "PROTOCOL_GROUPS",
           "PROTOCOL_GROUP_ORDER", "TIER_ORDER", "DEVELOPMENT_TRIALS"]

TOOL_VERSION = "evaluate 0.1.0"

# ---------------------------------------------------------------- locations (repo-relative)
EVAL_OUT_REL = Path("out/evaluate")
# WHY an own constant and not stitch.params.STITCH_OUT_REL: decision 051 item 1 (no import from stitch).
STITCH_OUT_REL = Path("out/stitch")
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
