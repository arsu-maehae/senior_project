"""Parameters and constants of the score stage (spec 05_score sections 2, 3 and 5; SC-01, SC-10, SC-42, SC-51;
decisions 062-066).

WHY one module: every value the path score depends on (lambda, the weights, alpha / beta, a / b, epsilon, the order
table pin, the identity exclusion list) is visible in one place, written into ``run_info.json``, and pinned by a test
to the freeze record (SC-42, decision 066). The development allowlist is imported from the clock step, never copied
(decision 046), as ``stitch.params`` and ``evaluate.params`` do.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from clock_offset.params import DEVELOPMENT_TRIALS

__all__ = ["TOOL_VERSION", "SCORE_OUT_REL", "STITCH_OUT_REL", "LABEL_OUT_REL", "ORDER_TABLE_FILE",
           "ORDER_TABLE_SHA256", "DEVELOPMENT_TRIALS", "ALLOWED_TRIALS", "VARIANTS", "PATH_VARIANTS", "VARIANT_B0",
           "METHOD_SEQUENCE", "METHOD_IDENTITY", "BASIS_DIRECT", "BASIS_SAME_TACTIC", "BASIS_INDIRECT",
           "BASIS_ABSENT", "BASIS_HOP_CHAIN", "DUMP_TECHNIQUE", "TIER_ORDER", "SYSTEM_ACCOUNTS",
           "EXCLUDED_READ_IMAGES", "EXCLUDED_READ_IMAGE_PATTERNS", "SCORE_DECIMALS", "TIE_DECIMALS",
           "LEVEL_MAX", "ScoreParams"]

TOOL_VERSION = "score 0.1.0"

# Locations (repo-relative). SC-03: nothing under ground_truth/ or data/ is ever named here.
SCORE_OUT_REL = "out/score"
STITCH_OUT_REL = "out/stitch"
LABEL_OUT_REL = "out/label"

# SC-10 / decision 062: the own order reference, in git beside this module.
ORDER_TABLE_FILE: Path = Path(__file__).resolve().parent / "order_table.json"
# SC-10, SC-42: SHA-256 of the order table's bytes with CRLF turned into LF (so a Windows checkout with
# core.autocrlf cannot change it; the label stage pins its rule files the same way, LB-13). Changing a template
# changes out() and every TacticScore (ATK-SC-10), so a changed table is refused until this literal changes too,
# which needs a new decision record (066 freeze).
ORDER_TABLE_SHA256 = "6bfae08b869178c618cef9b42b341eb9c78441ef2aeeb4cf9aeaaf2cfa07d61e"

# SC-01 / decisions 019, 046: development trials only until T10 widens the list by its own record.
ALLOWED_TRIALS: tuple[str, ...] = DEVELOPMENT_TRIALS

# Spec 3.6 / decision 065: the variants. ``PATH_VARIANTS`` rank the stitch paths (``ranked_paths.csv``, in this
# order); ``b0`` ranks label units (``b0_ranked.csv``).
PATH_VARIANTS: tuple[str, ...] = ("full", "b1", "b2")
VARIANT_B0 = "b0"
VARIANTS: tuple[str, ...] = PATH_VARIANTS + (VARIANT_B0,)

# SC-61 method names.
METHOD_SEQUENCE = "technique_sequence"     # path_steps.csv (spec 3.2)
METHOD_IDENTITY = "correction_k"           # hop_identity_values.csv (spec 3.4)

# SC-22a ``basis`` vocabulary, plus SC-21b's ``hop_chain``.
BASIS_DIRECT, BASIS_SAME_TACTIC, BASIS_INDIRECT, BASIS_ABSENT = "direct", "same_tactic", "indirect", "absent"
BASIS_HOP_CHAIN = "hop_chain"

# SC-20 / 056 item 7: the dump counts only through identity, never in a technique sequence.
DUMP_TECHNIQUE = "T1003.001"

# ST-48 link tiers, strongest first; ``best_tier_min`` = the last of these present on a path (045: reported only).
TIER_ORDER: tuple[str, ...] = ("A", "B", "C", "D")

# SC-51 (b') / decision 064: an R1 read is NOT counted when its image is one of these OS / AV binaries at its stated
# system folder (case-insensitive) AND its account is a system account. A same-named binary elsewhere, or under a
# user account, still counts (ATK-SC-04). Same account set as ``evaluate.params.SYSTEM_ACCOUNTS`` (spelled here
# because the scorer must not depend on the evaluation package).
SYSTEM_ACCOUNTS: frozenset[str] = frozenset({"system", "network service", "local service"})
EXCLUDED_READ_IMAGES: frozenset[str] = frozenset({
    r"c:\windows\system32\wbem\wmiprvse.exe",
    r"c:\windows\system32\csrss.exe",
    r"c:\windows\system32\wininit.exe",
    r"c:\program files\windows defender\msmpeng.exe",
})
# The Defender platform folder carries a version (``Platform\4.18.26080.3-0\``): one path segment, any name.
EXCLUDED_READ_IMAGE_PATTERNS: tuple[str, ...] = (
    r"^c:\\programdata\\microsoft\\windows defender\\platform\\[^\\]+\\msmpeng\.exe$",
)

SCORE_DECIMALS = 6     # spec 3: scores written with 6 decimals
TIE_DECIMALS = 12      # SC-41: ties decided on the value rounded to 12 decimals
LEVEL_MAX = 4          # SC-33: critical = 4, NodeScore = mean level / 4


@dataclass(frozen=True)
class ScoreParams:
    """Spec section 5 values, a-priori and frozen (decision 066; SC-42). Never tuned on development or test data.

    - ``lam`` (lambda) = 1/ln 2: one transition gives the length factor 1 - e^(-1/lambda) = 0.5 (SC-23, TPPR Eq. 7).
    - ``w1``..``w3`` = 1/3 each: LengthScore, NodeScore, IdentityCoherence (SC-40); sum 1 keeps scores in [0, 1].
    - ``alpha``, ``beta`` = 0.5: ScoreE = alpha * TacticScore + beta * TechniqueScore, the ScoreNI term dropped (062).
    - ``a``, ``b`` = 1: scale of TechniqueScore / TacticScore (TPPR Eq. 2, 3).
    - ``eps`` = 0.01: TPPR's "negligible probability for unobserved transitions" (p. 6), a floor of TechniqueScore.
    - ``order_tol_s`` = 5: decision 014; read from the stitch facts (``order_ok``), never re-applied here.
    """
    lam: float = 1.0 / math.log(2.0)
    w1: float = 1.0 / 3.0
    w2: float = 1.0 / 3.0
    w3: float = 1.0 / 3.0
    alpha: float = 0.5
    beta: float = 0.5
    a: float = 1.0
    b: float = 1.0
    eps: float = 0.01
    order_tol_s: float = 5.0

    def __post_init__(self) -> None:
        """Refuse parameter sets the spec forbids. WHY at construction: SC-40 needs w >= 0 and sum w = 1 so every
        score lies in [0, 1] and is comparable across trials; SC-22 needs alpha + beta = 1 (ScoreNI weight 0)."""
        ws = (self.w1, self.w2, self.w3)
        if min(ws) < 0 or not math.isclose(math.fsum(ws), 1.0, abs_tol=1e-12):
            raise ValueError(f"SC-40: weights must be >= 0 and sum to 1, got {ws}")
        if min(self.alpha, self.beta) < 0 or not math.isclose(self.alpha + self.beta, 1.0, abs_tol=1e-12):
            raise ValueError(f"SC-22: alpha + beta must be 1, got {self.alpha} + {self.beta}")
        if self.lam <= 0 or self.a <= 0 or self.b <= 0 or not 0 < self.eps <= 1:
            raise ValueError("SC-22/23: lambda, a, b must be > 0 and 0 < eps <= 1")
