"""Pin: the frozen-parameter copy in `src/evaluate/params.py` (decision 069 item 6) equals `src/score/params.py` and the
values written in decision 066 / the order-table hash of decision 067 (spec 05_score SC-42). Fast.

The expected values are written here from the decision text (lambda = 1/ln 2, w = 1/3 each, alpha = beta = 0.5, a = b = 1,
eps = 0.01) and the order table hash is recomputed from `order_table.json` (CRLF turned into LF, decision 067 item 1),
so neither copy in `src/` is trusted by the other.
"""
from __future__ import annotations

import hashlib
import math
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from evaluate import params as ep  # noqa: E402
from score import params as sp  # noqa: E402

DECISION_066 = {"lam": 1.0 / math.log(2.0), "w1": 1 / 3, "w2": 1 / 3, "w3": 1 / 3, "alpha": 0.5, "beta": 0.5, "a": 1.0,
                "b": 1.0, "eps": 0.01}
HASH_067 = "6bfae08b869178c618cef9b42b341eb9c78441ef2aeeb4cf9aeaaf2cfa07d61e"


def test_evaluate_frozen_copy_equals_decision_066_values():
    assert set(ep.FROZEN_SCORE_PARAMETERS) == set(DECISION_066)
    for name, want in DECISION_066.items():
        assert ep.FROZEN_SCORE_PARAMETERS[name] == pytest.approx(want, abs=1e-15), name
    assert sum(ep.FROZEN_SCORE_PARAMETERS[w] for w in ("w1", "w2", "w3")) == pytest.approx(1.0, abs=1e-15)
    assert ep.FROZEN_SCORE_PARAMETERS["alpha"] + ep.FROZEN_SCORE_PARAMETERS["beta"] == 1.0


def test_evaluate_frozen_copy_equals_the_score_stage_defaults():
    p = sp.ScoreParams()
    for name in DECISION_066:
        assert getattr(p, name) == pytest.approx(ep.FROZEN_SCORE_PARAMETERS[name], abs=1e-15), name


def test_frozen_order_table_hash_is_the_one_of_decision_067_the_score_stage_and_the_file():
    assert ep.FROZEN_ORDER_TABLE_SHA256 == HASH_067 == sp.ORDER_TABLE_SHA256
    raw = sp.ORDER_TABLE_FILE.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(raw).hexdigest() == HASH_067
    text = (REPO / "docs" / "decisions" / "067-score-implementation-readings.md").read_text(encoding="utf-8")
    assert HASH_067 in text


def test_decision_066_states_the_pinned_values():
    text = (REPO / "docs" / "decisions" / "066-score-parameter-freeze.md").read_text(encoding="utf-8")
    assert re.search(r"λ\s*=\s*\*\*?1/ln 2|\*\*λ = 1/ln 2\*\*", text)
    assert "w1 = w2 = w3 = 1/3" in text and "α = β = 0.5" in text and "a = b = 1" in text and "ε = 0.01" in text


def test_pin_tolerance_is_tight_and_covers_the_float_noise_of_one_third_and_ln2():
    assert ep.FROZEN_PARAM_TOLERANCE <= 1e-9
    assert abs((1 / 3 + 1 / 3 + 1 / 3) - 1.0) < ep.FROZEN_PARAM_TOLERANCE
    assert abs(1.0 / math.log(2.0) - 1.4426950408889634) < ep.FROZEN_PARAM_TOLERANCE


def test_keyed_development_trials_are_t00_of_s02_to_s07_and_a_subset_of_the_development_list():
    """Decision 019 split: development = t00 for S02-S07 + t01 for all; S01 t00 excluded."""
    assert tuple(ep.KEYED_DEVELOPMENT_TRIALS) == tuple(f"s0{i}_t00" for i in range(2, 8))
    assert set(ep.KEYED_DEVELOPMENT_TRIALS) <= set(ep.DEVELOPMENT_TRIALS)
    assert tuple(ep.DEVELOPMENT_TRIALS) == tuple(sp.ALLOWED_TRIALS) or set(ep.DEVELOPMENT_TRIALS) == set(sp.ALLOWED_TRIALS)
    assert "s01_t00" not in ep.KEYED_DEVELOPMENT_TRIALS
