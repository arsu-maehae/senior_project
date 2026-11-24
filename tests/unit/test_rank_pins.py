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


# ================================================================================================ SW-04 (spec 06 section 10)
# The frozen values at commit 6338884, the one the SW-04 sentence names, are read from git itself: neither copy in the
# working tree can then move the other (and a later edit of score/params.py cannot move the reference).
FREEZE_COMMIT = "6338884"
SW04_SENTENCE = ("Development-only sensitivity analysis: the sweep never changes a frozen default — λ, "
                 "w1–w3, α, β, a, b and ε stay as frozen in decision 066 at 6338884, and every "
                 "score, rank and H verdict uses only those values (decision 068).")


def _frozen_defaults_at_freeze_commit() -> dict[str, float]:
    """The ``ScoreParams`` field defaults of ``src/score/params.py`` at the freeze commit (ast, no import)."""
    import ast
    import subprocess
    try:
        src = subprocess.run(["git", "show", f"{FREEZE_COMMIT}:src/score/params.py"], cwd=REPO, check=True,
                             capture_output=True, text=True, encoding="utf-8").stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip(f"git object {FREEZE_COMMIT} is not available here")
    (cls,) = [n for n in ast.parse(src).body if isinstance(n, ast.ClassDef) and n.name == "ScoreParams"]
    out = {}
    for n in cls.body:
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            out[n.target.id] = float(eval(compile(ast.Expression(n.value), "<freeze>", "eval"), {"math": math}))
    return out


def test_sw04_score_params_defaults_equal_the_values_at_the_freeze_commit():
    old = _frozen_defaults_at_freeze_commit()
    for name in DECISION_066:
        assert getattr(sp.ScoreParams(), name) == pytest.approx(old[name], abs=1e-15), name
        assert old[name] == pytest.approx(DECISION_066[name], abs=1e-15), name


def test_sw04_evaluate_frozen_parameters_equal_the_values_at_the_freeze_commit():
    old = _frozen_defaults_at_freeze_commit()
    assert set(ep.FROZEN_SCORE_PARAMETERS) == set(DECISION_066)
    for name, want in ep.FROZEN_SCORE_PARAMETERS.items():
        assert want == pytest.approx(old[name], abs=1e-15), name


def test_sw04_order_table_pin_is_unchanged_since_the_freeze_commit():
    import subprocess
    try:
        old = subprocess.run(["git", "show", f"{FREEZE_COMMIT}:src/score/params.py"], cwd=REPO, check=True,
                             capture_output=True, text=True, encoding="utf-8").stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip(f"git object {FREEZE_COMMIT} is not available here")
    assert f'ORDER_TABLE_SHA256 = "{HASH_067}"' in old
    assert sp.ORDER_TABLE_SHA256 == ep.FROZEN_ORDER_TABLE_SHA256 == HASH_067


def test_sw04_the_sentence_is_one_sentence_naming_every_frozen_parameter_and_both_decisions():
    from evaluate import rank_report as rr
    assert rr.SW04_SENTENCE == SW04_SENTENCE
    assert SW04_SENTENCE.count(". ") == 0 and SW04_SENTENCE.endswith(".")           # one sentence
    for token in ("λ", "w1–w3", "α", "β", "a, b", "ε", "decision 066", "6338884", "decision 068", "never changes"):
        assert token in SW04_SENTENCE
