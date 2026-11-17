"""One place that decides what a missing real-data input does to a test (decision 053 item 3).

The real-data tests need files that are not in git (data/processed, data/sample, out/, ground_truth/approved,
data/trial_windows.csv, the archive). On another machine a missing input must skip the test. On the owner's machine it
must not: a skip there hid 58 tests when the old S04/S07 trials were archived (full suite 4448 passed + 1 skipped became
4390 passed + 59 skipped, and nothing failed).

    REQUIRE_REAL_DATA=1 python -m pytest      # a missing real-data input FAILS the test
    python -m pytest                          # the default: a missing input skips it

Use ``missing_input(reason)`` ONLY for an input that should exist on the owner's machine. A condition that is a
property of the data or of the machine (no symlink right, no 192.168.50.97 session in the trials) is not a missing
input: keep ``pytest.skip`` for it, and it stays visible in the skip count.
"""
from __future__ import annotations

import os
from typing import NoReturn

import pytest

ENV_VAR = "REQUIRE_REAL_DATA"
_TRUE = frozenset({"1", "true", "yes", "on"})


def required() -> bool:
    """True when ``REQUIRE_REAL_DATA`` is set to 1, true, yes or on (case-insensitive); unset or anything else is False."""
    return os.environ.get(ENV_VAR, "").strip().lower() in _TRUE


def missing_input(reason: str) -> NoReturn:
    """Fail the test if real data is required, else skip it. Never returns."""
    if required():
        pytest.fail(f"{ENV_VAR}=1 and a real-data input is missing: {reason}", pytrace=False)
    pytest.skip(reason)
