"""Root pytest configuration: the `out/` guard (T7.7, decision 054).

The test suite must not write anywhere under `out/` (pipeline outputs that other stages read with recorded hashes).
A session-scoped autouse fixture snapshots the whole `out/` folder when the session starts and again when it ends,
and fails the session (an error on the last test's teardown, so the exit code is non-zero) if any file or folder was
added, removed, changed, or rewritten with the same bytes. Real-data tests write to tmp folders instead (`--out`).
It lives in the ROOT conftest so it covers every collected test, also the normaliser tests under `src/`.
The snapshot logic is `tests/unit/out_guard.py` (tested by `tests/unit/test_out_guard.py`).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO / "tests" / "unit"))

import out_guard  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def out_folder_unchanged():
    """Fail the session if any test wrote under `out/` (decision 054)."""
    root = REPO / "out"
    before = out_guard.snapshot(root)
    yield
    found = out_guard.diff(before, out_guard.snapshot(root))
    if found:
        pytest.fail(out_guard.report(found), pytrace=False)
