"""PostToolUse hook: run the fast unit tests after Claude edits a code file.

Works from Git Bash or PowerShell because it is plain Python.
Paths are resolved from this script's location, so the working directory does not matter.
Only edits under src/ or tests/ run the tests; any other edit (docs, data, config) exits at once.
Tests marked "slow" (they open real trial databases) are skipped here; run them with `pytest -m slow`.
Exit 2 makes Claude Code show the failure to Claude (the edit already happened).
Pytest exit code 5 ("no tests collected") counts as success.
"""
import json
import os
import pathlib
import subprocess
import sys

NO_TESTS_COLLECTED = 5
CODE_DIRS = ("src", "tests")

repo = pathlib.Path(__file__).resolve().parents[2]
tests = repo / "tests" / "unit"


def edited_path(raw: str) -> str | None:
    """The edited file's path from the hook input JSON (tool_input.file_path / notebook_path), else None."""
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return None
    tool_input = data.get("tool_input") if isinstance(data, dict) else None
    if not isinstance(tool_input, dict):
        return None
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    return path if isinstance(path, str) and path else None


def is_code_path(path: str, root: pathlib.Path) -> bool:
    """True if path (absolute, or relative to the repo) lies under <root>/src or <root>/tests."""
    full = pathlib.Path(path)
    if not full.is_absolute():
        full = root / full
    full_norm = os.path.normcase(os.path.abspath(full))
    for name in CODE_DIRS:
        base = os.path.normcase(os.path.abspath(root / name))
        if full_norm.startswith(base + os.sep):
            return True
    return False


def main() -> int:
    path = edited_path(sys.stdin.read())
    if path is None or not is_code_path(path, repo):
        return 0
    if not tests.is_dir():
        return 0
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "-m", "not slow", str(tests)],
        capture_output=True,
        text=True,
        cwd=repo,
    )
    if result.returncode not in (0, NO_TESTS_COLLECTED):
        tail = (result.stdout + result.stderr).strip().splitlines()[-15:]
        print("unit tests failed:\n" + "\n".join(tail), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
