"""PostToolUse hook: run the fast unit tests after Claude edits a file.

Works from Git Bash or PowerShell because it is plain Python.
Paths are resolved from this script's location, so the working directory does not matter.
Exit 2 makes Claude Code show the failure to Claude (the edit already happened).
Pytest exit code 5 ("no tests collected") counts as success.
"""
import pathlib
import subprocess
import sys

NO_TESTS_COLLECTED = 5

repo = pathlib.Path(__file__).resolve().parents[2]
tests = repo / "tests" / "unit"

if not tests.is_dir():
    sys.exit(0)

result = subprocess.run(
    [sys.executable, "-m", "pytest", "-q", "-x", str(tests)],
    capture_output=True,
    text=True,
    cwd=repo,
)
if result.returncode not in (0, NO_TESTS_COLLECTED):
    tail = (result.stdout + result.stderr).strip().splitlines()[-15:]
    print("unit tests failed:\n" + "\n".join(tail), file=sys.stderr)
    sys.exit(2)
sys.exit(0)
