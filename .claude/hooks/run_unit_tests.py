"""PostToolUse hook: run the fast unit tests after Claude edits a file.

Works from Git Bash or PowerShell because it is plain Python.
Exit 2 makes Claude Code show the failure to Claude (the edit already happened).
"""
import pathlib
import subprocess
import sys

if not pathlib.Path("tests/unit").is_dir():
    sys.exit(0)

result = subprocess.run(
    [sys.executable, "-m", "pytest", "-q", "-x", "tests/unit"],
    capture_output=True,
    text=True,
)
if result.returncode != 0:
    tail = (result.stdout + result.stderr).strip().splitlines()[-15:]
    print("unit tests failed:\n" + "\n".join(tail), file=sys.stderr)
    sys.exit(2)
sys.exit(0)
