"""``python -m x10_validate`` (run with ``src`` on the path, e.g. cwd=src or PYTHONPATH=src)."""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
