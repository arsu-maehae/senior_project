"""``python -m x10_validate``; run from the repository root after ``pip install -e .`` (see README)."""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
