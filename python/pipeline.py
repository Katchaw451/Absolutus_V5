#!/usr/bin/env python3
"""Backward-compat shim. Prefer: absolutus parse"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from absolutus.parsers import main  # noqa: E402

if __name__ == "__main__":
    main()
