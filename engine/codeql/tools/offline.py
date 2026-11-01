#!/usr/bin/env python3
"""Operator entry point for preparing, importing, and checking CodeQL airgap kits."""
from pathlib import Path
import sys

_REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO))

from core.config import pin_raptor_dir_in_environ  # noqa: E402

pin_raptor_dir_in_environ()

from packages.codeql.offline import main  # noqa: E402

if __name__ == '__main__':
    raise SystemExit(main())
