"""Module entry point: ``python -m cve_env`` → the argparse CLI."""

from __future__ import annotations

import sys

from cve_env.cli import main

if __name__ == "__main__":
    sys.exit(main())
