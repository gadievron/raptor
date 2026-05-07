#!/usr/bin/env python3
"""Build source inventory for a target codebase.

Utility script invoked by skill markdown (map.md MAP-0, stage-0-inventory.md).
Not a user-facing command.

Usage:
    python3 build_inventory.py --repo <path> --out <dir>
"""

import argparse
import sys
from pathlib import Path

# build_inventory.py -> repo root. Belt + braces against subprocess
# invocation under a sandboxed env that strips PYTHONPATH.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.inventory import build_inventory, format_coverage_summary


def main():
    ap = argparse.ArgumentParser(description="Build source inventory")
    ap.add_argument("--repo", required=True, help="Target repository or directory")
    ap.add_argument("--out", required=True, help="Output directory for checklist.json")
    args = ap.parse_args()

    try:
        inventory = build_inventory(args.repo, args.out)
        print(format_coverage_summary(inventory))
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
