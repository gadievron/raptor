#!/usr/bin/env python3
"""Build source inventory for a target codebase.

Utility script invoked by skill markdown (map.md MAP-0, stage-0-inventory.md).
Not a user-facing command.

Usage:
    python3 build_inventory.py --repo <path> --out <dir>
"""

import argparse
import sys

from core.inventory import build_inventory, format_coverage_summary


def main():
    ap = argparse.ArgumentParser(description="Build source inventory")
    ap.add_argument("--repo", required=True, help="Target repository or directory")
    ap.add_argument("--out", required=True, help="Output directory for checklist.json")
    args = ap.parse_args()

    # Pre-create the --out directory. Pre-fix
    # `build_inventory(args.repo, args.out)` assumed `args.out`
    # already existed and bombed with FileNotFoundError when it
    # didn't. Operators got "Error: [Errno 2] No such file or
    # directory: '<out>/checklist.json'" with no breadcrumb that
    # they needed to mkdir the parent first.
    # mkdir(parents=True, exist_ok=True) is no-op when the dir
    # already exists; harmless to add unconditionally.
    from pathlib import Path
    try:
        Path(args.out).mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"Error: cannot create --out directory {args.out!r}: {e}",
              file=sys.stderr)
        sys.exit(1)

    try:
        inventory = build_inventory(args.repo, args.out)
        print(format_coverage_summary(inventory))
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
