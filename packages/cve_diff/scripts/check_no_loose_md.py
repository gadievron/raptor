#!/usr/bin/env python3
"""Block new loose *.md files at the repo root.

The reference project accumulated 170+ loose markdown files at the root; the
plan's structural invariant is: markdown lives under `docs/`, not at the root,
with a small allowlist for CLAUDE.md / README.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

ALLOWED = {"README.md", "CLAUDE.md", "LICENSE.md", "CHANGELOG.md"}
ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    offenders = sorted(
        p.name for p in ROOT.glob("*.md") if p.is_file() and p.name not in ALLOWED
    )
    if offenders:
        print("Loose markdown files at repo root are not allowed. Move them under docs/.")
        for name in offenders:
            print(f"  - {name}")
        print(f"\nAllowed at root: {sorted(ALLOWED)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
