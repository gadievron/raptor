#!/usr/bin/env python3
"""Forbid `return <expr> or True` / `return <expr> or False` in cve_diff/.

Invariant #9 (from the plan): patterns like ``return value or True`` short-
circuit the caller's boolean check, turning every False into True. This was
Bug #9 in the reference project — a healing-stage always reported success
because its return statement hid the real result behind ``or True``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "cve_diff"

# Match `return ... or True` or `return ... or False` on one line.
PATTERN = re.compile(r"^\s*return\s+.+\s+or\s+(?:True|False)\s*(?:#.*)?$")


def main() -> int:
    offenders: list[tuple[Path, int, str]] = []
    for py in PKG.rglob("*.py"):
        for lineno, line in enumerate(py.read_text().splitlines(), start=1):
            if PATTERN.match(line):
                offenders.append((py, lineno, line.rstrip()))

    if offenders:
        print("Forbidden `return ... or True/False` pattern (invariant #9):")
        for path, lineno, line in offenders:
            rel = path.relative_to(ROOT)
            print(f"  {rel}:{lineno}: {line}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
