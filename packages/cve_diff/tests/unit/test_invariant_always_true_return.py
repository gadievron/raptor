"""
Invariant #9: forbid `return <expr> or True` / `return <expr> or False`.

These short-circuit the caller's boolean check, turning every False into True.
"""

from __future__ import annotations

import re
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent.parent / "cve_diff"
_PATTERN = re.compile(r"\breturn\b\s+.+\s+or\s+(True|False)\b")


def test_no_always_true_return_in_package() -> None:
    violations: list[str] = []
    for py in sorted(PKG.rglob("*.py")):
        for i, line in enumerate(py.read_text().splitlines(), 1):
            if _PATTERN.search(line) and not line.strip().startswith("#"):
                violations.append(f"{py.relative_to(PKG)}:{i}: {line.strip()}")
    assert violations == [], "return <expr> or True/False found:\n" + "\n".join(violations)
