"""Test-path detection used across reachability + supply-chain detectors.

Single source of truth for "is this file part of the project's test
suite?" — both layers want to deprioritise hits in test code (test
fixtures intentionally contain things that would flag in production:
mocked exfil destinations, fake malicious imports, deliberately
unsafe code paths). The reachability layer was the original consumer;
supply-chain detectors now share the same logic so a project's own
test corpus doesn't surface as a finding against itself.

Conventions covered:

  - ``tests/``, ``test/``, ``__tests__/``, ``spec/``, ``e2e/`` —
    common test-directory names across Python, JS/TS, Ruby, Go.
  - ``test_*.py``, ``*_test.py``, ``*.test.{py,js,ts,jsx,tsx}``,
    ``*.spec.{py,js,ts,jsx,tsx}`` — common test-file naming
    conventions.

Operators who DO need findings from test files (e.g. a security-
research repo where the test corpus IS the analysis target) can
filter the SBOM / findings.json themselves; we don't (yet) ship a
``--include-tests`` toggle.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Set

# Directory names treated as test trees. Same set across both
# reachability and supply-chain — a project's "tests" dir is its
# tests dir regardless of which detector is asking.
TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "e2e"}

# Test-file naming conventions across the languages /sca handles.
# Cross-ecosystem extension landed after the docker-moby sweep
# surfaced exfil-detector false positives on `*_test.go` — the
# original regex covered Python + JS/TS but missed Go / Ruby /
# Java / Rust / C# / PHP test conventions.
#
# Python:  test_x.py, x_test.py, x.test.py, x.spec.py
# JS/TS:   x.test.{js,ts,jsx,tsx,mjs,cjs},
#          x.spec.{js,ts,jsx,tsx,mjs,cjs}
# Go:      x_test.go
# Ruby:    x_test.rb, x_spec.rb
# Java/Kt: XTest.{java,kt}, XTests.{java,kt}, XIT.{java,kt}
#          (Integration Test convention)
# Rust:    x_test.rs
# C#/.NET: XTest.cs, XTests.cs
# PHP:     XTest.php
_TEST_FILE_RE = re.compile(
    r"^("
    r"test_.*\.py"
    r"|.*_test\.py"
    r"|.*\.test\.(?:py|js|ts|jsx|tsx|mjs|cjs)"
    r"|.*\.spec\.(?:py|js|ts|jsx|tsx|mjs|cjs)"
    r"|.*_test\.go"
    r"|.*_test\.rb"
    r"|.*_spec\.rb"
    r"|.*Test\.(?:java|kt)"
    r"|.*Tests\.(?:java|kt)"
    r"|.*IT\.(?:java|kt)"
    r"|.*_test\.rs"
    r"|.*Test\.cs"
    r"|.*Tests\.cs"
    r"|.*Test\.php"
    r")$",
)


def is_test_path(path: Path, target: Path) -> bool:
    """True if ``path`` is part of the project's test suite.

    Filename conventions (``test_*.py``, ``*.test.js``, etc.) AND
    test-directory ancestors (``tests/``, ``__tests__/``, etc.) both
    qualify. ``target`` is the project root used to bound the
    ancestor check — paths outside ``target`` are tested by their
    full ``parts`` so e.g. an absolute fixture path under a tests/
    dir still classifies correctly.
    """
    if _TEST_FILE_RE.match(path.name):
        return True
    try:
        rel = path.relative_to(target)
    except ValueError:
        rel = path
    return any(part in TEST_DIR_NAMES for part in rel.parts)


__all__ = ["TEST_DIR_NAMES", "is_test_path"]
