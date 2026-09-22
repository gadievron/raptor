"""The codeql pack-probe verification must not silently go stale.

Why this test exists
--------------------
core/security/codeql_trust.py documents the pack gate as
defense-in-depth on empirical grounds: the probe
(core/security/scripts/codeql-pack-probe) verified that ``database
create`` consumes no repo-tree pack config on the CLI release named
by ``PACK_PROBE_VERIFIED_CLI``. Pack/workspace semantics are
version-mobile, and the CLI is host-installed — nothing in-tree
changes when an operator upgrades it. This test is the mechanical
reminder: it fails when the host CLI is newer than the anchor at
major.minor granularity, until the probe is re-run and the anchor
bumped (or, on a probe failure, the gate's framing revisited).

Skips when no codeql is on PATH (CI runners without the toolchain).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_GATE = _REPO / "core" / "security" / "codeql_trust.py"


def _anchor() -> str:
    # Textual read, not an import: the anchor must be checkable
    # without dragging the module's import chain into this test.
    m = re.search(r'^PACK_PROBE_VERIFIED_CLI = "(\d+\.\d+\.\d+)"$',
                  _GATE.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, "PACK_PROBE_VERIFIED_CLI constant missing from codeql_trust.py"
    return m.group(1)


def _major_minor(version: str) -> tuple[int, int]:
    parts = version.split(".")
    return int(parts[0]), int(parts[1])


# slow = nightly tier, deliberately: not for runtime (one warm JVM
# `codeql version` is sub-second) but for failure blast radius. A
# routine CLI minor upgrade must redden ONE nightly lane until the
# probe re-runs and the anchor is bumped — not every session's fast
# battery on a shared host. Fast-tier would make the reminder a
# recurring cross-session tax; softer than a nightly hard-fail
# (a warning) would be ignored and the verification would go stale,
# which is the failure mode this test exists to prevent.
@pytest.mark.slow
class TestCliVersionAnchor(unittest.TestCase):
    def test_host_cli_not_newer_than_verified_anchor(self) -> None:
        codeql = shutil.which("codeql")
        if not codeql:
            self.skipTest("no codeql CLI on PATH")
        proc = subprocess.run(
            [codeql, "version", "--format=terse"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            # repr-escaped: stderr comes from whatever `codeql` resolves
            # to — raw bytes must not reach the terminal/CI log.
            self.skipTest(
                f"codeql version probe failed: {proc.stderr[:200]!r}")
        host = proc.stdout.strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+", host):
            self.skipTest(f"unparseable codeql version: {host[:40]!r}")
        anchor = _anchor()
        self.assertLessEqual(
            _major_minor(host), _major_minor(anchor),
            f"host codeql CLI {host} is newer than the pack-probe "
            f"anchor {anchor}: run core/security/scripts/"
            f"codeql-pack-probe — on exit 0 bump "
            f"PACK_PROBE_VERIFIED_CLI in core/security/codeql_trust.py; "
            f"on exit 1 the pack gate became load-bearing on this CLI — "
            f"revisit its docstring and walk boundaries first.",
        )


if __name__ == "__main__":
    unittest.main()
