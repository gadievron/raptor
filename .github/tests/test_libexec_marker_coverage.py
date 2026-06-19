"""Verify every libexec script wires the trust-marker check.

Why this test exists
--------------------
Every libexec/raptor-* script must refuse to run unless reached through
the trusted launcher (CLAUDECODE / _RAPTOR_TRUSTED). That check is wired
one of two ways:

* Standard scripts call the shared ``core.security._trust_guard``
  helper (``require_trusted_caller()``) on the first lines after the
  repo root is added to ``sys.path`` -- dependency-free, in the tiny
  ``core.security`` package, so it still runs before any heavy import.
* A handful of special shims (pid1/seatbelt, ``python3 -I`` isolated
  launchers) keep the check INLINED, marked by the box-drawing sentinel
  comment ``# ─── trust-marker check``, because they run before any
  ``sys.path`` manipulation by design.

The cost of either approach is that a future contributor adding a new
libexec script could forget to wire it. This test catches that: every
script must carry one of the two markers near the top, and the trust
vars must be referenced wherever the gate actually lives (inline in the
shim, or in the shared helper module).
"""

from __future__ import annotations

import unittest
from pathlib import Path


# parents[2] = .github/tests -> .github -> repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects libexec/ in its own
# worktree (RAPTOR_DIR may point at a different checkout).
REPO = Path(__file__).resolve().parents[2]
LIBEXEC = REPO / "libexec"
TRUST_GUARD = REPO / "core" / "security" / "_trust_guard.py"

# Inline sentinel (special shims) and the shared-helper call (standard
# scripts). A script is covered if it carries either one. The sentinel
# uses box-drawing rules (U+2500), matching the literal text in the shims.
_SENTINEL = "# ─── trust-marker check"
_HELPER_MARKER = "require_trusted_caller"
_TRUST_VARS = ("CLAUDECODE", "_RAPTOR_TRUSTED")


def _libexec_scripts() -> list[Path]:
    """All `libexec/raptor-*` files (excluding test dir + caches)."""
    out = []
    for p in sorted(LIBEXEC.glob("raptor-*")):
        if p.is_dir():
            continue
        out.append(p)
    return out


def _first_marker_line(text: str) -> int | None:
    """1-based line of the first trust-marker (inline sentinel or helper
    call), or None if neither is present."""
    for i, line in enumerate(text.splitlines(), 1):
        if _SENTINEL in line or _HELPER_MARKER in line:
            return i
    return None


class LibexecMarkerCoverageTests(unittest.TestCase):
    """Every libexec/raptor-* script must wire the trust-marker check."""

    def test_at_least_one_libexec_script_exists(self):
        """Sanity -- guards against the test silently passing on a broken
        worktree where libexec/ is empty.
        """
        self.assertGreater(len(_libexec_scripts()), 0,
                           msg="no libexec scripts discovered")

    def test_every_script_wires_trust_check(self):
        """Each script carries either the inline sentinel or the shared
        require_trusted_caller() helper call."""
        missing = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text and _HELPER_MARKER not in text:
                missing.append(path.name)
        self.assertEqual(
            missing, [],
            msg=(
                "These libexec scripts are missing the trust-marker check. "
                "Add the helper (`from core.security._trust_guard import "
                "require_trusted_caller; require_trusted_caller()`) near the "
                "top, or paste the inline sentinel block from a special "
                "shim.\nMissing: " + ", ".join(missing)
            ),
        )

    def test_helper_references_all_trust_vars(self):
        """The shared helper -- the gate for standard scripts -- must check
        every documented trust marker. (Inline shims are checked below.)"""
        text = TRUST_GUARD.read_text(encoding="utf-8", errors="replace")
        missing_vars = [v for v in _TRUST_VARS if v not in text]
        self.assertEqual(
            missing_vars, [],
            msg=f"{TRUST_GUARD} does not reference {missing_vars}",
        )

    def test_inline_checks_reference_all_trust_vars(self):
        """Special shims that inline the check must gate on every documented
        trust marker. Helper-based scripts delegate to the shared module
        (covered by test_helper_references_all_trust_vars)."""
        problems = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text:
                continue  # delegates to the shared helper
            missing_vars = [v for v in _TRUST_VARS if v not in text]
            if missing_vars:
                problems.append(f"{path.name}: missing {missing_vars}")
        self.assertEqual(
            problems, [],
            msg="inline trust-marker checks reference incomplete env-var "
                "sets:\n" + "\n".join(problems),
        )

    def test_check_appears_near_top(self):
        """The check must run before any meaningful work -- i.e., before
        ``sys.path`` is mutated (if any) and before non-stdlib imports.

        Heuristic: the marker (inline sentinel or helper call) must appear
        within the first 100 lines. That's loose enough to permit long
        module docstrings (raptor-pid1-shim has a 60-line one and lands at
        line ~72) but tight enough to catch a check accidentally pushed to
        the bottom of the file.
        """
        late = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            line = _first_marker_line(text)
            if line is not None and line > 100:
                late.append(f"{path.name}: line {line}")
        self.assertEqual(
            late, [],
            msg="trust-marker checks appear too late in these scripts "
                "(must be within first 100 lines):\n" + "\n".join(late),
        )


if __name__ == "__main__":
    unittest.main()
