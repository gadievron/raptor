"""Verify every libexec script has the inline trust-marker check.

Why this test exists
--------------------
The trust-marker check is intentionally inlined in every libexec
script (not factored into a shared helper) so it cannot be subverted
by a single helper-module compromise and so it remains visible at the
top of every script during code review.

The cost of that decision is that future contributors who add a new
libexec script could forget to paste in the block. This test catches
that — every libexec/raptor-* file must contain the sentinel comment
``# ─── trust-marker check`` near the top, and the marker must
gate on at least one of the trusted-caller env vars.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path


REPO = Path(os.environ["RAPTOR_DIR"])
LIBEXEC = REPO / "libexec"

_SENTINEL = "# ─── trust-marker check"
_TRUST_VARS = ("CLAUDECODE", "_RAPTOR_TRUSTED")


def _libexec_scripts() -> list[Path]:
    """All `libexec/raptor-*` files (excluding test dir + caches)."""
    out = []
    for p in sorted(LIBEXEC.glob("raptor-*")):
        if p.is_dir():
            continue
        out.append(p)
    return out


class LibexecMarkerCoverageTests(unittest.TestCase):
    """Every libexec/raptor-* script must inline the trust-marker check."""

    def test_at_least_one_libexec_script_exists(self):
        """Sanity — guards against the test silently passing on a broken
        worktree where libexec/ is empty.
        """
        self.assertGreater(len(_libexec_scripts()), 0,
                           msg="no libexec scripts discovered")

    def test_every_script_has_sentinel_comment(self):
        """The sentinel comment opens (and closes) the check block."""
        missing = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text:
                missing.append(path.name)
        self.assertEqual(
            missing, [],
            msg=(
                "These libexec scripts are missing the inline trust-marker "
                "check. Paste the block from any existing script (search "
                "for `# ─── trust-marker check`).\nMissing: "
                + ", ".join(missing)
            ),
        )

    def test_check_references_all_trust_vars(self):
        """The check must gate on every documented trust marker.

        Catches drift like: someone adds a new marker to docs/CONTRIBUTING
        but forgets to update some scripts. All scripts must check the
        same set.
        """
        problems = []
        for path in _libexec_scripts():
            text = path.read_text(encoding="utf-8", errors="replace")
            if _SENTINEL not in text:
                continue  # covered by the sentinel test above
            missing_vars = [v for v in _TRUST_VARS if v not in text]
            if missing_vars:
                problems.append(f"{path.name}: missing {missing_vars}")
        self.assertEqual(
            problems, [],
            msg="trust-marker checks reference incomplete env-var sets:\n"
                + "\n".join(problems),
        )

    def test_check_appears_near_top(self):
        """The check must run before any meaningful work — i.e., before
        ``sys.path`` is mutated (if any) and before non-stdlib imports.

        Heuristic: the sentinel must appear within the first 100 lines.
        That's loose enough to permit long module docstrings (raptor-
        pid1-shim has a 60-line one and lands at line ~72) but tight
        enough to catch a check accidentally pushed to the bottom of
        the file.
        """
        late = []
        for path in _libexec_scripts():
            lines = path.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
            for i, line in enumerate(lines, 1):
                if _SENTINEL in line:
                    if i > 100:
                        late.append(f"{path.name}: line {i}")
                    break
        self.assertEqual(
            late, [],
            msg="trust-marker checks appear too late in these scripts "
                "(must be within first 100 lines):\n" + "\n".join(late),
        )


if __name__ == "__main__":
    unittest.main()
