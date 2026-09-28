"""Doc-lint: PROGRESSIVE LOADING router targets exist on disk.

Why this test exists
--------------------
CLAUDE.md's PROGRESSIVE LOADING section is a trigger-to-file router:
the always-resident kernel names a file, and the session loads it at
the trigger instead of relying on resident memory. A router row whose
path has been moved, renamed, or deleted silently degrades the session
back to training-memory guesses — exactly the failure mode the router
was built to prevent, and one no python test catches.

Mechanical rule: every backticked repo-relative path (any backticked
token containing ``/``) inside the PROGRESSIVE LOADING section must
exist in the worktree, and the section must keep a non-vacuous number
of routed rows so a truncated table cannot pass silently.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

_SECTION_RE = re.compile(
    r"(?ms)^## PROGRESSIVE LOADING\n(.*?)(?=^## |\Z)"
)
_BACKTICKED_RE = re.compile(r"`([^`\n]+)`")

# Non-vacuity floor: the router table ships with far more rows than
# this; the floor only guards against the section (or its parser
# match) collapsing to nothing.
MIN_ROUTED_PATHS = 8


def _router_section() -> str:
    text = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    match = _SECTION_RE.search(text)
    if match is None:
        raise AssertionError("CLAUDE.md has no PROGRESSIVE LOADING section")
    return match.group(1)


def _routed_paths(section: str) -> list[str]:
    """Backticked tokens that look like repo-relative paths.

    A ``/`` marks a path (``tiers/recovery.md``); slash-free tokens
    (tool names, flags) are prose, not router targets.
    """
    return [
        token
        for token in _BACKTICKED_RE.findall(section)
        if "/" in token and not token.startswith("-")
    ]


class ProgressiveRouterTargetTests(unittest.TestCase):
    def test_section_present(self) -> None:
        """Sanity — the router section itself must exist."""
        self.assertTrue(_router_section().strip())

    def test_router_non_vacuous(self) -> None:
        """A truncated or reformatted table must not pass silently."""
        paths = _routed_paths(_router_section())
        self.assertGreaterEqual(
            len(paths),
            MIN_ROUTED_PATHS,
            msg=(
                "PROGRESSIVE LOADING routes fewer paths than the "
                f"non-vacuity floor ({len(paths)} < {MIN_ROUTED_PATHS}); "
                "if the table legitimately shrank, adjust the floor "
                "with the change that shrank it"
            ),
        )

    def test_every_routed_path_exists(self) -> None:
        """Every routed file (or directory) must exist in the tree."""
        missing = [
            token
            for token in _routed_paths(_router_section())
            if not (REPO / token).exists()
        ]
        self.assertEqual(
            missing,
            [],
            msg=(
                "PROGRESSIVE LOADING routes to paths that do not exist: "
                f"{missing} — fix the router row or restore the file"
            ),
        )


if __name__ == "__main__":
    unittest.main()
