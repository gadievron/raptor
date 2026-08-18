"""Drift-guard: target-repo git callers must use core.git's wrappers.

These call sites run git against repositories cloned from untrusted
sources, where a hostile ``.git/config`` (core.fsmonitor,
core.hooksPath, filter drivers, ...) executes attacker commands on
ordinary git operations. Each of them once built bare ``["git", ...]``
argvs (or re-derived a private ``-c`` pin list that drifted behind
core's). This test pins the adoption so the bypasses cannot silently
come back.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# (file, wrapper-name that must appear, forbidden fragments)
_SITES = (
    (
        "core/dataflow/cvefix_bridge.py",
        "safe_git_readonly_command",
        ('["git", "-C"',),
    ),
    (
        "core/audit/corpus/run_corpus.py",
        "safe_git_command",
        ('["git", "-C"',),
    ),
    (
        "raptor_agentic.py",
        "safe_git_command",
        # The re-derived private pin list: safe_git_command already
        # carries hooksPath (and much more); a literal re-pin here
        # means the site regressed to its own list.
        ('"core.hooksPath=/dev/null"', '["git"] + git_safe'),
    ),
)


class TestSafeGitAdoption(unittest.TestCase):
    def test_target_repo_git_sites_use_core_wrappers(self):
        for rel, wrapper, forbidden in _SITES:
            with self.subTest(file=rel):
                text = (REPO / rel).read_text(encoding="utf-8")
                self.assertIn(
                    wrapper, text,
                    f"{rel} no longer routes git through core.git.{wrapper}",
                )
                for frag in forbidden:
                    self.assertNotIn(
                        frag, text,
                        f"{rel} regressed to a bare/private git argv "
                        f"({frag!r})",
                    )


if __name__ == "__main__":
    unittest.main()
