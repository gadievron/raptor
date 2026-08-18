"""Doc-lint: run-lifecycle invocations in the skill/command markdown.

Why this test exists
--------------------
The RUN LIFECYCLE contract in CLAUDE.md is executed literally by the
model: skill and command markdown bodies are the source of truth for
the exact CLI lines the session runs (SLASH-COMMAND DISPATCH rule 3).
A doc that drifts from ``libexec/raptor-run-lifecycle``'s actual
surface — a renamed subcommand, or a ``start`` example without
``--target`` — produces broken runs that no python test catches.

Two mechanical rules, matching the script's dispatch (its ``main()``
accepts exactly start/complete/fail/cancel, and CLAUDE.md mandates
``--target`` on every ``start``):

* every ``raptor-run-lifecycle <word>`` reference in CLAUDE.md and
  .claude/**/*.md must use a real subcommand;
* every invocation line that starts with
  ``libexec/raptor-run-lifecycle start`` must carry ``--target``.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

# parents[2] = .github/tests → .github → repo root. Anchor to this
# file, not $RAPTOR_DIR, so the test inspects its own worktree.
REPO = Path(__file__).resolve().parents[2]

VALID_SUBCOMMANDS = {"start", "complete", "fail", "cancel"}

# `raptor-run-lifecycle` followed on the same line by a bare word.
# Backticks, em-dashes, punctuation etc. end the match, so prose like
# "resolved by `raptor-run-lifecycle`:" is not treated as an
# invocation.
_SUBCOMMAND_RE = re.compile(r"raptor-run-lifecycle[ \t]+([a-z][a-z-]*)")


def _doc_files() -> list[Path]:
    docs = [REPO / "CLAUDE.md"]
    docs += sorted((REPO / ".claude").rglob("*.md"))
    return [p for p in docs if p.is_file()]


class LifecycleDocSyntaxTests(unittest.TestCase):
    def test_docs_exist(self):
        """Sanity — the doc set must not silently shrink to nothing."""
        self.assertGreater(len(_doc_files()), 1, msg="doc set unexpectedly empty")

    def test_subcommands_are_real(self):
        problems = []
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                for m in _SUBCOMMAND_RE.finditer(line):
                    if m.group(1) not in VALID_SUBCOMMANDS:
                        problems.append(
                            f"{doc.relative_to(REPO)}:{i}: "
                            f"unknown subcommand {m.group(1)!r}"
                        )
        self.assertEqual(
            problems, [],
            msg=(
                "docs reference raptor-run-lifecycle subcommands the "
                "script does not dispatch (valid: "
                f"{sorted(VALID_SUBCOMMANDS)}):\n" + "\n".join(problems)
            ),
        )

    def test_start_invocations_carry_target(self):
        problems = []
        for doc in _doc_files():
            text = doc.read_text(encoding="utf-8", errors="replace")
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped.startswith("libexec/raptor-run-lifecycle start"):
                    continue
                if "--target" not in stripped:
                    problems.append(f"{doc.relative_to(REPO)}:{i}: {stripped}")
        self.assertEqual(
            problems, [],
            msg=(
                "raptor-run-lifecycle start invocations without --target "
                "(CLAUDE.md mandates it on every start):\n"
                + "\n".join(problems)
            ),
        )


if __name__ == "__main__":
    unittest.main()
