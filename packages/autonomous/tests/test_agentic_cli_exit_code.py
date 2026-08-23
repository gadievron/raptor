"""Regression test: ``main()`` in raptor_agentic.py never falls through.

``main`` feeds ``sys.exit(main())``. Pre-fix, the successful end of the
full pipeline fell off the end of the function and returned an implicit
``None`` — ``sys.exit(None)`` happens to exit 0, but any caller that
treats the return value as an int (or any future refactor that maps the
code differently) would silently misreport success. The fix makes the
success path return an explicit ``0``.

The test asserts structurally (via ``ast``, no import of the module and
no pipeline execution) that the final statement of ``main`` is an
explicit ``return 0``.
"""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

# parents[3] climbs:
#   [0] packages/autonomous/tests/
#   [1] packages/autonomous/
#   [2] packages/
#   [3] <repo root>
REPO_ROOT = Path(__file__).resolve().parents[3]
RAPTOR_AGENTIC = REPO_ROOT / "raptor_agentic.py"


class MainExitCodeTests(unittest.TestCase):
    """The CLI entry point ends with an explicit success return."""

    def test_main_ends_with_explicit_return_zero(self):
        tree = ast.parse(RAPTOR_AGENTIC.read_text(encoding="utf-8"))
        mains = [
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "main"
        ]
        self.assertEqual(len(mains), 1, "expected exactly one top-level main()")
        last = mains[0].body[-1]
        self.assertIsInstance(
            last, ast.Return,
            "main() must not fall through — sys.exit(main()) needs an "
            "explicit exit code",
        )
        self.assertIsInstance(last.value, ast.Constant)
        self.assertEqual(
            last.value.value, 0,
            "the pipeline-complete fallthrough path is the success path; "
            "its exit code is 0",
        )


if __name__ == "__main__":
    unittest.main()
