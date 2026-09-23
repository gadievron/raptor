"""Degrade-lane messages reach stderr, not a piped stdout consumer.

The OpenAnt soft-skip ("OpenAnt unavailable") printed to stdout while
its hard-error twin and every other degrade lane in main() print to
stderr — a consumer piping stdout swallowed the skip notice. Pinned
structurally (the lane needs a full OpenAnt phase to drive live).
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


def _print_calls_containing(tree: ast.AST, needle: str) -> list[ast.Call]:
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"):
            continue
        for arg in node.args:
            if isinstance(arg, ast.JoinedStr):
                literal = "".join(
                    part.value for part in arg.values
                    if isinstance(part, ast.Constant)
                    and isinstance(part.value, str))
            elif isinstance(arg, ast.Constant) and isinstance(
                    arg.value, str):
                literal = arg.value
            else:
                continue
            if needle in literal:
                found.append(node)
    return found


def _prints_to_stderr(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "file" and isinstance(kw.value, ast.Attribute):
            if (kw.value.attr == "stderr"
                    and isinstance(kw.value.value, ast.Name)
                    and kw.value.value.id == "sys"):
                return True
    return False


class OpenAntDegradeStreamTests(unittest.TestCase):

    def test_soft_skip_and_hard_error_share_the_stream(self):
        tree = ast.parse(RAPTOR_AGENTIC.read_text(encoding="utf-8"))
        for needle in ("OpenAnt unavailable", "OpenAnt scan failed"):
            calls = _print_calls_containing(tree, needle)
            self.assertTrue(calls, f"no print carrying {needle!r}")
            for call in calls:
                self.assertTrue(
                    _prints_to_stderr(call),
                    f"print carrying {needle!r} must go to stderr like "
                    "every other degrade lane",
                )


if __name__ == "__main__":
    unittest.main()
