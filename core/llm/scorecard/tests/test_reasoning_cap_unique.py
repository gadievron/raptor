"""Parse-time drift guard for `_MAX_REASONING_CHARS`.

F007: the integer cap on disagreement-sample reasoning text length
(`_MAX_REASONING_CHARS = 500`) was duplicated in 4 producer files under
`core/llm/scorecard/`. The constant slices `analysis_reasoning` /
`this_reasoning` / `sample_reasoning` before persisting into a
disagreement sample, so all 4 producers must agree or the on-disk
sample lengths diverge.

This test:

  1. Pins the canonical constant to the package root,
     `core.llm.scorecard._MAX_REASONING_CHARS`.
  2. Verifies the 4 producers import it from the package root and do
     NOT define their own module-level copy (parse-time AST scan —
     fails if anyone reintroduces the duplicate).

Pattern parallels FT1 §1 (F005 `CWE_TO_VULN_TYPE` dedupe).
"""

from __future__ import annotations

import ast
import pathlib
import unittest


SCORECARD_DIR = pathlib.Path(__file__).resolve().parents[1]
PRODUCERS = [
    "tool_evidence.py",
    "judge.py",
    "consensus.py",
    "reasoning_divergence.py",
]


def _module_level_const_value(py_path: pathlib.Path, name: str) -> int | None:
    """Return the integer literal assigned to `name` at module scope, or None."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name) and tgt.id == name:
                    if isinstance(node.value, ast.Constant) and isinstance(
                        node.value.value, int
                    ):
                        return node.value.value
        elif isinstance(node, ast.AnnAssign):
            tgt = node.target
            if (
                isinstance(tgt, ast.Name)
                and tgt.id == name
                and node.value is not None
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, int)
            ):
                return node.value.value
    return None


class MaxReasoningCharsDriftGuard(unittest.TestCase):

    def test_canonical_constant_is_exported_from_package_root(self) -> None:
        """F007: `_MAX_REASONING_CHARS` lives in core.llm.scorecard."""
        from core.llm import scorecard

        self.assertTrue(hasattr(scorecard, "_MAX_REASONING_CHARS"))
        self.assertIsInstance(scorecard._MAX_REASONING_CHARS, int)
        # Pin the historical value so we notice if anyone bumps it.
        self.assertEqual(scorecard._MAX_REASONING_CHARS, 500)

    def test_no_producer_redefines_constant_at_module_scope(self) -> None:
        """F007: any duplicate definition is parse-time drift risk."""
        offenders: list[str] = []
        for fname in PRODUCERS:
            path = SCORECARD_DIR / fname
            self.assertTrue(path.is_file(), f"{path} missing")
            value = _module_level_const_value(path, "_MAX_REASONING_CHARS")
            if value is not None:
                offenders.append(
                    f"{fname}: defines _MAX_REASONING_CHARS={value} at "
                    "module scope; import from `core.llm.scorecard` instead."
                )
        self.assertEqual(
            offenders,
            [],
            "F007 drift: producer modules redefine the canonical cap.\n"
            + "\n".join(offenders),
        )

    def test_all_producers_import_canonical_constant(self) -> None:
        """Every producer must import the constant from the package root."""
        missing: list[str] = []
        for fname in PRODUCERS:
            path = SCORECARD_DIR / fname
            tree = ast.parse(path.read_text(encoding="utf-8"))
            found = False
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    # Relative import (level >= 1, e.g. `from . import X` or
                    # `from .scorecard import X`) into the scorecard package
                    # OR an absolute import from core.llm.scorecard.
                    is_package_root_relative = (
                        node.level == 1 and node.module is None
                    )
                    is_absolute_root = (
                        node.level == 0
                        and node.module == "core.llm.scorecard"
                    )
                    if is_package_root_relative or is_absolute_root:
                        for alias in node.names:
                            if alias.name == "_MAX_REASONING_CHARS":
                                found = True
                                break
                if found:
                    break
            if not found:
                missing.append(fname)
        self.assertEqual(
            missing,
            [],
            "Producers missing `from core.llm.scorecard import "
            f"_MAX_REASONING_CHARS`: {missing}",
        )


if __name__ == "__main__":
    unittest.main()
