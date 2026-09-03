"""The SCA artefact pointers must survive from producer to consumer.

``sca_findings_path`` is set by whichever SCA mode runs (mechanical or
deep) and read twice, far downstream: ``run_validation_phase`` merges the
dependency findings, and the final report publishes the path. A second
``= None`` initialiser sitting between the mechanical producer and those
consumers silently dropped every mechanical-mode dependency finding out
of validation and left ``outputs.sca_findings`` null on the default path.

The clobber is invisible in a 4000-line ``main()``, so guard it
structurally rather than by re-running the whole workflow.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from raptor_agentic import _sca_mode

_POINTERS = ("sca_findings_path", "sca_report_path")


def _main_function() -> ast.FunctionDef:
    tree = ast.parse((REPO_ROOT / "raptor_agentic.py").read_text("utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node
    msg = "raptor_agentic.main() not found"
    raise AssertionError(msg)


def _assignments(name: str) -> list[tuple[int, bool]]:
    """``(lineno, assigns_none)`` for every binding of ``name`` in main()."""
    found = []
    for node in ast.walk(_main_function()):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                found.append((
                    node.lineno,
                    isinstance(node.value, ast.Constant)
                    and node.value.value is None,
                ))
    return sorted(found)


class TestScaPointerWiring(unittest.TestCase):

    def test_pointers_are_initialised_exactly_once(self):
        for name in _POINTERS:
            with self.subTest(pointer=name):
                assignments = _assignments(name)
                self.assertTrue(assignments, f"{name} is never assigned")
                none_inits = [ln for ln, is_none in assignments if is_none]
                self.assertEqual(
                    len(none_inits), 1,
                    f"{name} is re-initialised to None at lines "
                    f"{none_inits} — a second initialiser clobbers whatever "
                    f"an earlier SCA phase produced",
                )

    def test_the_only_none_init_precedes_every_producer(self):
        for name in _POINTERS:
            with self.subTest(pointer=name):
                assignments = _assignments(name)
                none_init = next(ln for ln, is_none in assignments if is_none)
                producers = [ln for ln, is_none in assignments if not is_none]
                self.assertTrue(producers, f"{name} is never given a value")
                self.assertLess(none_init, min(producers))


class TestScaMode(unittest.TestCase):

    def test_deep_wins_over_mechanical(self):
        self.assertEqual(_sca_mode(True, False), "deep")
        # The gate makes this combination unreachable, but "deep"
        # remains the honest answer if it ever occurs.
        self.assertEqual(_sca_mode(True, True), "deep")

    def test_mechanical_when_the_subprocess_phase_ran(self):
        self.assertEqual(_sca_mode(False, True), "mechanical")

    def test_none_when_no_sca_phase_ran(self):
        # No agent installed: reporting "mechanical" named a phase that
        # never existed.
        self.assertEqual(_sca_mode(False, False), "none")


if __name__ == "__main__":
    unittest.main()
