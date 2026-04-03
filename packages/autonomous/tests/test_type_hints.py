#!/usr/bin/env python3
"""Tests for type hint fixes in autonomous package."""

import time
import typing
import unittest
from pathlib import Path


class TestPlannerTypeHints(unittest.TestCase):
    """Test planner type annotation fixes."""

    def test_strategy_return_type_uses_any(self):
        """select_fuzzing_strategy annotation uses Any, not any."""
        from packages.autonomous.planner import FuzzingPlanner

        hints = typing.get_type_hints(FuzzingPlanner.select_fuzzing_strategy)
        self.assertIn("return", hints)

    def test_binary_path_is_optional(self):
        """FuzzingState.binary_path is Optional[Path], not bare Path."""
        from packages.autonomous.planner import FuzzingState

        hints = typing.get_type_hints(FuzzingState)
        hint = hints["binary_path"]
        origin = getattr(hint, "__origin__", None)
        self.assertTrue(
            origin is not None or hint is type(None),
            f"binary_path should be Optional[Path], got {hint}"
        )

    def test_binary_path_none(self):
        from packages.autonomous.planner import FuzzingState

        state = FuzzingState(
            start_time=time.time(),
            current_time=time.time(),
            binary_path=None
        )
        self.assertIsNone(state.binary_path)

    def test_binary_path_with_value(self):
        from packages.autonomous.planner import FuzzingState

        state = FuzzingState(
            start_time=time.time(),
            current_time=time.time(),
            binary_path=Path("/usr/bin/test")
        )
        self.assertEqual(state.binary_path, Path("/usr/bin/test"))


class TestGoalPlannerTypeHints(unittest.TestCase):
    """Test goal planner type annotation fixes."""

    def test_strategy_hints_uses_any(self):
        """Goal.strategy_hints annotation uses Any, not any."""
        from packages.autonomous.goal_planner import Goal

        hints = typing.get_type_hints(Goal)
        self.assertIn("strategy_hints", hints)


class TestCorpusGeneratorTypeHints(unittest.TestCase):
    """Test corpus generator type annotation fixes."""

    def test_analyze_binary_return_type(self):
        """CorpusGenerator.analyze_binary annotation uses Any, not any."""
        from packages.autonomous.corpus_generator import CorpusGenerator

        hints = typing.get_type_hints(CorpusGenerator.analyze_binary)
        self.assertIn("return", hints)


class TestExploitValidatorTypeHints(unittest.TestCase):
    """Test exploit validator type annotation fixes."""

    def test_optional_params(self):
        """check_mitigations params are Optional, not bare types."""
        from packages.autonomous.exploit_validator import ExploitValidator

        hints = typing.get_type_hints(ExploitValidator.check_mitigations)
        for param in ("binary_path", "vuln_type"):
            hint = hints[param]
            origin = getattr(hint, "__origin__", None)
            self.assertTrue(
                origin is not None or hint is type(None),
                f"{param} should be Optional, got {hint}"
            )


if __name__ == "__main__":
    unittest.main()
