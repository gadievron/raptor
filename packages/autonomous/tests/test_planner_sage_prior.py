#!/usr/bin/env python3
"""FuzzingPlanner + SAGE mechanical prior integration."""

import os
import unittest
from unittest import mock

from packages.autonomous.planner import FuzzingPlanner, FuzzingState


class TestPlannerSageMechanicalPrior(unittest.TestCase):
    def test_high_confidence_mopt_appends_extra_flags(self):
        rows = [
            {"content": "AFL++ MOpt mode worked best on similar binaries", "confidence": 0.9},
        ]
        planner = FuzzingPlanner(
            memory=None,
            sage_planning_notes="notes",
            sage_strategy_rows=rows,
        )
        state = FuzzingState(start_time=0.0, current_time=1.0)
        with mock.patch.dict(os.environ, {"RAPTOR_SAGE_AFL_PRIOR": "1"}, clear=False):
            strat = planner.select_fuzzing_strategy(state)
        self.assertIn("-L", strat.get("extra_flags", []))
        self.assertIn("0", strat.get("extra_flags", []))

    def test_respects_disable_env(self):
        rows = [{"content": "enable MOpt", "confidence": 0.99}]
        planner = FuzzingPlanner(
            memory=None,
            sage_strategy_rows=rows,
        )
        state = FuzzingState(start_time=0.0, current_time=1.0)
        with mock.patch.dict(os.environ, {"RAPTOR_SAGE_AFL_PRIOR": "0"}, clear=False):
            strat = planner.select_fuzzing_strategy(state)
        self.assertNotIn("-L", strat.get("extra_flags", []))


if __name__ == "__main__":
    unittest.main()
