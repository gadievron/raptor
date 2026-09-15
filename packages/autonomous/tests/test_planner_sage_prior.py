#!/usr/bin/env python3
"""FuzzingPlanner + SAGE mechanical prior integration."""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from packages.autonomous.planner import FuzzingPlanner, FuzzingState


def _stamped_strategy_row(strategy_id, confidence=0.9):
    """Build a strategy-outcome row the way core.sage.hooks stores it,
    including the row-MAC token that authorises mechanical flag use."""
    from core.sage import rowmac
    from core.sage.hooks import _afl_flags_from_text

    content = (
        f"Fuzzing strategy outcome for repo demo: "
        f"strategy {strategy_id}, binary fingerprint abc123, "
        f"duration 300s, executions 100000, unique crashes 2, "
        f"hangs 0, exploitable crashes 1."
    )
    fields = {
        "kind": "afl_flags",
        "strategy": strategy_id,
        "fingerprint": "abc123",
        "flags": " ".join(_afl_flags_from_text(content)),
    }
    return {"content": rowmac.stamp(content, fields), "confidence": confidence}


class TestPlannerSageMechanicalPrior(unittest.TestCase):
    def setUp(self):
        # Keep the row-MAC key out of the checkout's .sage/ state.
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        patcher = mock.patch(
            "core.sage.rowmac._key_path",
            return_value=Path(self._tmp.name) / "rowmac.key",
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_high_confidence_mopt_appends_extra_flags(self):
        rows = [_stamped_strategy_row("mopt-havoc")]
        planner = FuzzingPlanner(
            memory=None,
            sage_strategy_rows=rows,
        )
        state = FuzzingState(start_time=0.0, current_time=1.0)
        with mock.patch.dict(os.environ, {"RAPTOR_SAGE_AFL_PRIOR": "1"}, clear=False):
            strat = planner.select_fuzzing_strategy(state)
        self.assertIn("-L", strat.get("extra_flags", []))
        self.assertIn("0", strat.get("extra_flags", []))

    def test_unstamped_row_appends_no_flags(self):
        """Rows without a valid row MAC never become argv flags."""
        rows = [
            {"content": "AFL++ MOpt mode worked best on similar binaries", "confidence": 0.9},
        ]
        planner = FuzzingPlanner(
            memory=None,
            sage_strategy_rows=rows,
        )
        state = FuzzingState(start_time=0.0, current_time=1.0)
        with mock.patch.dict(os.environ, {"RAPTOR_SAGE_AFL_PRIOR": "1"}, clear=False):
            strat = planner.select_fuzzing_strategy(state)
        self.assertNotIn("-L", strat.get("extra_flags", []))

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

    def test_disable_env_shared_toggle_spellings(self):
        """All shared falsy spellings disable — pre-fix ``off`` was
        silently ignored (only 0/false/no were recognised)."""
        rows = [_stamped_strategy_row("mopt-havoc")]
        state = FuzzingState(start_time=0.0, current_time=1.0)
        for value in ("off", "false", "no", "OFF"):
            planner = FuzzingPlanner(memory=None, sage_strategy_rows=rows)
            with mock.patch.dict(
                os.environ, {"RAPTOR_SAGE_AFL_PRIOR": value}, clear=False
            ):
                strat = planner.select_fuzzing_strategy(state)
            self.assertNotIn(
                "-L", strat.get("extra_flags", []),
                f"RAPTOR_SAGE_AFL_PRIOR={value} did not disable the prior",
            )

    def test_enable_env_shared_toggle_spellings(self):
        rows = [_stamped_strategy_row("mopt-havoc")]
        state = FuzzingState(start_time=0.0, current_time=1.0)
        for value in ("1", "true", "yes", "on"):
            planner = FuzzingPlanner(memory=None, sage_strategy_rows=rows)
            with mock.patch.dict(
                os.environ, {"RAPTOR_SAGE_AFL_PRIOR": value}, clear=False
            ):
                strat = planner.select_fuzzing_strategy(state)
            self.assertIn(
                "-L", strat.get("extra_flags", []),
                f"RAPTOR_SAGE_AFL_PRIOR={value} did not keep the prior on",
            )

    def test_unrecognised_env_value_keeps_default_on(self):
        rows = [_stamped_strategy_row("mopt-havoc")]
        planner = FuzzingPlanner(memory=None, sage_strategy_rows=rows)
        state = FuzzingState(start_time=0.0, current_time=1.0)
        with mock.patch.dict(
            os.environ, {"RAPTOR_SAGE_AFL_PRIOR": "disable"}, clear=False
        ):
            strat = planner.select_fuzzing_strategy(state)
        self.assertIn("-L", strat.get("extra_flags", []))


class TestDecisionHistorySerialisation(unittest.TestCase):
    def test_action_stored_as_string_not_enum(self):
        import json
        planner = FuzzingPlanner(memory=None)
        state = FuzzingState(start_time=0.0, current_time=1.0)
        planner.decide_next_action(state)
        assert planner.decision_history
        entry = planner.decision_history[-1]
        json.dumps(entry)
        assert isinstance(entry["action"], str)
        assert "Action." not in entry["action"]


if __name__ == "__main__":
    unittest.main()


class TestDecisionTreeOrdering(unittest.TestCase):
    """The stop rule (long dead campaign) must not be shadowed by the
    coverage-stall rule: a dead campaign always has stalled coverage,
    so the stall rule alone would keep it alive forever."""

    @staticmethod
    def _dead_campaign_state() -> FuzzingState:
        now = time.time()
        return FuzzingState(
            start_time=now - 7200,          # 2h elapsed
            current_time=now,
            total_crashes=0,
            crashes_last_minute=0,
            coverage_plateau_duration=1000,  # coverage stalled too
        )

    def test_dead_campaign_stops_despite_stalled_coverage(self):
        from packages.autonomous.planner import Action
        planner = FuzzingPlanner(memory=None)
        action = planner.decide_next_action(self._dead_campaign_state())
        self.assertEqual(action, Action.STOP_FUZZING)

    def test_stalled_but_crashing_campaign_changes_mutator(self):
        from packages.autonomous.planner import Action
        now = time.time()
        state = FuzzingState(
            start_time=now - 7200,
            current_time=now,
            total_crashes=3,                 # progress exists
            crashes_last_minute=0,
            coverage_plateau_duration=1000,
        )
        planner = FuzzingPlanner(memory=None)
        self.assertEqual(
            planner.decide_next_action(state), Action.CHANGE_MUTATOR,
        )

    def test_zero_target_duration_means_stop_now(self):
        now = time.time()
        state = FuzzingState(
            start_time=now - 10,
            current_time=now,
            total_crashes=0,
            crashes_last_minute=0,
        )
        planner = FuzzingPlanner(memory=None)
        # 0 is a set duration that has already elapsed, not "unset".
        self.assertFalse(planner.should_continue_fuzzing(state, target_duration=0))
        self.assertTrue(planner.should_continue_fuzzing(state, target_duration=None))

    def test_decision_history_bounded_with_true_total(self):
        planner = FuzzingPlanner(memory=None)
        now = time.time()
        state = FuzzingState(start_time=now - 1, current_time=now,
                             crashes_last_minute=1)
        for _ in range(planner._DECISION_HISTORY_MAX + 5):
            planner.decide_next_action(state)
        summary = planner.get_decision_summary()
        self.assertEqual(
            summary["total_decisions"], planner._DECISION_HISTORY_MAX + 5,
        )
        self.assertEqual(
            len(summary["decisions"]), planner._DECISION_HISTORY_MAX,
        )
