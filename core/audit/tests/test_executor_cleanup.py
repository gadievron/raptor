"""Tests for the executor-failure cleanup path in the orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock

from core.audit.orchestrator import _cleanup_after_executor_failure


class TestCleanupAfterExecutorFailure:
    def test_all_steps_run(self, monkeypatch) -> None:
        import core.audit.orchestrator as orch

        drained = []
        monkeypatch.setattr(
            orch, "_drain_study_consumer",
            lambda thread, queue, budget_exhausted=False: drained.append(
                (thread, queue, budget_exhausted),
            ),
        )
        throttle = MagicMock()
        study_queue = MagicMock()
        thread = MagicMock()
        collector = MagicMock()

        _cleanup_after_executor_failure(
            throttle, study_queue, thread, collector,
        )

        study_queue.signal_producer_done.assert_called_once()
        assert drained == [(thread, study_queue, True)]
        throttle.close.assert_called_once()
        collector.flush.assert_called_once()

    def test_partial_failures_do_not_stop_later_steps(
        self, monkeypatch,
    ) -> None:
        import core.audit.orchestrator as orch

        monkeypatch.setattr(
            orch, "_drain_study_consumer",
            MagicMock(side_effect=RuntimeError("drain broke")),
        )
        throttle = MagicMock()
        throttle.close.side_effect = RuntimeError("close broke")
        study_queue = MagicMock()
        study_queue.signal_producer_done.side_effect = RuntimeError("boom")
        collector = MagicMock()

        # Must not raise, and the collector flush must still happen.
        _cleanup_after_executor_failure(
            throttle, study_queue, MagicMock(), collector,
        )
        collector.flush.assert_called_once()

    def test_tolerates_absent_optionals(self) -> None:
        throttle = MagicMock()
        _cleanup_after_executor_failure(throttle, None, None, None)
        throttle.close.assert_called_once()
