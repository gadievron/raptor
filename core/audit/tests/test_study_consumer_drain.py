"""Drain/shutdown seam for the study consumer.

A real run spent ~10 minutes (43% of wall time) inside a blind
``join(timeout=600)`` while the consumer was stuck in a doomed
study-prep subprocess whose LLM seeding call timed out and retried.
The drain is now state-aware: budget-exhausted runs request an
immediate cooperative stop (killing the in-flight prep subprocess),
idle consumers are stopped after a short no-progress grace, and only
an actively-working consumer with budget remaining is allowed the
full historical cap.
"""

from __future__ import annotations

import subprocess
import threading
import time
import types

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _drain_study_consumer,
    _LockedOutcomes,
    _run_study_prep,
    _study_consumer_loop,
    _StudyStopRequested,
)


class _FakeProc:
    """Killable stand-in for a study-prep subprocess."""

    def __init__(self):
        self.killed = threading.Event()
        self.returncode = None

    def kill(self):
        self.killed.set()
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def _capture(monkeypatch, level):
    import core.audit.orchestrator as _orch

    lines = []

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))

    monkeypatch.setattr(_orch.logger, level, _sink)
    return lines


class TestStudyQueueStop:
    def test_dequeue_returns_immediately_after_stop(self):
        q = StudyQueue()
        q.request_stop()
        t0 = time.monotonic()
        batch = q.dequeue_batch(timeout=30.0)
        assert batch == []
        assert time.monotonic() - t0 < 1.0, (
            "dequeue must not block once a stop was requested"
        )

    def test_stop_wakes_a_blocked_dequeue(self):
        q = StudyQueue()
        got = {}

        def _consume():
            got["batch"] = q.dequeue_batch(timeout=30.0)

        t = threading.Thread(target=_consume, daemon=True)
        t.start()
        time.sleep(0.1)
        q.request_stop()
        t.join(timeout=5)
        assert not t.is_alive(), "stop must wake the dequeue wait"
        assert got["batch"] == []

    def test_is_done_true_after_stop_even_with_items(self):
        q = StudyQueue()
        q.enqueue(StudyRequest(
            question="what is x?", source_file="a.c", source_function="f",
        ))
        assert not q.is_done()
        q.request_stop()
        assert q.is_done()

    def test_stop_kills_registered_inflight_proc(self):
        q = StudyQueue()
        proc = _FakeProc()
        q.register_inflight(proc)
        q.request_stop()
        assert proc.killed.is_set()

    def test_stop_racing_ahead_of_registration_still_kills(self):
        q = StudyQueue()
        q.request_stop()
        proc = _FakeProc()
        q.register_inflight(proc)
        assert proc.killed.is_set()


class TestRunStudyPrepInterruptible:
    def test_stop_kills_subprocess_and_raises(self):
        q = StudyQueue()
        result = {}

        def _run():
            try:
                _run_study_prep(
                    ["/bin/sleep", "60"],
                    env={},
                    timeout=60,
                    study_queue=q,
                )
            except _StudyStopRequested:
                result["stopped"] = True
            except Exception as exc:  # noqa: BLE001
                result["error"] = exc

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        q.request_stop()
        t.join(timeout=15)
        assert not t.is_alive(), "prep must unwind after a stop request"
        assert result.get("stopped") is True
        assert time.monotonic() - t0 < 10, (
            "stop must interrupt the prep wait promptly, not ride out "
            "the full timeout"
        )

    def test_timeout_contract_preserved(self):
        q = StudyQueue()
        with pytest.raises(subprocess.TimeoutExpired):
            _run_study_prep(
                ["/bin/sleep", "60"], env={}, timeout=0.2, study_queue=q,
            )

    def test_completes_normally(self):
        q = StudyQueue()
        proc = _run_study_prep(
            ["/bin/true"], env={}, timeout=30, study_queue=q,
        )
        assert proc.returncode == 0


def _idle_consumer_thread(q):
    """A consumer-shaped thread that loops on the queue like the real
    inner loop's dequeue wait (idle: not working, empty queue)."""

    def _loop():
        while not q.is_done():
            q.dequeue_batch(max_items=15, timeout=1.0)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


class TestDrainStudyConsumer:
    def test_budget_exhausted_stops_immediately(self, monkeypatch):
        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        q.signal_producer_done()
        t = _idle_consumer_thread(q)
        t0 = time.monotonic()
        _drain_study_consumer(t, q, budget_exhausted=True)
        elapsed = time.monotonic() - t0
        assert not t.is_alive()
        assert elapsed < 10, (
            f"budget-exhausted drain must not idle (took {elapsed:.1f}s)"
        )
        assert any("requesting stop" in m for m in warnings), (
            "forced stop must be announced loudly"
        )

    def test_idle_no_progress_stops_after_grace(self, monkeypatch):
        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        # Producer NOT done and queue empty: without a stop this
        # consumer would sit in dequeue waits until the 600s cap.
        t = _idle_consumer_thread(q)
        t0 = time.monotonic()
        _drain_study_consumer(
            t, q,
            budget_exhausted=False,
            no_progress_grace_s=1.0,
            poll_s=0.2,
            timeout_s=30.0,
        )
        elapsed = time.monotonic() - t0
        assert not t.is_alive()
        assert elapsed < 15, (
            f"idle drain must stop after the grace, took {elapsed:.1f}s"
        )
        assert any("no progress" in m for m in warnings)

    def test_working_consumer_is_not_stopped_within_cap(self):
        q = StudyQueue()
        q.set_working(True)
        done = threading.Event()

        def _work():
            done.wait(timeout=3.0)

        t = threading.Thread(target=_work, daemon=True)
        t.start()
        _drain_study_consumer(
            t, q,
            budget_exhausted=False,
            no_progress_grace_s=0.5,
            poll_s=0.1,
            timeout_s=1.2,
        )
        # The drain hit its cap without requesting a stop: a working
        # consumer with budget left is allowed to finish.
        assert not q.stop_requested
        done.set()
        t.join(timeout=5)

    def test_clean_exit_needs_no_stop(self, monkeypatch):
        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        q.signal_producer_done()
        t = _idle_consumer_thread(q)   # exits immediately: is_done()
        _drain_study_consumer(t, q, budget_exhausted=False)
        assert not t.is_alive()
        assert not q.stop_requested
        assert warnings == []


class TestConsumerLoopHonoursStop:
    def test_loop_exits_when_stop_requested_midway(self, monkeypatch):
        import core.audit.orchestrator as _orch

        # Prep succeeds instantly and produces the study list.
        def fake_prep(cmd, **kwargs):
            return types.SimpleNamespace(returncode=0, stderr="")

        monkeypatch.setattr(_orch, "_run_study_prep", fake_prep)

        q = StudyQueue()
        for i in range(30):
            q.enqueue(StudyRequest(
                question=f"what is c{i}?",
                source_file="a.c",
                source_function=f"fn{i}",
            ))
        # No producer_done: without the stop the loop would keep
        # waiting for more batches.
        q.request_stop()

        shared = types.SimpleNamespace(domain_model=None)
        t0 = time.monotonic()
        _study_consumer_loop(
            q,
            OrchestratorConfig(target_path=".", out_dir=None),
            shared,
            lambda ctx, cfg: None,
            _LockedOutcomes(),
            OrchestratorResult(),
            checklist={"files": []},
            context_map=None,
            evidence_index={},
            sarif_cache=None,
            entry_points=set(),
            start_time=time.monotonic(),
            on_progress=None,
        )
        assert time.monotonic() - t0 < 5, (
            "consumer loop must exit promptly once a stop is requested"
        )
