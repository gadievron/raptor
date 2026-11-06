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
import sys
import threading
import time
import types

import pytest

from core.testing.poll_clock import install_poll_clock
from core.testing.processes import reap_on_exit
from core.testing.wallclock import wall_deadline

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
        # The regression is the dequeue serving its full 300s timeout
        # despite the stop; 10s of load headroom stays unambiguously
        # on the prompt-return side of that bound.
        with wall_deadline(10.0, code_bound_s=300.0,
                           what="dequeue after stop"):
            batch = q.dequeue_batch(timeout=300.0)
        assert batch == []

    def test_stop_wakes_a_blocked_dequeue(self, monkeypatch):
        q = StudyQueue()
        got = {}

        def _consume():
            got["batch"] = q.dequeue_batch(timeout=30.0)

        waiting = threading.Event()
        original_wait = q._not_empty.wait

        def wait_until_notified(timeout=None):
            # Still holding the condition: request_stop cannot race ahead of
            # the real wait releasing that lock and parking the consumer.
            waiting.set()
            return original_wait(timeout)

        monkeypatch.setattr(q._not_empty, "wait", wait_until_notified)
        t = threading.Thread(target=_consume)
        try:
            t.start()
            assert waiting.wait(timeout=5), "consumer never entered dequeue wait"
            q.request_stop()
            t.join(timeout=5)
            assert not t.is_alive(), "stop must wake the dequeue wait"
            assert got["batch"] == []
        finally:
            q.request_stop()
            # Wake even if the stop notifier itself is the regression.
            with q._not_empty:
                q._not_empty.notify_all()
            if t.ident is not None:
                t.join(timeout=5)
                assert not t.is_alive(), "dequeue consumer leaked"

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
    def test_stop_kills_subprocess_and_raises(self, monkeypatch):
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

        registered = threading.Event()
        children = []
        original_register = q.register_inflight

        def register(proc):
            # Retain ownership even if registration itself fails.
            children.append(proc)
            original_register(proc)
            registered.set()

        monkeypatch.setattr(q, "register_inflight", register)
        t = threading.Thread(target=_run)
        try:
            t.start()
            assert registered.wait(timeout=5), "prep child was never registered"
            assert children[0].poll() is None, "prep exited before cancellation"
            t0 = time.monotonic()
            q.request_stop()
            t.join(timeout=15)
            assert not t.is_alive(), "prep must unwind after a stop request"
            assert result.get("stopped") is True
            assert time.monotonic() - t0 < 10, (
                "stop must interrupt the prep wait promptly, not ride out "
                "the full timeout"
            )
        finally:
            q.request_stop()
            for child in children:
                with reap_on_exit(child):
                    pass
            if t.ident is not None:
                t.join(timeout=15)
                assert not t.is_alive(), "prep consumer leaked"

    def test_timeout_contract_preserved(self):
        q = StudyQueue()
        with pytest.raises(subprocess.TimeoutExpired):
            _run_study_prep(
                ["/bin/sleep", "60"], env={}, timeout=0.2, study_queue=q,
            )

    def test_completes_normally(self):
        q = StudyQueue()
        proc = _run_study_prep(
            [sys.executable, "-c", "pass"], env={}, timeout=30, study_queue=q,
        )
        assert proc.returncode == 0


@pytest.fixture
def drain_clock(monkeypatch):
    import core.audit.orchestrator as orch

    return install_poll_clock(monkeypatch, orch)


class _TimedConsumer:
    """Thread-shaped lifecycle whose joins consume only logical time.

    Queue notification and process cancellation use native workers above;
    drain-policy tests need only join, liveness, and a completion instant.
    """

    def __init__(self, clock, queue, *, finish_at=float("inf"), cooperative=True):
        self.clock = clock
        self.queue = queue
        self.finish_at = finish_at
        self.cooperative = cooperative
        self.joins = []

    def is_alive(self):
        return (self.clock.seconds < self.finish_at
                and not (self.cooperative and self.queue.stop_requested))

    def join(self, timeout):
        assert timeout > 0, "drain must use bounded, positive joins"
        self.joins.append(timeout)
        self.clock.sleep(min(timeout, self.finish_at - self.clock.seconds))


class TestDrainStudyConsumer:
    def test_budget_exhausted_stops_immediately(self, monkeypatch, drain_clock):
        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        t = _TimedConsumer(drain_clock, q)
        assert t.is_alive()
        _drain_study_consumer(t, q, budget_exhausted=True)
        assert not t.is_alive()
        assert q.stop_requested
        assert drain_clock.seconds == 0
        assert t.joins == []
        assert any("requesting stop" in m for m in warnings), (
            "forced stop must be announced loudly"
        )

    def test_idle_no_progress_stops_after_grace(self, monkeypatch, drain_clock):
        from core.audit.orchestrator import _STUDY_DRAIN_NO_PROGRESS_S

        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        t = _TimedConsumer(drain_clock, q)
        _drain_study_consumer(t, q, budget_exhausted=False)
        assert not t.is_alive()
        assert q.stop_requested
        # Exercise the shipped grace rather than shortening it for the test.
        assert drain_clock.seconds == _STUDY_DRAIN_NO_PROGRESS_S
        assert any("no progress" in m for m in warnings)

    def test_working_consumer_is_not_stopped_within_cap(self, drain_clock):
        from core.audit.orchestrator import _STUDY_DRAIN_NO_PROGRESS_S

        q = StudyQueue()
        q.set_working(True)
        done_at = 2 * _STUDY_DRAIN_NO_PROGRESS_S
        t = _TimedConsumer(drain_clock, q, finish_at=done_at)
        _drain_study_consumer(t, q, budget_exhausted=False)
        assert not t.is_alive()
        assert drain_clock.seconds == done_at
        assert not q.stop_requested

    def test_abandonment_carries_a_stop(self, monkeypatch, drain_clock):
        from core.audit.orchestrator import _study_drain_timeout_s

        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        q.set_working(True)
        t = _TimedConsumer(drain_clock, q, cooperative=False)
        _drain_study_consumer(t, q, budget_exhausted=False)
        assert t.is_alive(), "precondition: the drain abandoned a live consumer"
        assert drain_clock.seconds == _study_drain_timeout_s()
        assert q.stop_requested, "abandonment must request a cooperative stop"
        assert any("abandoning" in m for m in warnings)

    def test_clean_exit_needs_no_stop(self, monkeypatch, drain_clock):
        warnings = _capture(monkeypatch, "warning")
        q = StudyQueue()
        q.signal_producer_done()
        t = _TimedConsumer(drain_clock, q, finish_at=0)
        _drain_study_consumer(t, q, budget_exhausted=False)
        assert not t.is_alive()
        assert not q.stop_requested
        assert t.joins == []
        assert drain_clock.seconds == 0
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


class TestDrainCeilingCoversMaxWall:
    """The drain's effective hard ceiling must cover the longest wall
    a single study batch attempt can legitimately hold — a bound below
    it abandons a healthy escalated retry mid-generation after
    billing — while never sinking below the historical 600s floor."""

    def test_ceiling_covers_the_escalated_wall(self):
        from core.audit.orchestrator import (
            _STUDY_DRAIN_TIMEOUT_S,
            _study_drain_timeout_s,
        )
        from core.concepts.study import _max_batch_wall_timeout
        effective = _study_drain_timeout_s()
        # Direction 1: never below the longest single-call wall.
        assert effective >= _max_batch_wall_timeout()
        # Direction 2: never below the historical floor either.
        assert effective >= _STUDY_DRAIN_TIMEOUT_S
        # Shipped numbers: 3x multiplier -> 990s escalated wall.
        assert effective == 990

    def test_ceiling_tracks_the_multiplier_both_directions(
        self, monkeypatch,
    ):
        import core.concepts.study as study
        from core.audit.orchestrator import _study_drain_timeout_s
        # Multiplier up: the ceiling follows the stretched wall.
        monkeypatch.setattr(
            study, "_TRUNCATION_ESCALATION_MULTIPLIER", 6)
        assert _study_drain_timeout_s() == 1980
        # Multiplier down to no-stretch: the wall's own 660s floor
        # (>= the 600s drain floor) holds — the ceiling never shrinks
        # below either floor.
        monkeypatch.setattr(
            study, "_TRUNCATION_ESCALATION_MULTIPLIER", 1)
        assert _study_drain_timeout_s() == 660

    def test_drain_resolves_derived_ceiling_when_unspecified(
        self, monkeypatch, drain_clock,
    ):
        import core.audit.orchestrator as _orch
        resolved = []

        def _fake_ceiling() -> float:
            resolved.append(True)
            return 5.0

        monkeypatch.setattr(
            _orch, "_study_drain_timeout_s", _fake_ceiling)
        dead = _TimedConsumer(drain_clock, StudyQueue(), finish_at=0)
        _drain_study_consumer(dead, None, budget_exhausted=False)
        assert resolved, (
            "an unspecified timeout_s must resolve the derived ceiling"
        )
        # An explicit timeout_s bypasses the derivation.
        resolved.clear()
        _drain_study_consumer(
            dead, None, budget_exhausted=False, timeout_s=1.0,
        )
        assert not resolved
