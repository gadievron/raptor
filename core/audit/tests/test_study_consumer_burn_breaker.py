"""Study-consumer burn breaker.

Each run_study invocation is a fresh phase with fresh abort counters,
so a deterministic failure that kills every invocation was never
terminal for the LANE: the consumer warned, marked the batch studied,
and bought the next batch's failing calls. These tests pin the three
trips that now disable the lane loudly (config-shaped on sight,
consecutive invocation failures, failure rate over a minimum sample),
the partial-success truncation-cap disable, and the cooperative-stop
plumbing that lets the drain path interrupt a RUNNING phase.

Hermetic: prep is faked, run_study is monkeypatched, no LLM calls.
"""

from __future__ import annotations

import time
import types

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _LockedOutcomes,
    _study_consumer_loop,
)


def _capture_warnings(monkeypatch):
    import core.audit.orchestrator as _orch

    lines = []

    def _sink(msg, *args, **kwargs):
        try:
            lines.append(str(msg) % args if args else str(msg))
        except (TypeError, ValueError):
            lines.append(str(msg))

    monkeypatch.setattr(_orch.logger, "warning", _sink)
    return lines


def _queue_with_batches(n_items: int) -> StudyQueue:
    q = StudyQueue()
    for i in range(n_items):
        q.enqueue(StudyRequest(
            question=f"what is concept{i}?",
            source_file="a.c",
            source_function=f"fn{i}",
        ))
    q.signal_producer_done()
    return q


def _wire(monkeypatch, tmp_path, run_study):
    """Fake prep + client; install *run_study* as the phase."""
    import core.audit.orchestrator as _orch
    import core.concepts.study as _study_mod
    import core.llm.client as _client_mod

    def fake_prep(cmd, **kwargs):
        (tmp_path / "study-list.json").write_text("[]")
        return types.SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(_orch, "_run_study_prep", fake_prep)
    monkeypatch.setattr(_study_mod, "run_study", run_study)
    monkeypatch.setattr(
        _client_mod, "LLMClient",
        lambda *a, **kw: types.SimpleNamespace(total_cost=0.0),
    )
    # Growing domain model on every reload: the starvation guard must
    # not stop the loop before the breaker under test does.
    concepts = {"n": 0}

    def fake_load(_config):
        concepts["n"] += 1
        return {"concepts": [
            {"id": f"c{i}"} for i in range(concepts["n"])
        ]}

    monkeypatch.setattr(_orch, "_load_domain_model", fake_load)


def _run_loop(config, queue):
    shared = types.SimpleNamespace(domain_model=None)
    _study_consumer_loop(
        queue, config, shared, lambda ctx, cfg: None,
        _LockedOutcomes(), OrchestratorResult(),
        checklist={"files": []},
        context_map=None,
        evidence_index={},
        sarif_cache=None,
        entry_points=set(),
        start_time=time.monotonic(),
        on_progress=None,
    )


def _config(tmp_path):
    return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)


class TestConsecutiveInvocationFailures:
    def test_three_consecutive_failures_disable_the_lane(
        self, monkeypatch, tmp_path,
    ):
        calls = []

        def failing_run_study(*a, **kw):
            calls.append(1)
            msg = "all 8 attempted Phase 2 batch(es) failed"
            raise RuntimeError(msg)

        _wire(monkeypatch, tmp_path, failing_run_study)
        warnings = _capture_warnings(monkeypatch)

        # 6 batches' worth of questions; only 3 may be bought.
        _run_loop(_config(tmp_path), _queue_with_batches(90))

        assert len(calls) == 3, (
            f"lane must disable after 3 failed invocations, bought "
            f"{len(calls)}"
        )
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "consecutive" in disabled[0]


class TestConfigShapedFailureDisablesOnSight:
    def test_single_config_shaped_failure_disables(
        self, monkeypatch, tmp_path,
    ):
        """The phase concluded the failure is deterministic for this
        configuration (persistent output truncation past its cap) —
        strike-counting would just re-buy it."""
        calls = []

        def config_shaped_run_study(*a, **kw):
            calls.append(1)
            err = RuntimeError("all batches failed — truncation")
            err.config_shaped = True
            raise err

        _wire(monkeypatch, tmp_path, config_shaped_run_study)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(_config(tmp_path), _queue_with_batches(90))

        assert len(calls) == 1
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "config-shaped" in disabled[0]

    def test_config_shaped_marker_read_through_wrapper_chain(
        self, monkeypatch, tmp_path,
    ):
        calls = []

        def wrapped_run_study(*a, **kw):
            calls.append(1)
            inner = RuntimeError("truncation")
            inner.config_shaped = True
            try:
                raise inner
            except RuntimeError as e:
                msg = "study wrapper"
                raise RuntimeError(msg) from e

        _wire(monkeypatch, tmp_path, wrapped_run_study)
        warnings = _capture_warnings(monkeypatch)
        _run_loop(_config(tmp_path), _queue_with_batches(90))
        assert len(calls) == 1
        assert any("config-shaped" in m for m in warnings)


class TestFailureRateTrip:
    def test_interleaved_failures_trip_the_rate_arm(
        self, monkeypatch, tmp_path,
    ):
        """A lane failing half its invocations INTERLEAVED with
        successes never reaches 3 consecutive failures, yet burns
        half its spend on nothing — the rate arm is what stops it
        (observed live: ~50% study failure sustained for hours with
        the consecutive counter never past 1)."""
        outcomes = iter("FSFSFSFF")  # 8 runs: 5 fail, 3 succeed
        calls = []

        def flaky_run_study(*a, **kw):
            calls.append(1)
            if next(outcomes, "S") == "F":
                msg = "all batches failed"
                raise RuntimeError(msg)

        _wire(monkeypatch, tmp_path, flaky_run_study)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(_config(tmp_path), _queue_with_batches(15 * 12))

        assert len(calls) == 8, (
            f"rate arm must trip at 5/8 failed, bought {len(calls)}"
        )
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "burn rate" in disabled[0]


class TestTruncationCapPartialSuccess:
    def test_truncation_capped_success_disables_after_bookkeeping(
        self, monkeypatch, tmp_path,
    ):
        """The interleaved-successes variant INSIDE one invocation:
        the phase salvaged batches but hit its cumulative truncation
        cap. Its results are kept; the lane still disables — every
        further invocation re-buys the same per-batch burn."""
        calls = []

        def capped_run_study(*a, **kw):
            calls.append(1)
            stats = kw.get("phase_stats")
            if stats is not None:
                stats["truncation_failures"] = 6
                stats["truncation_capped"] = True

        _wire(monkeypatch, tmp_path, capped_run_study)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(_config(tmp_path), _queue_with_batches(90))

        assert len(calls) == 1
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "output-truncation cap" in disabled[0]


class TestCooperativeStopReachesThePhase:
    def test_run_study_receives_live_stop_flag(
        self, monkeypatch, tmp_path,
    ):
        """run_study gets a should_stop wired to the queue's stop
        flag: the drain path's request_stop can now interrupt a
        RUNNING phase at its next paid-call boundary instead of the
        abandoned daemon thread buying batches until process exit."""
        seen = {}

        def recording_run_study(*a, **kw):
            seen["should_stop"] = kw.get("should_stop")

        _wire(monkeypatch, tmp_path, recording_run_study)
        _capture_warnings(monkeypatch)

        queue = _queue_with_batches(2)
        _run_loop(_config(tmp_path), queue)

        stop = seen.get("should_stop")
        assert callable(stop), "run_study must receive should_stop"
        assert stop() is False
        queue.request_stop()
        assert stop() is True


class TestLaneTruncationBudget:
    def test_sub_cap_churn_across_invocations_disables(
        self, monkeypatch, tmp_path,
    ):
        """Invocations that partially SUCCEED with a few truncation
        failures each reset the consecutive counter and count as
        successes for the rate arm — sub-cap churn tripped nothing
        while paying for zero-yield calls every invocation. The
        lane-cumulative budget is the arm that sees it."""
        from core.audit.orchestrator import (
            _STUDY_LANE_TRUNCATION_BUDGET,
        )
        per_invocation = 5  # under the per-phase cap of 6
        calls = []

        def churn_run_study(*a, **kw):
            calls.append(1)
            stats = kw.get("phase_stats")
            if stats is not None:
                stats["truncation_failures"] = per_invocation
                stats["truncation_capped"] = False

        _wire(monkeypatch, tmp_path, churn_run_study)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(_config(tmp_path), _queue_with_batches(15 * 12))

        expected = -(-_STUDY_LANE_TRUNCATION_BUDGET // per_invocation)
        assert len(calls) == expected, (
            f"lane must disable once the cumulative budget "
            f"({_STUDY_LANE_TRUNCATION_BUDGET}) is exhausted at "
            f"{per_invocation}/invocation — expected {expected} "
            f"invocations, bought {len(calls)}"
        )
        disabled = [m for m in warnings if "DISABLED" in m]
        assert len(disabled) == 1
        assert "sub-cap churn budget exhausted" in disabled[0]

    def test_failed_invocations_also_feed_the_lane_budget(
        self, monkeypatch, tmp_path,
    ):
        """Truncation failures reported by an invocation that then
        FAILED (non-truncation cause) accumulate too — the budget is
        lane-wide, not success-path-only."""
        calls = []

        def churn_then_fail_run_study(*a, **kw):
            calls.append(1)
            stats = kw.get("phase_stats")
            if stats is not None:
                stats["truncation_failures"] = 5
            if len(calls) % 2 == 0:
                msg = "all batches failed"
                raise RuntimeError(msg)

        _wire(monkeypatch, tmp_path, churn_then_fail_run_study)
        warnings = _capture_warnings(monkeypatch)

        _run_loop(_config(tmp_path), _queue_with_batches(15 * 12))

        # 5, 10, 15: budget (12) exhausted at the 3rd invocation
        # regardless of which paths the invocations took.
        assert len(calls) == 3
        assert any(
            "sub-cap churn budget exhausted" in m for m in warnings
        )
