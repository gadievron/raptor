"""Tests for core.audit.executor."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.task_graph import TaskGraph
from core.llm.concurrency import derive_max_workers


def _gap(file: str, name: str, priority: float = 0.5) -> dict[str, Any]:
    return {"file": file, "name": name, "priority_score": priority, "line_start": 1}


def _edge(cf: str, c: str, ef: str, e: str) -> dict[str, Any]:
    return {"caller_file": cf, "caller": c, "callee_file": ef, "callee": e}


@dataclass
class _FakeResult:
    outcomes: list = field(default_factory=list)
    reviewed: int = 0
    findings: int = 0
    suspicious: int = 0
    suspicious_tool_backed: int = 0
    clean: int = 0
    dormant: int = 0
    errors: int = 0
    error_counts: dict = field(default_factory=dict)
    total_cost_usd: float = 0.0
    prefilter_skipped: int = 0
    prefilter_hits: int = 0
    terminated_by: str = ""
    tier_counters: dict = field(default_factory=dict)
    cost_tracker: Any = None
    clean_checks: int = 0
    clean_check_rescues: int = 0
    sweep_validated: int = 0
    sweep_demoted: int = 0
    refinement_rounds: int = 0
    synthesis_amplified: int = 0
    skipped: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if self.cost_tracker is None:
            self.cost_tracker = MagicMock()


def _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw):
    outcome = MagicMock()
    outcome.status = "clean"
    outcome.cost_usd = 0.0
    outcome.model = None
    outcome.hypothesis = ""
    outcome.hypotheses = []
    outcome.evidence_tool = ""
    outcome.review_result = None
    outcome.body = "clean"
    outcome.file = gap["file"]
    outcome.function = gap["name"]
    outcome.line = 1
    return outcome


class TestRunExecutorSync:
    def test_serial_processes_all_tasks(self) -> None:
        wq = [_gap("a.py", "f1"), _gap("a.py", "f2"), _gap("a.py", "f3")]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        reviewed_keys: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed_keys.append(f"{gap['file']}:{gap['name']}")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=tracking_review,
        )

        assert stats.completed == 3
        assert stats.dispatched == 3
        assert len(reviewed_keys) == 3

    def test_respects_dependency_order(self) -> None:
        wq = [_gap("a.py", "caller", 0.9), _gap("a.py", "callee", 0.5)]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        graph = TaskGraph.from_workqueue(wq, edges)
        result = _FakeResult()
        order: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            order.append(f"{gap['file']}:{gap['name']}")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=tracking_review,
        )

        assert order == ["a.py:callee", "a.py:caller"]

    def test_budget_check_stops_early(self) -> None:
        wq = [_gap("a.py", f"f{i}") for i in range(5)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        call_count = [0]

        def budget_fn():
            return call_count[0] >= 2

        def counting_review(gap, shared, config, review_fn, result_obj, **kw):
            call_count[0] += 1
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            budget_check=budget_fn,
            review_one_fn=counting_review,
        )

        assert stats.budget_stopped
        assert stats.completed == 2

    def test_budget_exceeded_runtime_error(self) -> None:
        wq = [_gap("a.py", "f1")]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()

        def exploding_review(gap, shared, config, review_fn, result_obj, **kw):
            raise RuntimeError("LLM budget exceeded")

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=exploding_review,
        )

        assert stats.budget_stopped
        assert result.terminated_by == "llm_budget_exceeded"

    def test_empty_graph(self) -> None:
        graph = TaskGraph.from_workqueue([], [])
        result = _FakeResult()
        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=_mock_review_fn,
        )
        assert stats.completed == 0
        assert stats.dispatched == 0

    def test_passes_collector(self) -> None:
        wq = [_gap("a.py", "f1")]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        collector = MagicMock()
        received_collector = [None]

        def capturing_review(gap, shared, config, review_fn, result_obj, **kw):
            received_collector[0] = kw.get("collector")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            collector=collector,
            review_one_fn=capturing_review,
        )

        assert received_collector[0] is collector

    def test_wall_time_recorded(self) -> None:
        graph = TaskGraph.from_workqueue([_gap("a.py", "f1")], [])
        result = _FakeResult()
        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=_mock_review_fn,
        )
        assert stats.wall_time_s > 0


class TestDeriveMaxWorkers:
    def test_known_model_uses_half_rpm(self, monkeypatch) -> None:
        monkeypatch.setattr("core.llm.model_data.rpm_for", lambda m, default=0: 40)
        assert derive_max_workers("test-model") == 20

    def test_unknown_model_returns_one(self, monkeypatch) -> None:
        monkeypatch.setattr("core.llm.model_data.rpm_for", lambda m, default=0: 0)
        assert derive_max_workers("unknown") == 1

    def test_capped_at_32(self, monkeypatch) -> None:
        monkeypatch.setattr("core.llm.model_data.rpm_for", lambda m, default=0: 10000)
        assert derive_max_workers("fast-model") == 32

    def test_low_rpm_floors_to_one(self, monkeypatch) -> None:
        monkeypatch.setattr("core.llm.model_data.rpm_for", lambda m, default=0: 1)
        assert derive_max_workers("slow-model") == 1

    def test_odd_rpm_floors_division(self, monkeypatch) -> None:
        monkeypatch.setattr("core.llm.model_data.rpm_for", lambda m, default=0: 7)
        assert derive_max_workers("odd-model") == 3


class TestOnTick:
    def test_on_tick_called_per_task(self) -> None:
        wq = [_gap("a.py", "f1"), _gap("a.py", "f2")]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        ticked: list[str] = []

        def tick(gap):
            ticked.append(gap["name"])

        run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=_mock_review_fn,
            on_tick=tick,
        )

        assert len(ticked) == 2
        assert set(ticked) == {"f1", "f2"}


class TestAsyncPath:
    def test_parallel_processes_all_tasks(self) -> None:
        wq = [_gap("a.py", f"f{i}") for i in range(6)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=3),
            review_one_fn=_mock_review_fn,
        )

        assert stats.completed == 6
        assert stats.dispatched == 6

    def test_parallel_respects_dependencies(self) -> None:
        wq = [_gap("a.py", "caller", 0.9), _gap("a.py", "callee", 0.5)]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        graph = TaskGraph.from_workqueue(wq, edges)
        result = _FakeResult()
        order: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            order.append(gap["name"])
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=4),
            review_one_fn=tracking_review,
        )

        assert order.index("callee") < order.index("caller")

    def test_parallel_on_tick(self) -> None:
        wq = [_gap("a.py", "f1"), _gap("a.py", "f2"), _gap("a.py", "f3")]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        ticked: list[str] = []

        def tick(gap):
            ticked.append(gap["name"])

        run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=2),
            review_one_fn=_mock_review_fn,
            on_tick=tick,
        )

        assert set(ticked) == {"f1", "f2", "f3"}

    def test_parallel_stops_on_shutdown(self) -> None:
        from core.audit.orchestrator import _shutdown_event

        wq = [_gap("a.py", f"f{i}") for i in range(10)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        call_count = [0]

        def slow_review(gap, shared, config, review_fn, result_obj, **kw):
            call_count[0] += 1
            if call_count[0] >= 3:
                _shutdown_event.set()
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        _shutdown_event.clear()
        try:
            stats = run_executor_sync(
                graph, MagicMock(), MagicMock(), MagicMock(), result,
                ExecutorConfig(max_workers=2),
                review_one_fn=slow_review,
            )
            assert stats.budget_stopped
            assert stats.completed < 10
        finally:
            _shutdown_event.clear()

    def test_stop_with_pending_glance_and_no_inflight(self, monkeypatch) -> None:
        """Budget stop while glance tasks are queued and nothing is in
        flight must exit cleanly, not crash on ``asyncio.wait(set())``.

        Sequence: the lone ready task completes, its post-completion
        dispatch queues two glance-tier dependents (below batch size),
        THEN the stop flag flips — the main loop must not await an
        empty inflight set."""
        from dataclasses import dataclass

        @dataclass
        class FakeBucket:
            value: str

        @dataclass
        class FakeTriageResult:
            bucket: FakeBucket

        wq = [
            _gap("a.py", "base", 0.9),
            _gap("a.py", "g1", 0.5),
            _gap("a.py", "g2", 0.5),
        ]
        # g1/g2 depend on base: ready only after base completes.
        edges = [
            _edge("a.py", "g1", "a.py", "base"),
            _edge("a.py", "g2", "a.py", "base"),
        ]
        graph = TaskGraph.from_workqueue(wq, edges)
        result = _FakeResult()

        triage = {
            "a.py:g1:1": FakeTriageResult(FakeBucket("glance")),
            "a.py:g2:1": FakeTriageResult(FakeBucket("glance")),
        }
        shared = MagicMock()
        shared.triage_results = triage

        def fake_batch_review_fn(contexts, config):
            raise AssertionError("no batch should run after the stop")

        import core.audit.executor as executor_mod
        monkeypatch.setattr(executor_mod, "_get_batch_review_fn",
                            lambda shared, config: fake_batch_review_fn)

        stop = [False]

        real_pop_ready = graph.pop_ready
        pop_calls = [0]

        def tracking_pop_ready(n):
            tasks = real_pop_ready(n)
            pop_calls[0] += 1
            if pop_calls[0] == 2:
                # The post-completion dispatch that queues g1/g2 into
                # glance_pending — flip the stop right after it.
                stop[0] = True
            return tasks

        graph.pop_ready = tracking_pop_ready

        stats = run_executor_sync(
            graph, MagicMock(), shared, MagicMock(), result,
            ExecutorConfig(max_workers=2),
            review_one_fn=_mock_review_fn,
            budget_check=lambda: stop[0],
        )

        assert stats.budget_stopped
        assert stats.completed == 1  # only "base"; g1/g2 dropped

    def test_parallel_progress_checkpoint(self, tmp_path) -> None:
        import json

        import core.audit.executor as executor_mod

        meta = {"status": "running", "extra": {}}
        meta_path = tmp_path / ".raptor-run.json"
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        wq = [_gap("a.py", f"f{i}") for i in range(5)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()

        config = MagicMock()
        config.out_dir = tmp_path

        old_interval = executor_mod._PROGRESS_CHECKPOINT_INTERVAL
        executor_mod._PROGRESS_CHECKPOINT_INTERVAL = 0.0
        try:
            run_executor_sync(
                graph, MagicMock(), MagicMock(), config, result,
                ExecutorConfig(max_workers=2),
                review_one_fn=_mock_review_fn,
            )
        finally:
            executor_mod._PROGRESS_CHECKPOINT_INTERVAL = old_interval

        updated = json.loads(meta_path.read_text(encoding="utf-8"))
        assert "progress" in updated.get("extra", {})


class TestCycleRepass:
    def _cycle_graph(self):
        """A→B→A cycle with a transitive dependent (top→A)."""
        wq = [
            _gap("a.py", "top", 0.9),
            _gap("a.py", "A", 0.5),
            _gap("a.py", "B", 0.3),
        ]
        edges = [
            _edge("a.py", "top", "a.py", "A"),
            _edge("a.py", "A", "a.py", "B"),
            _edge("a.py", "B", "a.py", "A"),
        ]
        return TaskGraph.from_workqueue(wq, edges)

    def test_serial_repass_reviews_affected(self) -> None:
        graph = self._cycle_graph()
        result = _FakeResult()
        reviewed: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed.append(f"{gap['file']}:{gap['name']}")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=tracking_review,
        )

        assert stats.completed == 3
        assert stats.repass_completed >= 1
        from collections import Counter
        counts = Counter(reviewed)
        repass_keys = {k for k, c in counts.items() if c > 1}
        assert len(repass_keys) >= 1

    def test_parallel_repass_reviews_affected(self) -> None:
        graph = self._cycle_graph()
        result = _FakeResult()
        reviewed: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            reviewed.append(f"{gap['file']}:{gap['name']}")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=2),
            review_one_fn=tracking_review,
        )

        assert stats.completed == 3
        assert stats.repass_completed >= 1

    def test_budget_stop_skips_repass(self) -> None:
        graph = self._cycle_graph()
        result = _FakeResult()
        call_count = [0]

        def budget_fn():
            return call_count[0] >= 2

        def counting_review(gap, shared, config, review_fn, result_obj, **kw):
            call_count[0] += 1
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            budget_check=budget_fn,
            review_one_fn=counting_review,
        )

        assert stats.budget_stopped
        assert stats.repass_completed == 0

    def test_no_cycle_no_repass(self) -> None:
        wq = [_gap("a.py", "caller", 0.9), _gap("a.py", "callee", 0.5)]
        edges = [_edge("a.py", "caller", "a.py", "callee")]
        graph = TaskGraph.from_workqueue(wq, edges)
        result = _FakeResult()

        stats = run_executor_sync(
            graph, MagicMock(), MagicMock(), MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=_mock_review_fn,
        )

        assert stats.completed == 2
        assert stats.repass_completed == 0


class TestBatchWiringThroughConfig:
    """The batch path engages when ``config.llm_client`` is set —
    pinned end-to-end through the REAL ``_get_batch_review_fn`` and
    ``make_batch_review_fn`` (no monkeypatched dispatch), because the
    wiring was dead in production for want of the attribute."""

    @staticmethod
    def _glance_shared(n: int):
        from dataclasses import dataclass

        @dataclass
        class FakeBucket:
            value: str

        @dataclass
        class FakeTriageResult:
            bucket: FakeBucket

        shared = MagicMock()
        shared.triage_results = {
            f"a.py:f{i}:1": FakeTriageResult(FakeBucket("glance"))
            for i in range(n)
        }
        return shared

    @staticmethod
    def _config(client):
        cfg = MagicMock()
        cfg.llm_client = client
        cfg.models = ["default"]
        return cfg

    def test_no_client_disables_batching(self) -> None:
        from core.audit.executor import _get_batch_review_fn
        cfg = MagicMock()
        cfg.llm_client = None
        assert _get_batch_review_fn(MagicMock(), cfg) is None

    def test_client_enables_batching(self) -> None:
        from core.audit.executor import _get_batch_review_fn
        fn = _get_batch_review_fn(MagicMock(), self._config(MagicMock()))
        assert callable(fn)

    def test_default_model_sentinel_not_resolved(self) -> None:
        # models=["default"] must not be passed to config_for_model.
        from core.audit.executor import _get_batch_review_fn
        client = MagicMock()
        fn = _get_batch_review_fn(MagicMock(), self._config(client))
        assert callable(fn)
        client.config.config_for_model.assert_not_called()

    def test_glance_tasks_take_one_llm_call(self, monkeypatch) -> None:
        import json

        n = 10
        wq = [_gap("a.py", f"f{i}") for i in range(n)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()
        shared = self._glance_shared(n)

        client = MagicMock()
        response = MagicMock()
        response.content = json.dumps([
            {"file": "a.py", "function": f"f{i}",
             "status": "clean", "body": "safe"}
            for i in range(n)
        ])
        response.model = "test-model"
        response.cost = 0.01
        client.generate.return_value = response
        client.config.config_for_model.side_effect = AssertionError

        import core.audit.orchestrator as orch_mod
        monkeypatch.setattr(
            orch_mod, "_build_context",
            lambda config, gap, *a, **kw: {
                "file": gap["file"], "function": gap["name"],
                "source": "pass", "line_start": 1, "line_end": 2,
            },
        )

        collector = MagicMock()
        individual: list[str] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            individual.append(gap["name"])
            return _mock_review_fn(
                gap, shared, config, review_fn, result_obj, **kw)

        stats = run_executor_sync(
            graph, MagicMock(), shared, self._config(client), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=tracking_review,
            collector=collector,
        )

        assert stats.completed == n
        assert client.generate.call_count == 1, (
            "ten glance functions must ride ONE LLM call"
        )
        assert individual == [], "no per-function fallback expected"
        assert collector.submit.call_count == n
        assert result.clean == n


class TestAsyncGlanceBatch:
    """Verify the parallel executor batches glance-tier tasks."""

    def test_parallel_batches_glance_tasks(self, monkeypatch) -> None:
        from dataclasses import dataclass

        @dataclass
        class FakeBucket:
            value: str

        @dataclass
        class FakeTriageResult:
            bucket: FakeBucket

        wq = [_gap("a.py", f"f{i}") for i in range(15)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()

        triage = {f"a.py:f{i}:1": FakeTriageResult(FakeBucket("glance")) for i in range(12)}
        for i in range(12, 15):
            triage[f"a.py:f{i}:1"] = FakeTriageResult(FakeBucket("investigate"))

        shared = MagicMock()
        shared.triage_results = triage

        individual_keys: list[str] = []
        batch_calls: list[int] = []

        def tracking_review(gap, shared, config, review_fn, result_obj, **kw):
            individual_keys.append(f"{gap['file']}:{gap['name']}")
            return _mock_review_fn(gap, shared, config, review_fn, result_obj, **kw)

        def fake_batch_review_fn(contexts, config):
            batch_calls.append(len(contexts))
            outcomes = []
            for ctx in contexts:
                o = MagicMock()
                o.status = "clean"
                o.cost_usd = 0.0
                o.model = None
                o.hypothesis = ""
                o.hypotheses = []
                o.evidence_tool = ""
                o.review_result = None
                o.body = "clean"
                o.file = ctx.get("file", "")
                o.function = ctx.get("function", "")
                o.line = 1
                outcomes.append(o)
            return outcomes

        import core.audit.executor as executor_mod
        monkeypatch.setattr(executor_mod, "_get_batch_review_fn",
                            lambda shared, config: fake_batch_review_fn)

        import core.audit.orchestrator as orch_mod
        monkeypatch.setattr(orch_mod, "_build_context",
                            lambda config, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]})
        monkeypatch.setattr(orch_mod, "_commit_outcome", lambda *a, **kw: None)

        stats = run_executor_sync(
            graph, MagicMock(), shared, MagicMock(), result,
            ExecutorConfig(max_workers=4),
            review_one_fn=tracking_review,
        )

        assert stats.completed == 15
        assert len(batch_calls) >= 1
        assert sum(batch_calls) == 12
        assert len(individual_keys) == 3

    def test_parallel_glance_remainder_flushed(self, monkeypatch) -> None:
        """Partial batch at end is still processed."""
        from dataclasses import dataclass

        @dataclass
        class FakeBucket:
            value: str

        @dataclass
        class FakeTriageResult:
            bucket: FakeBucket

        wq = [_gap("a.py", f"f{i}") for i in range(3)]
        graph = TaskGraph.from_workqueue(wq, [])
        result = _FakeResult()

        triage = {f"a.py:f{i}:1": FakeTriageResult(FakeBucket("glance")) for i in range(3)}
        shared = MagicMock()
        shared.triage_results = triage

        batch_calls: list[int] = []

        def fake_batch_review_fn(contexts, config):
            batch_calls.append(len(contexts))
            outcomes = []
            for ctx in contexts:
                o = MagicMock()
                o.status = "clean"
                o.cost_usd = 0.0
                o.model = None
                o.hypothesis = ""
                o.hypotheses = []
                o.evidence_tool = ""
                o.review_result = None
                o.body = "clean"
                o.file = ctx.get("file", "")
                o.function = ctx.get("function", "")
                o.line = 1
                outcomes.append(o)
            return outcomes

        import core.audit.executor as executor_mod
        monkeypatch.setattr(executor_mod, "_get_batch_review_fn",
                            lambda shared, config: fake_batch_review_fn)

        import core.audit.orchestrator as orch_mod
        monkeypatch.setattr(orch_mod, "_build_context",
                            lambda config, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]})
        monkeypatch.setattr(orch_mod, "_commit_outcome", lambda *a, **kw: None)

        stats = run_executor_sync(
            graph, MagicMock(), shared, MagicMock(), result,
            ExecutorConfig(max_workers=2),
            review_one_fn=_mock_review_fn,
        )

        assert stats.completed == 3
        assert len(batch_calls) >= 1
        assert sum(batch_calls) == 3


class TestGlanceFallbackBudget:
    """Budget exhaustion inside the glance-batch fallback path."""

    @staticmethod
    def _glance_setup(monkeypatch, n):
        from dataclasses import dataclass

        @dataclass
        class FakeBucket:
            value: str

        @dataclass
        class FakeTriageResult:
            bucket: FakeBucket

        wq = [_gap("a.py", f"f{i}") for i in range(n)]
        graph = TaskGraph.from_workqueue(wq, [])
        shared = MagicMock()
        shared.triage_results = {
            f"a.py:f{i}:1": FakeTriageResult(FakeBucket("glance"))
            for i in range(n)
        }

        def failing_batch_review_fn(contexts, config):
            raise ValueError("batch parse error")  # forces the fallback

        import core.audit.executor as executor_mod
        monkeypatch.setattr(executor_mod, "_get_batch_review_fn",
                            lambda shared, config: failing_batch_review_fn)

        import core.audit.orchestrator as orch_mod
        monkeypatch.setattr(
            orch_mod, "_build_context",
            lambda config, gap, *a, **kw: {
                "file": gap["file"], "function": gap["name"],
            },
        )
        return graph, shared

    def test_sync_budget_exceeded_in_fallback_stops_gracefully(
        self, monkeypatch,
    ) -> None:
        """A budget RuntimeError from the per-function fallback must set
        budget_stopped/terminated_by, not propagate out of
        run_executor_sync."""
        graph, shared = self._glance_setup(monkeypatch, 3)
        result = _FakeResult()

        def budget_review(gap, shared, config, review_fn, result_obj, **kw):
            raise RuntimeError("LLM budget exceeded")

        stats = run_executor_sync(
            graph, MagicMock(), shared, MagicMock(), result,
            ExecutorConfig(max_workers=1),
            review_one_fn=budget_review,
        )

        assert stats.budget_stopped
        assert result.terminated_by == "llm_budget_exceeded"
        assert stats.completed == 0

    def test_sync_non_budget_runtime_error_logged(
        self, monkeypatch, caplog,
    ) -> None:
        """A non-budget RuntimeError in the fallback is logged as a
        per-function failure and the batch continues."""
        import logging

        graph, shared = self._glance_setup(monkeypatch, 2)
        result = _FakeResult()

        def broken_review(gap, shared, config, review_fn, result_obj, **kw):
            raise RuntimeError("segfault in helper")

        with caplog.at_level(logging.WARNING, logger="core.audit.executor"):
            stats = run_executor_sync(
                graph, MagicMock(), shared, MagicMock(), result,
                ExecutorConfig(max_workers=1),
                review_one_fn=broken_review,
            )

        assert not stats.budget_stopped
        assert stats.completed == 2  # marked complete despite failures
        assert any(
            "glance fallback failed" in r.message for r in caplog.records
        )


class TestExecutorStatsToDict:
    def test_to_dict_round_trips(self) -> None:
        from core.audit.executor import ExecutorStats
        s = ExecutorStats(dispatched=10, completed=8, repass_completed=2,
                          budget_stopped=True, wall_time_s=123.456)
        d = s.to_dict()
        assert d["dispatched"] == 10
        assert d["completed"] == 8
        assert d["repass_completed"] == 2
        assert d["budget_stopped"] is True
        assert d["wall_time_s"] == 123.5
