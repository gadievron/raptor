"""The existing executor owner can wake while an unrelated review is waiting."""

import threading

from core.audit import orchestrator as orch
from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.shared_state import SharedState
from core.audit.task_graph import TaskGraph
from core.testing.audit_shutdown import isolated_audit_shutdown


def test_owner_runs_while_an_unrelated_review_is_still_waiting(tmp_path):
    started = threading.Event()
    released = threading.Event()
    owner_thread = threading.get_ident()
    seen = []
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", max_workers=2)
    result = orch.OrchestratorResult()
    graph = TaskGraph.from_workqueue([
        {"file": "owned.c", "name": "unrelated", "line_start": 1, "priority_score": 1.0},
    ], [])

    def work(gap, shared, cfg, reviewer, result, **kwargs):
        started.set()
        assert released.wait(5), "owner did not process ready information during the wait"
        return orch.ReviewOutcome("owned.c", "unrelated", "clean", "scripted review")

    def idle():
        assert threading.get_ident() == owner_thread
        if started.is_set():
            seen.append(not released.is_set())
            released.set()
            return None
        return 0.05

    with isolated_audit_shutdown(orch):
        try:
            stats = run_executor_sync(
                graph, lambda *args: None, SharedState(), config, result,
                ExecutorConfig(max_workers=2), review_one_fn=work, on_idle=idle,
            )
        finally:
            released.set()
    assert seen == [True]
    assert stats.completed == 1


def test_idle_owner_dispatches_new_ready_work_without_waiting_for_unrelated_review(tmp_path):
    from core.testing.wallclock import wall_deadline

    started = threading.Event()
    released = threading.Event()
    finished = threading.Event()
    continuation_started = threading.Event()
    owner_thread = threading.get_ident()
    injected = []
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", max_workers=2)
    result = orch.OrchestratorResult()
    graph = TaskGraph.from_workqueue([
        {"file": "owned.c", "name": "unrelated", "line_start": 1, "priority_score": 1.0},
    ], [])

    def work(gap, shared, cfg, reviewer, result, **kwargs):
        if gap["name"] == "continuation":
            assert threading.get_ident() != owner_thread
            assert not finished.is_set(), "continuation waited for the unrelated review"
            continuation_started.set()
            released.set()
        else:
            started.set()
            try:
                assert released.wait(5), "idle-injected work was not dispatched into the free slot"
            finally:
                finished.set()
        return orch.ReviewOutcome("owned.c", gap["name"], "clean", "scripted review")

    def idle():
        assert threading.get_ident() == owner_thread
        if started.is_set() and not injected:
            injected.append(graph.inject_task("knowledge-continuation", {
                "file": "owned.c", "name": "continuation", "line_start": 2,
            }, priority=2.0))
        return 0.05 if not continuation_started.is_set() else None

    with isolated_audit_shutdown(orch), wall_deadline(10, code_bound_s=float("inf"), what="idle graph dispatch"):
        try:
            stats = run_executor_sync(
                graph, lambda *args: None, SharedState(), config, result,
                ExecutorConfig(max_workers=2), review_one_fn=work, on_idle=idle,
            )
        finally:
            released.set()
    assert injected == [True]
    assert continuation_started.is_set()
    assert stats.completed == 2 and stats.failed == 0


def test_serial_dispatch_holds_the_shared_study_throttle_once(tmp_path):
    from contextlib import contextmanager
    held = []
    calls = []

    class Throttle:
        @contextmanager
        def acquire_sync(self):
            assert not held, "nested acquisition deadlocks a one-slot throttle"
            held.append(True)
            try:
                yield
            finally:
                held.pop()

    def work(gap, *args, **kwargs):
        assert held == [True]
        calls.append(gap["name"])
        return orch.ReviewOutcome("owned.c", gap["name"], "clean", "scripted")

    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    graph = TaskGraph.from_workqueue([{"file": "owned.c", "name": "f", "line_start": 1}], [])
    with isolated_audit_shutdown(orch):
        stats = run_executor_sync(graph, lambda *a: None, SharedState(), config,
            orch.OrchestratorResult(), ExecutorConfig(max_workers=1),
            review_one_fn=work, throttle=Throttle())
    assert calls == ["f"] and stats.completed == 1 and not held
