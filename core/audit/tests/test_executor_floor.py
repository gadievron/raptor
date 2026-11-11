"""Inert owned scheduler work: a typed floor must preserve its fatal policy."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import threading
from types import SimpleNamespace

import pytest

from core.audit import executor
from core.audit import orchestrator as orch
from core.audit.shared_state import SharedState
from core.audit.task_graph import TaskGraph
from core.sandbox.errors import SandboxFloorError, SandboxSetupError
from core.sandbox.tiers import ContainmentTier
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.parametrize('workers', [1, 2], ids=['serial', 'async'])
def test_typed_floor_reaches_owner(tmp_path, monkeypatch, workers):
    refusal = SandboxFloorError(
        'owned typed floor fixture', 'no actual environment action',
        achievable=ContainmentTier.LANDLOCK_ONLY,
        floor=ContainmentTier.MOUNT_NS,
    )
    graph = TaskGraph.from_workqueue([
        {'file': 'owned.py', 'name': 'only', 'line_start': 1, 'review_tier': 'full'},
    ], [])
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')
    result = orch.OrchestratorResult()
    calls = []

    def refuse(*args, **kwargs):
        calls.append(threading.get_ident())
        raise refusal

    def forbidden_model(*args, **kwargs):
        pytest.fail('model callback must not run')

    # Own and retire the pool explicitly; do not patch global asyncio state.
    with ThreadPoolExecutor(max_workers=2) as pool:
        loop = asyncio.new_event_loop()
        loop.set_default_executor(pool)
        local_asyncio = SimpleNamespace(**vars(asyncio))
        local_asyncio.new_event_loop = lambda: loop
        monkeypatch.setattr(executor, 'asyncio', local_asyncio)
        with isolated_audit_shutdown(orch):
            try:
                with pytest.raises(SandboxFloorError) as caught:
                    executor.run_executor_sync(
                        graph, forbidden_model, SharedState(), config, result,
                        executor.ExecutorConfig(max_workers=workers),
                        review_one_fn=refuse, on_idle=lambda: 0.05,
                    )
                assert caught.value is refusal
            finally:
                if not loop.is_closed():
                    loop.close()
                assert len(calls) == 1, 'proof must reach the inert review boundary'


@contextmanager
def _owned_loop(monkeypatch):
    with ThreadPoolExecutor(max_workers=2) as pool:
        loop = asyncio.new_event_loop()
        loop.set_default_executor(pool)
        local_asyncio = SimpleNamespace(**vars(asyncio))
        local_asyncio.new_event_loop = lambda: loop
        monkeypatch.setattr(executor, 'asyncio', local_asyncio)
        with isolated_audit_shutdown(orch):
            try:
                yield
            finally:
                if not loop.is_closed():
                    loop.close()


def _run(tmp_path, review, *, graph=None, shared=None, **kwargs):
    if graph is None:
        graph = TaskGraph.from_workqueue([
            {'file': 'owned.py', 'name': 'only', 'line_start': 1},
        ], [])
    result = orch.OrchestratorResult()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out')

    def forbidden_model(*args, **kw):
        pytest.fail('model callback must not run')

    # Exercise the supported owner-wakeup hook without relying on command-
    # sandbox cross-thread selector wakeups. It supplies no work or verdict.
    kwargs.setdefault('on_idle', lambda: 0.05)
    stats = executor.run_executor_sync(
        graph, forbidden_model, shared or SharedState(), config, result,
        executor.ExecutorConfig(max_workers=2), review_one_fn=review, **kwargs,
    )
    return stats, graph, result


def test_plain_setup_refusal_reaches_async_owner(tmp_path, monkeypatch):
    refusal = SandboxSetupError('owned setup fixture', 'no environment action')
    calls = []

    def refuse(*args, **kwargs):
        calls.append(True)
        raise refusal

    with _owned_loop(monkeypatch), pytest.raises(SandboxSetupError) as caught:
        _run(tmp_path, refuse)
    assert caught.value is refusal and calls == [True]


def test_floor_reaches_owner_during_quiesce_drain(tmp_path, monkeypatch):
    from core.audit.tests.test_dark_verify_parallel import _floor_error
    refusal = _floor_error()
    attempts, checkpoints = [], []

    def should_attempt():
        attempts.append(True)
        return True

    quiescer = SimpleNamespace(
        drain_bound_s=3.0, should_attempt=should_attempt,
        run_quiesced=lambda: checkpoints.append(True),
        note_drain_timeout=lambda n: pytest.fail('inert refusal did not drain'),
    )

    def refuse(*args, **kwargs):
        raise refusal

    with _owned_loop(monkeypatch), pytest.raises(SandboxFloorError) as caught:
        _run(tmp_path, refuse, quiescer=quiescer)
    assert caught.value is refusal and attempts and checkpoints == []


def test_floor_reaches_owner_from_requested_repass(tmp_path, monkeypatch):
    from core.audit.tests.test_dark_verify_parallel import _floor_error
    graph = TaskGraph.from_workqueue([
        {'file': 'owned.py', 'name': 'only', 'line_start': 1},
    ], [])
    # Supply one valid existing task through the graph's repass interface;
    # this tests exception harvesting, not SCC scheduling or cycle discovery.
    task = next(iter(graph._tasks.values()))
    monkeypatch.setattr(graph, 'repass_tasks', lambda: [task])
    refusal = _floor_error()
    calls = []

    def review(gap, *args, **kwargs):
        calls.append(gap['name'])
        if len(calls) > 1:
            raise refusal
        return orch.ReviewOutcome(gap['file'], gap['name'], 'clean', 'inert review')

    with _owned_loop(monkeypatch), pytest.raises(SandboxFloorError) as caught:
        _run(tmp_path, review, graph=graph)
    assert caught.value is refusal and calls == ['only', 'only']


def test_batch_refusal_reaches_owner(tmp_path, monkeypatch):
    from core.audit.tests.test_dark_verify_parallel import _floor_error
    refusal = _floor_error()
    calls = []
    shared = SharedState()
    shared.triage_results = {
        'owned.py:only:1': SimpleNamespace(bucket=SimpleNamespace(value='glance')),
    }

    def refuse_batch(*args, **kwargs):
        calls.append(True)
        raise refusal

    def forbidden(*args, **kwargs):
        pytest.fail('individual or model work must not run')

    monkeypatch.setattr(executor, '_get_batch_review_fn', lambda *args: forbidden)
    monkeypatch.setattr(executor, '_process_glance_batch', refuse_batch)
    with _owned_loop(monkeypatch), pytest.raises(SandboxFloorError) as caught:
        _run(tmp_path, forbidden, shared=shared)
    assert caught.value is refusal and calls == [True]


def test_ordinary_review_error_stays_per_task(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('owned ordinary task error')

    with _owned_loop(monkeypatch):
        stats, graph, result = _run(tmp_path, fail)
    assert stats.completed == stats.failed == 1
    assert graph.pending == 0 and result.errors == 1
    assert result.outcomes[0].status == 'error'


def test_ordinary_scaffolding_error_keeps_existing_backstop_policy(tmp_path, monkeypatch, caplog):
    def bad_tick(*args):
        raise RuntimeError('owned tick failure')

    def forbidden(*args, **kwargs):
        pytest.fail('review must not start after its tick failed')

    with _owned_loop(monkeypatch):
        stats, graph, _ = _run(tmp_path, forbidden, on_tick=bad_tick)
    assert stats.completed == 0 and graph.pending == 1
    assert 'unhandled task exception' in caplog.text


def test_healthy_task_still_completes(tmp_path, monkeypatch):
    calls = []

    def review(gap, *args, **kwargs):
        calls.append(gap['name'])
        return orch.ReviewOutcome(gap['file'], gap['name'], 'clean', 'inert review')

    with _owned_loop(monkeypatch):
        stats, graph, _ = _run(tmp_path, review)
    assert calls == ['only'] and stats.completed == 1 and stats.failed == 0
    assert graph.pending == 0
