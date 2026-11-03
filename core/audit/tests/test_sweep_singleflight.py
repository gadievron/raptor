"""Cold parallel memo misses must not multiply deterministic sweeps."""

from concurrent.futures import ThreadPoolExecutor
import threading
import time
from types import SimpleNamespace

import pytest

from core.audit.orchestrator import _memoized_sweep_step
from core.audit.sweep import SweepResult
from core.audit.sweep_memo import SweepMemo


def result(outcome='confirmed', **details):
    return SweepResult(tool='semgrep', file_path='a.c', function_name='f',
                       outcome=outcome, matches=[{'line': 4}], details=details)


def bound_flight_waits(memo):
    # A regression must fail rather than leave executor threads deadlocked
    # at teardown. Bound only this memo's events, not global Event.wait.
    with memo._lock:
        for completed in memo._flights.values():
            wait = completed.wait

            def bounded_wait(timeout=None, _wait=wait):
                assert _wait(timeout=2), 'nested memo dependency deadlocked'
                return True

            completed.wait = bounded_wait


def overlapping(memo, key, invoke, *, workers=8):
    """Hold the first work item until all callers have entered the guard."""
    start = threading.Barrier(workers)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def gated_runner():
        calls.append(1)
        entered.set()
        assert release.wait(5), 'test did not release the first runner'
        return invoke()

    def task(_):
        start.wait(timeout=5)
        return memo.get_or_run(key, gated_runner)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(task, i) for i in range(workers)]
        try:
            assert entered.wait(5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                with memo._lock:
                    waiting = memo.waits + 1
                if waiting == workers:
                    break
                time.sleep(.001)
            assert waiting == workers
        finally:
            release.set()
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except Exception as exc:
                outcomes.append(exc)
    assert memo._flights == {}
    return calls, outcomes


def test_one_execution_and_isolated_results():
    memo = SweepMemo()
    key = memo.make_key('semgrep', {'rule': 'r', 'file': 'f'})
    calls, outputs = overlapping(memo, key, result)
    assert len(calls) == 1
    assert len({id(r) for r in outputs}) == 8
    assert all(r.matches == [{'line': 4}] for r in outputs)
    outputs[0].matches.append({'line': 99})
    assert all(r.matches == [{'line': 4}] for r in outputs[1:])
    assert memo.misses == 1
    assert memo.hits == 7


@pytest.mark.parametrize('make_result', [
    lambda: result('error'),
    lambda: result(negative_control_error=True),
])
def test_uncacheable_results_are_retried_independently(make_result):
    memo = SweepMemo()
    key = memo.make_key('semgrep', {'rule': 'r', 'file': 'f'})
    calls, outputs = overlapping(memo, key, make_result)
    assert len(calls) == 8
    assert all(isinstance(r, SweepResult) for r in outputs)
    assert memo._entries == {}


def test_exception_not_shared_and_later_success_cached():
    memo = SweepMemo()
    key = memo.make_key('semgrep', {'rule': 'r', 'file': 'f'})
    attempts = []
    original = RuntimeError('transient tool failure')

    def runner():
        attempts.append(1)
        if len(attempts) == 1:
            raise original
        return result()

    calls, outputs = overlapping(memo, key, runner)
    assert 2 <= len(calls) <= 8
    assert sum(r is original for r in outputs) == 1
    assert sum(isinstance(r, SweepResult) for r in outputs) == 7


def test_distinct_keys_still_execute_in_parallel():
    memo = SweepMemo()
    together = threading.Barrier(2)

    def run(key):
        def runner():
            together.wait(timeout=5)
            return result()
        return memo.get_or_run((key,), runner)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, key) for key in ('a', 'b')]
        assert all(f.result(timeout=6).outcome == 'confirmed' for f in futures)
    assert memo._flights == {}


def test_nested_opposite_key_order_cannot_deadlock():
    memo = SweepMemo()
    together = threading.Barrier(2)

    def run(key, other):
        def outer():
            together.wait(timeout=5)
            bound_flight_waits(memo)
            memo.get_or_run((other,), result)
            return result()
        return memo.get_or_run((key,), outer)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, 'a', 'b'), pool.submit(run, 'b', 'a')]
        assert all(f.result(timeout=6).outcome == 'confirmed' for f in futures)
    assert memo._flights == {}


def test_nested_same_key_and_lock_cleanup_after_churn():
    memo = SweepMemo(max_entries=2)
    def nested():
        bound_flight_waits(memo)
        return memo.get_or_run(('a',), result)

    assert memo.get_or_run(('a',), nested).outcome == 'confirmed'
    for i in range(500):
        with pytest.raises(ValueError):
            memo.get_or_run((i,), lambda: (_ for _ in ()).throw(ValueError()))
    assert memo._flights == {}
    assert len(memo._entries) <= 2


def test_checkpoint_lookup_and_runner_are_coalesced(monkeypatch):
    import core.audit.sweep_checkpoint as checkpoint_module

    memo = SweepMemo()
    parts = {'rule': 'r', 'file': 'f'}
    key = memo.make_key('coccinelle', parts)
    config = SimpleNamespace(sweep_memo=memo, out_dir=None)
    lookup_calls, records, runner_calls = [], [], []

    class Checkpoint:
        def lookup(self, key):
            lookup_calls.append(key)
            return None

        def record(self, key, value):
            records.append((key, value))

    monkeypatch.setattr(checkpoint_module, 'checkpoint_for_run', lambda _: Checkpoint())
    # Use a proxy so the shared harness exercises the orchestrator's guard
    # instead of placing another guard around the whole call.
    class MemoProxy:
        _lock = memo._lock
        _flights = memo._flights

        @property
        def waits(self):
            return memo.waits

        def get_or_run(self, key, runner):
            return _memoized_sweep_step(config, 'coccinelle', parts, runner)

    def runner():
        runner_calls.append(1)
        return result()

    calls, outputs = overlapping(MemoProxy(), key, runner)
    assert len(calls) == len(runner_calls) == len(lookup_calls) == len(records) == 1
    assert all(r.outcome == 'confirmed' for r in outputs)


def test_lru_eviction_does_not_discard_active_guard():
    memo = SweepMemo(max_entries=1)
    key = ('running',)
    with memo.key_guard(key):
        for i in range(10):
            memo.put((i,), result())
        assert not memo._flights[key].is_set()
    assert memo._flights == {}


def test_failed_leader_releases_followers_for_parallel_retries():
    memo = SweepMemo()
    key = ('same',)
    remaining = threading.Barrier(7)
    attempts = []

    def runner():
        attempts.append(1)
        if len(attempts) > 1:
            remaining.wait(timeout=5)
        return result('error')

    calls, outputs = overlapping(memo, key, runner)
    assert len(calls) == 8
    assert all(r.outcome == 'error' for r in outputs)
