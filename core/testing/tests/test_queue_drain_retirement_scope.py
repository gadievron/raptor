"""Real queue cancellation assertions retain test-owned worker retirement."""

import concurrent.futures
from types import ModuleType
import pytest
import threading
from core.testing.module_views import module_function_view
import core.audit.tests.test_budget_terminal as native

@pytest.mark.parametrize("phase", ["normal", "body-error", "body-interrupt", "first-submit-error", "first-submit-interrupt", "second-submit-error", "second-submit-interrupt"])
def test_actual_queue_drain_caller_retires_worker(phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    class Queue:
        def __init__(self, queue, pool):
            self.queue, self.pool = queue, pool
        def check(self, value):
            if value is None:
                self.pool.retiring.set()
                assert self.pool.release.wait(5)
            return value
        def get(self, *args, **kwargs):
            return self.check(self.queue.get(*args, **kwargs))
        def get_nowait(self):
            return self.check(self.queue.get_nowait())
        def put(self, value):
            return self.queue.put(value)
    class Pool(real):
        def __init__(self, *args, **kwargs):
            assert kwargs == {'max_workers': 1}
            super().__init__(*args, **kwargs)
            self.release, self.retiring = threading.Event(), threading.Event()
            self.waits = []
            self._work_queue = Queue(self._work_queue, self)
            pools.append(self)
        def submit(self, target, *args, **kwargs):
            first = not self._threads
            if first:
                started = threading.Event()
                def running():
                    started.set()
                    return target(*args, **kwargs)
                future = super().submit(running)
                assert started.wait(5), "first real task did not start"
            else:
                future = super().submit(target, *args, **kwargs)
            self.futures = getattr(self, 'futures', []) + [future]
            if phase.startswith('first-submit-' if first else 'second-submit-'):
                raise error('owned submit failure')
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                self.release.set()
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
    wait = concurrent.futures.wait
    calls = []
    def observe_wait(*args, **kwargs):
        outcome = wait(*args, **kwargs)
        calls.append(outcome)
        if phase.startswith('body-'):
            raise error('owned body failure')
        return outcome
    futures_view = ModuleType('concurrent.futures')
    vars(futures_view).update(vars(concurrent.futures))
    futures_view.wait = observe_wait
    concurrent_view = ModuleType('concurrent')
    vars(concurrent_view).update(vars(concurrent))
    concurrent_view.futures = futures_view
    function = native.TestQueueDrainCancellation.test_drain_cancelled_future_never_notifies_waiters
    view = module_function_view(native, bindings={'ThreadPoolExecutor': Pool, 'concurrent': concurrent_view, '_owned_case': function})
    assert view._owned_case.__code__ is function.__code__
    try:
        if phase == 'normal':
            view._owned_case(native.TestQueueDrainCancellation())
        else:
            with pytest.raises(error, match='owned .* failure'):
                view._owned_case(native.TestQueueDrainCancellation())
        assert len(pools) == 1
        pool = pools[0]
        expected = [(True, False)] if 'submit-' in phase else [(False, True), (True, False)]
        assert pool.waits == expected
        assert pool.retiring.is_set() and pool.release.is_set()
        assert len(pool._threads) == 1
        assert all(not worker.is_alive() for worker in pool._threads)
        assert all(future.done() for future in pool.futures)
        if 'submit-' not in phase:
            assert len(calls) == 1
            assert calls[0][0] == set()
            assert calls[0][1] == {pool.futures[1]}
            assert pool.futures[1].cancelled()
        assert concurrent.futures.ThreadPoolExecutor is real
        assert concurrent.futures.wait is wait
        assert native.ThreadPoolExecutor is real
        assert native.concurrent is concurrent
    finally:
        for pool in pools:
            pool.release.set()
            real.shutdown(pool, wait=True)
            assert all(not worker.is_alive() for worker in pool._threads)
