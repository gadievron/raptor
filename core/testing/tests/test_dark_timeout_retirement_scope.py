"""The actual timeout fixture releases its real barrier before joining on every exit."""

from contextlib import contextmanager
import builtins
import concurrent.futures
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_dark_concurrent as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

@contextmanager
def exercise(tmp_path, phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools, barriers = [], []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
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
            started = threading.Event()
            def running():
                started.set()
                return target(*args, **kwargs)
            self.future = super().submit(running)
            assert started.wait(5)
            if phase.startswith('submit-'):
                raise error('owned submit failure')
            return self.future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                assert len(barriers) == 1 and barriers[0].is_set(), 'native barrier not released before join'
                self.release.set()
            result = super().shutdown(wait=wait, cancel_futures=cancel_futures)
            if not wait and phase.startswith('drain-'):
                raise error('owned drain shutdown failure')
            return result
    futures = ModuleType('concurrent.futures')
    vars(futures).update(vars(concurrent.futures))
    futures.ThreadPoolExecutor = Pool
    root = ModuleType('concurrent')
    vars(root).update(vars(concurrent))
    root.futures = futures
    importer = builtins.__import__
    def local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'concurrent.futures' and level == 0:
            return futures if fromlist else root
        return importer(name, globals, locals, fromlist, level)
    def event():
        barrier = threading.Event()
        barriers.append(barrier)
        return barrier
    threads = ModuleType('threading')
    vars(threads).update(vars(threading))
    threads.Event = event
    function = native.TestDrainDarkProbes.test_timeout_abandons_slow_probes
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': threads}, import_hook=local)
    assert view._owned_case.__code__ is function.__code__
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        try:
            yield lambda: view._owned_case(native.TestDrainDarkProbes(), tmp_path), pools, barriers
        finally:
            for barrier in barriers:
                barrier.set()
            for pool in pools:
                pool.release.set()
                real.shutdown(pool, wait=True)
                assert all(not worker.is_alive() for worker in pool._threads)


@pytest.mark.parametrize('phase', ['normal', 'drain-error', 'drain-interrupt', 'submit-error', 'submit-interrupt'])
def test_actual_timeout_caller_releases_barrier_and_retires_worker(tmp_path, phase):
    real = concurrent.futures.ThreadPoolExecutor
    event_class = threading.Event
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(tmp_path, phase) as (invoke, pools, barriers):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned .* failure'):
                invoke()
        assert len(pools) == len(barriers) == 1
        pool = pools[0]
        expected = [(True, False)] if phase.startswith('submit-') else [(False, False), (True, False)]
        assert pool.waits == expected
        assert barriers[0].is_set()
        assert pool.future.done() and not pool.future.cancelled()
        assert pool.retiring.is_set() and pool.release.is_set()
        assert len(pool._threads) == 1
        assert all(not worker.is_alive() for worker in pool._threads)
        assert concurrent.futures.ThreadPoolExecutor is real
        assert threading.Event is event_class
        assert native.threading is threading
