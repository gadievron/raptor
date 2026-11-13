"""Actual dark-result drain tests retire their own real workers."""

from contextlib import contextmanager
import builtins
import concurrent.futures
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_dark_concurrent as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs

METHODS = ['test_confirmed_promotes_to_finding', 'test_nonreproduction_preserves_dark', 'test_none_result_handled_but_no_verdict', 'test_counter_consistency_under_concurrency', 'test_results_file_written']

@contextmanager
def exercise(tmp_path, method, phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    drain_calls = []
    class Queue:
        def __init__(self, queue, pool):
            self.queue, self.pool = queue, pool
        def check(self, value):
            if value is None:
                self.pool.retiring.set()
                assert self.pool.release.wait(5), 'owned retirement gate not released'
            return value
        def get(self, *args, **kwargs):
            return self.check(self.queue.get(*args, **kwargs))
        def get_nowait(self):
            return self.check(self.queue.get_nowait())
        def put(self, value):
            return self.queue.put(value)
    class Pool(real):
        def __init__(self, *args, **kwargs):
            assert kwargs == {'max_workers': 4 if method == 'test_counter_consistency_under_concurrency' else 1}
            super().__init__(*args, **kwargs)
            self.release, self.retiring = threading.Event(), threading.Event()
            self.waits = []
            self._work_queue = Queue(self._work_queue, self)
            pools.append(self)
        def submit(self, *args, **kwargs):
            future = super().submit(*args, **kwargs)
            self.futures = getattr(self, 'futures', []) + [future]
            if phase.startswith('submit-'):
                raise error('owned submit failure')
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                self.release.set()
            return super().shutdown(wait=wait, cancel_futures=cancel_futures)
    namespace = ModuleType('concurrent.futures')
    vars(namespace).update(vars(concurrent.futures))
    namespace.ThreadPoolExecutor = Pool
    root = ModuleType('concurrent')
    vars(root).update(vars(concurrent))
    root.futures = namespace
    importer = builtins.__import__
    def local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'concurrent.futures' and level == 0:
            return namespace if fromlist else root
        return importer(name, globals, locals, fromlist, level)
    original_drain = native._drain_dark_probes
    def drain(*args, **kwargs):
        result = original_drain(*args, **kwargs)
        drain_calls.append(result)
        if phase.startswith('drain-'):
            raise error('owned drain failure')
        return result
    function = getattr(native.TestDrainDarkProbes, method)
    view = module_function_view(native, bindings={'_owned_case': function, '_drain_dark_probes': drain}, import_hook=local)
    assert view._owned_case.__code__ is function.__code__
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        try:
            yield lambda: view._owned_case(native.TestDrainDarkProbes(), tmp_path), pools, drain_calls
        finally:
            for pool in pools:
                pool.release.set()
                real.shutdown(pool, wait=True)
                assert all(not worker.is_alive() for worker in pool._threads)


@pytest.mark.parametrize('method', METHODS)
@pytest.mark.parametrize('phase', ['normal', 'drain-error', 'drain-interrupt', 'submit-error', 'submit-interrupt'])
def test_actual_drain_caller_retires_workers(tmp_path, method, phase):
    real = concurrent.futures.ThreadPoolExecutor
    original_drain = native._drain_dark_probes
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(tmp_path, method, phase) as (invoke, pools, drain_calls):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned .* failure'):
                invoke()
        assert len(pools) == 1
        pool = pools[0]
        expected = [(True, False)] if phase.startswith('submit-') else [(False, False), (True, False)]
        assert pool.waits == expected
        assert len(drain_calls) == (0 if phase.startswith('submit-') else 1)
        assert pool.retiring.is_set() and pool.release.is_set()
        limit = 4 if method == 'test_counter_consistency_under_concurrency' else 1
        assert 1 <= len(pool._threads) <= limit
        assert all(not worker.is_alive() for worker in pool._threads)
        assert all(future.done() for future in pool.futures)
        assert concurrent.futures.ThreadPoolExecutor is real
        assert native._drain_dark_probes is original_drain
