"""Nonreproduction futures retire while the actual refutation recorder stays reachable."""

from contextlib import contextmanager
import concurrent.futures
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_dark_nonreproduction as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs



@contextmanager
def exercise(tmp_path, status, evidence, phase):
    real = concurrent.futures.ThreadPoolExecutor
    pools = []
    error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
    original_recorder = native.orch._sc_record_refutation
    recorder_checks = []
    injected = []
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
            assert kwargs == {'max_workers': 1}
            super().__init__(*args, **kwargs)
            self.release, self.retiring = threading.Event(), threading.Event()
            self.waits = []
            self._work_queue = Queue(self._work_queue, self)
            pools.append(self)
        def submit(self, *args, **kwargs):
            future = super().submit(*args, **kwargs)
            self.future = future
            if phase.startswith('submit-'):
                raise error('owned submit failure')
            return future
        def shutdown(self, wait=True, *, cancel_futures=False):
            self.waits.append((wait, cancel_futures))
            if wait:
                self.release.set()
            if not wait:
                recorder = native.orch._drain_dark_probes.__globals__['_sc_record_refutation']
                assert recorder is native.orch._sc_record_refutation
                assert recorder is not original_recorder
                recorder_checks.append(recorder)
            result = super().shutdown(wait=wait, cancel_futures=cancel_futures)
            if not wait and phase == 'recorder-control':
                recorder(scope='owned refutation control')
                injected.append(True)
            if not wait and phase.startswith('drain-'):
                raise error('owned drain shutdown failure')
            return result
    namespace = ModuleType('concurrent.futures')
    vars(namespace).update(vars(concurrent.futures))
    namespace.ThreadPoolExecutor = Pool
    root = ModuleType('concurrent')
    vars(root).update(vars(concurrent))
    root.futures = namespace
    function = native.test_nonreproduction_preserves_verdict_evidence_and_counts
    view = module_function_view(native, bindings={'_owned_case': function, 'concurrent': root})
    assert view._owned_case.__code__ is function.__code__
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / 'state')
        try:
            yield lambda: view._owned_case(tmp_path, owner, 'early', status, evidence), pools, recorder_checks, injected
        finally:
            for pool in pools:
                pool.release.set()
                real.shutdown(pool, wait=True)
                assert all(not worker.is_alive() for worker in pool._threads)


@pytest.mark.parametrize('status', ['dark', 'suspicious', 'finding'])
@pytest.mark.parametrize('evidence', ['', 'llm-claimed:smt', 'smt:check-overflow'])
@pytest.mark.parametrize('phase', ['normal', 'drain-error', 'drain-interrupt', 'submit-error', 'submit-interrupt', 'recorder-control'])
def test_actual_nonreproduction_caller_retires_worker(tmp_path, status, evidence, phase):
    real = concurrent.futures.ThreadPoolExecutor
    original_recorder = native.orch._sc_record_refutation
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(tmp_path, status, evidence, phase) as (invoke, pools, recorder_checks, injected):
        if phase == 'normal':
            invoke()
        elif phase == 'recorder-control':
            with pytest.raises(AssertionError) as failure:
                invoke()
            assert 'owned refutation control' in str(failure.value)
            assert injected == [True]
        else:
            with pytest.raises(error, match='owned .* failure'):
                invoke()
        assert len(pools) == 1
        pool = pools[0]
        expected = [(True, False)] if phase.startswith('submit-') else [(False, False), (True, False)]
        assert pool.waits == expected
        assert len(recorder_checks) == (0 if phase.startswith('submit-') else 1)
        assert pool.future.done()
        assert pool.retiring.is_set() and pool.release.is_set()
        assert len(pool._threads) == 1
        assert all(not worker.is_alive() for worker in pool._threads)
        assert concurrent.futures.ThreadPoolExecutor is real
        assert native.concurrent is concurrent
    assert native.orch._sc_record_refutation is original_recorder
