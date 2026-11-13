"""Actual paused-dispatch caller releases its guard before worker retirement."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_postloop_environment_gate as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.output = closure['out']
            gate = closure['gate']
            cells = dict(zip(gate.__code__.co_freevars, (c.cell_contents for c in gate.__closure__)))
            self.guard = cells['guard']
            assert type(self.guard) is native._StubGuard
            review = closure['do_review']
            cells = dict(zip(review.__code__.co_freevars, (c.cell_contents for c in review.__closure__)))
            self.calls = cells['calls']
            def running(*args, **kwargs):
                assert release.wait(5), 'owned worker gate not released'
                return target(*args, **kwargs)
            kwargs['target'] = running
            super().__init__(*args, **kwargs)
            self.index, self.joins = len(threads), []
            threads.append(self)
        def start(self):
            if self.index == 0 and phase.startswith('before-'):
                raise error('owned start failure')
            if phase == 'normal':
                release.set()
            super().start()
            if self.index == 0 and phase.startswith('after-'):
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestCollectReviewsDispatchGate.test_parallel_pause_defers_dispatch_then_resumes
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestCollectReviewsDispatchGate()), threads
    finally:
        for thread in threads:
            thread.guard.resume()
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest
from core.audit.executor import review_work_inflight
from core.analysis import reach_audit

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_paused_dispatch_caller_retires_worker(phase):
    real = threading.Thread
    count = review_work_inflight()
    graph = reach_audit._joern_server.get()
    with exercise(phase) as (invoke, threads):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        started = thread.ident is not None
        assert started == (not phase.startswith('before-'))
        assert not thread.is_alive()
        assert bool(thread.joins) == started
        assert thread.guard._release.is_set()
        assert sorted(thread.calls) == ([0, 1, 2, 3] if started else [])
        assert len(thread.output) == int(started)
        if started:
            assert sorted(thread.output[0]) == [0, 1, 2, 3]
            assert thread.guard.ticks == 4
        function = native.TestCollectReviewsDispatchGate.test_parallel_pause_defers_dispatch_then_resumes
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == 'run')
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert native.threading is threading
        assert review_work_inflight() == count
        assert reach_audit._joern_server.get() is graph
