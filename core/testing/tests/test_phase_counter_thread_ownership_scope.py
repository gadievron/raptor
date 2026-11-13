"""Actual counter-smoke workers retire after success and partial starts."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_parallel_phase_i as native
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
            self.result = closure['result']
            assert type(self.result) is native.OrchestratorResult
            def running(*args, **kwargs):
                assert release.wait(5), 'owned worker gate not released'
                return target(*args, **kwargs)
            kwargs['target'] = running
            super().__init__(*args, **kwargs)
            self.index, self.joins = len(threads), []
            threads.append(self)
        def start(self):
            if self.index == 1 and phase.startswith('before-'):
                raise error('owned start failure')
            super().start()
            if self.index == 1 and phase.startswith('after-'):
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestParallelPhaseIDispatch.test_counter_mutations_are_locked
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestParallelPhaseIDispatch(), None), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_counter_caller_retires_workers(phase):
    real = threading.Thread
    with exercise(phase) as (invoke, threads):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 2
        started = [t for t in threads if t.ident is not None]
        assert len(started) == (1 if phase.startswith('before-') else 2)
        assert all(not t.is_alive() for t in threads)
        assert all(t.joins for t in started)
        assert all(not t.joins for t in threads if t.ident is None)
        function = native.TestParallelPhaseIDispatch.test_counter_mutations_are_locked
        codes = {code.co_name: code for code in function.__code__.co_consts if isinstance(code, type(function.__code__))}
        assert [t.native_target.__code__ for t in threads] == [codes['lane_a'], codes['lane_b']]
        result = threads[0].result
        assert result.findings == 500
        assert result.suspicious == (100 if len(started) == 2 else -400)
        assert result.clean == (-400 if len(started) == 2 else 100)
        assert threading.Thread is real
        assert native.threading is threading
