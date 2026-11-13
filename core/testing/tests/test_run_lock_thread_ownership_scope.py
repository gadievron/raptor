"""The run-lock re-entry caller retires its worker while the handle is held."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_run_lock as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.results = closure['results']
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
    function = native.test_in_process_reacquisition_is_a_noop
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(tmp_path), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_reentry_caller_retires_worker(phase, tmp_path):
    real = threading.Thread
    with exercise(phase, tmp_path) as (invoke, threads):
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
        function = native.test_in_process_reacquisition_is_a_noop
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == 'worker')
        assert thread.native_target.__code__ is code
        assert len(thread.results) == int(started)
        if started:
            assert not isinstance(thread.results[0], native.AuditRunLocked)
            assert not thread.results[0].held
        assert threading.Thread is real
        assert native.threading is threading
