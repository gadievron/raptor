"""The actual bounded-memo single-flight caller owns its worker lifetime."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_codeql_sweep_memo as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.memo, self.results = closure['memo'], closure['results']
            compute = closure['slow_compute']
            cells = dict(zip(compute.__code__.co_freevars, (cell.cell_contents for cell in compute.__closure__)))
            self.release, self.entered, self.computes = cells['release'], cells['entered'], cells['computes']
            assert type(self.memo) is native.BoundedMemo
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
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestBoundedMemo.test_concurrent_same_key_collapses_to_one_compute
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestBoundedMemo()), threads
    finally:
        for thread in threads:
            thread.release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_memo_caller_releases_and_retires_workers(phase):
    real = threading.Thread
    with exercise(phase) as (invoke, threads):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 4
        started = [t for t in threads if t.ident is not None]
        expected = 4 if phase == 'normal' else 1 if phase.startswith('before-') else 2
        assert len(started) == expected
        assert all(not t.is_alive() for t in threads)
        assert all(t.joins for t in started)
        assert all(not t.joins for t in threads if t.ident is None)
        function = native.TestBoundedMemo.test_concurrent_same_key_collapses_to_one_compute
        code = next(code for code in function.__code__.co_consts if isinstance(code, type(function.__code__)) and code.co_name == 'worker')
        assert all(t.native_target.__code__ is code for t in threads)
        first = threads[0]
        assert first.entered.is_set()
        assert first.release.is_set()
        assert first.computes == [1]
        assert len(first.results) == expected
        assert all(value == 'value' for value, _ in first.results)
        assert sum(cached for _, cached in first.results) == expected - 1
        assert threading.Thread is real
        assert native.threading is threading
