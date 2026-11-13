"""The actual prompt concurrency test retires real threads after partial starts."""

from contextlib import contextmanager
import threading
from types import CodeType, ModuleType
import pytest
import core.llm.multi_model.tests.test_prompt_helpers as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    release = threading.Event()
    threads, produced = [], []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    original = native.wrap_model_output
    def wrap(*args, **kwargs):
        block = original(*args, **kwargs)
        produced.append(block)
        return block
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
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
    function = native.TestWrapModelOutput.test_thread_safe_under_concurrent_calls
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace, 'wrap_model_output': wrap})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestWrapModelOutput()), threads, produced
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()


@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_prompt_concurrency_caller_retires_every_started_worker(phase):
    real = threading.Thread
    original = native.wrap_model_output
    function = native.TestWrapModelOutput.test_thread_safe_under_concurrent_calls
    worker_code = next(code for code in function.__code__.co_consts
                       if isinstance(code, CodeType) and code.co_name == 'worker')
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(phase) as (invoke, threads, produced):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 50
        started = [thread for thread in threads if thread.ident is not None]
        expected = 50 if phase == 'normal' else 1 if phase.startswith('before-') else 2
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.joins for thread in started)
        assert all(not thread.joins for thread in threads if thread.ident is None)
        assert all(thread.native_target.__code__ is worker_code for thread in threads)
        assert len(produced) == expected
        assert all(block.kind == 'ANALYSIS' for block in produced)
        assert len({block.content for block in produced}) == expected
        assert threading.Thread is real
        assert native.threading is threading
        assert native.wrap_model_output is original
