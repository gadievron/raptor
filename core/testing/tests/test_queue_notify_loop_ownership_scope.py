"""Actual queue notification caller closes its loop after worker retirement."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_study_consumer as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    release = threading.Event()
    threads, loops = [], []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.queue = closure['q']
            assert type(self.queue) is native.StudyQueue
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
            assert not loops[0].is_closed()
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestStudyQueueConcepts.test_set_event_loop_and_notify
    real_loop_factory = native.asyncio.new_event_loop
    def new_loop():
        loop = real_loop_factory()
        loops.append(loop)
        if phase.startswith('body-'):
            def fail_wait(coro):
                coro.close()
                raise error('owned loop failure')
            loop.run_until_complete = fail_wait
        return loop
    async_namespace = ModuleType('asyncio')
    vars(async_namespace).update(vars(native.asyncio))
    async_namespace.new_event_loop = new_loop
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace, 'asyncio': async_namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestStudyQueueConcepts()), threads, loops
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()
        for loop in loops:
            loop.close()

import pytest

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt', 'body-error', 'body-interrupt'])
def test_actual_notify_caller_retires_before_loop_close(phase):
    real = threading.Thread
    factory = native.asyncio.new_event_loop
    with exercise(phase) as (invoke, threads, loops):
        if phase == 'normal':
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned (start|loop) failure'):
                invoke()
        assert len(loops) == len(threads) == 1
        thread, loop = threads[0], loops[0]
        started = thread.ident is not None
        assert started == (not phase.startswith('before-'))
        assert not thread.is_alive()
        assert bool(thread.joins) == started
        assert loop.is_closed()
        expected = frozenset() if started else frozenset({'sk_buff'})
        assert thread.queue.pending_concepts() == expected
        function = native.TestStudyQueueConcepts.test_set_event_loop_and_notify
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == '_mark')
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert native.threading is threading
        assert native.asyncio.new_event_loop is factory
