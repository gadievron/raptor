"""Actual queue wake-up fixture callers retire their owned workers."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_study_consumer as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(case, phase):
    real = threading.Thread
    release = threading.Event()
    threads = []
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
            release.set()
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = getattr(native.TestStudyQueue, case)
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestStudyQueue()), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest

@pytest.mark.parametrize('case', ['test_dequeue_blocks_then_returns', 'test_signal_producer_done_wakes_waiter'])
@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_queue_wakeup_caller_retires_worker(case, phase):
    real = threading.Thread
    with exercise(case, phase) as (invoke, threads):
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
        function = getattr(native.TestStudyQueue, case)
        name = '_producer' if case == 'test_dequeue_blocks_then_returns' else '_signal'
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == name)
        assert thread.native_target.__code__ is code
        queue = thread.queue
        if name == '_producer':
            batch = queue.dequeue_batch(timeout=0)
            if started and phase != 'normal':
                assert len(batch) == 1
                item = batch[0]
                assert type(item) is native.StudyRequest
                assert (item.question, item.source_file, item.source_function) == ('q?', 'f.c', 'fn')
            else:
                assert batch == []
            assert not queue.producer_done()
        else:
            assert queue.producer_done() == started
            assert queue.is_done() == started
        assert threading.Thread is real
        assert native.threading is threading
