"""Actual paused consumer caller retires without dispatching a study batch."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_postloop_environment_gate as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.queue, self.result = cells['queue'], cells['result']
            self.guard = cells['config'].environment_guard_state
            cells = dict(zip(self.guard.tick.__code__.co_freevars, (c.cell_contents for c in self.guard.tick.__closure__)))
            self.entered = cells['entered_guard']
            self.joins = []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith('before-'):
                raise error('owned start failure')
            super().start()
            assert self.entered.wait(5), 'actual consumer did not reach guard'
            if phase.startswith('after-'):
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread = Thread
    function = native.TestStudyConsumerGate.test_pause_defers_batch_and_conclusion_stops_drain
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestStudyConsumerGate(), tmp_path), threads
    finally:
        for thread in threads:
            thread.guard.concluded = True
            thread.guard.resume()
            thread.queue.request_stop()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()

import pytest

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_paused_consumer_caller_retires_worker(phase, tmp_path):
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
        assert thread.entered.is_set() == started
        assert not thread.is_alive()
        assert bool(thread.joins) == started
        assert thread.guard.concluded
        assert thread.guard._release.is_set()
        assert thread.queue.stop_requested
        assert type(thread.queue) is native._orch.StudyQueue
        with thread.queue._not_empty:
            # Normal native assertions consume the untouched batch themselves.
            assert len(thread.queue._queue) == (0 if phase == 'normal' else 1)
            if phase != 'normal':
                item = thread.queue._queue[0]
                assert (item.question, item.source_file, item.source_function) == ('what is sk_buff?', 'a.c', 'f')
                assert not thread.queue._working
        if started:
            assert thread.result.terminated_by == 'environment'
            assert thread.result.environment_fault == thread.guard.conclude_reason
        function = native.TestStudyConsumerGate.test_pause_defers_batch_and_conclusion_stops_drain
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == 'run')
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert native.threading is threading
