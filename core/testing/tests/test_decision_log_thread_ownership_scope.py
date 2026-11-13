"""The actual decision-log concurrency test retires partially started writer threads."""

from contextlib import contextmanager
import threading
from types import CodeType, ModuleType
import pytest
import core.dispatch.broker.tests.test_decision_log as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase, log_path):
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
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
    function = native.TestDecisionLog.test_concurrent_writes
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestDecisionLog(), log_path), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=5)
                assert not thread.is_alive()


@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_log_writer_caller_retires_every_started_worker(tmp_path, phase):
    real = threading.Thread
    function = native.TestDecisionLog.test_concurrent_writes
    worker_code = next(code for code in function.__code__.co_consts
                       if isinstance(code, CodeType) and code.co_name == 'writer')
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    log_path = tmp_path / 'decisions.jsonl'
    with exercise(phase, log_path) as (invoke, threads):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 4
        started = [thread for thread in threads if thread.ident is not None]
        expected = 4 if phase == 'normal' else 1 if phase.startswith('before-') else 2
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.joins for thread in started)
        assert all(not thread.joins for thread in threads if thread.ident is None)
        assert all(thread.native_target.__code__ is worker_code for thread in threads)
        records = native.DecisionLog(log_path).read_all()
        assert len(records) == 50 * expected
        assert {record.selected_model for record in records} == {f'model-{i}' for i in range(expected)}
        for i in range(expected):
            assert sum(record.selected_model == f'model-{i}' for record in records) == 50
        assert all(record.reason == 'concurrent' for record in records)
        assert threading.Thread is real
        assert native.threading is threading
