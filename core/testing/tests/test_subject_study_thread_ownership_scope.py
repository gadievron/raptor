"""The actual in-flight subject-study fixture owns its outer worker before start."""

from contextlib import contextmanager
import builtins
import threading
from types import CodeType, ModuleType
import pytest
import core.concepts.tests.test_subject_study as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    real = threading.Thread
    threads, events = [], []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.subjects = closure['subjects']
            self.errors = closure['errors']
            self.joins = []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if phase.startswith('before-'):
                raise error('owned start failure')
            super().start()
            if phase.startswith('after-'):
                assert len(events) == 2 and events[0].wait(5), 'actual second batch did not start'
                raise error('owned start failure')
        def join(self, *args, **kwargs):
            self.joins.append((args, kwargs))
            return super().join(*args, **kwargs)
    def event():
        owned = threading.Event()
        events.append(owned)
        return owned
    namespace = ModuleType('threading')
    vars(namespace).update(vars(threading))
    namespace.Thread, namespace.Event = Thread, event
    importer = builtins.__import__
    def local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'threading' and level == 0:
            return namespace
        return importer(name, globals, locals, fromlist, level)
    function = native.test_explanation_is_available_while_another_study_batch_is_inflight
    view = module_function_view(native, import_hook=local)
    assert view.test_explanation_is_available_while_another_study_batch_is_inflight.__code__ is function.__code__
    with pytest.MonkeyPatch.context() as owner:
        try:
            yield lambda: view.test_explanation_is_available_while_another_study_batch_is_inflight(owner), threads, events
        finally:
            for event in events:
                event.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=5)
                    assert not thread.is_alive()


@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_subject_caller_retires_worker_after_partial_start(phase):
    from core.concepts import study

    real = threading.Thread
    original_parser = study._parse_batch_response
    function = native.test_explanation_is_available_while_another_study_batch_is_inflight
    worker_code = next(code for code in function.__code__.co_consts
                       if isinstance(code, CodeType) and code.co_name == 'work')
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with exercise(phase) as (invoke, threads, events):
        if phase == 'normal':
            invoke()
        else:
            with pytest.raises(error, match='owned start failure'):
                invoke()
        assert len(threads) == 1 and len(events) == 2
        thread = threads[0]
        assert not thread.is_alive()
        assert thread.native_target.__code__ is worker_code
        assert events[1].is_set()
        assert not thread.errors
        if phase.startswith('before-'):
            assert thread.ident is None and not thread.joins
            assert not events[0].is_set()
            assert thread.subjects.snapshot() == ()
        else:
            assert thread.ident is not None and thread.joins
            assert events[0].is_set()
            snapshot = thread.subjects.snapshot()
            assert len(snapshot) == 2
            assert {row.request_id for row in snapshot} == {'owned-request', 'other-request'}
            assert all(row.status == 'partial' for row in snapshot)
        assert threading.Thread is real
    assert study._parse_batch_response is original_parser
