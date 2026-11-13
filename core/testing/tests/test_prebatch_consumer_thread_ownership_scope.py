"""Actual pre-batch fixture stops and retires workers before mock undo."""
from contextlib import contextmanager
from pathlib import Path
import threading
from types import ModuleType
import pytest
import core.audit.tests.test_postloop_environment_gate as native
import core.concepts.study as study_module
from core.testing.module_views import module_function_view

BINDINGS = ((study_module, 'run_study'), (native._orch, '_run_llm_client'), (native._orch, '_client_class_cost'), (native._orch, '_resolve_multilang_requests'))
NORMAL = {'normal-stop': 'test_stop_during_prebatch_pause_skips_the_batch', 'normal-conclusion': 'test_conclusion_during_prebatch_pause_books_and_stops', 'normal-healthy': 'test_healthy_gate_still_dispatches_the_batch'}

@contextmanager
def exercise(phase, tmp_path):
    real = threading.Thread
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    with pytest.MonkeyPatch.context() as patch:
        class Thread(real):
            def __init__(self, *args, **kwargs):
                target = kwargs['target']
                self.native_target = target
                cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
                self.queue, self.result, self.config = cells['queue'], cells['result'], cells['config']
                self.guard = self.config.environment_guard_state
                assert type(self.guard) is native._NthTickPauseGuard
                assert list(Path(self.config.target_path).iterdir()) == []
                self.fakes = tuple(getattr(owner, name) for owner, name in BINDINGS)
                callback = study_module.run_study
                cells = dict(zip(callback.__code__.co_freevars, (c.cell_contents for c in callback.__closure__)))
                self.study_ran = cells['study_ran']
                self.joins = []
                super().__init__(*args, **kwargs)
                threads.append(self)
            def start(self):
                if phase.startswith('before-'):
                    raise error('owned start failure')
                super().start()
                assert self.guard.paused.wait(10), 'actual consumer did not reach tick2'
                if phase.startswith('after-'):
                    raise error('owned start failure')
            def join(self, *args, **kwargs):
                self.joins.append((args, kwargs))
                assert tuple(getattr(owner, name) for owner, name in BINDINGS) == self.fakes
                return super().join(*args, **kwargs)
        namespace = ModuleType('threading')
        vars(namespace).update(vars(threading))
        namespace.Thread = Thread
        function = native.TestStudyConsumerPreBatchGate._drive
        view = module_function_view(native, bindings={'_owned_drive': function, 'threading': namespace})
        assert view._owned_drive.__code__ is function.__code__
        owner = native.TestStudyConsumerPreBatchGate()
        owner._drive = view._owned_drive.__get__(owner, type(owner))
        def invoke():
            if phase in NORMAL:
                return getattr(owner, NORMAL[phase])(tmp_path, patch)
            def on_paused(queue, guard):
                if phase.startswith('callback-'):
                    raise error('owned callback failure')
            return owner._drive(tmp_path, patch, on_paused=on_paused)
        try:
            yield invoke, threads
        finally:
            for thread in threads:
                thread.queue.request_stop()
                thread.guard.release.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=10)
                    assert not thread.is_alive()

@pytest.mark.parametrize('phase', ['normal-stop', 'normal-conclusion', 'normal-healthy', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt', 'callback-error', 'callback-interrupt'])
def test_actual_prebatch_helper_retires_before_patch_undo(phase, tmp_path):
    real = threading.Thread
    borrowed = tuple(getattr(owner, name) for owner, name in BINDINGS)
    with exercise(phase, tmp_path) as (invoke, threads):
        if phase in NORMAL:
            invoke()
        else:
            error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
            with pytest.raises(error, match='owned (start|callback) failure'):
                invoke()
        assert len(threads) == 1
        thread = threads[0]
        started = thread.ident is not None
        assert started == (not phase.startswith('before-'))
        assert thread.guard.paused.is_set() == started
        assert not thread.is_alive()
        assert bool(thread.joins) == started
        assert thread.queue.stop_requested
        assert thread.guard.release.is_set()
        assert thread.study_ran.is_set() == (phase == 'normal-healthy')
        assert list(Path(thread.config.target_path).iterdir()) == []
        function = native.TestStudyConsumerPreBatchGate._drive
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and c.co_name == 'run')
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert native.threading is threading
    for (owner, name), value in zip(BINDINGS, borrowed):
        assert getattr(owner, name) is value
