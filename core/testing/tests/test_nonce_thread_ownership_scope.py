from contextlib import contextmanager
import pytest
from core.security import prompt_telemetry
import threading
from types import ModuleType
import packages.llm_analysis.tests.test_defense_wiring as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
    patch = pytest.MonkeyPatch()
    borrowed = prompt_telemetry.defense_telemetry
    native._isolated_defense_telemetry.__wrapped__(patch)
    real = threading.Thread
    release = threading.Event()
    threads = []
    error = KeyboardInterrupt if 'interrupt' in phase else RuntimeError
    class Thread(real):
        def __init__(self, *args, **kwargs):
            target = kwargs['target']
            self.native_target = target
            cells = dict(zip(target.__code__.co_freevars, (c.cell_contents for c in target.__closure__)))
            self.task = cells['task']
            self.nonces = cells['nonces']
            self.errors = cells['errors']
            assert type(self.task) is native.AnalysisTask
            self.completed = False
            def running(*args, **kwargs):
                assert release.wait(10), 'owned worker gate not released'
                result = target(*args, **kwargs)
                self.completed = True
                return result
            kwargs['target'] = running
            self.index, self.joins = len(threads), []
            super().__init__(*args, **kwargs)
            threads.append(self)
        def start(self):
            if self.index == 1 and phase.startswith('before-'):
                raise error('owned start failure')
            if phase == 'normal':
                release.set()
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
    function = native.TestNonceTracking.test_nonce_thread_safety
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestNonceTracking()), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()
        patch.undo()
        assert prompt_telemetry.defense_telemetry is borrowed


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_nonce_workers_retire_before_telemetry_restoration(phase):
    real_thread = threading.Thread
    borrowed = prompt_telemetry.defense_telemetry
    with exercise(phase) as (invoke, threads):
        pinned = prompt_telemetry.defense_telemetry
        assert pinned is not borrowed
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 10
        started = [thread for thread in threads if thread.ident is not None]
        expected = 10 if phase == "normal" else (1 if phase.startswith("before-") else 2)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert not threads[0].errors
        assert len(threads[0].nonces) >= min(expected, 2)
        assert all(isinstance(nonce, str) and nonce for nonce in threads[0].nonces)
        assert all(thread.native_target.__code__.co_name == "build_and_collect" for thread in threads)
        assert prompt_telemetry.defense_telemetry is pinned
        assert threading.Thread is real_thread
    assert prompt_telemetry.defense_telemetry is borrowed
