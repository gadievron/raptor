from contextlib import contextmanager
import pytest
import threading
from types import ModuleType
import packages.llm_analysis.tests.test_prompt_budget_integration as native
from core.testing.module_views import module_function_view

@contextmanager
def exercise(phase):
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
            self.results = cells['results']
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
    function = native.TestDispatchTlsBudget.test_tls_budget_isolation_across_threads
    view = module_function_view(native, bindings={'_owned_case': function, 'threading': namespace})
    assert view._owned_case.__code__ is function.__code__
    try:
        yield lambda: view._owned_case(native.TestDispatchTlsBudget()), threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_tls_budget_workers_retire_on_every_exit(phase):
    original_thread = threading.Thread
    with exercise(phase) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 2
        started = [thread for thread in threads if thread.ident is not None]
        expected = 2 if phase == "normal" else (0 if phase.startswith("before-") else 1)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        expected_results = {"a": 111, "b": 222} if phase == "normal" else ({"a": 111} if expected else {})
        assert threads[0].results == expected_results
        assert not hasattr(threads[0].task._tls_budget, "tokens")
        assert all(thread.native_target.__code__.co_name == "set_budget" for thread in threads)
        assert threading.Thread is original_thread
