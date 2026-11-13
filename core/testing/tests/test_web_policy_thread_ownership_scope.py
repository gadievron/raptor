from contextlib import contextmanager
import builtins
import threading
from types import ModuleType
import packages.web.tests.test_execution_policy as native
import pytest
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
            self.policy = cells['policy']
            assert type(self.policy) is native.WebExecutionPolicy
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
    original_import = builtins.__import__
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'threading' and level == 0:
            return namespace
        return original_import(name, globals, locals, fromlist, level)
    function = native.test_audit_recording_is_atomic_under_concurrent_authorizers
    view = module_function_view(native, bindings={'_owned_case': function}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    try:
        yield view._owned_case, threads
    finally:
        release.set()
        for thread in threads:
            if thread.ident is not None:
                real.join(thread, timeout=30)
                assert not thread.is_alive()


@pytest.mark.parametrize("phase", ["normal", "before-error", "after-error", "before-interrupt", "after-interrupt"])
def test_authorizer_workers_retire_before_caller_exit(phase):
    original_thread = threading.Thread
    original_import = builtins.__import__
    with exercise(phase) as (invoke, threads):
        if phase == "normal":
            invoke()
        else:
            error = KeyboardInterrupt if "interrupt" in phase else RuntimeError
            with pytest.raises(error, match="owned start failure"):
                invoke()
        assert len(threads) == 8
        started = [thread for thread in threads if thread.ident is not None]
        expected = 8 if phase == "normal" else (1 if phase.startswith("before-") else 2)
        assert len(started) == expected
        assert all(not thread.is_alive() for thread in threads)
        assert all(thread.completed and thread.joins for thread in started)
        assert all(not thread.completed and not thread.joins for thread in threads if thread.ident is None)
        assert all(thread.native_target.__code__.co_name == "_authorize_many" for thread in threads)
        summary = threads[0].policy.report()["summary"]
        assert summary["total_actions"] == 500 * expected
        assert summary["allowed_actions"] == 500 * expected
        assert summary["denied_actions"] == 0
        assert threading.Thread is original_thread
        assert builtins.__import__ is original_import
