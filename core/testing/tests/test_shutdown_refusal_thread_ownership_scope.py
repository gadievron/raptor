"""Actual worker-thread signal refusal caller retires before state restoration."""
from contextlib import contextmanager
import threading
from types import ModuleType
import core.audit.tests.test_sigterm_grace as native
from core.testing.module_views import module_function_view
from core.testing.audit_shutdown import isolated_audit_shutdown
import pytest
import builtins

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
            closure = dict(zip(target.__code__.co_freevars, (cell.cell_contents for cell in target.__closure__)))
            self.results = closure['results']
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
    function = native.TestInstallSigtermGrace.test_worker_thread_refuses
    real_import = builtins.__import__
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'threading' and level == 0:
            return namespace
        return real_import(name, globals, locals, fromlist, level)
    view = module_function_view(native, bindings={'_owned_case': function}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    with isolated_audit_shutdown(native.orch), pytest.MonkeyPatch.context() as patch:
        try:
            yield lambda: view._owned_case(native.TestInstallSigtermGrace(), patch), threads
        finally:
            release.set()
            for thread in threads:
                if thread.ident is not None:
                    real.join(thread, timeout=5)
                    assert not thread.is_alive()

import signal

@pytest.mark.parametrize('phase', ['normal', 'before-error', 'after-error', 'before-interrupt', 'after-interrupt'])
def test_actual_refusal_caller_retires_worker(phase):
    real = threading.Thread
    names = ('_sigterm_event', '_shutdown_event', '_sigterm_state', '_sigterm_flush_hooks', 'os', '_threading')
    borrowed = {name: getattr(native.orch, name) for name in names}
    old_state = dict(native.orch._sigterm_state)
    disposition = signal.getsignal(signal.SIGTERM)
    with exercise(phase) as (invoke, threads):
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
        assert thread.results == ([False] if started else [])
        assert native.orch._sigterm_state['installed'] is False
        function = native.TestInstallSigtermGrace.test_worker_thread_refuses
        code = next(c for c in function.__code__.co_consts if isinstance(c, type(function.__code__)) and 'install_sigterm_grace' in c.co_names)
        assert thread.native_target.__code__ is code
        assert threading.Thread is real
        assert signal.getsignal(signal.SIGTERM) == disposition
    for name, value in borrowed.items():
        assert getattr(native.orch, name) is value
    assert native.orch._sigterm_state == old_state
    assert signal.getsignal(signal.SIGTERM) == disposition
