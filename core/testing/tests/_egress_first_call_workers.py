from pathlib import Path
import os
import socket
import subprocess
import sys
import threading
from types import ModuleType

# This owned interpreter may execute only in-process Python/file operations.
denied_calls = []
def denied(*args, **kwargs):
    denied_calls.append('native_or_transport')
    raise AssertionError('unexpected child launch or transport')
subprocess.Popen = denied
for name in ('fork', 'forkpty', 'system', 'posix_spawn', 'posix_spawnp', 'execv', 'execve', 'execvp', 'execvpe'):
    if hasattr(os, name):
        setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
root, scratch = map(Path, sys.argv[1:3])
sys.path.insert(0, str(root))
# Match the reviewed Linux process-libc bootstrap; never discover native tools.
import ctypes.util
from unittest.mock import patch
with patch.object(ctypes.util, 'find_library', side_effect=lambda name: None if name == 'c' else denied()):
    from core.sandbox import preexec
    assert preexec._get_libc() is not None
from core.config import RaptorConfig
RaptorConfig.LOG_DIR = scratch / 'logs'
import inspect
import pytest
from core.llm.tests import test_egress as native
from core.llm import egress
from core.sandbox import proxy
from core.testing.llm_env import reset_llm_egress_state, PROXY_ENV_VARS
from core.testing.module_views import module_function_view
error_name, stage, after_text, state = sys.argv[3:7]
after = after_text == 'True'
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned egress first-call worker fault') if error else None
workers, barriers, fired, stub_calls = [], [], [], []
entered, waiting, release = threading.Event(), threading.Event(), threading.Event()
class Barrier(threading.Barrier):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        barriers.append(self)
    def wait(self, *args, **kwargs):
        waiting.set()
        return super().wait(*args, **kwargs)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.errors = inspect.getclosurevars(kwargs['target']).nonlocals['errors']
        workers.append(self)
    def start(self):
        selected = stage == 'start' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert waiting.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert entered.wait(5)
            fired.append(True)
            raise failure
        release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
class BodyPatch(pytest.MonkeyPatch):
    def setattr(self, target, name, value, *args, **kwargs):
        if target is proxy and name == 'get_proxy':
            original_stub = value
            assert original_stub.__name__ == 'slow_get_proxy'
            def gated_stub(*a, **kw):
                entered.set()
                assert release.wait(10), 'native proxy stub was not released'
                result = original_stub(*a, **kw)
                stub_calls.append(result)
                return result
            value = gated_stub
        return super().setattr(target, name, value, *args, **kwargs)
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread, thread_view.Barrier = Worker, Barrier
inherited_import = __import__
def import_local(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'threading':
        return thread_view
    return inherited_import(name, globals, locals, fromlist, level)
view = module_function_view(native, bindings={'_owned_native': native.TestEnableIsThreadSafe.test_racing_first_callers_snapshot_operator_env_once}, import_hook=import_local)
assert view._owned_native.__code__ is native.TestEnableIsThreadSafe.test_racing_first_callers_snapshot_operator_env_once.__code__
with pytest.MonkeyPatch.context() as prior:
    if state == 'missing':
        prior.setenv('HTTPS_PROXY', '')
        prior.delenv('HTTPS_PROXY')
    else:
        prior.setenv('HTTPS_PROXY', '' if state == 'empty' else 'http://owned-inherited.invalid:81')
    prior_snapshot = {'owned': state} if state == 'borrowed' else None
    prior.setattr(egress, '_enabled', state == 'borrowed')
    prior.setattr(egress, '_original_proxy_env', prior_snapshot)
    environment = {name: (name in os.environ, os.environ.get(name)) for name in (*PROXY_ENV_VARS, 'OLLAMA_HOST')}
    with pytest.MonkeyPatch.context() as fixture_patch:
        fixture = reset_llm_egress_state(fixture_patch)
        next(fixture)
        with BodyPatch.context() as body_patch:
            try:
                try:
                    view._owned_native(native.TestEnableIsThreadSafe(), body_patch)
                except BaseException as caught:
                    assert failure is not None and caught is failure
                else:
                    assert failure is None
                assert fired == ([True] if failure else [])
                assert len(workers) == 2 and len(barriers) == 1
                assert not any(worker.is_alive() for worker in workers)
            finally:
                started = sum(worker.ident is not None for worker in workers)
                if started < 2:
                    for barrier in barriers:
                        barrier.abort()
                release.set()
                for worker in workers:
                    if worker.ident is not None:
                        threading.Thread.join(worker, timeout=30)
                        assert not worker.is_alive()
                started = sum(worker.ident is not None for worker in workers)
                if started == 2:
                    assert len(stub_calls) >= 1
                    assert len(stub_calls) + len(workers[0].errors) == 2
                    assert all(isinstance(e, threading.BrokenBarrierError) for e in workers[0].errors)
                    assert egress._enabled
                    assert egress._original_proxy_env == {'HTTPS_PROXY': 'http://proxy.corp:3128'}
                    assert os.environ['HTTPS_PROXY'] == 'http://127.0.0.1:51234'
                else:
                    assert len(workers[0].errors) == started
                    assert all(isinstance(e, threading.BrokenBarrierError) for e in workers[0].errors)
                    assert not stub_calls and not egress._enabled and egress._original_proxy_env is None
        fixture.close()
    assert egress._enabled == (state == 'borrowed')
    assert egress._original_proxy_env is prior_snapshot
    assert {name: (name in os.environ, os.environ.get(name)) for name in environment} == environment
assert not denied_calls, denied_calls
print('EGRESS_FIRST_CALL_WORKER_OK')
