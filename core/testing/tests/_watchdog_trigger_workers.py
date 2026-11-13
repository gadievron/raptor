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
from core.run.tests import test_parent_liveness as native
from core.run import parent_liveness
from core.testing.module_views import module_function_view
import pytest
from contextlib import contextmanager
for name in ('kill', 'killpg', '_exit'):
    setattr(os, name, denied)
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
mode, stage, after = sys.argv[4], sys.argv[5], sys.argv[6] == 'True'
if mode == 'control':
    from core.testing.tests.test_thread_handshake_contracts import test_watchdog_probe_retires_worker_on_assertion_failure
    test_watchdog_probe_retires_worker_on_assertion_failure(stage)
    assert not denied_calls, denied_calls
    print('WATCHDOG_TRIGGER_WORKER_OK')
    sys.exit(0)
failure = error('owned watchdog lifecycle fault') if error else None
action_entered, action_release = threading.Event(), threading.Event()
workers, fired = [], []
borrowed_action, borrowed_threads = parent_liveness._terminate_group, parent_liveness.threading
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.resume = self.flipped = self.polled = None
        if mode == 'change':
            values = inspect.getclosurevars(production.time.sleep).nonlocals
            self.resume, self.polled = values['resume'], values['polled']
            self.flipped = inspect.getclosurevars(production.os.getppid).nonlocals['flipped']
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert (self.polled if mode == 'change' else action_entered).wait(5)
            fired.append(True)
            raise failure
        action_release.set()
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert action_entered.wait(5)
            fired.append(True)
            raise failure
        action_release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
production = module_function_view(parent_liveness, bindings={'threading': thread_view})
original = (native.TestTrigger.test_ppid_change_fires if mode == 'change'
            else native.TestTrigger.test_already_orphaned_expected_parent_fires)
owner = module_function_view(native, bindings={'parent_liveness': production, '_owned_case': original, '_owned_terminate': native._stub_terminate.__wrapped__, '_owned_thread_scope': native._owned_watchdog_threads.__wrapped__})
# Contextlib's wrapper is foreign; rewrap the exact original generator with
# its private globals so its constructor binding belongs to this consumer.
assert owner._owned_thread_scope.__code__ is native._owned_watchdog_threads.__wrapped__.__code__
owner._owned_watchdog_threads = contextmanager(owner._owned_thread_scope)
assert owner._owned_case.__code__ is original.__code__
assert production.start_orphan_watchdog.__code__ is parent_liveness.start_orphan_watchdog.__code__
with pytest.MonkeyPatch.context() as patch:
    calls = owner._owned_terminate(patch)
    record = production._terminate_group
    def recorded_action(label):
        action_entered.set()
        assert action_release.wait(5), 'owned recorder was not released'
        record(label)
    patch.setattr(production, '_terminate_group', recorded_action)
    try:
        try:
            if mode == 'change':
                owner._owned_case(native.TestTrigger(), patch, calls)
            else:
                owner._owned_case(native.TestTrigger(), calls)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 1 and not workers[0].is_alive()
        started = workers[0].ident is not None
        assert calls == ([('trigger' if mode == 'change' else 'orphaned')] if started else [])
        assert production.threading is thread_view
    finally:
        action_release.set()
        for worker in workers:
            if worker.flipped is not None:
                worker.flipped.set()
                worker.resume.set()
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=5)
                assert not worker.is_alive()
assert parent_liveness._terminate_group is borrowed_action
assert parent_liveness.threading is borrowed_threads
assert not denied_calls, denied_calls
print('WATCHDOG_TRIGGER_WORKER_OK')
