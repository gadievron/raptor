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
from core.sandbox.tests import test_scratch_owner_cleanup as native
from core.sandbox import host
from core.testing.module_views import module_function_view
error_name, stage, after_text, position_text = sys.argv[3:7]
after, position = after_text == 'True', int(position_text)
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned scratch cleanup caller fault') if error else None
workers, fired, instances, remove_calls, native_releases, run_errors = [], [], [], [], [], []
entered, rescue = threading.Event(), threading.Event()
real_remove = native.rmtree_hardened
owned_path = scratch / 'owned'
def gated_remove(path):
    assert Path(path) == owned_path and Path(path).exists()
    remove_calls.append(path)
    entered.set()
    assert rescue.wait(10), 'owned tree removal was not released'
    return real_remove(path)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        target = kwargs['target']
        assert target.__name__ == '_cleanup_owned_output' and isinstance(target.__self__, host.SandboxHost)
        super().__init__(*args, **kwargs)
        self.position = len(workers)
        self.instance = target.__self__
        instances.append(self.instance)
        workers.append(self)
    def run(self):
        try:
            super().run()
        except BaseException as caught:
            run_errors.append(caught)
    def start(self):
        selected = stage == 'start' and self.position == position and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert native_releases[0][0].wait(3)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and self.position == position and not fired
        if selected and not after:
            assert entered.wait(5)
            fired.append(True)
            raise failure
        rescue.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
def thread_factory(*args, **kwargs):
    target = kwargs.get('target')
    if getattr(target, '__name__', '') == '_cleanup_owned_output' and isinstance(getattr(target, '__self__', None), host.SandboxHost):
        return Worker(*args, **kwargs)
    return threading.Thread(*args, **kwargs)
class BodyPatch(pytest.MonkeyPatch):
    def setattr(self, target, name, value, *args, **kwargs):
        if target is host and name == 'rmtree_hardened':
            assert value.__name__ == 'remove'
            values = inspect.getclosurevars(value).nonlocals
            native_releases.append((values['entered'], values['release'], values['calls']))
        return super().setattr(target, name, value, *args, **kwargs)
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = thread_factory
view = module_function_view(native, bindings={'threading': thread_view, 'rmtree_hardened': gated_remove})
assert view.test_concurrent_host_cleanup_removes_tree_once.__code__ is native.test_concurrent_host_cleanup_removes_tree_once.__code__
borrowed_remove, borrowed_threads = host.rmtree_hardened, native.threading
with BodyPatch.context() as patcher:
    try:
        try:
            view.test_concurrent_host_cleanup_removes_tree_once(scratch, patcher)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 2 and instances[0] is instances[1]
        instance = instances[0]
        assert not instance._thread.is_alive() and instance._thread.ident is not None
        assert instance._closed and instance._write_fd is None and instance._read_fd is None
        assert not any(worker.is_alive() for worker in workers)
    finally:
        for _, release, _ in native_releases:
            release.set()
        rescue.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=3)
                assert not worker.is_alive()
        assert not run_errors, run_errors
        lock_free = instances[0]._daemon_fds_lock.acquire(blocking=False)
        if lock_free:
            instances[0]._daemon_fds_lock.release()
        assert lock_free
        started = sum(worker.ident is not None for worker in workers)
        if started:
            assert remove_calls == [str(owned_path)] and native_releases[0][2] == [str(owned_path)]
            assert not owned_path.exists() and instances[0]._owned_output is None
        else:
            assert not remove_calls and not native_releases[0][2]
            assert owned_path.exists() and instances[0]._owned_output == str(owned_path)
            # The unstarted callers leave ownership with the real host fixture.
            instances[0]._cleanup_owned_output()
            assert not owned_path.exists() and instances[0]._owned_output is None
assert host.rmtree_hardened is borrowed_remove and native.threading is borrowed_threads
assert not denied_calls, denied_calls
print('SCRATCH_CLEANUP_WORKER_OK')
