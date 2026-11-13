import json
import builtins
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
from contextlib import contextmanager
from core.project.tests import test_project as native
import core.atomic_fs.fs_lock as fs_lock
from core.testing.module_views import module_function_view
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
if stage == 'unlocked':
    from core.testing.tests.test_thread_handshake_contracts import test_project_contention_probe_rejects_an_unlocked_rewrite
    with pytest.MonkeyPatch.context() as patch:
        test_project_contention_probe_rejects_an_unlocked_rewrite(scratch, patch)
    assert not denied_calls, denied_calls
    print('PROJECT_PIN_WORKER_OK')
    sys.exit(0)
failure = error('owned project pin lifecycle fault') if error else None
acquired, rescue = threading.Event(), threading.Event()
workers, holders, acquisitions, fired, closed, sentinels = [], [], [], [], [], []
real_try = fs_lock._try_flock_nb
main_ident = threading.get_ident()
def gate_acquisition(fd):
    result = real_try(fd)
    if result and holders and threading.get_ident() != main_ident:
        stamp = os.fstat(fd)
        if (stamp.st_dev, stamp.st_ino) == holders[0][2:]:
            acquisitions.append(fd)
            acquired.set()
            assert rescue.wait(10), 'owned marker acquisition was not released'
    return result
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def open_holder(path, flags, mode):
    fd = os.open(path, flags, mode)
    stamp = os.fstat(fd)
    holders.append((fd, Path(path), stamp.st_dev, stamp.st_ino))
    return fd
def close_holder(fd):
    assert len(holders) == 1 and fd == holders[0][0]
    assert not workers[0].is_alive()
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == holders[0][2:]
    closed.append(fd)
    assert len(closed) == 1
    os.close(fd)
    sentinel = os.open(scratch / 'caller-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
os_view.open, os_view.close = open_holder, close_holder
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        values = inspect.getclosurevars(kwargs['target']).nonlocals
        self.done, self.errors = values['done'], values['errors']
        self.blocked = inspect.getclosurevars(fs_lock._try_flock_nb).nonlocals['blocked']
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert self.blocked.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            assert acquired.wait(5)
            fired.append(True)
            raise failure
        rescue.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'threading' and level == 0:
        return thread_view
    return builtins.__import__(name, globals, locals, fromlist, level)
original = native.TestRenamePinRewriteLocked.test_rewrite_blocks_on_the_marker_lock
owner = module_function_view(native, bindings={'os': os_view, '_owned_case': original}, import_hook=owned_import)
assert owner._owned_case.__code__ is original.__code__
with contextmanager(native._user_state_in_tmp.__wrapped__)(scratch / 'state'):
    case = native.TestRenamePinRewriteLocked('test_rewrite_blocks_on_the_marker_lock')
    try:
        case.setUp()
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(fs_lock, '_try_flock_nb', gate_acquisition)
            try:
                try:
                    owner._owned_case(case)
                except BaseException as caught:
                    assert failure is not None and caught is failure
                else:
                    assert failure is None
                assert fired == ([True] if failure else [])
                assert len(workers) == len(holders) == 1 and not workers[0].is_alive()
                started = workers[0].ident is not None
                assert len(acquisitions) == int(started)
                assert workers[0].done.is_set() == started and not workers[0].errors
                marker = holders[0][1].with_name('.raptor-run.json')
                assert json.loads(marker.read_text())['project'] == ('new' if started else 'old')
                assert (case.mgr.load('new') is not None) == started
                stamp = os.fstat(holders[0][0])
                assert (stamp.st_dev, stamp.st_ino) == holders[0][2:]
            finally:
                rescue.set()
                for worker in workers:
                    if worker.ident is not None:
                        threading.Thread.join(worker, timeout=10)
                        assert not worker.is_alive()
    finally:
        assert case.doCleanups()
    try:
        assert len(closed) == 1
        for fd, dev, ino in sentinels:
            stamp = os.fstat(fd)
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
    finally:
        for fd, _, _ in sentinels:
            os.close(fd)
assert fs_lock._try_flock_nb is real_try
assert not denied_calls, denied_calls
print('PROJECT_PIN_WORKER_OK')
