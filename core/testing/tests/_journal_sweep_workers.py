import json
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
from core.coverage.tests import test_journal_sweep_oplock as native
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned sweep worker lifecycle fault') if error else None
fired = []
entered, release = threading.Event(), threading.Event()
workers, holders, closed, sentinels, executed = [], [], [], [], []
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def start(self):
        if stage == 'start' and not after:
            fired.append(True)
            raise failure
        super().start()
        if stage == 'start':
            assert entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        release.set()
        value = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return value
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
with pytest.MonkeyPatch.context() as patch:
    pin_user_state_dirs(patch, scratch / 'state')
    project = native.project_env.__wrapped__(scratch, patch)
    os_view = ModuleType('os')
    vars(os_view).update(vars(os))
    def opened(path, flags, mode=0o777):
        assert path == str(project.dir / native.OP_LOCK_NAME)
        fd = os.open(path, flags, mode)
        stamp = os.fstat(fd)
        holders.append((fd, stamp.st_dev, stamp.st_ino))
        return fd
    def close(fd):
        assert len(holders) == 1 and fd == holders[0][0]
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == holders[0][1:]
        closed.append(fd)
        assert len(closed) == 1
        os.close(fd)
        peer = os.open(scratch / 'caller-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(peer)
        sentinels.append((peer, stamp.st_dev, stamp.st_ino))
    os_view.open, os_view.close = opened, close
    def sweep(name):
        entered.set()
        if stage != 'normal':
            assert release.wait(10)
        from core.coverage.journal_sweep import SweepRefused
        try:
            result = native._sweep(name)
        except SweepRefused:
            executed.append('refused')
            raise
        executed.append('returned')
        return result
    original = native.TestSweepHoldsOpLock.test_sweep_refuses_while_the_lock_is_held
    owner = module_function_view(native, bindings={'os': os_view, 'threading': thread_view, '_sweep': sweep, '_owned_case': original})
    assert owner._owned_case.__code__ is original.__code__
    try:
        try:
            owner._owned_case(native.TestSweepHoldsOpLock(), project, patch)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == len(holders) == len(closed) == 1
        assert not workers[0].is_alive()
        started = workers[0].ident is not None
        expected = ('refused' if stage == 'normal' or (stage == 'join' and after) else 'returned')
        assert executed == ([expected] if started else [])
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
        try:
            operation = json.loads((project.dir / native.OP_LOCK_NAME).read_text())['operation']
            assert operation == ('journal-reindex-sweep' if executed == ['returned'] else 'run-start:scan')
        finally:
            for fd, dev, ino in sentinels:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
                os.close(fd)
assert not denied_calls, denied_calls
print('JOURNAL_SWEEP_WORKER_OK')
