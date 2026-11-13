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
from core.inventory.tests import test_checklist_lock_bounded as native
import core.inventory as inventory
from core.testing.module_views import module_function_view
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned FIFO writer lifecycle fault') if error else None
entered = threading.Event()
workers, locks, opened, returned, peers, closed, sentinels, fired = [], [], [], [], [], [], [], []
blocking = stage == 'start' and after
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def blocking_open(path, flags, mode=0o777):
    assert Path(path) == scratch / 'checklist.lock'
    assert flags & os.O_NONBLOCK and flags & os.O_WRONLY
    opened.append(True)
    entered.set()
    fd = os.open(path, flags & ~os.O_NONBLOCK, mode)
    returned.append(fd)
    return fd
os_view.open = blocking_open
entry_view = module_function_view(inventory, bindings={'os': os_view, '_owned_enter': inventory._checklist_lock.__enter__})
assert entry_view._owned_enter.__code__ is inventory._checklist_lock.__enter__.__code__
class OwnedLock(inventory._checklist_lock):
    __enter__ = entry_view._owned_enter
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        locks.append(self)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        values = inspect.getclosurevars(kwargs['target']).nonlocals
        self.errors, self.done = values['errors'], values['done']
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
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
peer_view = ModuleType('os')
vars(peer_view).update(vars(os))
def open_peer(path, flags):
    assert Path(path) == scratch / 'checklist.lock'
    assert flags == os.O_RDONLY | os.O_NONBLOCK
    fd = os.open(path, flags)
    stamp = os.fstat(fd)
    peers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_peer(fd):
    assert len(peers) == 1 and fd == peers[0][0]
    assert workers[0].done.is_set() and not workers[0].is_alive()
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == peers[0][1:]
    closed.append(fd)
    assert len(closed) == 1
    os.close(fd)
    sentinel = os.open(scratch / 'caller-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
peer_view.open, peer_view.close = open_peer, close_peer
owner = module_function_view(native, bindings={'threading': thread_view, 'os': peer_view, '_checklist_lock': OwnedLock if blocking else inventory._checklist_lock})
try:
    try:
        owner.test_fifo_at_lock_path_fails_the_update_promptly(scratch)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == 1 and not workers[0].is_alive()
    started = workers[0].ident is not None
    assert workers[0].done.is_set() == started
    assert len(workers[0].errors) == int(started)
    if started:
        assert isinstance(workers[0].errors[0], OSError)
    if blocking:
        assert len(locks) == len(returned) == len(peers) == len(closed) == 1
        assert opened == [True] and locks[0]._lock_fd is None
    else:
        assert not opened and not returned and not peers and not closed
finally:
    # Independent rescue protects the proof if native retirement regresses.
    rescue = None
    if workers and workers[0].is_alive():
        rescue = os.open(scratch / 'checklist.lock', os.O_RDONLY | os.O_NONBLOCK)
    try:
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
    finally:
        if rescue is not None:
            os.close(rescue)
        for fd, dev, ino in sentinels:
            stamp = os.fstat(fd)
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
            os.close(fd)
assert not denied_calls, denied_calls
print('CHECKLIST_FIFO_WORKER_OK')
