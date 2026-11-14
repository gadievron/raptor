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
from core.annotations.tests import test_locking_bounded as native
from core.annotations import storage
from core.testing.module_views import module_function_view
mode = sys.argv[3]
assert mode in {'regression', 'normal', 'cross-uid'}
if mode == 'cross-uid':
    import pytest
    with pytest.MonkeyPatch.context() as patcher:
        native.test_cross_uid_lock_file_is_still_adopted(scratch, patcher)
    assert not denied_calls
    print('ANNOTATION_FIFO_RELEASE_OK')
    raise SystemExit(0)
assert storage._HAS_FCNTL
fifo = scratch / 'notes.md.lock'
workers, reader_fds, closed, sentinels, violations = [], [], [], [], []
entered = threading.Event()
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def blocking_open(path, flags, mode=0o777):
    assert Path(path) == fifo and flags & os.O_NONBLOCK
    assert flags & os.O_ACCMODE == os.O_RDONLY
    entered.set()
    fd = os.open(path, flags & ~os.O_NONBLOCK if sys.argv[3] == 'regression' else flags, mode)
    stamp = os.fstat(fd)
    reader_fds.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_reader(fd):
    if closed:
        violations.append('stale annotation reader close')
        raise AssertionError(violations[-1])
    assert len(reader_fds) == 1 and fd == reader_fds[0][0]
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == reader_fds[0][1:]
    os.close(fd)
    closed.append(fd)
    sentinel = os.open(scratch / 'reader-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
os_view.open, os_view.close = blocking_open, close_reader
production = module_function_view(storage, bindings={'os': os_view, '_owned_lock_generator': storage._file_lock.__wrapped__})
assert production._owned_lock_generator.__code__ is storage._file_lock.__wrapped__.__code__
owned_lock = contextmanager(production._owned_lock_generator)
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        values = inspect.getclosurevars(kwargs['target']).nonlocals
        self.errors, self.done = values['errors'], values['done']
        self.join_timeouts = []
        workers.append(self)
    def join(self, timeout=None):
        self.join_timeouts.append(timeout)
        return super().join(timeout=timeout)
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
peer_records, peer_closed = [], []
owner_os = ModuleType('os')
vars(owner_os).update(vars(os))
def open_peer(path, flags):
    assert Path(path) == fifo and flags == os.O_WRONLY | os.O_NONBLOCK
    fd = os.open(path, flags)
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == (fifo.stat().st_dev, fifo.stat().st_ino)
    peer_records.append(fd)
    return fd
def close_peer(fd):
    assert fd in peer_records and fd not in peer_closed
    assert not workers[0].is_alive()
    os.close(fd)
    peer_closed.append(fd)
owner_os.open, owner_os.close = open_peer, close_peer
owner = module_function_view(native, bindings={'threading': thread_view, '_file_lock': owned_lock, 'os': owner_os})
peer = None
try:
    try:
        owner.test_fifo_at_lock_path_is_refused_loudly(scratch)
    except AssertionError as caught:
        assert mode == 'regression'
        assert 'writer wedged opening the planted FIFO lock path' in str(caught)
    else:
        assert mode == 'normal', 'blocking FIFO regression was not detected'
    assert entered.is_set() and len(workers) == 1 and not workers[0].is_alive()
    assert workers[0].join_timeouts == [10, 10]
    assert workers[0].done.is_set() and len(reader_fds) == 1
    assert peer_closed == peer_records
    if mode == 'regression':
        assert len(peer_records) == 1
finally:
    if workers and workers[0].is_alive():
        peer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    try:
        for worker in workers:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=10)
                assert not worker.is_alive()
        assert len(reader_fds) == len(closed) == 1 and not violations
        assert workers[0].done.is_set() and len(workers[0].errors) == 1
        assert isinstance(workers[0].errors[0], storage.AnnotationFileError)
        assert 'not a regular file' in str(workers[0].errors[0])
        assert (scratch / 'notes.md').read_text() == 'x'
        for fd, dev, ino in sentinels:
            stamp = os.fstat(fd)
            assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
    finally:
        if peer is not None:
            os.close(peer)
        for fd, _, _ in sentinels:
            os.close(fd)
assert not denied_calls, denied_calls
print('ANNOTATION_FIFO_RELEASE_OK')
