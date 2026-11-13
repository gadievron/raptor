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
from core.inventory.tests import test_perlasm as native
import core.inventory.perlasm as perlasm
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs
import pytest
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned perlasm FIFO lifecycle fault') if error else None
blocking = stage == 'start' and after
entered = threading.Event()
workers, fifo_paths, reader_fds, reader_closed, peers, peer_closed, sentinels, fired = [], [], [], [], [], [], [], []
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def open_output(path, flags, *args, **kwargs):
    if Path(path).name == 'out.S':
        assert flags & os.O_NONBLOCK and flags & os.O_NOFOLLOW
        fifo_paths.append(Path(path))
        entered.set()
        fd = os.open(path, flags & ~os.O_NONBLOCK if blocking else flags, *args, **kwargs)
        stamp = os.fstat(fd)
        reader_fds.append((fd, stamp.st_dev, stamp.st_ino))
        return fd
    return os.open(path, flags, *args, **kwargs)
def close_output(fd):
    assert len(reader_fds) == 1 and fd == reader_fds[0][0]
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == reader_fds[0][1:]
    reader_closed.append(fd)
    assert len(reader_closed) == 1
    os.close(fd)
os_view.open, os_view.close = open_output, close_output
production = module_function_view(perlasm, bindings={'os': os_view})
assert production.generate_asm.__code__ is perlasm.generate_asm.__code__
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import inspect
        self.result = inspect.getclosurevars(kwargs['target']).nonlocals['result']
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
    assert Path(path) == fifo_paths[0] and flags == os.O_WRONLY | os.O_NONBLOCK
    fd = os.open(path, flags)
    stamp = os.fstat(fd)
    peers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_peer(fd):
    assert len(peers) == 1 and fd == peers[0][0]
    assert not workers[0].is_alive() and len(reader_closed) == 1
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == peers[0][1:]
    peer_closed.append(fd)
    assert len(peer_closed) == 1
    os.close(fd)
    sentinel = os.open(scratch / 'caller-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
peer_view.open, peer_view.close = open_peer, close_peer
imports = dict(vars(builtins))
def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name in ('threading', 'os'):
        return thread_view if name == 'threading' else peer_view
    return builtins.__import__(name, globals, locals, fromlist, level)
imports['__import__'] = owned_import
original = native.TestGenerationAndCache.test_fifo_output_is_refused_without_blocking
owner = module_function_view(native, bindings={'generate_asm': production.generate_asm, '_owned_case': original, '__builtins__': imports})
assert owner._owned_case.__code__ is original.__code__
with pytest.MonkeyPatch.context() as patch:
    pin_user_state_dirs(patch, scratch / 'state')
    target = native.target.__wrapped__(scratch)
    try:
        try:
            owner._owned_case(native.TestGenerationAndCache(), target, scratch, patch)
        except BaseException as caught:
            assert failure is not None and caught is failure
        else:
            assert failure is None
        assert fired == ([True] if failure else [])
        assert len(workers) == 1 and not workers[0].is_alive()
        started = workers[0].ident is not None
        assert len(fifo_paths) == len(reader_fds) == len(reader_closed) == int(started)
        if started:
            assert not fifo_paths[0].exists()
            assert len(workers[0].result) == 1
            cached, gap = workers[0].result[0]
            assert cached is None and gap is not None and 'regular file' in gap
        assert len(peers) == len(peer_closed)
        assert len(peers) == 1 if blocking else len(peers) <= 1
        assert not list((scratch / 'cache').glob('*.S'))
    finally:
        rescue = None
        if workers and workers[0].is_alive() and fifo_paths:
            rescue = os.open(fifo_paths[0], os.O_WRONLY | os.O_NONBLOCK)
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
print('PERLASM_FIFO_WORKER_OK')
