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
from core.build.tests import test_macro_config as native
from core.build import macro_config
from core.security import capped_read
from core.testing.module_views import module_function_view
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[sys.argv[3]]
stage, after = sys.argv[4], sys.argv[5] == 'True'
failure = error('owned macro FIFO lifecycle fault') if error else None
blocking = stage == 'start' and after
fired, peers, peer_closed, sentinels = [], [], [], []
entered = threading.Event()
workers, reader_fds, closed = [], [], []
fifo = scratch / 'compile_commands.json'
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def blocking_open(path, flags, **kwargs):
    assert Path(path) == fifo and flags & os.O_NONBLOCK
    entered.set()
    fd = os.open(path, flags & ~os.O_NONBLOCK if blocking else flags, **kwargs)
    stamp = os.fstat(fd)
    reader_fds.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_reader(fd):
    assert len(reader_fds) == 1 and fd == reader_fds[0][0]
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == reader_fds[0][1:]
    closed.append(fd)
    assert len(closed) == 1
    os.close(fd)
os_view.open, os_view.close = blocking_open, close_reader
reader = module_function_view(capped_read, bindings={'os': os_view})
production = module_function_view(macro_config, bindings={'read_capped_text': reader.read_capped_text})
assert production._read_bounded.__code__ is macro_config._read_bounded.__code__
assert reader._read_capped_or_raise.__code__ is capped_read._read_capped_or_raise.__code__
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcome = inspect.getclosurevars(kwargs['target']).nonlocals['outcome']
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
    assert Path(path) == fifo and flags == os.O_WRONLY | os.O_NONBLOCK
    fd = os.open(path, flags)
    stamp = os.fstat(fd)
    peers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_peer(fd):
    assert len(peers) == 1 and fd == peers[0][0]
    assert not workers[0].is_alive() and len(closed) == 1
    stamp = os.fstat(fd)
    assert (stamp.st_dev, stamp.st_ino) == peers[0][1:]
    peer_closed.append(fd)
    assert len(peer_closed) == 1
    os.close(fd)
    sentinel = os.open(scratch / 'caller-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
    stamp = os.fstat(sentinel)
    sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
peer_view.open, peer_view.close = open_peer, close_peer
def owned_import(name, globals=None, locals=None, fromlist=(), level=0):
    if level == 0 and name in ('threading', 'os'):
        return thread_view if name == 'threading' else peer_view
    if level == 0 and name == 'core.build.macro_config' and tuple(fromlist) == ('_read_bounded',):
        return production
    return builtins.__import__(name, globals, locals, fromlist, level)
owner = module_function_view(native, import_hook=owned_import)
assert owner.test_read_bounded_fifo_refused_without_blocking.__code__ is native.test_read_bounded_fifo_refused_without_blocking.__code__
try:
    try:
        owner.test_read_bounded_fifo_refused_without_blocking(scratch)
    except BaseException as caught:
        assert failure is not None and caught is failure
    else:
        assert failure is None
    assert fired == ([True] if failure else [])
    assert len(workers) == 1 and not workers[0].is_alive()
    started = workers[0].ident is not None
    assert len(reader_fds) == len(closed) == int(started)
    assert workers[0].outcome == (['refused'] if started else [])
    assert len(peers) == len(peer_closed)
    assert len(peers) == 1 if blocking else len(peers) <= 1
    if stage == 'normal':
        regular = scratch / 'regular.json'
        regular.write_text('{"defines":1}')
        assert macro_config._read_bounded(regular, 1024) == '{"defines":1}'
finally:
    rescue = None
    if workers and workers[0].is_alive():
        rescue = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
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
print('MACRO_FIFO_WORKER_OK')
