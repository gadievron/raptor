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
import stat
import pytest
from core.sandbox.tests import test_summary as native
from core.sandbox import summary
from core.testing.sandbox_state_scope import isolated_summary_state
from core.testing.state_isolation import pin_user_state_dirs
from core.testing.module_views import module_function_view
mode = sys.argv[3]
fault = mode.startswith(('start-', 'join-'))
failure = None
if fault:
    stage, timing, error_name = mode.split('-')
    failure = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt}[error_name]('owned summary FIFO caller fault')
fired = []
workers, readers, closed, sentinels, peer_fds, peer_closed, violations = [], [], [], [], [], [], []
entered = threading.Event()
renamed = []
original_summary = summary.summarize_and_write
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def open_reader(path, flags, *args, **kwargs):
    selected = Path(path).name.startswith(summary.DENIALS_FILE + '.summarising.')
    if selected:
        assert stat.S_ISFIFO(Path(path).lstat().st_mode)
        assert flags & os.O_NONBLOCK and flags & os.O_ACCMODE == os.O_RDONLY
        renamed.append(Path(path))
        entered.set()
        if mode != 'normal':
            flags &= ~os.O_NONBLOCK
    fd = os.open(path, flags, *args, **kwargs)
    if selected:
        stamp = os.fstat(fd)
        readers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def close_reader(fd):
    if readers and fd == readers[0][0]:
        if closed:
            violations.append('stale summary FIFO reader close')
            raise AssertionError(violations[-1])
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == readers[0][1:]
        os.close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / 'reader-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(sentinel)
        sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
    else:
        os.close(fd)
os_view.open, os_view.close = open_reader, close_reader
native_os = ModuleType('os')
vars(native_os).update(vars(os))
def open_peer(path, flags):
    assert flags == os.O_WRONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0)
    assert Path(path) in renamed or Path(path) == scratch / summary.DENIALS_FILE
    fd = os.open(path, flags)
    peer_fds.append(fd)
    return fd
def close_peer(fd):
    assert fd in peer_fds and fd not in peer_closed
    assert not workers[0].is_alive()
    os.close(fd)
    peer_closed.append(fd)
native_os.open, native_os.close = open_peer, close_peer
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.done = inspect.getclosurevars(kwargs['target']).nonlocals['done']
        workers.append(self)
    def start(self):
        if fault and stage == 'start' and timing == 'before':
            fired.append(True)
            raise failure
        super().start()
        if fault and stage == 'start':
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = fault and stage == 'join' and not fired
        if selected and timing == 'before':
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
rescue_peer = None
with pytest.MonkeyPatch.context() as state_patch:
    pin_user_state_dirs(state_patch, scratch)
    with isolated_summary_state():
        if mode == 'regular':
            native.TestSummarizeAndWrite().test_aggregates_jsonl_into_summary(scratch)
        else:
            production = module_function_view(summary, bindings={'os': os_view})
            assert production.summarize_and_write.__code__ is original_summary.__code__
            owner = module_function_view(native, bindings={'threading': thread_view, 'summary_mod': production, 'os': native_os, '_owned_native': native.TestSummarizeAndWrite.test_planted_fifo_does_not_hang_and_flags_summary})
            try:
                try:
                    owner._owned_native(native.TestSummarizeAndWrite(), scratch)
                except BaseException as caught:
                    if fault:
                        assert caught is failure
                    else:
                        assert mode == 'regression'
                        assert 'summarize_and_write hung on a planted FIFO' in str(caught)
                else:
                    assert mode == 'normal'
                assert len(workers) == 1
                assert fired == ([True] if fault else [])
                assert entered.is_set() == (workers[0].ident is not None)
                assert not workers[0].is_alive()
                assert peer_closed == peer_fds
                if mode == 'regression':
                    assert len(peer_fds) == 1
            finally:
                if workers and workers[0].is_alive():
                    rescue_peer = os.open(renamed[0], os.O_WRONLY | os.O_NONBLOCK)
                try:
                    for worker in workers:
                        if worker.ident is not None:
                            threading.Thread.join(worker, timeout=10)
                            assert not worker.is_alive()
                    started = workers[0].ident is not None
                    assert len(readers) == len(closed) == int(started) and not violations
                    if started:
                        assert len(workers[0].done) == 1
                        result = workers[0].done[0]
                        assert result is not None and 'non-regular' in result['planted_object'] and result['total_denials'] == 0
                        assert not (scratch / summary.DENIALS_FILE).exists()
                        assert all(not path.exists() for path in renamed)
                    else:
                        assert not workers[0].done and not renamed and not peer_fds
                    for fd, dev, ino in sentinels:
                        stamp = os.fstat(fd)
                        assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
                finally:
                    if rescue_peer is not None:
                        os.close(rescue_peer)
                    for fd, _, _ in sentinels:
                        os.close(fd)
assert summary.summarize_and_write is original_summary
assert not denied_calls, denied_calls
print('SUMMARY_FIFO_WORKER_OK')
