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
import stat
import pytest
from core.sandbox.tests import test_mount_ns_etc_copy as native
from core.sandbox import mount_ns
from core.testing.module_views import module_function_view
error_name, stage, after_text = sys.argv[3:6]
after = after_text == 'True'
error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'none': None}[error_name]
failure = error('owned etc copy caller fault') if error else None
workers, fired, run_errors, readers, closed, sentinels, violations = [], [], [], [], [], [], []
entered, release = threading.Event(), threading.Event()
source = scratch / 'src'
selected_path = source / 'restricted.conf'
os_view = ModuleType('os')
vars(os_view).update(vars(os))
def owned_open(path, flags, *args, **kwargs):
    assert Path(path).is_relative_to(source)
    fd = os.open(path, flags, *args, **kwargs)
    if Path(path) == selected_path:
        stamp = os.fstat(fd)
        readers.append((fd, stamp.st_dev, stamp.st_ino))
    return fd
def owned_read(fd, count):
    if readers and fd == readers[0][0]:
        stamp = os.fstat(fd)
        assert (stamp.st_dev, stamp.st_ino) == readers[0][1:]
        assert stat.S_ISREG(stamp.st_mode)
        entered.set()
        if stage == 'start' and after:
            assert release.wait(10), 'owned copy read was not released'
    return os.read(fd, count)
def owned_close(fd):
    if readers and fd == readers[0][0]:
        if closed:
            violations.append('stale etc copy reader close')
            raise AssertionError(violations[-1])
        os.close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / 'reader-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(sentinel)
        sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
    else:
        os.close(fd)
os_view.open, os_view.read, os_view.close = owned_open, owned_read, owned_close
borrowed_os = mount_ns.os
production = module_function_view(mount_ns, bindings={'os': os_view})
assert production._copy_etc_tree.__code__ is mount_ns._copy_etc_tree.__code__
class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)
    def run(self):
        try:
            super().run()
        except BaseException as caught:
            run_errors.append(caught)
    def start(self):
        selected = stage == 'start' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        super().start()
        if selected:
            assert entered.wait(5)
            fired.append(True)
            raise failure
    def join(self, timeout=None):
        selected = stage == 'join' and not fired
        if selected and not after:
            fired.append(True)
            raise failure
        release.set()
        result = super().join(timeout=timeout)
        if selected:
            fired.append(True)
            raise failure
        return result
thread_view = ModuleType('threading')
vars(thread_view).update(vars(threading))
thread_view.Thread = Worker
inherited_import = __import__
def import_local(name, globals=None, locals=None, fromlist=(), level=0):
    if not level and name == 'threading':
        return thread_view
    return inherited_import(name, globals, locals, fromlist, level)
owner = module_function_view(native, bindings={'_copy_etc_tree': production._copy_etc_tree, '_os_fault_consumer': production}, import_hook=import_local)
assert owner.test_fifo_never_wedges_the_copy.__code__ is native.test_fifo_never_wedges_the_copy.__code__
umask_fixture = native.hostile_umask.__wrapped__()
next(umask_fixture)
try:
    source = native.src_tree.__wrapped__(scratch)
    with pytest.MonkeyPatch.context() as patcher:
        try:
            if stage.startswith('control-'):
                owner.test_mode_bits_preserved(scratch, patcher, source, stage == 'control-copy')
            else:
                try:
                    owner.test_fifo_never_wedges_the_copy(scratch, patcher, source)
                except BaseException as caught:
                    assert failure is not None and caught is failure
                else:
                    assert failure is None
                assert fired == ([True] if failure else [])
                assert len(workers) == 1
                assert not workers[0].is_alive()
        finally:
            release.set()
            for worker in workers:
                if worker.ident is not None:
                    threading.Thread.join(worker, timeout=10)
                    assert not worker.is_alive()
            assert not run_errors, run_errors
            if workers and workers[0].ident is not None:
                fifo = scratch / 'dst/wedge.fifo'
                assert stat.S_ISFIFO(fifo.lstat().st_mode) and stat.S_IMODE(fifo.lstat().st_mode) == 0o620
                assert (scratch / 'dst/restricted.conf').read_text() == 'secret=1\n'
            assert len(readers) == len(closed) and len(readers) <= 1 and not violations
            for fd, dev, ino in sentinels:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
                os.close(fd)
finally:
    umask_fixture.close()
assert mount_ns.os is borrowed_os
assert native._copy_etc_tree is mount_ns._copy_etc_tree
assert not denied_calls, denied_calls
print('ETC_COPY_WORKER_OK')
