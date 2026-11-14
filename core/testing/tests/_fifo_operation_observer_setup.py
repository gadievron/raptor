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
import errno
import linecache
import stat as stat_module
import pytest
from core.testing.tests import test_fifo_watchdog_fixture_ownership as canonical
from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
real_open, real_stat, real_close = os.open, os.fstat, os.close
borrowed_os, borrowed_threading = canonical.os, canonical.threading
if outcome == 'control':
    case, operation_text, after_text, error_name = mode.split(':')
    error = {'None': None, 'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}[error_name]
    if case == 'callee':
        canonical.test_watchdog_returns_original_callee_error(error)
    else:
        operation = None if operation_text == 'none' else operation_text
        canonical._exercise(scratch, case, operation, after_text == '1', error)
    assert canonical.os is borrowed_os and canonical.threading is borrowed_threading
    assert not denied_calls
    print('FIFO_OPERATION_OBSERVER_OK')
    raise SystemExit(0)
operation_mode, phase = mode.split(':')
assert operation_mode in {'reader-open', 'reader-eof', 'writer'} and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned FIFO operation metadata fault')
workers, boxes, targets = [], [], []
real_thread = threading.Thread
class TrackingThread(real_thread):
    def __init__(self, *args, **kwargs):
        target = kwargs['target']
        assert target.__name__ == '_run'
        cells = dict(zip(target.__code__.co_freevars, target.__closure__))
        assert 'box' in cells
        boxes.append(cells['box'].cell_contents)
        targets.append(target)
        super().__init__(*args, **kwargs)
        workers.append(self)
private_threads = ModuleType('threading')
vars(private_threads).update(vars(threading))
private_threads.Thread = TrackingThread
owner = module_function_view(canonical, bindings={'threading': private_threads})
assert owner._exercise.__code__ is canonical._exercise.__code__
borrowed_owner = owner.os
opened, closed, sentinels, observed = [], [], [], []
def opening(path, flags, *args, **kwargs):
    assert Path(path) == scratch / 'owned.fifo'
    assert flags == (os.O_WRONLY if operation_mode == 'writer' else os.O_RDONLY)
    assert threading.current_thread() in workers
    value = real_open(path, flags, *args, **kwargs)
    opened.append(value)
    return value

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    assert threading.current_thread() in workers
    observed.append(fd)
    if phase == 'after':
        assert stat_module.S_ISFIFO(real_stat(fd).st_mode)
    raise failure

def close(fd):
    if fd not in opened:
        return real_close(fd)
    assert threading.current_thread() in workers and fd not in closed
    real_close(fd)
    closed.append(fd)
    value = real_open(scratch / 'new-owner', os.O_CREAT | os.O_RDWR, 0o600)
    assert value == fd
    info = real_stat(value)
    sentinels.append((value, info.st_dev, info.st_ino))
try:
    with pytest.MonkeyPatch.context() as patcher:
        patch_module_attribute(patcher, owner, 'os', 'open', opening)
        patch_module_attribute(patcher, owner, 'os', 'fstat', stat)
        patch_module_attribute(patcher, owner, 'os', 'close', close)
        with pytest.raises(AssertionError) as caught:
            owner._exercise(scratch, operation_mode, 'start', True, RuntimeError)
        tail = caught.value.__traceback__
        while tail.tb_next:
            tail = tail.tb_next
        assert Path(tail.tb_frame.f_code.co_filename) == Path(canonical.__file__)
        assert linecache.getline(tail.tb_frame.f_code.co_filename, tail.tb_lineno).strip() == 'assert len(acquired) == 1'
    assert len(workers) == len(targets) == len(boxes) == 1
    assert workers[0].ident is not None and not workers[0].is_alive()
    assert boxes[0] == [('raised', failure)]
    assert len(opened) == 1 and observed == opened
    if expectation == 'baseline':
        assert not closed and stat_module.S_ISFIFO(real_stat(opened[0]).st_mode)
    else:
        assert expectation == 'candidate' and closed == opened and len(sentinels) == 1
        for fd, dev, ino in sentinels:
            info = real_stat(fd)
            assert (info.st_dev, info.st_ino) == (dev, ino)
            os.write(fd, b'caller-owned')
finally:
    assert all(worker.ident is not None and not worker.is_alive() for worker in workers)
    if sentinels:
        for fd, _, _ in sentinels:
            real_close(fd)
    else:
        for fd in opened:
            try:
                real_stat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                real_close(fd)
assert canonical.os is borrowed_os and canonical.threading is borrowed_threading and owner.os is borrowed_owner
assert not denied_calls
print('FIFO_OPERATION_OBSERVER_OK')
