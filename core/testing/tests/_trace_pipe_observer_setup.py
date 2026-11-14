from pathlib import Path
import os
import socket
import subprocess
import sys

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
import ctypes
import resource
import errno
import pytest
from unittest.mock import Mock
from core.testing.tests import test_expected_crash_cleanup as native
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
assert expectation in {'baseline', 'candidate'}
# Bootstrap above is complete. Never enter a real tracer or child branch.
ctypes.CDLL = denied
resource.setrlimit = denied
os.kill = denied
os.waitpid = denied
borrowed_native, borrowed_module, borrowed_ctypes = native.os, native.module.os, native.module.ctypes
original_trace = native.module._trace
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
calls = []
def trace(*args, **kwargs):
    assert isinstance(native.module.ctypes.CDLL, Mock)
    assert native.module.os.fork is not os.fork
    assert native.module.os.waitpid is not os.waitpid
    assert native.module.os.execvpe is denied
    calls.append(True)
    return original_trace(*args, **kwargs)
if outcome == 'control':
    stage, error_name = mode.split('-')
    error = {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt, 'None': None}[error_name]
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(native.module, '_trace', trace)
        native.test_trace_setup_pipe_closes_after_fork_or_read_failure(stage, error, patcher)
    assert calls == [True] and not denied_calls
    assert native.module._trace is original_trace and native.os is borrowed_native
    assert native.module.os is borrowed_module and native.module.ctypes is borrowed_ctypes
    print('TRACE_PIPE_OBSERVER_OK')
    raise SystemExit(0)
position_text, phase = mode.split('-')
position = int(position_text)
assert position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned trace pipe metadata failure')
opened, observed, closed, sentinels, triggered = [], [], [], [], []
def pipe():
    pair = real_pipe()
    opened.extend(pair)
    return pair

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    observed.append(fd)
    selected = len(observed) == position
    if selected and phase == 'before':
        triggered.append(failure)
        raise failure
    info = real_stat(fd)
    if selected:
        triggered.append(failure)
        raise failure
    return info

def close(fd):
    if fd not in opened:
        return real_close(fd)
    assert fd not in closed
    real_close(fd)
    closed.append(fd)
    value = os.open(scratch / ('sentinel-' + str(fd)), os.O_CREAT | os.O_RDWR, 0o600)
    assert value == fd
    info = real_stat(value)
    sentinels.append((value, info.st_dev, info.st_ino))
try:
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(native.module, '_trace', trace)
        patch_module_attribute(patcher, native, 'os', 'pipe', pipe)
        patch_module_attribute(patcher, native, 'os', 'fstat', stat)
        patch_module_attribute(patcher, native, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            native.test_trace_setup_pipe_closes_after_fork_or_read_failure('fork', OSError, patcher)
        assert caught.value is failure
    assert calls == [True] and triggered == [failure] and len(opened) == 2
    if expectation == 'baseline':
        assert phase == 'before'
        assert closed == opened[:position - 1]
        assert all(real_stat(fd) for fd in opened[position - 1:])
    else:
        assert sorted(closed) == sorted(opened) and len(closed) == 2
    for fd, dev, ino in sentinels:
        info = real_stat(fd)
        assert (info.st_dev, info.st_ino) == (dev, ino)
        os.write(fd, b'caller-owned')
finally:
    sentinel_fds = {x[0] for x in sentinels}
    for fd in opened:
        if fd in sentinel_fds:
            continue
        try:
            real_stat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            real_close(fd)
    for fd, _, _ in sentinels:
        real_close(fd)
assert native.module._trace is original_trace and native.os is borrowed_native
assert native.module.os is borrowed_module and native.module.ctypes is borrowed_ctypes
assert not denied_calls
print('TRACE_PIPE_OBSERVER_OK')
