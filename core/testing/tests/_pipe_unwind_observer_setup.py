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
import errno
import linecache
import pytest
from core.testing.tests import test_helper_unwind_cleanup as native
from core.testing import pipes
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
assert expectation in {'baseline', 'candidate'}
assert outcome in {'error', 'interrupt', 'control'}
borrowed_native, borrowed_support = native.os, pipes.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    with pytest.MonkeyPatch.context() as patcher:
        if mode.startswith('transfer-'):
            native.test_pipe_success_transfers_open_descriptors(mode == 'transfer-fork', patcher)
        else:
            _, stage, position, error_name = mode.split('-')
            native.test_pipe_unwind_attempts_every_descriptor(stage, int(position), {'OSError': OSError, 'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt}[error_name], patcher)
    assert native.os is borrowed_native and pipes.os is borrowed_support
    assert not denied_calls
    print('PIPE_UNWIND_OBSERVER_OK')
    raise SystemExit(0)
position_text, phase = mode.split('-')
position = int(position_text)
assert position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned pipe metadata observation failure')
opened, observed, closed, sentinels = [], [], [], []
triggered = []
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
        patch_module_attribute(patcher, native, 'os', 'pipe', pipe)
        patch_module_attribute(patcher, native, 'os', 'fstat', stat)
        patch_module_attribute(patcher, native, 'os', 'close', close)
        # The original test catches the injected BaseException, then its
        # unchanged two-pair cardinality oracle rejects interrupted setup.
        with pytest.raises(AssertionError) as caught:
            native.test_pipe_unwind_attempts_every_descriptor('allocation', 0, OSError, patcher)
        tail = caught.value.__traceback__
        while tail.tb_next:
            tail = tail.tb_next
        assert linecache.getline(tail.tb_frame.f_code.co_filename, tail.tb_lineno).strip() == 'assert len(pairs) == 2'
    assert triggered == [failure] and len(opened) == 2
    if expectation == 'baseline':
        assert position == 1 and not closed
        assert all(real_stat(fd) for fd in opened)
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
assert native.os is borrowed_native and pipes.os is borrowed_support
assert not denied_calls
print('PIPE_UNWIND_OBSERVER_OK')
