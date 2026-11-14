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
import pytest
from core.testing.tests import test_spawn_pipe_binding_ownership as native
from core.testing import pipes as support
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
borrowed_native, borrowed_support = native.os, support.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    assert mode in {'argv', 'second-pipe', 'pool'}
    with pytest.MonkeyPatch.context() as patcher:
        native.test_allocation_scope_preserves_outer_consumer_tracker(mode, patcher, None)
    assert native.os is borrowed_native and support.os is borrowed_support
    assert not denied_calls
    print('SPAWN_OUTER_TRACKER_OK')
    raise SystemExit(0)
kind, position_text, phase = mode.rsplit('-', 2)
position = int(position_text)
assert kind in {'argv', 'second-pipe', 'pool'} and position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned outer spawn metadata fault')
opened, observed, closed, sentinels, triggered = [], [], [], [], []
def pipe():
    pair = real_pipe()
    opened.extend(pair)
    return pair

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    observed.append(fd)
    chosen = len(observed) == position
    if chosen and phase == 'before':
        triggered.append(failure)
        raise failure
    info = real_stat(fd)
    if chosen:
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
        patch_module_attribute(patcher, support, 'os', 'pipe', pipe)
        patch_module_attribute(patcher, native, 'os', 'fstat', stat)
        patch_module_attribute(patcher, native, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            native.test_allocation_scope_preserves_outer_consumer_tracker(kind, patcher, None)
        assert caught.value is failure
    assert len(opened) == 2 and triggered == [failure]
    if expectation == 'baseline':
        assert phase == 'before' and closed == opened[:position - 1]
        assert all(real_stat(fd) for fd in opened[position - 1:])
    else:
        assert expectation == 'candidate' and sorted(closed) == sorted(opened) and len(closed) == 2
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
assert native.os is borrowed_native and support.os is borrowed_support
assert not denied_calls
print('SPAWN_OUTER_TRACKER_OK')
