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
from contextlib import contextmanager
import pytest
from core.testing.tests import test_fd_restore_cleanup as native
from core.sandbox.tests import test_fork_safe_warn as module
from core.testing import fds as support
from core.testing.module_bindings import patch_module_attribute
os.dup2 = denied  # The selected native fault helper provides an inert local redirect.
mode, outcome, expectation = sys.argv[3:6]
MODES = {'pipe-first-before', 'pipe-first-after', 'pipe-second-before', 'pipe-second-after', 'dup-before', 'dup-after'}
assert (mode in MODES and outcome in {'error', 'interrupt'}) or (mode.startswith('native-') and outcome == 'control') and expectation in {'baseline', 'candidate'}
if outcome == 'control':
    with pytest.MonkeyPatch.context() as control_patcher:
        if mode == 'native-handoff':
            with native._intercept_descriptors(module, control_patcher, OSError, 'none') as state:
                pair = module.os.pipe()
                duplicate = support.os.dup(pair[0])
                assert state.duplicates == [duplicate] and state.redirects == []
                for fd in (*pair, duplicate):
                    os.fstat(fd)
                    os.close(fd)
        else:
            _, index, fault, error_name = mode.split('-')
            error = {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt}[error_name]
            native.test_warning_capture_failure_closes_descriptors(native._WARNS[int(index)], fault, error, control_patcher)
    assert not denied_calls
    print('FD_RESTORE_OBSERVER_OK')
    raise SystemExit(0)
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned snapshot observer metadata fault')
opened, observed, closed, sentinels, states = [], [], [], [], []
borrowed_native, borrowed_module, borrowed_support = native.os, module.os, support.os
real_pipe, real_dup, real_stat, real_close = os.pipe, os.dup, os.fstat, os.close
original_intercept = native._intercept_descriptors
stdio = {fd: (real_stat(fd).st_dev, real_stat(fd).st_ino) for fd in (1, 2)}
with pytest.MonkeyPatch.context() as patcher:
    @contextmanager
    def tracking(*args, **kwargs):
        with original_intercept(*args, **kwargs) as state:
            states.append(state)
            yield state
    patcher.setattr(native, '_intercept_descriptors', tracking)
    def pipe():
        pair = real_pipe()
        opened.extend(pair)
        return pair
    def dup(fd):
        value = real_dup(fd)
        opened.append(value)
        return value
    def stat(fd):
        if fd not in opened:
            return real_stat(fd)
        observed.append(fd)
        position = 2 if mode.startswith('pipe-second-') else 1
        if len(observed) == position and mode.endswith('-before'):
            raise failure
        info = real_stat(fd)
        if len(observed) == position:
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
    if mode.startswith('pipe-'):
        patch_module_attribute(patcher, native, 'os', 'pipe', pipe)
    else:
        patch_module_attribute(patcher, native, 'os', 'dup', dup)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            native.test_warning_capture_failure_closes_descriptors(native._WARNS[0], 'body', OSError, patcher)
        assert caught.value is failure and len(states) == 1 and states[0].redirects == []
        expected = 2 if mode.startswith('pipe-') else 1
        assert len(opened) == expected
        if expectation == 'baseline':
            assert mode in {'pipe-first-before', 'dup-before'} and not closed
            assert all(real_stat(fd) for fd in opened)
        else:
            assert sorted(closed) == sorted(opened) and len(closed) == expected
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
assert native.os is borrowed_native and module.os is borrowed_module and support.os is borrowed_support
assert native._intercept_descriptors is original_intercept
assert all((real_stat(fd).st_dev, real_stat(fd).st_ino) == stamp for fd, stamp in stdio.items())
assert not denied_calls
print('FD_RESTORE_OBSERVER_OK')
