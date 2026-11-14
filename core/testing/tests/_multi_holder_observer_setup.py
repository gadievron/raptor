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
from core.testing.tests import test_lock_fixture_setup_ownership as native
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
borrowed_native = native.os
borrowed_modules = [(module, module.os) for module, name in native.CASES]
real_open, real_stat, real_close = os.open, os.fstat, os.close
if outcome == 'control':
    index_text, phase, after_text, error_name = mode.split(':')
    module, name = native.CASES[int(index_text)]
    error = {'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}[error_name]
    with pytest.MonkeyPatch.context() as patcher:
        native.test_actual_lock_fixture_construction_failure_retires_holder(scratch, patcher, None, module, name, phase, error, after_text == '1')
    assert native.os is borrowed_native and all(module.os is prior for module, prior in borrowed_modules)
    assert not denied_calls
    print('MULTI_HOLDER_OBSERVER_OK')
    raise SystemExit(0)
index_text, phase = mode.split(':')
module, name = native.CASES[int(index_text)]
assert phase in {'before', 'after'} and outcome in {'error', 'interrupt'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned multi holder metadata fault')
opened, closed, sentinels, observed = [], [], [], []
def opening(path, *args, **kwargs):
    assert Path(path).is_relative_to(scratch)
    value = real_open(path, *args, **kwargs)
    opened.append(value)
    return value

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    observed.append(fd)
    if phase == 'after':
        real_stat(fd)
    raise failure

def close(fd):
    if fd not in opened:
        return real_close(fd)
    assert fd not in closed
    real_close(fd)
    closed.append(fd)
    value = real_open(scratch / 'new-owner', os.O_CREAT | os.O_RDWR, 0o600)
    assert value == fd
    info = real_stat(value)
    sentinels.append((value, info.st_dev, info.st_ino))
try:
    with pytest.MonkeyPatch.context() as patcher:
        patch_module_attribute(patcher, native, 'os', 'open', opening)
        patch_module_attribute(patcher, native, 'os', 'fstat', stat)
        patch_module_attribute(patcher, native, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            native.test_actual_lock_fixture_construction_failure_retires_holder(scratch, patcher, None, module, name, 'event', OSError, False)
        assert caught.value is failure
    assert len(opened) == 1 and observed == opened
    if expectation == 'baseline':
        assert not closed and real_stat(opened[0])
    else:
        assert expectation == 'candidate' and closed == opened and len(sentinels) == 1
        for fd, dev, ino in sentinels:
            info = real_stat(fd)
            assert (info.st_dev, info.st_ino) == (dev, ino)
            os.write(fd, b'caller-owned')
finally:
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
assert native.os is borrowed_native and all(module.os is prior for module, prior in borrowed_modules)
assert not denied_calls
print('MULTI_HOLDER_OBSERVER_OK')
