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
import pytest
from core.testing.tests import test_stream_handoff_cleanup as native
from core.binary import _elf_worker_child as child
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
assert mode in {'before', 'after'} and outcome in {'error', 'interrupt'}
assert expectation == 'candidate'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned duplicate observer fault')
opened, observed, closed, sentinels = [], [], [], []
borrowed_native, borrowed_dup = native.os, os.dup
real_dup, real_stat, real_close = os.dup, os.fstat, os.close
with pytest.MonkeyPatch.context() as patcher:
    patcher.setattr(child, '_collect', denied)
    patcher.setattr(child, '_install_limits', denied)
    def dup(fd):
        value = real_dup(fd)
        opened.append(value)
        assert real_stat(value).st_size == len(b'validated input')
        return value
    def stat(fd):
        if fd not in opened:
            return real_stat(fd)
        assert fd in opened
        observed.append(fd)
        if mode == 'after':
            real_stat(fd)
        raise failure
    def close(fd):
        if fd not in opened:
            return real_close(fd)
        assert opened == [fd] and not closed
        real_close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / 'caller-sentinel', os.O_CREAT | os.O_RDWR, 0o600)
        info = real_stat(sentinel)
        assert sentinel == fd
        sentinels.append((sentinel, info.st_dev, info.st_ino))
    patch_module_attribute(patcher, native, 'os', 'dup', dup)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            native.test_descriptor_argument_failure_closes_duplicate('constructor', OSError, scratch, patcher)
        assert caught.value is failure and len(opened) == 1 and observed == opened
        assert closed == opened and len(sentinels) == 1
        for fd, dev, ino in sentinels:
            info = real_stat(fd)
            assert (info.st_dev, info.st_ino) == (dev, ino)
            os.write(fd, b'caller-owned')
    finally:
        for fd in opened:
            if fd not in closed:
                real_close(fd)
        for fd, _, _ in sentinels:
            real_close(fd)
assert native.os is borrowed_native and os.dup is borrowed_dup
assert not denied_calls
print('DESCRIPTOR_OBSERVER_OK')
