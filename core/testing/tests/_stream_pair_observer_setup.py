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
import importlib
import pytest
from core.testing.tests import test_stream_handoff_cleanup as native
from core.testing import streams as support
from core.sandbox import seatbelt_audit as audit
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
kind, position = mode.split('-')
position = int(position)
assert kind in {'gate', 'cleanup'} and position in (1, 2)
assert outcome in {'error', 'interrupt'} and expectation == 'candidate'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned stream pair observer fault')
pairs, observed, closed, sentinels = [], [], [], []
borrowed_native, borrowed_os, borrowed_adopt = native.os, support.os, support.adopt_fd
module = importlib.import_module(native._MODULES[kind])
borrowed_module_os = vars(module).get('os')
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
with pytest.MonkeyPatch.context() as patcher:
    patcher.setattr(audit.LogStreamer, 'start', denied)
    patcher.setattr(audit.LogStreamer, '_warm_up_until_attached', denied)
    def pipe():
        pair = real_pipe()
        pairs.append(pair)
        return pair
    def stat(fd):
        if not pairs or fd not in pairs[0]:
            return real_stat(fd)
        info = real_stat(fd)
        observed.append(fd)
        if len(observed) == position:
            raise failure
        return info
    def close(fd):
        if not pairs or fd not in pairs[0]:
            return real_close(fd)
        assert fd not in closed
        real_close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / ('sentinel-' + str(fd)), os.O_CREAT | os.O_RDWR, 0o600)
        info = real_stat(sentinel)
        assert sentinel == fd
        sentinels.append((sentinel, info.st_dev, info.st_ino))
    patch_module_attribute(patcher, native, 'os', 'pipe', pipe)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            with native._warmup_resources(kind, 'none', OSError, scratch, patcher) as state:
                next(state.fixture)
        assert caught.value is failure
        assert len(pairs) == 1 and observed[:position] == list(pairs[0])[:position]
        assert state.streams == []
        assert support.os is borrowed_os and support.adopt_fd is borrowed_adopt
        assert vars(module).get('os') is borrowed_module_os
        assert sorted(closed) == sorted(pairs[0]) and len(closed) == 2
        assert state.entries == []
        for fd, dev, ino in sentinels:
            info = real_stat(fd)
            assert (info.st_dev, info.st_ino) == (dev, ino)
            os.write(fd, b'caller-owned')
    finally:
        sentinel_fds = {x[0] for x in sentinels}
        for pair in pairs:
            for fd in pair:
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
assert native.os is borrowed_native and support.os is borrowed_os and support.adopt_fd is borrowed_adopt
assert not denied_calls
print('STREAM_PAIR_OBSERVER_OK')
