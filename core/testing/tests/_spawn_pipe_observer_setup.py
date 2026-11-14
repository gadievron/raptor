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
from core.testing.tests import test_spawn_pipe_setup_cleanup as native
from core.testing import pipes as pipe_consumer
from core.testing.module_bindings import patch_module_attribute
position, outcome, expectation = int(sys.argv[3]), sys.argv[4], sys.argv[5]
assert position in (1, 2) and outcome in {'error', 'interrupt'}
assert expectation == 'candidate'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned pipe recorder metadata fault')
pairs, observations, closes, sentinels = [], [], [], []
borrowed_consumer, borrowed_native = pipe_consumer.os, native.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
with pytest.MonkeyPatch.context() as patcher:
    def pipe():
        pair = real_pipe()
        pairs.append(pair)
        return pair
    def stat(fd):
        info = real_stat(fd)
        observations.append(fd)
        if len(observations) == position:
            raise failure
        return info
    def close(fd):
        real_close(fd)
        closes.append(fd)
        sentinel = os.open(scratch / ('sentinel-' + str(fd)), os.O_CREAT | os.O_RDWR, 0o600)
        info = real_stat(sentinel)
        sentinels.append((sentinel, info.st_dev, info.st_ino))
    patch_module_attribute(patcher, pipe_consumer, 'os', 'pipe', pipe)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            native.test_shim_preparation_or_spawn_failure_releases_pipes(
                native._SHIMS[0][0], 2, 'argv', OSError, patcher)
        assert caught.value is failure
        assert len(pairs) == 1 and observations[:position] == list(pairs[0])[:position]
        assert sorted(closes) == sorted(pairs[0]) and len(closes) == 2
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
assert pipe_consumer.os is borrowed_consumer and native.os is borrowed_native
assert not denied_calls
print('SPAWN_PIPE_OBSERVER_OK')
