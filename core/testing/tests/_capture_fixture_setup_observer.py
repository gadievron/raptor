from pathlib import Path
import os
import socket
import subprocess
import sys
import threading

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
from core.container.tests import test_capture_setup_cleanup as native
from core.container import proc
from core.testing.module_bindings import patch_module_attribute
position, outcome, expectation = int(sys.argv[3]), sys.argv[4], sys.argv[5]
assert position in (1, 2) and outcome in {'error', 'interrupt'}
assert expectation == 'candidate'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned capture observer metadata fault')
pairs, observations, closes, sentinels = [], [], [], []
borrowed_os, borrowed_threads, borrowed_run = proc.os, proc.threading, proc.subprocess
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
    patch_module_attribute(patcher, native, 'os', 'pipe', pipe)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    generator = native.capture_fault.__wrapped__(patcher)
    install = next(generator)
    owned = install('none', None)
    retired = False
    def retire():
        global retired
        if retired:
            return
        retired = True
        try:
            next(generator)
        except StopIteration:
            pass
        else:
            raise AssertionError('fixture yielded twice')
        finally:
            generator.close()
    try:
        if outcome == 'interrupt':
            with pytest.raises(KeyboardInterrupt) as caught:
                owned.invoke()
            assert caught.value is failure
        else:
            result = owned.invoke()
            assert result.returncode is None and 'owned capture observer metadata fault' in result.stderr
        assert len(pairs) == 1 and observations[:position] == list(pairs[0])[:position]
        assert owned.spawns == [] and owned.threads and all(not worker.is_alive() for worker in owned.threads)
        assert sorted(closes) == sorted(pairs[0]) and len(closes) == 2
        assert owned.pipes == []
        retire()
        for fd, dev, ino in sentinels:
            info = real_stat(fd)
            assert (info.st_dev, info.st_ino) == (dev, ino)
            os.write(fd, b'caller-owned')
    finally:
        retire()
        for worker in owned.threads:
            if worker.ident is not None:
                threading.Thread.join(worker, timeout=2)
                assert not worker.is_alive()
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
assert proc.os is borrowed_os and proc.threading is borrowed_threads and proc.subprocess is borrowed_run
assert not denied_calls
print('CAPTURE_FIXTURE_OBSERVER_OK')
