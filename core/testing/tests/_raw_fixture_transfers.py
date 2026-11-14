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
from core.source.tests import test_owned_fd_stream as native
from core.source import streams as canonical
consumer, outcome, expectation = sys.argv[3:6]
assert consumer in {'raw', 'stream', 'setup-before', 'setup-after'} and outcome in {'normal', 'error', 'interrupt'}
assert expectation == 'candidate'
failure = None if outcome == 'normal' else {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned stream body fault')
if consumer.startswith('setup-'):
    from core.testing.module_bindings import patch_module_attribute
    base_view = native.module_function_view
    opened, closed, sentinels = [], [], []
    def opening(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        opened.append(fd)
        return fd
    def closing(fd):
        assert opened == [fd] and not closed
        os.close(fd)
        closed.append(fd)
        sentinel = os.open(scratch / 'setup-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
        stamp = os.fstat(sentinel)
        sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
    def fail_view(*args, **kwargs):
        if consumer == 'setup-after':
            base_view(*args, **kwargs)
        raise failure
    borrowed_os, borrowed_streams = native.os, native.streams
    with pytest.MonkeyPatch.context() as setup_patch:
        patch_module_attribute(setup_patch, native, 'os', 'open', opening)
        patch_module_attribute(setup_patch, native, 'os', 'close', closing)
        setup_patch.setattr(native, 'module_function_view', fail_view)
        generator = native.owned_fd.__wrapped__(scratch)
        try:
            with pytest.raises(type(failure)) as caught:
                next(generator)
            assert caught.value is failure and len(opened) == 1 and closed == opened
            generator.close()
            for fd, dev, ino in sentinels:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
        finally:
            generator.close()
            for fd, _, _ in sentinels:
                os.close(fd)
    assert native.os is borrowed_os and native.streams is borrowed_streams
    assert native.module_function_view is base_view
    assert not denied_calls
    print('RAW_FIXTURE_TRANSFER_OK')
    raise SystemExit(0)
borrowed_os, borrowed_streams = native.os, native.streams
canonical_os, canonical_owner = canonical.os, canonical.owned_fd
fixture = native.owned_fd.__wrapped__(scratch)
replacement = None
try:
    fd, path = next(fixture)
    assert native.streams.owned_fd.__wrapped__.__code__ is canonical.owned_fd.__wrapped__.__code__
    assert native.streams.open_owned_fd.__wrapped__.__code__ is canonical.open_owned_fd.__wrapped__.__code__
    original = os.fstat(fd)
    try:
        manager = native.streams.owned_fd(fd) if consumer == 'raw' else native.streams.open_owned_fd(fd, 'rb')
        with manager as adopted:
            if consumer == 'raw':
                assert adopted == fd
            else:
                assert adopted.read(1) == b'o'
            if failure is not None:
                raise failure
    except BaseException as caught:
        assert caught is failure
    else:
        assert failure is None
    with pytest.raises(OSError) as gone:
        os.fstat(fd)
    assert gone.value.errno == errno.EBADF
    replacement = os.open(path, os.O_RDWR)
    assert replacement == fd, 'owned immediate reopen did not reuse descriptor'
    current = os.fstat(replacement)
    assert (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino)
    assert os.read(replacement, 32) == b'owned bytes'
    os.lseek(replacement, 0, os.SEEK_SET)
    fixture.close()
    if expectation == 'baseline':
        with pytest.raises(OSError) as lost:
            os.fstat(replacement)
        assert lost.value.errno == errno.EBADF
    else:
        after = os.fstat(replacement)
        assert (after.st_dev, after.st_ino) == (current.st_dev, current.st_ino)
        assert os.read(replacement, 32) == b'owned bytes'
    assert native.os is borrowed_os and native.streams is borrowed_streams
    assert canonical.os is canonical_os and canonical.owned_fd is canonical_owner
finally:
    fixture.close()
    if replacement is not None:
        try:
            os.fstat(replacement)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            os.close(replacement)
assert not denied_calls, denied_calls
print('RAW_FIXTURE_TRANSFER_OK')
