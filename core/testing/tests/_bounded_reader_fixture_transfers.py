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
from core.json.tests import test_bounded_lifecycle as native
from core.json import bounded
from core.testing.module_bindings import patch_module_attribute
consumer, outcome, expectation = sys.argv[3:6]
assert consumer in {'borrow-once', 'borrow-twice', 'observe-before', 'observe-after'}
assert outcome in {'normal', 'error', 'interrupt'} and expectation == 'candidate'
failure = None if outcome == 'normal' else {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned reader fixture fault')
borrowed_os, borrowed_native_os = bounded.os, native.os
replacement, sentinels, opened, closed = None, [], [], []
with pytest.MonkeyPatch.context() as patcher:
    if consumer.startswith('observe-'):
        def opening(*args, **kwargs):
            fd = os.open(*args, **kwargs)
            opened.append(fd)
            return fd
        def checking(fd):
            assert fd in opened
            if consumer == 'observe-after':
                os.fstat(fd)
            raise failure
        def closing(fd):
            assert opened == [fd] and not closed
            os.close(fd)
            closed.append(fd)
            sentinel = os.open(scratch / 'observer-sentinel', os.O_RDWR | os.O_CREAT, 0o600)
            stamp = os.fstat(sentinel)
            sentinels.append((sentinel, stamp.st_dev, stamp.st_ino))
        patch_module_attribute(patcher, native, 'os', 'open', opening)
        patch_module_attribute(patcher, native, 'os', 'fstat', checking)
        patch_module_attribute(patcher, native, 'os', 'close', closing)
    generator = native.reader.__wrapped__(scratch, patcher)
    reader = next(generator)
    fixture_retired = False
    def retire_fixture():
        global fixture_retired
        if fixture_retired:
            return
        fixture_retired = True
        try:
            next(generator)
        except StopIteration:
            pass
        else:
            raise AssertionError('native reader fixture yielded twice')
        finally:
            generator.close()
    try:
        if consumer.startswith('observe-'):
            reader.install()
            with pytest.raises(type(failure)) as caught:
                bounded.load_json_bounded(reader.path, max_bytes=16)
            assert caught.value is failure and len(opened) == 1 and not reader.owners
            retire_fixture()
            assert closed == opened and len(sentinels) == 1
            for fd, dev, ino in sentinels:
                stamp = os.fstat(fd)
                assert (stamp.st_dev, stamp.st_ino) == (dev, ino)
        else:
            reads = 2 if consumer == 'borrow-twice' else 1
            for _ in range(reads):
                reader.install('read' if failure else None, failure)
                if failure is None:
                    assert bounded.load_json_bounded(reader.path, max_bytes=16) == {'ok': True}
                else:
                    with pytest.raises(type(failure)) as caught:
                        bounded.load_json_bounded(reader.path, max_bytes=16)
                    assert caught.value is failure
            assert len(reader.owners) == len(reader.closed) == reads
            fd, identity = reader.owners[-1]
            assert reader.closed == [fd] * reads
            with pytest.raises(OSError) as gone:
                os.fstat(fd)
            assert gone.value.errno == errno.EBADF
            replacement = os.open(reader.path, os.O_RDONLY)
            assert replacement == fd
            stamp = os.fstat(replacement)
            assert (stamp.st_dev, stamp.st_ino) == identity
            retire_fixture()
            after = os.fstat(replacement)
            assert (after.st_dev, after.st_ino) == identity
            assert os.read(replacement, 32) == b'{"ok":true}'
    finally:
        retire_fixture()
        if replacement is not None:
            try:
                os.fstat(replacement)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                os.close(replacement)
        for fd in opened:
            if fd not in closed:
                os.close(fd)
        for fd, _, _ in sentinels:
            os.close(fd)
assert bounded.os is borrowed_os and native.os is borrowed_native_os
assert not denied_calls, denied_calls
print('BOUNDED_READER_FIXTURE_OK')
