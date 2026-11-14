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
from core.coverage.tests import test_journal_rollback_refusal as native
from core.coverage import journal
consumer, outcome, expectation = sys.argv[3:6]
assert consumer in {'before', 'after'}
assert outcome in {'error', 'interrupt'} and expectation == 'candidate'
borrowed_os, borrowed_fcntl = journal.os, journal.fcntl
replacement = None
with pytest.MonkeyPatch.context() as patcher:
    generator = native.rollback_probe.__wrapped__(scratch, patcher)
    state = next(generator)
    retired = False
    def retire_fixture():
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
        failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned rollback refusal')
        state['rollback_error'] = failure
        state['after_effect'] = consumer == 'after'
        state['cleanup_fault'] = 'both'
        with pytest.raises(type(failure)) as caught:
            state['append']()
        assert caught.value is failure
        native.assert_rollback_refused(state)
        fd = state['opened'][0]
        path = state['path']
        content = path.read_bytes()
        assert content == state['before'] + (b'' if consumer == 'after' else state['fragment'])
        replacement = os.open(path, os.O_RDONLY)
        assert replacement == fd
        identity = os.fstat(replacement)
        retire_fixture()
        after = os.fstat(replacement)
        assert (after.st_dev, after.st_ino) == (identity.st_dev, identity.st_ino)
        assert os.read(replacement, len(content) + 1) == content
    finally:
        retire_fixture()
        if replacement is not None:
            try:
                os.fstat(replacement)
            except OSError as error:
                assert error.errno == errno.EBADF
            else:
                os.close(replacement)
assert journal.os is borrowed_os and journal.fcntl is borrowed_fcntl
assert not denied_calls, denied_calls
print('COVERAGE_ROLLBACK_FIXTURE_OK')
