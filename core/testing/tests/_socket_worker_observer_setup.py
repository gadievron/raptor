from pathlib import Path
import os
import socket
import subprocess
import sys
import threading
from types import ModuleType

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
import ast
import errno
import pytest
from core.testing.tests import test_socket_worker_cleanup as native
from core.testing import sockets as support
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
kind, phase = mode.split('-', 1)
assert kind in {'parser', 'usage', 'trickle'}
assert expectation in {'baseline', 'candidate'}
source = root / ('core/sandbox/tests/test_parser_jail.py' if kind == 'parser' else 'core/llm/dispatcher/tests/test_usage_scan_jail.py')
text = source.read_text()
class_name = '_TricklingWorker' if kind == 'trickle' else '_FakeWorker'
tree = ast.parse(text, filename=str(source))
selected = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name]
assert len(selected) == 1 and not selected[0].decorator_list and not selected[0].bases
future = ast.parse('from __future__ import annotations').body[0]
view = ModuleType('owned_socket_fixture_class')
vars(view).update({'__file__': str(source), 'socket_worker_setup': support.socket_worker_setup, 'threading': threading, 'socket': socket, 'os': os})
exec(compile(ast.Module(body=[future, selected[0]], type_ignores=[]), str(source), 'exec'), vars(view))
borrowed_native, borrowed_support = native.os, support.os
borrowed_module = native._module
real_dup, real_stat, real_close = os.dup, os.fstat, os.close
if outcome == 'control':
    fault, error_name = phase.rsplit('-', 1)
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(native, '_module', lambda selected_kind: view)
        native.test_socket_worker_setup_releases_duplicate_and_thread(kind, fault, {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt}[error_name], patcher)
    assert native.os is borrowed_native and support.os is borrowed_support and native._module is borrowed_module
    assert not denied_calls
    print('SOCKET_WORKER_OBSERVER_OK')
    raise SystemExit(0)
assert phase in {'before', 'after'} and outcome in {'error', 'interrupt'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned socket duplicate metadata fault')
opened, closed, sentinels, reached = [], [], [], []
def dup(fd):
    value = real_dup(fd)
    opened.append(value)
    return value

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    reached.append(fd)
    if phase == 'after':
        real_stat(fd)
    raise failure

def close(fd):
    if fd not in opened:
        return real_close(fd)
    assert fd not in closed
    real_close(fd)
    closed.append(fd)
    value = os.open(scratch / 'sentinel', os.O_CREAT | os.O_RDWR, 0o600)
    assert value == fd
    info = real_stat(value)
    sentinels.append((value, info.st_dev, info.st_ino))
try:
    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(native, '_module', lambda selected_kind: view)
        patch_module_attribute(patcher, native, 'os', 'dup', dup)
        patch_module_attribute(patcher, native, 'os', 'fstat', stat)
        patch_module_attribute(patcher, native, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            native.test_socket_worker_setup_releases_duplicate_and_thread(kind, 'socket', OSError, patcher)
        assert caught.value is failure
    assert len(opened) == 1 and reached == opened
    if expectation == 'baseline':
        assert not closed and real_stat(opened[0])
    else:
        assert closed == opened and len(sentinels) == 1
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
assert native.os is borrowed_native and support.os is borrowed_support and native._module is borrowed_module
assert not denied_calls
print('SOCKET_WORKER_OBSERVER_OK')
