from pathlib import Path
import os
import socket
import subprocess
import sys
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
import builtins
import errno
from contextlib import contextmanager
from types import SimpleNamespace
import pytest
from core.testing.tests import test_pipe_setup_cleanup as canonical
from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute
from core.testing import pipes as support
mode, outcome, expectation = sys.argv[3:6]
unsafe_name = 'core.sandbox.tests.test_landlock_audit_drain'
assert unsafe_name not in sys.modules
source = root / 'core/sandbox/tests/test_landlock_audit_drain.py'
tree = ast.parse(source.read_text(), filename=str(source))
names = set(canonical._DRAINS)
nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
assert len(nodes) == len(names) and all(not n.decorator_list for n in nodes)
caller = ModuleType('owned_drain_startup_callers')
vars(caller).update({'__file__': str(source), 'mod': SimpleNamespace(_DRAIN_IDLE_POLL_S=0.2, _DRAIN_FINAL_SWEEP_S=0.2, _DRAIN_MAX_BYTES_PER_FD=33554432), 'pipes_for_setup': support.pipes_for_setup, '_spawn_child': denied, 'os': os, 'time': __import__('time')})
exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), vars(caller))
family = ModuleType('core.sandbox.tests')
family.test_landlock_audit_drain = caller
original_import = builtins.__import__
def importing(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'core.sandbox.tests' and level == 0:
        assert tuple(fromlist) == ('test_landlock_audit_drain',)
        return family
    assert name != unsafe_name
    return original_import(name, globals, locals, fromlist, level)
owner = module_function_view(canonical, bindings={'_pipes': canonical._pipes.__wrapped__}, import_hook=importing)
owner._pipes = contextmanager(owner._pipes)
assert owner.test_drain_startup_failure_releases_pipes.__code__ is canonical.test_drain_startup_failure_releases_pipes.__code__
borrowed_canonical, borrowed_owner, borrowed_support = canonical.os, owner.os, support.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    index, fault, error_name = mode.split(':')
    error = {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt}[error_name]
    with pytest.MonkeyPatch.context() as patcher:
        owner.test_drain_startup_failure_releases_pipes(canonical._DRAINS[int(index)], fault, error, patcher)
    assert canonical.os is borrowed_canonical and owner.os is borrowed_owner and support.os is borrowed_support
    assert unsafe_name not in sys.modules and not denied_calls
    print('PIPE_SETUP_OBSERVER_OK')
    raise SystemExit(0)
position_text, phase = mode.split('-')
position = int(position_text)
assert position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned startup pipe metadata fault')
opened, observed, closed, sentinels, triggered = [], [], [], [], []
def pipe():
    pair = real_pipe()
    opened.extend(pair)
    return pair

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    observed.append(fd)
    selected = len(observed) == position
    if selected and phase == 'before':
        triggered.append(failure)
        raise failure
    info = real_stat(fd)
    if selected:
        triggered.append(failure)
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
try:
    with pytest.MonkeyPatch.context() as patcher:
        patch_module_attribute(patcher, owner, 'os', 'fstat', stat)
        patch_module_attribute(patcher, owner, 'os', 'close', close)
        patch_module_attribute(patcher, support, 'os', 'pipe', pipe)
        with pytest.raises(type(failure)) as caught:
            owner.test_drain_startup_failure_releases_pipes(canonical._DRAINS[0], 'spawn', OSError, patcher)
        assert caught.value is failure
    assert len(opened) == 2 and triggered == [failure]
    if expectation == 'baseline':
        assert phase == 'before' and closed == opened[:position - 1]
        assert all(real_stat(fd) for fd in opened[position - 1:])
    else:
        assert expectation == 'candidate' and sorted(closed) == sorted(opened) and len(closed) == 2
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
assert canonical.os is borrowed_canonical and owner.os is borrowed_owner and support.os is borrowed_support
assert unsafe_name not in sys.modules and not denied_calls
print('PIPE_SETUP_OBSERVER_OK')
