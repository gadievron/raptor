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
from contextlib import ExitStack, contextmanager, suppress
from types import FunctionType
import pytest
from core.testing.tests import test_capture_fd_cleanup as canonical
from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute
from core.sandbox import _spawn

# Load only the real retained-write fixture, never module-level capability probes.
unsafe_name = 'core.sandbox.tests.test_capture_post_exit_drain'
assert unsafe_name not in sys.modules
source = root / 'core/sandbox/tests/test_capture_post_exit_drain.py'
tree = ast.parse(source.read_text(), filename=str(source))
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'retained_write_ends')
assert len(node.decorator_list) == 1 and ast.unparse(node.decorator_list[0]) == '_pytest.fixture'
node.decorator_list = []
future = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == '__future__']
assert len(future) == 1 and [x.name for x in future[0].names] == ['annotations']
capture = ModuleType('owned_capture_fixture')
capture.__file__ = str(source)
vars(capture).update(ExitStack=ExitStack, suppress=suppress, os=os)
exec(compile(ast.Module(body=[*future, node], type_ignores=[]), str(source), 'exec'), vars(capture))
capture.retained_write_ends = pytest.fixture(capture.retained_write_ends)
assert '_userns_available' not in vars(capture)
family = ModuleType('core.sandbox.tests')
family.test_capture_post_exit_drain = capture
original_import = builtins.__import__
def importing(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'core.sandbox.tests' and level == 0:
        assert tuple(fromlist) == ('test_capture_post_exit_drain',)
        return family
    assert name != unsafe_name
    return original_import(name, globals, locals, fromlist, level)
raw_record = canonical._descriptors.__wrapped__
owner = module_function_view(canonical, bindings={'_descriptors': raw_record}, import_hook=importing)
owner._descriptors = contextmanager(owner._descriptors)
names = ['test_capture_dup_failure_rolls_back_only_current_call', 'test_capture_fixture_closes_retained_fds_on_every_exit']
assert all(getattr(owner, name).__code__ is getattr(canonical, name).__code__ for name in names)
import errno
from core.testing.pipes import pipes_for_setup
mode, outcome, expectation = sys.argv[3:6]
companion_path = root / 'core/testing/tests/test_capture_fixture_pipe_ownership.py'
companion_tree = ast.parse(companion_path.read_text(), filename=str(companion_path))
exercise = next(n for n in companion_tree.body if isinstance(n, ast.FunctionDef) and n.name == '_exercise')
assert not exercise.decorator_list
companion = ModuleType('owned_capture_allocator_companion')
vars(companion).update(contextmanager=contextmanager, ExitStack=ExitStack, os=os, FunctionType=FunctionType, ModuleType=ModuleType, pytest=pytest, _spawn=_spawn, capture=capture, native=owner, pipes_for_setup=pipes_for_setup)
exec(compile(ast.Module(body=[exercise], type_ignores=[]), str(companion_path), 'exec'), vars(companion))
borrowed_companion, borrowed_canonical, borrowed_open, borrowed_capture = companion.os, canonical.os, _spawn._open_capture_pipes, capture.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    caller, phase_name, after_name, error_name = mode.split(':')
    phase = None if phase_name == 'none' else phase_name
    error = {'None': None, 'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}[error_name]
    with pytest.MonkeyPatch.context() as patcher:
        companion._exercise(patcher, caller, phase, error, after_name == '1')
    assert companion.os is borrowed_companion and canonical.os is borrowed_canonical
    assert _spawn._open_capture_pipes is borrowed_open and capture.os is borrowed_capture
    assert unsafe_name not in sys.modules and not denied_calls
    print('CAPTURE_ALLOCATOR_OBSERVER_OK')
    raise SystemExit(0)
caller, position_text, phase = mode.rsplit(':', 2)
position = int(position_text)
assert caller in {'duplicate', 'fixture-exit'} and position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned capture allocator metadata fault')
opened, observed, closed, sentinels, triggered = [], [], [], [], []
def pipe():
    pair = real_pipe()
    opened.extend(pair)
    return pair

def stat(fd):
    if fd not in opened:
        return real_stat(fd)
    observed.append(fd)
    chosen = len(observed) == position
    if chosen and phase == 'before':
        triggered.append(failure)
        raise failure
    info = real_stat(fd)
    if chosen:
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
        patch_module_attribute(patcher, companion, 'os', 'pipe', pipe)
        patch_module_attribute(patcher, companion, 'os', 'fstat', stat)
        patch_module_attribute(patcher, companion, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            companion._exercise(patcher, caller)
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
assert companion.os is borrowed_companion and canonical.os is borrowed_canonical
assert _spawn._open_capture_pipes is borrowed_open and capture.os is borrowed_capture
assert unsafe_name not in sys.modules and not denied_calls
print('CAPTURE_ALLOCATOR_OBSERVER_OK')
