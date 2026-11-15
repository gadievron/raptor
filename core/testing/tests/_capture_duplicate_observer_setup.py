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
mode, outcome, expectation = sys.argv[3:6]
CONTROLS = {'native-duplicate-0-1-OSError': {'kind': 'native-duplicate', 'prior': False, 'position': 1, 'error': 'OSError'}, 'native-duplicate-0-1-KeyboardInterrupt': {'kind': 'native-duplicate', 'prior': False, 'position': 1, 'error': 'KeyboardInterrupt'}, 'native-duplicate-0-2-OSError': {'kind': 'native-duplicate', 'prior': False, 'position': 2, 'error': 'OSError'}, 'native-duplicate-0-2-KeyboardInterrupt': {'kind': 'native-duplicate', 'prior': False, 'position': 2, 'error': 'KeyboardInterrupt'}, 'native-duplicate-1-1-OSError': {'kind': 'native-duplicate', 'prior': True, 'position': 1, 'error': 'OSError'}, 'native-duplicate-1-1-KeyboardInterrupt': {'kind': 'native-duplicate', 'prior': True, 'position': 1, 'error': 'KeyboardInterrupt'}, 'native-duplicate-1-2-OSError': {'kind': 'native-duplicate', 'prior': True, 'position': 2, 'error': 'OSError'}, 'native-duplicate-1-2-KeyboardInterrupt': {'kind': 'native-duplicate', 'prior': True, 'position': 2, 'error': 'KeyboardInterrupt'}, 'native-fixture-close': {'kind': 'native-fixture', 'finish': 'close'}, 'native-fixture-interrupt': {'kind': 'native-fixture', 'finish': 'interrupt'}, 'native-fixture-normal': {'kind': 'native-fixture', 'finish': 'normal'}, 'pipe-positive-duplicate': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': None, 'after': False, 'error': None}, 'pipe-duplicate-allocate-0-RuntimeError': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'allocate', 'after': False, 'error': 'RuntimeError'}, 'pipe-duplicate-allocate-0-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'allocate', 'after': False, 'error': 'KeyboardInterrupt'}, 'pipe-duplicate-allocate-0-SystemExit': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'allocate', 'after': False, 'error': 'SystemExit'}, 'pipe-duplicate-record-0-RuntimeError': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': False, 'error': 'RuntimeError'}, 'pipe-duplicate-record-0-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': False, 'error': 'KeyboardInterrupt'}, 'pipe-duplicate-record-0-SystemExit': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': False, 'error': 'SystemExit'}, 'pipe-duplicate-record-1-RuntimeError': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': True, 'error': 'RuntimeError'}, 'pipe-duplicate-record-1-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': True, 'error': 'KeyboardInterrupt'}, 'pipe-duplicate-record-1-SystemExit': {'kind': 'pipe-proof', 'caller': 'duplicate', 'phase': 'record', 'after': True, 'error': 'SystemExit'}, 'pipe-positive-fixture-exit': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': None, 'after': False, 'error': None}, 'pipe-fixture-exit-allocate-0-RuntimeError': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'allocate', 'after': False, 'error': 'RuntimeError'}, 'pipe-fixture-exit-allocate-0-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'allocate', 'after': False, 'error': 'KeyboardInterrupt'}, 'pipe-fixture-exit-allocate-0-SystemExit': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'allocate', 'after': False, 'error': 'SystemExit'}, 'pipe-fixture-exit-record-0-RuntimeError': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': False, 'error': 'RuntimeError'}, 'pipe-fixture-exit-record-0-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': False, 'error': 'KeyboardInterrupt'}, 'pipe-fixture-exit-record-0-SystemExit': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': False, 'error': 'SystemExit'}, 'pipe-fixture-exit-record-1-RuntimeError': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': True, 'error': 'RuntimeError'}, 'pipe-fixture-exit-record-1-KeyboardInterrupt': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': True, 'error': 'KeyboardInterrupt'}, 'pipe-fixture-exit-record-1-SystemExit': {'kind': 'pipe-proof', 'caller': 'fixture-exit', 'phase': 'record', 'after': True, 'error': 'SystemExit'}}
if mode in CONTROLS:
    assert outcome == 'control' and expectation == 'candidate'
    case = CONTROLS[mode]
    borrowed_os, borrowed_open, borrowed_capture = canonical.os, _spawn._open_capture_pipes, capture.os
    with pytest.MonkeyPatch.context() as control_patch:
        if case['kind'] == 'native-duplicate':
            error_type = {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt}[case['error']]
            owner.test_capture_dup_failure_rolls_back_only_current_call(case['prior'], case['position'], error_type, control_patch)
        elif case['kind'] == 'native-fixture':
            owner.test_capture_fixture_closes_retained_fds_on_every_exit(case['finish'], control_patch)
        else:
            companion_path = root / 'core/testing/tests/test_capture_fixture_pipe_ownership.py'
            companion_tree = ast.parse(companion_path.read_text(), filename=str(companion_path))
            exercise = next(n for n in companion_tree.body if isinstance(n, ast.FunctionDef) and n.name == '_exercise')
            assert not exercise.decorator_list
            assert all(isinstance(n, ast.Constant) for n in exercise.args.defaults)
            companion = ModuleType('owned_capture_pipe_companion')
            vars(companion).update(ExitStack=ExitStack, contextmanager=contextmanager, os=os, FunctionType=FunctionType, ModuleType=ModuleType, pytest=pytest, _spawn=_spawn, capture=capture, native=owner, pipes_for_setup=canonical.pipes_for_setup)
            exec(compile(ast.Module(body=[exercise], type_ignores=[]), str(companion_path), 'exec'), vars(companion))
            error_type = {None: None, 'RuntimeError': RuntimeError, 'KeyboardInterrupt': KeyboardInterrupt, 'SystemExit': SystemExit}[case['error']]
            companion._exercise(control_patch, case['caller'], case['phase'], error_type, case['after'])
    assert canonical.os is borrowed_os and _spawn._open_capture_pipes is borrowed_open and capture.os is borrowed_capture
    assert unsafe_name not in sys.modules and not denied_calls
    print('CAPTURE_DUPLICATE_OBSERVER_OK')
    raise SystemExit(0)
assert mode in {'duplicate-before', 'duplicate-after', 'fixture-exit-before', 'fixture-exit-after'}
assert outcome in {'error', 'interrupt'} and expectation == 'candidate'
caller = 'duplicate' if mode.startswith('duplicate-') else 'fixture-exit'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned capture duplicate observer fault')
opened, observed, closed, sentinels = [], [], [], []
borrowed_canonical, borrowed_open = canonical.os, _spawn._open_capture_pipes
borrowed_capture = capture.os
real_dup, real_stat, real_close = os.dup, os.fstat, os.close
with pytest.MonkeyPatch.context() as patcher:
    patch_module_attribute(patcher, owner, 'resource', 'setrlimit', denied)
    def dup(fd):
        value = real_dup(fd)
        opened.append(value)
        assert len(opened) == 1
        real_stat(value)
        return value
    def stat(fd):
        if fd not in opened:
            return real_stat(fd)
        observed.append(fd)
        if mode.endswith('-after'):
            real_stat(fd)
        raise failure
    def close(fd):
        if fd not in opened:
            return real_close(fd)
        assert not closed
        real_close(fd)
        closed.append(fd)
        value = os.open(scratch / 'caller-sentinel', os.O_CREAT | os.O_RDWR, 0o600)
        assert value == fd
        info = real_stat(value)
        sentinels.append((value, info.st_dev, info.st_ino))
    patch_module_attribute(patcher, owner, 'os', 'dup', dup)
    patch_module_attribute(patcher, owner, 'os', 'fstat', stat)
    patch_module_attribute(patcher, owner, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            if caller == 'duplicate':
                owner.test_capture_dup_failure_rolls_back_only_current_call(False, 2, OSError, patcher)
            else:
                owner.test_capture_fixture_closes_retained_fds_on_every_exit('normal', patcher)
        assert caught.value is failure and len(opened) == 1 and observed == opened
        assert _spawn._open_capture_pipes is borrowed_open and capture.os is borrowed_capture
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
assert canonical.os is borrowed_canonical and _spawn._open_capture_pipes is borrowed_open
assert unsafe_name not in sys.modules
assert not denied_calls
print('CAPTURE_DUPLICATE_OBSERVER_OK')
