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
from contextlib import contextmanager, ExitStack
from types import SimpleNamespace
import pytest
from core.testing.tests import test_pipe_setup_cleanup as canonical
from core.testing.module_views import module_function_view
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
unsafe_name = 'packages.joern.tests.test_pidns_tier'
assert unsafe_name not in sys.modules
source = root / 'packages/joern/tests/test_pidns_tier.py'
tree = ast.parse(source.read_text(), filename=str(source))
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'TestReadAchievedTier')
assert not cls.bases and not cls.decorator_list
method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == '_read')
assert not method.decorator_list
cls.body = [method]
future = ast.parse('from __future__ import annotations').body[0]
tier = ModuleType('owned_tier_pipe_reader')
vars(tier).update({'__file__': str(source), 'os': os, 'server_mod': SimpleNamespace(_read_achieved_tier=denied)})
exec(compile(ast.Module(body=[future, cls], type_ignores=[]), str(source), 'exec'), vars(tier))
family = ModuleType('packages.joern.tests')
family.test_pidns_tier = tier
original_import = builtins.__import__
def importing(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'packages.joern.tests' and level == 0:
        assert tuple(fromlist) == ('test_pidns_tier',)
        return family
    assert name != unsafe_name
    return original_import(name, globals, locals, fromlist, level)
native = module_function_view(canonical, bindings={'_pipes': canonical._pipes.__wrapped__}, import_hook=importing)
native._pipes = contextmanager(native._pipes)
assert native.test_tier_reader_closes_owned_pipe_ends.__code__ is canonical.test_tier_reader_closes_owned_pipe_ends.__code__
companion_path = root / 'core/testing/tests/test_pipe_fault_binding_ownership.py'
companion_tree = ast.parse(companion_path.read_text(), filename=str(companion_path))
selected = [n for n in companion_tree.body if isinstance(n, ast.FunctionDef) and n.name in {'_record', '_owned_pipe', 'test_actual_tier_write_fault_keeps_outer_pipe_tracker'}]
assert len(selected) == 3
for node in selected:
    node.decorator_list = []
owner = ModuleType('owned_outer_pipe_tracker')
vars(owner).update({'__file__': str(companion_path), 'os': os, 'ModuleType': ModuleType, 'pytest': pytest, 'tier': tier, 'native': native, 'contextmanager': contextmanager, 'ExitStack': ExitStack})
exec(compile(ast.Module(body=selected, type_ignores=[]), str(companion_path), 'exec'), vars(owner))
borrowed_owner, borrowed_native, borrowed_tier = owner.os, native.os, tier.os
borrowed_canonical = canonical.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    with pytest.MonkeyPatch.context() as patcher:
        owner.test_actual_tier_write_fault_keeps_outer_pipe_tracker(patcher, mode)
    assert owner.os is borrowed_owner and native.os is borrowed_native and tier.os is borrowed_tier
    assert canonical.os is borrowed_canonical and unsafe_name not in sys.modules and not denied_calls
    print('OUTER_PIPE_TRACKER_OK')
    raise SystemExit(0)
position_text, phase = mode.split('-')
position = int(position_text)
assert position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned outer tracker metadata fault')
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
        patch_module_attribute(patcher, owner, 'os', 'pipe', pipe)
        patch_module_attribute(patcher, owner, 'os', 'fstat', stat)
        patch_module_attribute(patcher, owner, 'os', 'close', close)
        with pytest.raises(type(failure)) as caught:
            owner.test_actual_tier_write_fault_keeps_outer_pipe_tracker(patcher, 'normal')
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
assert owner.os is borrowed_owner and native.os is borrowed_native and tier.os is borrowed_tier
assert canonical.os is borrowed_canonical and unsafe_name not in sys.modules and not denied_calls
print('OUTER_PIPE_TRACKER_OK')
