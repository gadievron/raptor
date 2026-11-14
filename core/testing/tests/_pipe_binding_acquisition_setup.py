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
import errno
import pytest
from core.testing import pipes as support
from core.testing.tests import test_pipe_setup_cleanup as native
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
source = root / 'core/testing/tests/test_pipe_fault_binding_ownership.py'
tree = ast.parse(source.read_text(), filename=str(source))
selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in {'_record', '_owned_pipe', 'test_pipe_scope_owns_only_selected_consumer'}]
assert {'_record', 'test_pipe_scope_owns_only_selected_consumer'} <= {n.name for n in selected}
for node in selected:
    node.decorator_list = []
owner = ModuleType('owned_pipe_binding_callers')
tier = ModuleType('owned_identity_only_other_consumer')
tier.os = os
from contextlib import ExitStack
vars(owner).update({'__file__': str(source), 'os': os, 'ModuleType': ModuleType, 'pytest': pytest, 'pipe_support': support, 'tier': tier, 'native': native, 'ExitStack': ExitStack})
exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), 'exec'), vars(owner))
borrowed_owner, borrowed_support, borrowed_native = owner.os, support.os, native.os
real_pipe, real_stat, real_close = os.pipe, os.fstat, os.close
if outcome == 'control':
    state, finish = mode.split('-')
    with pytest.MonkeyPatch.context() as patcher:
        owner.test_pipe_scope_owns_only_selected_consumer(patcher, support, state, finish)
    assert owner.os is borrowed_owner and support.os is borrowed_support and native.os is borrowed_native
    assert not denied_calls
    print('PIPE_BINDING_ACQUISITION_OK')
    raise SystemExit(0)
state, position_text, phase = mode.split('-')
position = int(position_text)
assert state in {'ordinary', 'borrowed'} and position in (1, 2) and phase in {'before', 'after'}
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned unrelated pipe metadata fault')
pairs, observed, closed, sentinels, triggered = [], [], [], [], []
def pipe():
    pair = real_pipe()
    pairs.append(pair)
    return pair

def stat(fd):
    if len(pairs) != 2 or fd not in pairs[1]:
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
    if len(pairs) != 2 or fd not in pairs[1]:
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
        patch_module_attribute(patcher, support, 'os', 'pipe', pipe)
        with pytest.raises(type(failure)) as caught:
            owner.test_pipe_scope_owns_only_selected_consumer(patcher, support, state, 'normal')
        assert caught.value is failure
    assert len(pairs) == 2 and triggered == [failure]
    for fd in pairs[0]:
        with pytest.raises(OSError) as missing:
            real_stat(fd)
        assert missing.value.errno == errno.EBADF
    if expectation == 'baseline':
        assert phase == 'before' and closed == list(pairs[1][:position - 1])
        assert all(real_stat(fd) for fd in pairs[1][position - 1:])
    else:
        assert expectation == 'candidate' and sorted(closed) == sorted(pairs[1]) and len(closed) == 2
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
assert owner.os is borrowed_owner and support.os is borrowed_support and native.os is borrowed_native
assert not denied_calls
print('PIPE_BINDING_ACQUISITION_OK')
