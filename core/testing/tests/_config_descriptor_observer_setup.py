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
import pytest
from core.testing.tests import test_capture_fd_cleanup as native
from core.sandbox.tests import test_evidence as module
from core.sandbox import tracer
from core.testing.module_bindings import patch_module_attribute
mode, outcome, expectation = sys.argv[3:6]
CONTROLS = {'native-keeper-OSError': {'fault': 'keeper', 'error': 'OSError'}, 'native-keeper-KeyboardInterrupt': {'fault': 'keeper', 'error': 'KeyboardInterrupt'}, 'native-cli-OSError': {'fault': 'cli', 'error': 'OSError'}, 'native-cli-KeyboardInterrupt': {'fault': 'cli', 'error': 'KeyboardInterrupt'}, 'native-config-positive': {'control': 'positive'}, 'native-config-reuse': {'control': 'reuse'}}
if mode in CONTROLS:
    assert outcome == 'control' and expectation == 'candidate'
    case = CONTROLS[mode]
    borrowed_native, borrowed_ev, borrowed_module_os = native.os, module.ev, module.os
    borrowed_cli, borrowed_trace = tracer._cli_main, tracer.trace
    with pytest.MonkeyPatch.context() as control_patch:
        control_patch.setattr(tracer, 'trace', denied)
        control_patch.setattr(tracer, '_set_non_dumpable', denied)
        if case.get('control') == 'positive':
            module.TestTracerFdConfigConsumption().test_cli_reads_fd_path_config_and_closes_fd(scratch, control_patch)
        elif case.get('control') == 'reuse':
            native.test_config_cleanup_preserves_a_reused_descriptor(scratch, control_patch)
        else:
            error_type = {'OSError': OSError, 'KeyboardInterrupt': KeyboardInterrupt}[case['error']]
            native.test_config_descriptor_is_reclaimed_when_setup_or_cli_fails(case['fault'], error_type, scratch, control_patch)
    assert native.os is borrowed_native and module.ev is borrowed_ev and module.os is borrowed_module_os
    assert tracer._cli_main is borrowed_cli and tracer.trace is borrowed_trace
    assert not denied_calls
    print('CONFIG_DESCRIPTOR_OBSERVER_OK')
    raise SystemExit(0)
assert mode in {'anonymous-before', 'anonymous-after', 'keeper-before', 'keeper-after'}
assert outcome in {'error', 'interrupt'} and expectation == 'candidate'
failure = {'error': RuntimeError, 'interrupt': KeyboardInterrupt}[outcome]('owned config descriptor observer fault')
opened, observed, closed, sentinels = [], [], [], []
borrowed_native, borrowed_ev, borrowed_module_os = native.os, module.ev, module.os
borrowed_cli, borrowed_trace = tracer._cli_main, tracer.trace
real_anonymous, real_dup, real_stat, real_close = module.ev.anonymous_fd, os.dup, os.fstat, os.close
with pytest.MonkeyPatch.context() as patcher:
    patcher.setattr(tracer, 'trace', denied)
    patcher.setattr(tracer, '_set_non_dumpable', denied)
    def anonymous(*args, **kwargs):
        fd = real_anonymous(*args, **kwargs)
        opened.append(fd)
        assert real_stat(fd).st_size > 0
        return fd
    def dup(fd):
        value = real_dup(fd)
        opened.append(value)
        assert real_stat(value).st_size > 0
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
    if mode.startswith('anonymous-'):
        patch_module_attribute(patcher, module, 'ev', 'anonymous_fd', anonymous)
    else:
        patch_module_attribute(patcher, native, 'os', 'dup', dup)
    patch_module_attribute(patcher, native, 'os', 'fstat', stat)
    patch_module_attribute(patcher, native, 'os', 'close', close)
    try:
        with pytest.raises(type(failure)) as caught:
            native.test_config_descriptor_is_reclaimed_when_setup_or_cli_fails('cli', OSError, scratch, patcher)
        assert caught.value is failure and len(opened) == 1 and observed == opened
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
assert native.os is borrowed_native and module.ev is borrowed_ev and module.os is borrowed_module_os
assert tracer._cli_main is borrowed_cli and tracer.trace is borrowed_trace
assert not denied_calls
print('CONFIG_DESCRIPTOR_OBSERVER_OK')
