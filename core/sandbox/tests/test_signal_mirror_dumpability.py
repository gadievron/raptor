"""Trusted signal mirroring keeps signal evidence without a second core dump."""

import json
import signal
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn
from core.testing.module_views import module_function_view
from core.testing.standalone_cli import run_standalone_cli


class MirroredExit(BaseException):
    pass


@pytest.mark.parametrize('mode', ['ok', 'refused', 'error', 'missing'])
@pytest.mark.parametrize('reset_fails', [False, True])
def test_mirror_disables_dumpability_before_preserving_signal(mode, reset_fails):
    events = []
    terminal = MirroredExit()

    def prctl(*args):
        events.append(('prctl', args))
        if mode == 'error':
            raise OSError('owned prctl failure')
        return -1 if mode == 'refused' else 0

    def reset(sig, disposition):
        events.append(('signal', sig, disposition))
        if reset_fails:
            raise ValueError('owned signal reset failure')

    def terminate(code):
        events.append(('exit', code))
        raise terminal

    view = module_function_view(_spawn, bindings={
        'os': SimpleNamespace(
            getpid=lambda: 123,
            kill=lambda pid, sig: events.append(('kill', pid, sig)),
            _exit=terminate,
        ),
        'signal': SimpleNamespace(signal=reset, SIG_DFL=signal.SIG_DFL),
        'warn_post_fork': lambda message: events.append(('warning', message)),
    })
    with pytest.raises(MirroredExit) as caught:
        view._mirror_signal_exit(signal.SIGABRT, None if mode == 'missing' else prctl)
    assert caught.value is terminal
    assert events[-3:] == [
        ('signal', signal.SIGABRT, signal.SIG_DFL),
        ('kill', 123, signal.SIGABRT),
        ('exit', 128 + signal.SIGABRT),
    ]
    if mode != 'missing':
        assert events[0] == ('prctl', (4, 0, 0, 0, 0))
    warnings = [event for event in events if event[0] == 'warning']
    assert len(warnings) == (0 if mode == 'ok' else 1)


def test_mirror_does_not_swallow_cancellation_from_core_suppression():
    cancellation = KeyboardInterrupt('owned interruption')

    def interrupted(*args):
        raise cancellation

    with pytest.raises(KeyboardInterrupt) as caught:
        _spawn._mirror_signal_exit(signal.SIGABRT, interrupted)
    assert caught.value is cancellation


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != 'linux', reason='Linux signal-mirroring backend')
@pytest.mark.parametrize('signal_name', ['SIGABRT', 'SIGSEGV', 'SIGXCPU'])
def test_native_mirror_retains_signal_without_core_dump(signal_name):
    # The helper owns and reaps its child even if the mirror stops terminating.
    # Run in a fresh interpreter, rather than forking pytest's worker threads.
    # This boundary needs the kernel's final signal/core status; a crash
    # wrapper substituting SIGKILL would erase the evidence under test.
    script = r'''
import ctypes, json, os, resource, signal, sys, time
from core.sandbox._spawn import _mirror_signal_exit

sig = getattr(signal, sys.argv[1])
prctl = ctypes.CDLL(None, use_errno=True).prctl
pid = os.fork()
if pid == 0:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _mirror_signal_exit(sig, prctl)
    os._exit(90)  # A broken returning mirror must not enter the parent's cleanup.
reaped = False
try:
    deadline = time.monotonic() + 5
    while True:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited:
            reaped = True
            break
        if time.monotonic() >= deadline:
            raise AssertionError('owned mirror child did not terminate')
        time.sleep(0.01)
    print(json.dumps({'signal': os.WTERMSIG(status) if os.WIFSIGNALED(status) else None,
                      'core_dumped': os.WCOREDUMP(status)}))
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
'''
    result = run_standalone_cli(
        [sys.executable, '-c', script, signal_name],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data == {'signal': int(getattr(signal, signal_name)), 'core_dumped': False}
