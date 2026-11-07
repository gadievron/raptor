"""Pidfd signal refusal cannot strand a still-owned probe child."""
import errno
import os
import signal
from unittest.mock import Mock

import pytest

from core.sandbox import ptrace_probe as probe

from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def calls(monkeypatch):
    opened, closed, killed = Mock(return_value=42), Mock(), Mock()
    patch_module_attribute(monkeypatch, probe, 'os', 'pidfd_open', opened, raising=False)
    patch_module_attribute(monkeypatch, probe, 'os', 'close', closed)
    patch_module_attribute(monkeypatch, probe, 'os', 'kill', killed)
    return opened, closed, killed


@pytest.mark.parametrize('error', [OSError(errno.ENOSYS, 'unsupported'),
                                   PermissionError(errno.EPERM, 'blocked'), AttributeError('missing')])
def test_signal_failure_falls_back_only_after_child_check(monkeypatch, calls, error):
    _, closed, killed = calls
    patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', Mock(side_effect=error), raising=False)
    wait = Mock(side_effect=[(0, 0), (123, signal.SIGKILL)])
    patch_module_attribute(monkeypatch, probe, 'os', 'waitpid', wait)
    probe._try_kill_and_reap(123)
    killed.assert_called_once_with(123, signal.SIGKILL)
    closed.assert_called_once_with(42)
    assert wait.call_args_list[0].args == (123, os.WNOHANG)


@pytest.mark.parametrize('result', [ChildProcessError(), (123, 0)])
def test_lost_or_terminal_child_is_not_signalled(monkeypatch, calls, result):
    _, closed, killed = calls
    patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)
    wait = Mock(side_effect=result) if isinstance(result, Exception) else Mock(return_value=result)
    patch_module_attribute(monkeypatch, probe, 'os', 'waitpid', wait)
    probe._try_kill_and_reap(123)
    killed.assert_not_called()
    closed.assert_called_once_with(42)


def test_pinned_process_gone_does_not_fall_back(monkeypatch, calls):
    _, closed, killed = calls
    patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone')), raising=False)
    patch_module_attribute(monkeypatch, probe, 'os', 'waitpid', Mock(return_value=(123, 0)))
    probe._try_kill_and_reap(123)
    killed.assert_not_called()
    closed.assert_called_once_with(42)


@pytest.mark.parametrize('pid', [0, -1, True, 1 << 31])
def test_invalid_pid_is_ignored(calls, pid):
    opened, closed, killed = calls
    probe._try_kill_and_reap(pid)
    opened.assert_not_called()
    closed.assert_not_called()
    killed.assert_not_called()


@pytest.mark.skipif(not hasattr(os, 'fork') or not hasattr(os, 'pidfd_open'), reason='requires fork and pidfds')
def test_real_child_is_reaped_when_pidfd_signalling_is_blocked(monkeypatch):
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    try:
        try:
            fd = os.pidfd_open(child)
        except OSError:
            pytest.skip('kernel does not permit pidfd_open')
        else:
            os.close(fd)
        sender = Mock(side_effect=PermissionError(errno.EPERM, 'blocked'))
        patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', sender, raising=False)
        probe._try_kill_and_reap(child)
        sender.assert_called_once()
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            if waited == 0:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)


def test_interrupted_ownership_check_retries_before_signal(monkeypatch, calls):
    _, _, killed = calls
    patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)
    wait = Mock(side_effect=[InterruptedError(), (0, 0), (123, signal.SIGKILL)])
    patch_module_attribute(monkeypatch, probe, 'os', 'waitpid', wait)
    probe._try_kill_and_reap(123)
    assert wait.call_count == 3
    killed.assert_called_once_with(123, signal.SIGKILL)


def test_ownership_check_respects_cleanup_deadline(monkeypatch, calls):
    _, _, killed = calls
    patch_module_attribute(monkeypatch, probe, 'signal', 'pidfd_send_signal', Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)
    patch_module_attribute(monkeypatch, probe, 'os', 'waitpid', Mock(side_effect=InterruptedError()))
    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, probe, "time", 'monotonic', Mock(side_effect=[100.0, 106.0]))
        probe._try_kill_and_reap(123)
    killed.assert_not_called()
