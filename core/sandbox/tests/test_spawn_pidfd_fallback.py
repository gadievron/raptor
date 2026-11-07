"""Main spawn cleanup retains direct-child signaling when pidfds fail."""
import errno
import os
import signal
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import _spawn as spawn

from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('failure', ['open', 'send'])
def test_same_group_child_is_killed_after_pidfd_failure(monkeypatch, failure):
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        assert os.getpgid(process.pid) == os.getpgrp()
        if failure == 'open':
            patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'fd pressure')), raising=False)
        else:
            patch_module_attribute(monkeypatch, spawn, 'signal', 'pidfd_send_signal', Mock(side_effect=PermissionError(errno.EPERM, 'blocked')), raising=False)
        spawn._kill_and_reap(process.pid)
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
    finally:
        process.kill()
        process.wait(timeout=5)


def test_failed_signals_cannot_leave_an_unbounded_wait(monkeypatch, caplog):
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitid', Mock(return_value=None))
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgid', lambda pid: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgrp', lambda: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    patch_module_attribute(monkeypatch, spawn, 'os', 'kill', Mock(side_effect=PermissionError(errno.EPERM, 'blocked')))
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitpid', Mock(return_value=(0, 0)))
    patch_module_attribute(monkeypatch, spawn, "time", 'sleep', lambda delay: None)
    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, spawn, "time", 'monotonic', Mock(side_effect=[100.0, 106.0]))
        spawn._kill_and_reap(123)
    assert 'did not reap within cleanup budget' in caplog.text
    assert spawn.os.waitpid.call_args.args == (123, os.WNOHANG)


def test_lost_ownership_during_fallback_prevents_numeric_signals(monkeypatch):
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitid', Mock(side_effect=[None, ChildProcessError(errno.ECHILD, 'lost')]))
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgid', lambda pid: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    kill, killpg = Mock(), Mock()
    patch_module_attribute(monkeypatch, spawn, 'os', 'kill', kill)
    patch_module_attribute(monkeypatch, spawn, 'os', 'killpg', killpg)
    spawn._kill_and_reap(123)
    kill.assert_not_called()
    killpg.assert_not_called()


def test_stopped_status_does_not_complete_reaping(monkeypatch):
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitid', Mock(return_value=None))
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgid', lambda pid: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgrp', lambda: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(return_value=42), raising=False)
    patch_module_attribute(monkeypatch, spawn, 'signal', 'pidfd_send_signal', Mock(), raising=False)
    patch_module_attribute(monkeypatch, spawn, 'os', 'close', Mock())
    stopped = (signal.SIGSTOP << 8) | 0x7f
    wait = Mock(side_effect=[(123, stopped), InterruptedError(), (123, 0)])
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitpid', wait)
    patch_module_attribute(monkeypatch, spawn, "time", 'sleep', lambda delay: None)
    spawn._kill_and_reap(123)
    assert wait.call_count == 3


def test_interrupted_ownership_check_retries(monkeypatch):
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitid', Mock(side_effect=[InterruptedError(), None, None]))
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgid', lambda pid: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgrp', lambda: 123)
    patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    killed = Mock()
    patch_module_attribute(monkeypatch, spawn, 'os', 'kill', killed)
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitpid', Mock(return_value=(123, 0)))
    spawn._kill_and_reap(123)
    killed.assert_called_once_with(123, signal.SIGKILL)


def test_pinned_process_gone_preserves_group_sweep_without_pid_fallback(monkeypatch):
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitid', Mock(return_value=None))
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgid', lambda pid: 456)
    patch_module_attribute(monkeypatch, spawn, 'os', 'getpgrp', lambda: 789)
    patch_module_attribute(monkeypatch, spawn, 'os', 'pidfd_open', Mock(return_value=42), raising=False)
    patch_module_attribute(monkeypatch, spawn, 'signal', 'pidfd_send_signal', Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone')), raising=False)
    patch_module_attribute(monkeypatch, spawn, 'os', 'close', Mock())
    killed, groups = Mock(), Mock()
    patch_module_attribute(monkeypatch, spawn, 'os', 'kill', killed)
    patch_module_attribute(monkeypatch, spawn, 'os', 'killpg', groups)
    patch_module_attribute(monkeypatch, spawn, 'os', 'waitpid', Mock(return_value=(123, 0)))
    spawn._kill_and_reap(123)
    killed.assert_not_called()
    groups.assert_called_once_with(456, signal.SIGKILL)
