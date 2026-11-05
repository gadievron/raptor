"""Main spawn cleanup retains direct-child signaling when pidfds fail."""
import errno
import os
import signal
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import _spawn as spawn


@pytest.mark.parametrize('failure', ['open', 'send'])
def test_same_group_child_is_killed_after_pidfd_failure(monkeypatch, failure):
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        assert os.getpgid(process.pid) == os.getpgrp()
        if failure == 'open':
            monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'fd pressure')), raising=False)
        else:
            monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', Mock(side_effect=PermissionError(errno.EPERM, 'blocked')), raising=False)
        spawn._kill_and_reap(process.pid)
        with pytest.raises(ChildProcessError):
            os.waitpid(process.pid, os.WNOHANG)
    finally:
        process.kill()
        process.wait(timeout=5)


def test_failed_signals_cannot_leave_an_unbounded_wait(monkeypatch, caplog):
    monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))
    monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)
    monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)
    monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    monkeypatch.setattr(spawn.os, 'kill', Mock(side_effect=PermissionError(errno.EPERM, 'blocked')))
    monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(0, 0)))
    monkeypatch.setattr(spawn.time, 'sleep', lambda delay: None)
    with monkeypatch.context() as scoped:
        scoped.setattr(spawn.time, 'monotonic', Mock(side_effect=[100.0, 106.0]))
        spawn._kill_and_reap(123)
    assert 'did not reap within cleanup budget' in caplog.text
    assert spawn.os.waitpid.call_args.args == (123, os.WNOHANG)


def test_lost_ownership_during_fallback_prevents_numeric_signals(monkeypatch):
    monkeypatch.setattr(spawn.os, 'waitid', Mock(side_effect=[None, ChildProcessError(errno.ECHILD, 'lost')]))
    monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)
    monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    kill, killpg = Mock(), Mock()
    monkeypatch.setattr(spawn.os, 'kill', kill)
    monkeypatch.setattr(spawn.os, 'killpg', killpg)
    spawn._kill_and_reap(123)
    kill.assert_not_called()
    killpg.assert_not_called()


def test_stopped_status_does_not_complete_reaping(monkeypatch):
    monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))
    monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)
    monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)
    monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(return_value=42), raising=False)
    monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', Mock(), raising=False)
    monkeypatch.setattr(spawn.os, 'close', Mock())
    stopped = (signal.SIGSTOP << 8) | 0x7f
    wait = Mock(side_effect=[(123, stopped), InterruptedError(), (123, 0)])
    monkeypatch.setattr(spawn.os, 'waitpid', wait)
    monkeypatch.setattr(spawn.time, 'sleep', lambda delay: None)
    spawn._kill_and_reap(123)
    assert wait.call_count == 3


def test_interrupted_ownership_check_retries(monkeypatch):
    monkeypatch.setattr(spawn.os, 'waitid', Mock(side_effect=[InterruptedError(), None, None]))
    monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)
    monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)
    monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'full')), raising=False)
    killed = Mock()
    monkeypatch.setattr(spawn.os, 'kill', killed)
    monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(123, 0)))
    spawn._kill_and_reap(123)
    killed.assert_called_once_with(123, signal.SIGKILL)


def test_pinned_process_gone_preserves_group_sweep_without_pid_fallback(monkeypatch):
    monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))
    monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 456)
    monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 789)
    monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(return_value=42), raising=False)
    monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone')), raising=False)
    monkeypatch.setattr(spawn.os, 'close', Mock())
    killed, groups = Mock(), Mock()
    monkeypatch.setattr(spawn.os, 'kill', killed)
    monkeypatch.setattr(spawn.os, 'killpg', groups)
    monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(123, 0)))
    spawn._kill_and_reap(123)
    killed.assert_not_called()
    groups.assert_called_once_with(456, signal.SIGKILL)
