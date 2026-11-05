"""Both cleanup owners recover when pidfd signaling is unavailable."""
import errno
import os
import select
import signal
from unittest.mock import Mock

import pytest

from core.sandbox import probes
from core.sandbox import _landlock_audit as audit


@pytest.fixture(params=['probe', 'audit'])
def cleanup(request):
    if request.param == 'probe':
        return lambda pid, fd: probes._cleanup_probe_child(pid, 'test', pidfd=fd)
    return lambda pid, fd: audit._kill_and_reap(pid, timeout_s=0.5)


@pytest.mark.parametrize('error', [PermissionError(errno.EPERM, 'blocked'),
                                   OSError(errno.ENOSYS, 'unsupported'), AttributeError('missing')])
def test_verified_child_uses_pid_fallback(cleanup, monkeypatch, error):
    killed = Mock()
    monkeypatch.setattr(os, 'pidfd_open', Mock(return_value=42), raising=False)
    monkeypatch.setattr(os, 'close', Mock())
    monkeypatch.setattr(os, 'kill', killed)
    monkeypatch.setattr(signal, 'pidfd_send_signal', Mock(side_effect=error), raising=False)
    monkeypatch.setattr(os, 'waitpid', lambda pid, flags: (pid, 0) if killed.called else (0, 0))
    cleanup(123, 42)
    assert killed.call_count == 1
    assert killed.call_args.args[0] == 123


def test_lost_ownership_after_pidfd_error_prevents_fallback(cleanup, monkeypatch):
    sender = Mock(side_effect=PermissionError(errno.EPERM, 'blocked'))
    killed = Mock()
    monkeypatch.setattr(os, 'pidfd_open', Mock(return_value=42), raising=False)
    monkeypatch.setattr(os, 'close', Mock())
    monkeypatch.setattr(os, 'kill', killed)
    monkeypatch.setattr(signal, 'pidfd_send_signal', sender, raising=False)

    def wait(pid, flags):
        if sender.called:
            raise ChildProcessError()
        return 0, 0

    monkeypatch.setattr(os, 'waitpid', wait)
    cleanup(123, 42)
    killed.assert_not_called()


def test_pinned_process_gone_does_not_signal_pid(cleanup, monkeypatch):
    sender = Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone'))
    killed = Mock()
    monkeypatch.setattr(os, 'pidfd_open', Mock(return_value=42), raising=False)
    monkeypatch.setattr(os, 'close', Mock())
    monkeypatch.setattr(os, 'kill', killed)
    monkeypatch.setattr(signal, 'pidfd_send_signal', sender, raising=False)
    monkeypatch.setattr(os, 'waitpid', lambda pid, flags: (pid, 0) if sender.called else (0, 0))
    cleanup(123, 42)
    killed.assert_not_called()


@pytest.mark.skipif(not hasattr(os, 'fork') or not hasattr(os, 'pidfd_open'), reason='requires fork and pidfds')
def test_real_child_cleanup_with_blocked_pidfd_signal(cleanup, monkeypatch):
    child = os.fork()
    if child == 0:
        while True:
            signal.pause()
    fd = None
    try:
        try:
            fd = os.pidfd_open(child)
        except OSError:
            pytest.skip('kernel does not permit pidfds')
        sender = Mock(side_effect=PermissionError(errno.EPERM, 'blocked'))
        monkeypatch.setattr(signal, 'pidfd_send_signal', sender, raising=False)
        cleanup(child, fd)
        assert sender.called
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            if waited == 0:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)


@pytest.mark.skipif(not hasattr(os, 'fork') or not hasattr(os, 'pidfd_open'), reason='requires fork and pidfds')
def test_audit_kill_phase_falls_back_for_term_ignoring_child(monkeypatch):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.write(write_fd, b'R')
        os.close(write_fd)
        while True:
            signal.pause()
    os.close(write_fd)
    try:
        poller = select.poll()
        poller.register(read_fd, select.POLLIN)
        assert poller.poll(5000), 'child did not finish signal setup'
        assert os.read(read_fd, 1) == b'R'
        try:
            fd = os.pidfd_open(child)
        except OSError:
            pytest.skip('kernel does not permit pidfds')
        else:
            os.close(fd)
        sender = Mock(side_effect=PermissionError(errno.EPERM, 'blocked'))
        monkeypatch.setattr(signal, 'pidfd_send_signal', sender, raising=False)
        # A real child needs scheduling time after each signal under CI load.
        audit._kill_and_reap(child, timeout_s=1.0)
        assert [call.args[1] for call in sender.call_args_list] == [signal.SIGTERM, signal.SIGKILL]
        with pytest.raises(ChildProcessError):
            os.waitpid(child, os.WNOHANG)
    finally:
        os.close(read_fd)
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            if waited == 0:
                os.kill(child, signal.SIGKILL)
                os.waitpid(child, 0)
