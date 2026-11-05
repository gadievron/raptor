"""A failed worker status query must not skip termination and bounded reap."""
import subprocess
import sys
from unittest.mock import Mock

from core.sandbox import parser_jail as parser


def test_status_failure_still_kills_and_waits():
    proc = Mock(pid=123)
    proc.poll.side_effect = OSError('status unavailable')
    parser.ParserJail._reap_locked(proc)
    proc.kill.assert_called_once_with()
    proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)


def test_signal_failure_still_waits():
    proc = Mock(pid=123)
    proc.poll.side_effect = OSError('status unavailable')
    proc.kill.side_effect = ProcessLookupError('worker exited')
    parser.ParserJail._reap_locked(proc)
    proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)


def test_completed_worker_is_not_signaled():
    proc = Mock(pid=123)
    proc.poll.return_value = 0
    parser.ParserJail._reap_locked(proc)
    proc.kill.assert_not_called()
    proc.wait.assert_called_once_with(timeout=parser._READY_TIMEOUT_S)


def test_real_child_is_reaped_after_transient_poll_failure(monkeypatch):
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    original_poll = proc.poll
    calls = 0

    def fail_once():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError('transient status failure')
        return original_poll()

    try:
        monkeypatch.setattr(proc, 'poll', fail_once)
        monkeypatch.setattr(parser, '_READY_TIMEOUT_S', 0.5)
        parser.ParserJail._reap_locked(proc)
        assert proc.returncode is not None
        assert proc.returncode != 0
    finally:
        # Popen checks ownership/status before signaling our own child.
        proc.poll = original_poll
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
