"""Audit cleanup must verify ownership and never wait indefinitely."""

import errno
import os
import select
import signal
import subprocess
import sys
from unittest.mock import Mock

import pytest

from core.sandbox import _landlock_audit as audit

from core.testing.module_bindings import patch_module_attribute

PID = 1 << 30


@pytest.fixture
def pid_fallback(monkeypatch):
    monkeypatch.setattr(
        audit.os, "pidfd_open",
        Mock(side_effect=OSError(errno.ENOSYS, "no pidfd")), raising=False,
    )


@pytest.mark.parametrize("pid", [-1, 0])
def test_invalid_pid_never_signals(pid, monkeypatch):
    kill = Mock(side_effect=AssertionError("must not signal"))
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(pid)
    kill.assert_not_called()


@pytest.mark.parametrize("outcome", [
    (PID, 0), ChildProcessError(), OSError(errno.ECHILD, "gone"),
    OSError(errno.EIO, "unknown ownership"),
])
def test_reaped_or_lost_child_is_not_signaled(pid_fallback, monkeypatch, outcome):
    wait = Mock()
    if isinstance(outcome, BaseException):
        wait.side_effect = outcome
    else:
        wait.return_value = outcome
    kill = Mock()
    monkeypatch.setattr(audit.os, "waitpid", wait)
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(PID)
    kill.assert_not_called()


def test_signal_race_still_collects_terminal_status(pid_fallback, monkeypatch):
    wait = Mock(side_effect=[(0, 0), (PID, 0)])
    monkeypatch.setattr(audit.os, "waitpid", wait)
    monkeypatch.setattr(audit.os, "kill", Mock(side_effect=ProcessLookupError()))
    audit._kill_and_reap(PID)
    assert wait.call_count == 2
    assert all(call.args[1] == os.WNOHANG for call in wait.call_args_list)


def test_interrupted_ownership_check_retries_before_signaling(pid_fallback, monkeypatch):
    wait = Mock(side_effect=[InterruptedError(), (0, 0), (PID, 0)])
    kill = Mock()
    monkeypatch.setattr(audit.os, "waitpid", wait)
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(PID)
    kill.assert_called_once_with(PID, signal.SIGTERM)


def test_unreapable_child_stops_after_both_budgets(pid_fallback, monkeypatch, caplog):
    clock = iter(i / 100 for i in range(100))
    wait = Mock(return_value=(0, 0))
    kill = Mock()
    patch_module_attribute(monkeypatch, audit, "time", "monotonic", lambda: next(clock))
    patch_module_attribute(monkeypatch, audit, "time", "sleep", lambda delay: None)
    monkeypatch.setattr(audit.os, "waitpid", wait)
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(PID, timeout_s=0.02)
    assert [call.args[1] for call in kill.call_args_list] == [
        signal.SIGTERM, signal.SIGKILL,
    ]
    assert all(call.args[1] == os.WNOHANG for call in wait.call_args_list)
    assert "did not reap after SIGKILL" in caplog.text


@pytest.mark.parametrize("cancel", [False, True])
def test_pidfd_is_used_and_closed(monkeypatch, cancel):
    read_fd, write_fd = os.pipe()
    real_close = os.close
    closed = []
    send = Mock()

    def close(fd):
        closed.append(fd)
        real_close(fd)

    monkeypatch.setattr(audit.os, "pidfd_open", lambda pid: read_fd, raising=False)
    monkeypatch.setattr(audit.signal, "pidfd_send_signal", send, raising=False)
    monkeypatch.setattr(
        audit.os, "waitpid",
        Mock(side_effect=KeyboardInterrupt() if cancel else [(0, 0), (PID, 0)]),
    )
    monkeypatch.setattr(audit.os, "kill", Mock(side_effect=AssertionError("use pinned handle")))
    monkeypatch.setattr(audit, "_close_safely", close)
    try:
        if cancel:
            with pytest.raises(KeyboardInterrupt):
                audit._kill_and_reap(PID)
            send.assert_not_called()
        else:
            audit._kill_and_reap(PID)
            send.assert_called_once_with(read_fd, signal.SIGTERM)
        assert closed == [read_fd]
    finally:
        if read_fd not in closed:
            real_close(read_fd)
        real_close(write_fd)


@pytest.mark.skipif(not hasattr(select, "poll"), reason="requires POSIX polling")
def test_real_child_ignoring_term_is_killed_and_reaped():
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
         "print('ready', flush=True); time.sleep(60)"],
        stdout=subprocess.PIPE,
    )
    try:
        poller = select.poll()
        poller.register(proc.stdout, select.POLLIN)
        assert poller.poll(5000)
        assert proc.stdout.readline() == b"ready\n"
        audit._kill_and_reap(proc.pid, timeout_s=0.1)
        with pytest.raises(ChildProcessError):
            os.waitpid(proc.pid, os.WNOHANG)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()



def test_repeated_interruptions_are_bounded_without_signaling(
    pid_fallback, monkeypatch, caplog,
):
    clock = iter(i / 100 for i in range(100))
    kill = Mock()
    patch_module_attribute(monkeypatch, audit, "time", "monotonic", lambda: next(clock))
    monkeypatch.setattr(audit.os, "waitpid", Mock(side_effect=InterruptedError()))
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(PID, timeout_s=0.02)
    kill.assert_not_called()
    assert "could not verify child" in caplog.text


def test_stopped_child_is_not_mistaken_for_a_terminal_status(pid_fallback, monkeypatch):
    stopped = (signal.SIGSTOP << 8) | 0x7f
    kill = Mock()
    monkeypatch.setattr(audit.os, "waitpid", Mock(side_effect=[(PID, stopped), (PID, 0)]))
    monkeypatch.setattr(audit.os, "kill", kill)
    audit._kill_and_reap(PID)
    kill.assert_called_once_with(PID, signal.SIGTERM)
