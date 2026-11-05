"""Ptrace sentinel failures remain bounded and do not abandon children."""

import errno
import logging
import os
import signal
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import ptrace_probe as probe

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux ptrace probe internals")


PID = 424242
STOPPED = (signal.SIGSTOP << 8) | 0x7f


@pytest.fixture
def parent_probe(monkeypatch):
    cleanup, waits = [], []

    class Ptrace:
        def __call__(self, *args):
            return 0

    libc = SimpleNamespace(ptrace=Ptrace())
    monkeypatch.setattr(probe, "_get_libc", lambda: libc)
    monkeypatch.setattr(probe.os, "fork", lambda: PID)
    monkeypatch.setattr(probe, "_try_kill_and_reap", cleanup.append)

    def outcomes(values):
        iterator = iter(values)

        def wait(pid, options, *, deadline=None):
            waits.append((pid, options, deadline))
            value = next(iterator)
            if isinstance(value, BaseException):
                raise value
            return pid, value

        monkeypatch.setattr(probe, "_waitpid_eintr_safe", wait)

    return SimpleNamespace(outcomes=outcomes, cleanup=cleanup, waits=waits, libc=libc)


@pytest.mark.parametrize("status", [1 << 8, signal.SIGKILL])
def test_terminal_child_is_not_signalled_after_reaping(parent_probe, status):
    parent_probe.outcomes([status])
    assert probe._run_probe() is False
    assert parent_probe.cleanup == []


@pytest.mark.parametrize("phase", ["stop", "exit"])
def test_echild_does_not_signal_a_pid_no_longer_owned(parent_probe, phase):
    values = [OSError(errno.ECHILD, "already reaped")]
    if phase == "exit":
        values.insert(0, STOPPED)
    parent_probe.outcomes(values)
    assert probe._run_probe() is False
    assert parent_probe.cleanup == []


@pytest.mark.parametrize("phase", ["stop", "exit"])
def test_wait_timeout_cleans_up_unreaped_child(parent_probe, phase):
    values = [TimeoutError("probe deadline")]
    if phase == "exit":
        values.insert(0, STOPPED)
    parent_probe.outcomes(values)
    assert probe._run_probe() is False
    assert parent_probe.cleanup == [PID]


@pytest.mark.parametrize("phase", ["stop", "exit"])
def test_cancellation_cleans_up_and_propagates(parent_probe, phase):
    failure = KeyboardInterrupt()
    values = [failure]
    if phase == "exit":
        values.insert(0, STOPPED)
    parent_probe.outcomes(values)
    with pytest.raises(KeyboardInterrupt) as raised:
        probe._run_probe()
    assert raised.value is failure
    assert parent_probe.cleanup == [PID]


def test_stop_and_exit_share_one_deadline(parent_probe):
    parent_probe.outcomes([STOPPED, 0])
    assert probe._run_probe() is True
    deadlines = [call[2] for call in parent_probe.waits]
    assert len(deadlines) == 2
    assert deadlines[0] is not None
    assert deadlines[0] == deadlines[1]
    assert parent_probe.cleanup == []


def test_unexpected_parent_ptrace_error_still_cleans_up(parent_probe):
    parent_probe.outcomes([STOPPED])
    failure = RuntimeError("injected ctypes failure")

    class Ptrace:
        def __call__(self, *args):
            raise failure

    parent_probe.libc.ptrace = Ptrace()
    with pytest.raises(RuntimeError) as raised:
        probe._run_probe()
    assert raised.value is failure
    assert parent_probe.cleanup == [PID]


def test_nonblocking_wait_honors_deadline(monkeypatch):
    clock = [0.0]
    options = []

    def wait(pid, flags):
        options.append(flags)
        return 0, 0

    monkeypatch.setattr(probe.os, "waitpid", wait)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(TimeoutError):
        probe._waitpid_eintr_safe(PID, os.WUNTRACED, deadline=0.025)
    assert clock[0] == pytest.approx(0.025)
    assert options
    assert all(flags & os.WNOHANG for flags in options)
    assert all(flags & os.WUNTRACED for flags in options)


def test_eintr_retries_cannot_extend_deadline(monkeypatch):
    clock = [0.0]
    calls = []

    def wait(pid, flags):
        calls.append(True)
        clock[0] += 0.5
        raise InterruptedError()

    monkeypatch.setattr(probe.os, "waitpid", wait)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    with pytest.raises(TimeoutError):
        probe._waitpid_eintr_safe(PID, 0, deadline=1.0)
    assert len(calls) == 2
    assert clock[0] == 1.0


def test_terminal_result_can_be_collected_without_waiting(monkeypatch):
    monkeypatch.setattr(probe.os, "waitpid", lambda pid, flags: (pid, 0))
    monkeypatch.setattr(probe.time, "monotonic", lambda: 10.0)
    assert probe._waitpid_eintr_safe(PID, 0, deadline=1.0) == (PID, 0)


@pytest.fixture
def cleanup_probe(monkeypatch):
    signals = []

    def no_pidfd(*args):
        raise OSError(errno.ENOSYS, "pidfd unavailable")

    monkeypatch.setattr(probe.os, "pidfd_open", no_pidfd)
    # Cleanup checks child ownership before falling back to PID signalling.
    # Keep this synthetic child live and owned; the bounded reap is stubbed
    # separately by each test below.
    monkeypatch.setattr(probe.os, "waitpid", lambda pid, flags: (0, 0))
    monkeypatch.setattr(probe.os, "kill", lambda pid, sig: signals.append((pid, sig)))
    return signals


def test_cleanup_logs_a_bounded_reap_timeout(monkeypatch, cleanup_probe, caplog):
    deadlines = []

    def timeout(pid, options, *, deadline=None):
        deadlines.append(deadline)
        raise TimeoutError("injected cleanup timeout")

    monkeypatch.setattr(probe, "_waitpid_eintr_safe", timeout)
    with caplog.at_level(logging.WARNING, logger=probe.__name__):
        probe._try_kill_and_reap(PID)
    assert cleanup_probe == [(PID, signal.SIGKILL)]
    assert deadlines[0] is not None
    assert "cleanup budget" in caplog.text


def test_cleanup_waits_for_terminal_status_with_one_budget(monkeypatch, cleanup_probe):
    outcomes = iter([STOPPED, signal.SIGKILL])
    deadlines = []

    def wait(pid, options, *, deadline=None):
        deadlines.append(deadline)
        return pid, next(outcomes)

    monkeypatch.setattr(probe, "_waitpid_eintr_safe", wait)
    probe._try_kill_and_reap(PID)
    assert cleanup_probe == [(PID, signal.SIGKILL)]
    assert len(deadlines) == 2
    assert deadlines[0] == deadlines[1]


def test_child_exits_even_if_error_diagnostic_cannot_be_written(monkeypatch):
    class ChildExit(BaseException):
        pass

    exits = []

    class Ptrace:
        def __call__(self, *args):
            raise RuntimeError("injected child failure")

    def fail_write(*args):
        raise OSError(errno.EBADF, "stderr closed")

    def exit_child(code):
        exits.append(code)
        raise ChildExit()

    monkeypatch.setattr(probe, "_get_libc", lambda: SimpleNamespace(ptrace=Ptrace()))
    monkeypatch.setattr(probe, "os", SimpleNamespace(
        fork=lambda: 0, write=fail_write, _exit=exit_child,
    ))
    with pytest.raises(ChildExit):
        probe._run_probe()
    assert exits == [1]


def test_real_stalled_probe_child_is_killed_and_reaped(monkeypatch):
    from core.testing.wallclock import wall_deadline
    real_fork = os.fork
    children = []

    class StalledPtrace:
        def __call__(self, request, *args):
            if request == probe._PTRACE_TRACEME:
                # Test-only backstop: an unfixed blocking wait eventually
                # wakes too, well beyond the prompt-return test window.
                signal.signal(signal.SIGALRM, signal.SIG_DFL)
                signal.alarm(60)
                signal.pause()
            return 0

    def fork():
        pid = real_fork()
        if pid > 0:
            children.append(pid)
        return pid

    monkeypatch.setattr(probe, "_get_libc", lambda: SimpleNamespace(ptrace=StalledPtrace()))
    monkeypatch.setattr(probe.os, "fork", fork)
    monkeypatch.setattr(probe, "_PROBE_TIMEOUT_S", 0.1)
    try:
        with wall_deadline(20, code_bound_s=60, what="stalled ptrace availability probe"):
            assert probe._run_probe() is False
        assert len(children) == 1
        with pytest.raises(ChildProcessError):
            os.waitpid(children[0], os.WNOHANG)
    finally:
        for pid in children:
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def test_repeated_nonterminal_cleanup_events_cannot_extend_budget(
    monkeypatch, cleanup_probe, caplog,
):
    clock = [0.0]
    calls = []

    def wait(pid, options, *, deadline=None):
        calls.append(deadline)
        clock[0] += 0.5
        return pid, STOPPED

    monkeypatch.setattr(probe, "_waitpid_eintr_safe", wait)
    monkeypatch.setattr(probe.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(probe, "_REAP_TIMEOUT_S", 1.0)
    with caplog.at_level(logging.WARNING, logger=probe.__name__):
        probe._try_kill_and_reap(PID)
    assert calls == [1.0, 1.0]
    assert "cleanup budget" in caplog.text
