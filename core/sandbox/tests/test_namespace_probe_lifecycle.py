"""Simple namespace probes bound child waits without losing ownership."""

import ctypes
import errno
import os
import signal
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import probes

from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux namespace probes")
PID = 424242


@pytest.fixture(autouse=True)
def synthetic_pid_never_opens_a_real_pidfd(monkeypatch):
    real_open = getattr(os, "pidfd_open", None)

    def open_pidfd(pid):
        if pid == PID or real_open is None:
            raise OSError(errno.ENOSYS, "synthetic test child")
        return real_open(pid)

    patch_module_attribute(monkeypatch, probes, 'os', "pidfd_open", open_pidfd, raising=False)


@pytest.fixture
def clock(monkeypatch):
    value = [0.0]
    patch_module_attribute(monkeypatch, probes, "time", "monotonic", lambda: value[0])
    patch_module_attribute(monkeypatch, probes, "time", "sleep", lambda seconds: value.__setitem__(0, value[0] + seconds))
    monkeypatch.setattr(probes, "_PROBE_CHILD_TIMEOUT_S", 0.03)
    monkeypatch.setattr(probes, "_PROBE_CHILD_REAP_TIMEOUT_S", 0.03)
    return value


@pytest.mark.parametrize("status", [0, 1 << 8, signal.SIGKILL])
def test_terminal_status_is_collected_without_signalling(monkeypatch, status):
    kills = []
    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", lambda pid, options: (pid, status))
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    assert probes._wait_for_probe_child(PID, "test") == status
    assert kills == []


def test_echild_is_unavailable_without_signalling(monkeypatch):
    kills = []

    def reaped(*args):
        raise ChildProcessError(errno.ECHILD, "already reaped")

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", reaped)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    assert probes._wait_for_probe_child(PID, "test") is None
    assert kills == []


def test_timeout_kills_and_reaps_child(monkeypatch, clock):
    killed, reaped, options = [], [], []

    def wait(pid, flags):
        options.append(flags)
        if killed:
            reaped.append(pid)
            return pid, signal.SIGKILL
        return 0, 0

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: killed.append(args))
    assert probes._wait_for_probe_child(PID, "test") is None
    assert killed == [(PID, signal.SIGKILL)]
    assert reaped == [PID]
    assert options and all(flags & os.WNOHANG for flags in options)
    assert clock[0] == pytest.approx(0.03)


def test_cancellation_cleans_up_and_propagates(monkeypatch):
    failure = KeyboardInterrupt()
    killed, waits = [], []

    def wait(pid, flags):
        waits.append(True)
        if len(waits) == 1:
            raise failure
        if killed:
            return pid, signal.SIGKILL
        return 0, 0

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: killed.append(args))
    with pytest.raises(KeyboardInterrupt) as raised:
        probes._wait_for_probe_child(PID, "test")
    assert raised.value is failure
    assert killed == [(PID, signal.SIGKILL)]
    assert len(waits) == 3


@pytest.mark.parametrize("ownership", ["terminal", "reaped"])
def test_cleanup_rechecks_terminal_status_hidden_by_cancellation(monkeypatch, ownership):
    failure = KeyboardInterrupt()
    calls, kills = [], []

    def wait(pid, flags):
        calls.append(True)
        if len(calls) == 1:
            raise failure
        if ownership == "reaped":
            raise ChildProcessError(errno.ECHILD, "already reaped")
        return pid, 0

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    with pytest.raises(KeyboardInterrupt):
        probes._wait_for_probe_child(PID, "test")
    assert kills == []
    assert len(calls) == 2


def test_wait_and_cleanup_have_separate_bounded_budgets(monkeypatch, clock, caplog):
    kills = []
    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", lambda *args: (0, 0))
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    assert probes._wait_for_probe_child(PID, "test") is None
    assert kills == [(PID, signal.SIGKILL)]
    assert clock[0] == pytest.approx(0.06)
    assert "cleanup budget" in caplog.text


def test_eintr_retries_cannot_extend_probe_deadline(monkeypatch, clock):
    calls = []

    def interrupted(*args):
        calls.append(True)
        clock[0] += 0.01
        raise InterruptedError()

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", interrupted)
    with pytest.raises(TimeoutError):
        probes._poll_probe_child_exit(PID, 0.03)
    assert len(calls) == 3


def test_cleanup_does_not_signal_when_ownership_cannot_be_verified(monkeypatch, clock, caplog):
    kills = []

    def interrupted(*args):
        clock[0] += 0.01
        raise InterruptedError()

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", interrupted)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    probes._cleanup_probe_child(PID, "test")
    assert kills == []
    assert clock[0] == pytest.approx(0.03)
    assert "could not verify child" in caplog.text


@pytest.mark.parametrize("name", ["_staged_pidns_selftest", "_mount_ns_functional_selftest"])
def test_fork_failure_returns_unavailable(monkeypatch, name):
    def exhausted():
        raise OSError(errno.EAGAIN, "fork unavailable")

    patch_module_attribute(monkeypatch, probes, 'os', "fork", exhausted)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(mount=lambda *a: -1))
    assert getattr(probes, name)() is False


@pytest.mark.parametrize("name", ["_staged_pidns_selftest", "_mount_ns_functional_selftest"])
def test_real_stalled_namespace_probe_is_killed_and_reaped(monkeypatch, name):
    from core.testing.wallclock import wall_deadline
    real_fork = os.fork
    children = []

    def fork():
        pid = real_fork()
        if pid > 0:
            children.append(pid)
        return pid

    def stalled_unshare(flags):
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(60)
        signal.pause()
        # Never let a test-only wakeup fall through to actual mounts.
        raise OSError(errno.EPERM, "test-only unshare refusal")

    patch_module_attribute(monkeypatch, probes, 'os', "fork", fork)
    patch_module_attribute(monkeypatch, probes, 'os', "unshare", stalled_unshare)
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: SimpleNamespace(mount=lambda *a: -1))
    monkeypatch.setattr(probes, "_PROBE_CHILD_TIMEOUT_S", 0.1)
    try:
        with wall_deadline(20, code_bound_s=60, what="stalled namespace capability probe"):
            assert getattr(probes, name)() is False
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


def test_cleanup_wait_errors_remain_visible(monkeypatch, caplog):
    calls, kills = [], []

    def wait(pid, flags):
        calls.append(True)
        if len(calls) == 1:
            return 0, 0
        raise OSError(errno.EIO, "injected cleanup failure")

    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    probes._cleanup_probe_child(PID, "test")
    assert kills == [(PID, signal.SIGKILL)]
    assert "cleanup wait failed" in caplog.text


@pytest.mark.parametrize("outcome", ["exit", "cancel"])
def test_pidfd_is_released_and_binds_cleanup_signal(monkeypatch, outcome):
    read_fd, write_fd = os.pipe()
    waits, signals = [], []
    failure = KeyboardInterrupt()

    def wait(pid, flags):
        waits.append(True)
        if outcome == "cancel" and len(waits) == 1:
            raise failure
        return pid, signal.SIGKILL

    patch_module_attribute(monkeypatch, probes, 'os', "pidfd_open", lambda pid: read_fd)
    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'signal', "pidfd_send_signal", lambda fd, sig: signals.append((fd, sig)), raising=False)
    try:
        if outcome == "cancel":
            with pytest.raises(KeyboardInterrupt) as raised:
                probes._wait_for_probe_child(PID, "test")
            assert raised.value is failure
            assert signals == [(read_fd, signal.SIGKILL)]
        else:
            assert probes._wait_for_probe_child(PID, "test") == signal.SIGKILL
            assert signals == []
        with pytest.raises(OSError) as raised:
            os.fstat(read_fd)
        assert raised.value.errno == errno.EBADF
    finally:
        os.close(write_fd)
        try:
            os.close(read_fd)
        except OSError:
            pass


def test_missing_pidfd_signal_api_uses_verified_pid_fallback(monkeypatch):
    failure = KeyboardInterrupt()
    calls, kills = [], []

    def wait(pid, flags):
        calls.append(True)
        if len(calls) == 1:
            raise failure
        return (pid, signal.SIGKILL) if kills else (0, 0)

    def unusable_pidfd(*args):
        raise AssertionError("opened pidfd without a signal API")

    monkeypatch.delattr(patch_module_attribute(monkeypatch, probes, 'signal', "__name__", probes.signal.__name__), "pidfd_send_signal", raising=False)
    patch_module_attribute(monkeypatch, probes, 'os', "pidfd_open", unusable_pidfd)
    patch_module_attribute(monkeypatch, probes, 'os', "waitpid", wait)
    patch_module_attribute(monkeypatch, probes, 'os', "kill", lambda *args: kills.append(args))
    with pytest.raises(KeyboardInterrupt) as raised:
        probes._wait_for_probe_child(PID, "test")
    assert raised.value is failure
    assert kills == [(PID, signal.SIGKILL)]
