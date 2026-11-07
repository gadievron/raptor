"""Landlock verdict reads share a bounded, owned child lifecycle."""

import ctypes.util
import errno
import os
import select
import signal
import sys
import tempfile
import time

import pytest

from core.sandbox import landlock, probes

from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux Landlock probes")
PID = 424242


@pytest.fixture(autouse=True)
def _owned_local_probe_modules(monkeypatch):
    """Keep fork/read faults on the real probe code's private lookup graph."""
    import builtins
    from core.testing.module_views import module_function_view

    os_view = module_function_view(os)
    select_view = module_function_view(select)
    tempfile_view = module_function_view(tempfile)
    util_view = module_function_view(ctypes.util)
    ctypes_view = module_function_view(__import__("ctypes"), bindings={"util": util_view})
    imports = {"os": os_view, "select": select_view, "tempfile": tempfile_view}
    owned = {}

    def import_owned(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in imports:
            return imports[name]
        if level == 1 and name == "probes" and globals.get("__package__") == "core.sandbox":
            return owned["probes"]
        return builtins.__import__(name, globals, locals, fromlist, level)

    probe_view = module_function_view(probes, bindings={"os": os_view, "select": select_view}, import_hook=import_owned)
    owned["probes"] = probe_view
    landlock_view = module_function_view(
        landlock, bindings={"os": os_view, "select": select_view, "tempfile": tempfile_view, "ctypes": ctypes_view},
        import_hook=import_owned,
    )
    monkeypatch.setitem(globals(), "probes", probe_view)
    monkeypatch.setitem(globals(), "landlock", landlock_view)




def closed(fd):
    with pytest.raises(OSError) as raised:
        os.fstat(fd)
    assert raised.value.errno == errno.EBADF


def test_pipe_allocation_failure_is_unavailable(monkeypatch):
    def no_pipe():
        raise OSError(errno.EMFILE, "pipe unavailable")

    monkeypatch.setattr(landlock.os, "pipe", no_pipe)
    assert landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file") is False


@pytest.mark.parametrize("failure", [OSError(errno.EAGAIN, "fork failed"), KeyboardInterrupt(), SystemExit()])
def test_failed_fork_releases_both_pipe_ends(monkeypatch, failure):
    real_pipe = os.pipe
    fds = []

    def pipe():
        pair = real_pipe()
        fds.extend(pair)
        return pair

    def fork():
        raise failure

    monkeypatch.setattr(landlock.os, "pipe", pipe)
    monkeypatch.setattr(landlock.os, "fork", fork)
    if isinstance(failure, OSError):
        assert landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file") is False
    else:
        with pytest.raises(type(failure)) as raised:
            landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file")
        assert raised.value is failure
    assert len(fds) == 2
    for fd in fds:
        closed(fd)


@pytest.fixture
def verdict_fixture(monkeypatch):
    real_pipe = os.pipe
    fds = []
    verdict = [b"\x01"]
    status = [0]

    def pipe():
        pair = real_pipe()
        fds.extend(pair)
        if verdict[0]:
            os.write(pair[1], verdict[0])
        return pair

    def wait(pid, label, *, before_wait):
        try:
            before_wait(time.monotonic() + 1)
        except OSError:
            return None
        return status[0]

    monkeypatch.setattr(landlock.os, "pipe", pipe)
    monkeypatch.setattr(landlock.os, "fork", lambda: PID)
    monkeypatch.setattr(probes, "_wait_for_probe_child", wait)
    return fds, verdict, status


@pytest.mark.parametrize("byte,status,expected", [
    (b"\x01", 0, True), (b"\x01", 1 << 8, False),
    (b"\x01", signal.SIGKILL, False), (b"\x00", 0, False),
    (b"\x02", 0, False), (b"", 0, False),
])
def test_verdict_requires_successful_byte_and_clean_exit(verdict_fixture, byte, status, expected):
    fds, verdict, exit_status = verdict_fixture
    verdict[0], exit_status[0] = byte, status
    assert landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file") is expected
    for fd in fds:
        closed(fd)


def test_interrupted_verdict_read_retries_without_losing_byte(verdict_fixture, monkeypatch):
    fds, _, _ = verdict_fixture
    real_read = os.read
    calls = []

    def read(fd, size):
        calls.append(True)
        if len(calls) == 1:
            raise InterruptedError()
        return real_read(fd, size)

    monkeypatch.setattr(landlock.os, "read", read)
    assert landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file") is True
    assert len(calls) == 2
    for fd in fds:
        closed(fd)


def test_failed_writer_close_is_not_retried(verdict_fixture, monkeypatch):
    fds, _, _ = verdict_fixture
    real_close = os.close
    calls = []

    def close(fd):
        calls.append(fd)
        real_close(fd)
        if len(fds) == 2 and fd == fds[1]:
            raise InterruptedError("close already released the Linux descriptor")

    with monkeypatch.context() as patch:
        patch.setattr(landlock.os, "close", close)
        assert landlock._fork_and_run_selftest(None, 1, "probe", "grant", "file") is False
    assert calls.count(fds[1]) == 1
    for fd in fds:
        closed(fd)


@pytest.mark.parametrize("failure", [OSError(errno.EIO, "read failed"), ChildProcessError(errno.ECHILD, "callback error"), KeyboardInterrupt()])
def test_parent_action_failure_retains_child_cleanup(monkeypatch, failure):
    cleaned = []

    def no_pidfd(pid):
        raise OSError(errno.ENOSYS, "test has no kernel child")

    def action(deadline):
        raise failure

    monkeypatch.setattr(probes.os, "pidfd_open", no_pidfd, raising=False)
    monkeypatch.setattr(probes, "_cleanup_probe_child", lambda *args, **kwargs: cleaned.append(args))
    if isinstance(failure, OSError):
        assert probes._wait_for_probe_child(PID, "test", before_wait=action) is None
    else:
        with pytest.raises(KeyboardInterrupt) as raised:
            probes._wait_for_probe_child(PID, "test", before_wait=action)
        assert raised.value is failure
    assert cleaned == [(PID, "test")]


def test_parent_action_and_exit_share_deadline(monkeypatch):
    clock = [0.0]
    deadlines = []

    def no_pidfd(pid):
        raise OSError(errno.ENOSYS, "test has no kernel child")

    def action(deadline):
        deadlines.append(deadline)
        clock[0] += 4.0

    def wait(pid, deadline):
        deadlines.append(deadline)
        return 0

    patch_module_attribute(monkeypatch, probes, "time", "monotonic", lambda: clock[0])
    monkeypatch.setattr(probes.os, "pidfd_open", no_pidfd, raising=False)
    monkeypatch.setattr(probes, "_poll_probe_child_exit", wait)
    monkeypatch.setattr(probes, "_PROBE_CHILD_TIMEOUT_S", 5.0)
    assert probes._wait_for_probe_child(PID, "test", before_wait=action) == 0
    assert deadlines == [5.0, 5.0]


@pytest.mark.parametrize("phase", [
    "normal", "negative", "before_verdict", "after_verdict", "abnormal_exit", "read_error", "cancel",
])
def test_real_probe_child_and_artifacts_are_cleaned(monkeypatch, tmp_path, phase):
    from core.testing.wallclock import wall_deadline
    real_fork, real_pipe, real_exit, real_read = os.fork, os.pipe, os._exit, os.read
    children, fds = [], []
    parent = os.getpid()
    cancellation = KeyboardInterrupt()

    def stall():
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        signal.alarm(60)
        signal.pause()

    def fork():
        pid = real_fork()
        if pid > 0:
            children.append(pid)
        return pid

    def pipe():
        pair = real_pipe()
        fds.extend(pair)
        return pair

    def selftest(*args):
        if phase == "before_verdict":
            stall()
        return 0 if phase == "negative" else 1

    def exit_child(code):
        if os.getpid() != parent:
            if phase == "after_verdict":
                stall()
            if phase == "abnormal_exit":
                real_exit(5)
        real_exit(code)

    def read(fd, size):
        if phase == "read_error" and fds and fd == fds[0]:
            raise OSError(errno.EIO, "injected parent read error")
        return real_read(fd, size)

    class CancelPoll:
        def register(self, *args):
            pass

        def poll(self, *args):
            raise cancellation

    monkeypatch.setattr(landlock.ctypes.util, "find_library", lambda name: None)
    monkeypatch.setattr(landlock.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(landlock.os, "fork", fork)
    monkeypatch.setattr(landlock.os, "pipe", pipe)
    monkeypatch.setattr(landlock.os, "_exit", exit_child)
    monkeypatch.setattr(landlock.os, "read", read)
    monkeypatch.setattr(landlock, "_run_selftest_in_child", selftest)
    monkeypatch.setattr(probes, "_PROBE_CHILD_TIMEOUT_S", 0.1)
    if phase == "cancel":
        monkeypatch.setattr(probes.select, "poll", CancelPoll)
    try:
        with wall_deadline(20, code_bound_s=60, what="Landlock self-test lifecycle"):
            if phase == "cancel":
                with pytest.raises(KeyboardInterrupt) as raised:
                    landlock._landlock_functional_self_test(1)
                assert raised.value is cancellation
            else:
                assert landlock._landlock_functional_self_test(1) is (phase == "normal")
        assert len(children) == 1
        with pytest.raises(ChildProcessError):
            os.waitpid(children[0], os.WNOHANG)
        for fd in fds:
            closed(fd)
        assert not list(tmp_path.iterdir())
    finally:
        for pid in children:
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
                if waited == 0:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            except ChildProcessError:
                pass
