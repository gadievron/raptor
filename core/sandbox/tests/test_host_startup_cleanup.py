"""Host preparation owns pipes and private output until setup succeeds."""

import errno
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace

import pytest

from core.sandbox import host as host_mod


@pytest.fixture
def setup_tracker(monkeypatch, tmp_path):
    import core.sandbox
    from core.sandbox import context, python_paths
    target = tmp_path / "target"
    target.mkdir()
    owned = []
    fds = []
    real_mkdtemp, real_pipe = tempfile.mkdtemp, os.pipe

    def mkdtemp(prefix):
        path = real_mkdtemp(prefix=prefix, dir=tmp_path)
        owned.append(path)
        return path

    def pipe():
        pair = real_pipe()
        fds.extend(pair)
        return pair

    monkeypatch.setattr(host_mod.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(host_mod.os, "pipe", pipe)
    monkeypatch.setattr(host_mod, "_resolve_daemon_script", lambda: Path(__file__))
    monkeypatch.setattr(context, "_require_userns_or_optin", lambda *a, **kw: False)
    monkeypatch.setattr(python_paths, "python_runtime_tool_paths", lambda: [])

    def must_not_spawn(*args, **kwargs):
        raise AssertionError("backend should not run during failed preparation")

    monkeypatch.setattr(core.sandbox, "run", must_not_spawn)
    return SimpleNamespace(target=target, owned=owned, fds=fds, pipe=pipe)


def assert_cleaned(tracker, explicit):
    for fd in tracker.fds:
        with pytest.raises(OSError) as raised:
            os.fstat(fd)
        assert raised.value.errno == errno.EBADF
    assert all(not os.path.exists(path) for path in tracker.owned)
    if explicit is not None:
        assert (explicit / "keep").read_text() == "caller-owned"


@pytest.mark.parametrize("explicit_output", [False, True])
@pytest.mark.parametrize("stage", [
    "pipe1", "pipe2", "paths", "thread_constructor", "host_constructor", "thread_start",
])
def test_preparation_failure_releases_resources(
    setup_tracker, monkeypatch, tmp_path, explicit_output, stage,
):
    from core.sandbox import python_paths
    tracker = setup_tracker
    explicit = tmp_path / "explicit" if explicit_output else None
    if explicit is not None:
        explicit.mkdir()
        (explicit / "keep").write_text("caller-owned")
    failure = OSError(errno.EMFILE, "injected preparation failure")
    pipe_calls = []
    starts = []

    def pipe():
        pipe_calls.append(True)
        if stage == "pipe" + str(len(pipe_calls)):
            raise failure
        return tracker.pipe()

    def paths():
        if stage == "paths":
            raise failure
        return []

    class Thread:
        def __init__(self, *args, **kwargs):
            if stage == "thread_constructor":
                raise failure

        def start(self):
            starts.append(True)
            if stage == "thread_start":
                raise failure
            raise AssertionError("thread started before handle construction succeeded")

        def join(self, timeout):
            raise RuntimeError("not started")

    class Host(host_mod.SandboxHost):
        def __init__(self, **kwargs):
            if stage == "host_constructor":
                raise failure
            super().__init__(**kwargs)

    monkeypatch.setattr(host_mod.os, "pipe", pipe)
    monkeypatch.setattr(python_paths, "python_runtime_tool_paths", paths)
    monkeypatch.setattr(host_mod, "threading", SimpleNamespace(
        Thread=Thread, Lock=threading.Lock, Event=threading.Event,
    ))
    with pytest.raises(OSError) as raised:
        Host.start(target=tracker.target, output=explicit)
    assert raised.value is failure
    if stage == "host_constructor":
        assert not starts
    assert_cleaned(tracker, explicit)


def test_interrupted_thread_start_never_launches_backend(setup_tracker, monkeypatch):
    tracker = setup_tracker
    failure = KeyboardInterrupt()
    threads = []

    class InterruptedStart(threading.Thread):
        def start(self):
            threads.append(self)
            super().start()
            raise failure

    monkeypatch.setattr(host_mod, "threading", SimpleNamespace(
        Thread=InterruptedStart, Lock=threading.Lock, Event=threading.Event,
    ))
    with pytest.raises(KeyboardInterrupt) as raised:
        host_mod.SandboxHost.start(target=tracker.target)
    assert raised.value is failure
    assert not threads[0].is_alive()
    assert_cleaned(tracker, None)


def test_cancelled_ping_preserves_spawn_fds_until_backend_returns(
    setup_tracker, monkeypatch,
):
    import core.sandbox
    tracker = setup_tracker
    entered, release = threading.Event(), threading.Event()
    errors = []
    failure = KeyboardInterrupt()

    def delayed_backend(*args, **kwargs):
        entered.set()
        if not release.wait(5):
            errors.append("backend was not released")
        for fd in kwargs["pass_fds"]:
            try:
                os.fstat(fd)
            except OSError as exc:
                errors.append(exc)
        return SimpleNamespace(returncode=0, stderr=b"")

    class Host(host_mod.SandboxHost):
        def _rpc(self, payload, *, timeout):
            if payload["cmd"] == "ping":
                assert entered.wait(5)
                raise failure
            release.set()
            return {"ok": True}

    monkeypatch.setattr(core.sandbox, "run", delayed_backend)
    try:
        with pytest.raises(KeyboardInterrupt) as raised:
            Host.start(target=tracker.target)
        assert raised.value is failure
        assert not errors
        assert_cleaned(tracker, None)
    finally:
        release.set()


def test_dead_backend_releases_spawn_fds_and_reports_exit(setup_tracker, monkeypatch):
    import core.sandbox
    tracker = setup_tracker
    monkeypatch.setattr(core.sandbox, "run", lambda *a, **kw: SimpleNamespace(
        returncode=97, stderr=b"backend exited",
    ))
    with pytest.raises(host_mod.HostRPCError, match="daemon died during startup") as raised:
        host_mod.SandboxHost.start(target=tracker.target, startup_timeout=1)
    assert "rc=97" in str(raised.value)
    assert "backend exited" in str(raised.value)
    assert_cleaned(tracker, None)


@pytest.mark.parametrize("explicit_output", [False, True])
@pytest.mark.parametrize("stage", ["paths", "serialize", "cancel"])
def test_one_shot_setup_failure_removes_only_owned_output(
    setup_tracker, monkeypatch, tmp_path, explicit_output, stage,
):
    import core.sandbox
    from core.sandbox import python_paths
    tracker = setup_tracker
    explicit = tmp_path / "explicit" if explicit_output else None
    if explicit is not None:
        explicit.mkdir()
        (explicit / "keep").write_text("caller-owned")
    failure = KeyboardInterrupt() if stage == "cancel" else RuntimeError("path failure")

    def paths():
        if stage == "paths":
            raise failure
        return []

    def cancelled(*args, **kwargs):
        raise failure

    monkeypatch.setattr(python_paths, "python_runtime_tool_paths", paths)
    if stage == "cancel":
        monkeypatch.setattr(core.sandbox, "run", cancelled)
    payload = {"value": object()} if stage == "serialize" else {}
    expected = TypeError if stage == "serialize" else type(failure)
    with pytest.raises(expected) as raised:
        host_mod.one_shot_call(cmd="ping", payload=payload, target=tracker.target, output=explicit)
    if stage != "serialize":
        assert raised.value is failure
    assert_cleaned(tracker, explicit)


def test_real_pipe_start_ping_and_close_release_resources(setup_tracker, monkeypatch):
    import subprocess
    import sys
    import core.sandbox
    from core.sandbox import _daemon
    tracker = setup_tracker
    calls = []

    def backend(argv, **kwargs):
        calls.append(kwargs)
        return subprocess.run(
            [sys.executable, "-S", _daemon.__file__, *argv[3:]],
            pass_fds=kwargs["pass_fds"], capture_output=True, timeout=10,
        )

    monkeypatch.setattr(core.sandbox, "run", backend)
    host = host_mod.SandboxHost.start(target=tracker.target, startup_timeout=5)
    try:
        assert host._daemon_fds is None
        assert os.path.isdir(tracker.owned[0])
        assert len(calls) == 1
    finally:
        host.close()
    assert not host._thread.is_alive()
    assert_cleaned(tracker, None)


def test_close_defers_private_output_cleanup_until_worker_exit(setup_tracker, monkeypatch):
    import core.sandbox
    tracker = setup_tracker
    entered, release = threading.Event(), threading.Event()

    def delayed_backend(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(returncode=0, stderr=b"")

    class QuickJoinThread(threading.Thread):
        def join(self, timeout=None):
            super().join(timeout=0)

    class Host(host_mod.SandboxHost):
        def _rpc(self, payload, *, timeout):
            if payload["cmd"] == "ping":
                assert entered.wait(5)
            return {"ok": True}

    monkeypatch.setattr(core.sandbox, "run", delayed_backend)
    monkeypatch.setattr(host_mod, "threading", SimpleNamespace(
        Thread=QuickJoinThread, Lock=threading.Lock, Event=threading.Event,
    ))
    host = Host.start(target=tracker.target)
    try:
        host.close()
        assert host._thread.is_alive()
        assert os.path.isdir(tracker.owned[0])
        release.set()
        threading.Thread.join(host._thread, timeout=2)
        assert not host._thread.is_alive()
        assert host._owned_output is None
        assert_cleaned(tracker, None)
    finally:
        release.set()
        threading.Thread.join(host._thread, timeout=2)
