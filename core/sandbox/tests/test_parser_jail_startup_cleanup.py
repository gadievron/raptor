"""Parser startup releases uncommitted resources and keeps bounded backoff."""

import errno
import socket
import subprocess

import pytest

from core.sandbox import parser_jail as jail_mod

from core.testing.module_bindings import patch_module_attribute


class FakeProcess:
    pid = 12345

    def __init__(self):
        self.returncode = None
        self.kills = 0
        self.reaps = 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.kills += 1
        self.returncode = -9

    def wait(self, timeout):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("fake parser", timeout)
        self.reaps += 1
        return self.returncode


@pytest.mark.parametrize("stage", [
    "socketpair", "spawn", "spawn_close", "ready_timeout", "roundtrip_timeout",
    "protocol", "refused", "cancelled", "success",
])
def test_startup_owns_resources_until_commit(monkeypatch, stage):
    jail = jail_mod.ParserJail()
    real_socketpair = socket.socketpair
    sockets = []
    process = FakeProcess()
    failure = OSError(errno.EMFILE, "injected startup failure")
    timeout_calls = []

    class ParentSocket:
        def __init__(self, sock):
            self.sock = sock

        def settimeout(self, timeout):
            timeout_calls.append(timeout)
            if ((stage == "ready_timeout" and len(timeout_calls) == 1)
                    or (stage == "roundtrip_timeout" and len(timeout_calls) == 2)):
                raise failure
            self.sock.settimeout(timeout)

        def close(self):
            self.sock.close()

    class ChildSocket:
        def __init__(self, sock):
            self.sock = sock

        def fileno(self):
            return self.sock.fileno()

        def close(self):
            self.sock.close()
            if stage == "spawn_close":
                raise OSError(errno.EIO, "injected cleanup failure")

    def socketpair():
        if stage == "socketpair":
            raise failure
        parent, child = real_socketpair()
        sockets.extend((parent, child))
        return ParentSocket(parent), ChildSocket(child)

    def popen(*args, **kwargs):
        if stage in ("spawn", "spawn_close"):
            raise failure
        return process

    def ready(_):
        if stage == "protocol":
            raise jail_mod._ProtocolError("injected protocol failure")
        if stage == "refused":
            return {"ready": False, "error": "injected refusal"}
        if stage == "cancelled":
            raise KeyboardInterrupt()
        return {"ready": True, "landlock": True}

    patch_module_attribute(monkeypatch, jail_mod, "socket", "socketpair", socketpair)
    patch_module_attribute(monkeypatch, jail_mod, "subprocess", "Popen", popen)
    monkeypatch.setattr(jail, "_read_ready_frame", ready)
    monkeypatch.setattr(jail_mod, "_raptor_dir", lambda: "/tmp")
    try:
        if stage == "success":
            jail.start()
            assert jail._proc is process
            assert sockets[0].fileno() >= 0
            assert sockets[1].fileno() == -1
            assert process.kills == 0
            jail.stop()
        elif stage == "cancelled":
            with pytest.raises(KeyboardInterrupt):
                jail.start()
            assert jail._spawn_failures == 0
        else:
            with pytest.raises(jail_mod.ParserJailUnavailable) as raised:
                jail.start()
            if stage == "spawn_close":
                assert raised.value.__cause__ is failure
            assert jail._spawn_failures == 1
            assert jail._next_spawn_attempt > 0
            jail._next_spawn_attempt = float("inf")
            with pytest.raises(jail_mod.ParserJailUnavailable, match="backing off"):
                jail.start()
        assert all(sock.fileno() == -1 for sock in sockets)
        assert jail._proc is None
        assert jail._sock is None
        if stage not in ("socketpair", "spawn", "spawn_close"):
            assert process.kills == 1
            assert process.reaps == 1
    finally:
        jail.stop()
        for sock in sockets:
            sock.close()


@pytest.mark.parametrize("previous,delay", [
    (0, 0.1), (1, 0.2), (5, 3.2), (6, 5.0), (10000, 5.0),
])
def test_spawn_backoff_saturates_without_overflow(monkeypatch, previous, delay):
    jail = jail_mod.ParserJail()
    jail._spawn_failures = previous
    failure = jail_mod.ParserJailUnavailable("persistent outage")

    def unavailable():
        raise failure

    monkeypatch.setattr(jail, "_spawn_worker_locked", unavailable)
    patch_module_attribute(monkeypatch, jail_mod, "time", "monotonic", lambda: 100.0)
    with pytest.raises(jail_mod.ParserJailUnavailable) as raised:
        jail.start()
    assert raised.value is failure
    assert jail._spawn_failures == previous + 1
    assert jail._next_spawn_attempt == pytest.approx(100.0 + delay)
