"""Parent RPC failures keep their typed error and cleanup contracts."""

import errno
import fcntl
import json
import os
import resource
import struct
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.sandbox import host as host_mod
from core.sandbox.tests.pipe_host import fake_host
from core.testing.pipes import pipes_for_setup


def frame(body):
    return struct.pack("!I", len(body)) + body


def one_shot_fixture(monkeypatch, tmp_path, stdout):
    from core.sandbox import context
    import core.sandbox
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr(context, "_require_userns_or_optin", lambda *a, **kw: False)
    monkeypatch.setattr(host_mod, "_resolve_daemon_script", lambda: Path(__file__))

    def run(*args, **kwargs):
        request = json.loads(kwargs["input"][4:])
        data = stdout(request) if callable(stdout) else stdout
        return SimpleNamespace(stdout=data, stderr=b"", returncode=0)

    monkeypatch.setattr(core.sandbox, "run", run)
    return lambda: host_mod.one_shot_call(
        cmd="ping", payload={}, target=target, output=tmp_path / "output",
    )


@pytest.mark.parametrize("body", [
    b"[]", b"null", b"42", b"bad JSON", b"\xff",
    b'{"value":' + b"9" * 641 + b'}',
])
@pytest.mark.parametrize("mode", ["persistent", "one-shot"])
def test_malformed_reply_is_host_rpc_error(monkeypatch, tmp_path, body, mode):
    limit = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    read_fd = write_fd = None
    try:
        if mode == "one-shot":
            call = one_shot_fixture(monkeypatch, tmp_path, frame(body))
        else:
            read_fd, write_fd = os.pipe()
            os.write(write_fd, frame(body))
            host = object.__new__(host_mod.SandboxHost)
            host._read_fd = read_fd
            call = lambda: host._read_frame(timeout=1)
        with pytest.raises(host_mod.HostRPCError):
            call()
    finally:
        sys.set_int_max_str_digits(limit)
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)


@pytest.mark.parametrize("source", ["daemon", "one-shot"])
def test_decoder_recursion_error_is_typed(monkeypatch, source):
    failure = RecursionError("injected decoder failure")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(host_mod, "json", SimpleNamespace(loads=fail))
    with pytest.raises(host_mod.HostRPCError) as raised:
        host_mod._decode_response(b"{}", source=source)
    assert raised.value.__cause__ is failure


@pytest.mark.parametrize("data,cap,error", [
    (frame(b"123456789"), 8, "frame too large"),
    (frame(b"{}") + b"extra", 1024, "trailing bytes"),
    (struct.pack("!I", 8) + b"{}", 1024, "truncated"),
])
def test_one_shot_frame_bounds(monkeypatch, tmp_path, data, cap, error):
    monkeypatch.setattr(host_mod, "_MAX_REPLY_FRAME_BYTES", cap)
    call = one_shot_fixture(monkeypatch, tmp_path, data)
    with pytest.raises(host_mod.HostRPCError, match=error):
        call()


def test_one_shot_matching_reply_still_accepted(monkeypatch, tmp_path):
    def reply(request):
        return frame(json.dumps({"ok": True, "rid": request["rid"]}).encode())

    call = one_shot_fixture(monkeypatch, tmp_path, reply)
    assert call() == {"ok": True}


def test_close_releases_descriptors_after_nonobject_reply():
    host, thread, errors = fake_host(lambda request: [])
    owned = (host._read_fd, host._write_fd)
    try:
        host.close()
        assert not thread.is_alive()
        assert not errors
        for fd in owned:
            with pytest.raises(OSError) as raised:
                os.fstat(fd)
            assert raised.value.errno == errno.EBADF
    finally:
        for fd in owned:
            try:
                os.close(fd)
            except OSError:
                pass
        thread.join(2)


def test_high_numbered_reply_descriptor_is_supported():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard <= 2048:
        pytest.skip("host hard limit prevents high descriptor test")
    host, thread, errors = fake_host(lambda request: {"ok": True, "rid": request["rid"]})
    try:
        if soft != resource.RLIM_INFINITY and soft <= 2048:
            resource.setrlimit(resource.RLIMIT_NOFILE, (2049, hard))
        old_read = host._read_fd
        host._read_fd = fcntl.fcntl(old_read, fcntl.F_DUPFD, 2048)
        os.close(old_read)
        assert host._rpc({"cmd": "ping"}, timeout=2) == {"ok": True}
    finally:
        try:
            host.close()
        finally:
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
    assert not thread.is_alive()
    assert not errors


def test_zero_progress_request_write_raises_host_rpc_error(monkeypatch):
    calls = []

    def write(fd, data):
        calls.append(len(data))
        if len(calls) == 1:
            return 2
        if len(calls) == 2:
            return 0
        raise AssertionError("retried zero-progress write")

    monkeypatch.setattr(host_mod, "os", SimpleNamespace(write=write))
    host = object.__new__(host_mod.SandboxHost)
    host._write_fd = 123
    with pytest.raises(host_mod.HostRPCError, match="write to daemon failed"):
        host._write_frame({"cmd": "ping"})
    assert len(calls) == 2


def test_reply_eof_wakes_poll_without_waiting_for_deadline():
    with pipes_for_setup(1) as ((read_fd, write_fd),):
        host = object.__new__(host_mod.SandboxHost)
        host._read_fd = read_fd
    os.close(write_fd)
    try:
        with pytest.raises(host_mod.HostRPCError, match="daemon EOF"):
            host._read_exact(1, time.monotonic() + 10)
    finally:
        os.close(read_fd)
