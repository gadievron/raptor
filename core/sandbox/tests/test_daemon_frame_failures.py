"""RPC framing fails explicitly without crashing command dispatch."""

import errno
import json
import struct
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _daemon as daemon


def frame(value):
    body = json.dumps(value).encode("utf-8")
    return struct.pack("!I", len(body)) + body


def decode_response(data):
    assert len(data) >= 4, "daemon did not return a framed response"
    length, = struct.unpack("!I", data[:4])
    assert len(data) == length + 4
    return json.loads(data[4:])


@pytest.mark.parametrize("raw_frame,error", [
    (b"", "empty stdin"),
    (b"\x00", "truncated RPC header"),
    (b"\x00\x00\x00", "truncated RPC header"),
    (struct.pack("!I", 8) + b"{}", "truncated RPC body"),
    (struct.pack("!I", 64 * 1024 * 1024 + 1), "frame too large"),
    (frame([]), "JSON object"),
    (frame(None), "JSON object"),
    (frame("text"), "JSON object"),
    (frame(42), "JSON object"),
])
def test_one_shot_rejects_incomplete_or_nonobject_frame(raw_frame, error):
    result = subprocess.run(
        [sys.executable, "-S", daemon.__file__, "--one-shot"],
        input=raw_frame, capture_output=True, timeout=10,
    )
    response = decode_response(result.stdout)
    assert result.returncode == 1
    assert response["ok"] is False
    assert error in response["error"]
    assert b"Traceback" not in result.stderr


@pytest.mark.parametrize("command", [[], {}, None, 42, False])
def test_invalid_command_returns_structured_error(command):
    result = subprocess.run(
        [sys.executable, "-S", daemon.__file__, "--one-shot"],
        input=frame({"cmd": command, "rid": "request-1"}),
        capture_output=True, timeout=10,
    )
    response = decode_response(result.stdout)
    assert result.returncode == 1
    assert response["ok"] is False
    assert "unknown cmd" in response["error"]
    assert response["rid"] == "request-1"
    assert b"Traceback" not in result.stderr


def test_persistent_daemon_recovers_after_invalid_command():
    from core.sandbox.tests.test_daemon_rpc_hardening import _PipeDaemon
    worker = _PipeDaemon()
    try:
        response = worker.rpc({"cmd": [], "rid": "bad"})
        assert response["ok"] is False
        assert response["rid"] == "bad"
        pong = worker.rpc({"cmd": "ping", "rid": "next"})
        assert pong["ok"] is True
        assert pong["rid"] == "next"
    finally:
        worker.close()


def test_fragmented_consecutive_frames_are_read_without_overread(monkeypatch):
    first = {"cmd": "ping", "text": "a" * 32768}
    second = {"cmd": "close"}
    stream = bytearray(frame(first) + frame(second))

    def fragmented_read(fd, size):
        chunk = bytes(stream[:min(size, 7)])
        del stream[:len(chunk)]
        return chunk

    monkeypatch.setattr(daemon, "os", SimpleNamespace(read=fragmented_read))
    assert daemon._read_frame(123) == first
    assert daemon._read_frame(123) == second
    assert daemon._read_frame(123) is None


def test_partial_writes_deliver_one_complete_frame(monkeypatch):
    output = bytearray()

    def partial_write(fd, data):
        count = min(len(data), 3)
        output.extend(data[:count])
        return count

    monkeypatch.setattr(daemon, "os", SimpleNamespace(write=partial_write))
    payload = {"ok": True, "text": "multiple partial writes"}
    daemon._write_frame(123, payload)
    assert decode_response(output) == payload


def test_zero_progress_write_fails_instead_of_retrying_forever(monkeypatch):
    calls = []

    def stalled_write(fd, data):
        calls.append(len(data))
        if len(calls) == 1:
            return 2
        if len(calls) == 2:
            return 0
        raise AssertionError("retried a zero-progress frame write")

    monkeypatch.setattr(daemon, "os", SimpleNamespace(write=stalled_write))
    with pytest.raises(OSError) as raised:
        daemon._write_frame(123, {"ok": True})
    assert raised.value.errno == errno.EIO
    assert len(calls) == 2
