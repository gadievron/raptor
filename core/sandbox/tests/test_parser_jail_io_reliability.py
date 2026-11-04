"""Bounded parser exchanges and predictable handling of worker failures."""

import fcntl
import json
import resource
import socket
from types import SimpleNamespace

import pytest

from core.sandbox import parser_jail as jail_mod
from core.sandbox._request_head import ParsedRequestLine, ParseRefusal


@pytest.mark.parametrize("census", [[], {}, 1, None])
def test_invalid_census_is_a_protocol_refusal(monkeypatch, census):
    from core.sandbox.tests.test_parser_jail import _fake_subprocess, _READY_OK, _scripted
    payload = json.dumps({"ok": False, "reason": "refused", "census": census}).encode()
    monkeypatch.setattr(jail_mod, "subprocess", _fake_subprocess(_READY_OK, _scripted(payload)))
    jail = jail_mod.ParserJail()
    try:
        jail.start()
        got = jail.parse(b"CONNECT example.com:443 HTTP/1.1")
        assert isinstance(got, ParseRefusal)
        assert "protocol violation" in got.reason
        assert jail._proc is None
        assert jail._sock is None
    finally:
        jail.stop()


@pytest.mark.parametrize("frame", ["ready", "verdict"])
def test_decoder_recursion_failure_is_protocol_error(monkeypatch, frame):
    failure = RecursionError("injected decoder depth failure")

    def too_deep(*args, **kwargs):
        raise failure

    monkeypatch.setattr(jail_mod, "json", SimpleNamespace(loads=too_deep))
    if frame == "verdict":
        with pytest.raises(jail_mod._ProtocolError) as raised:
            jail_mod._validate_verdict(b"{}")
    else:
        parent, child = socket.socketpair()
        try:
            parent.settimeout(1)
            child.sendall(jail_mod.FRAME_HEADER.pack(2, jail_mod.READY_FRAME_ID) + b"{}")
            with pytest.raises(jail_mod._ProtocolError) as raised:
                jail_mod.ParserJail()._read_ready_frame(parent)
        finally:
            parent.close()
            child.close()
    assert raised.value.__cause__ is failure


@pytest.mark.parametrize("frame", ["ready", "verdict"])
def test_header_and_payload_share_one_deadline(monkeypatch, frame):
    clock = [0.0]
    monkeypatch.setattr(jail_mod.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(jail_mod, "_READY_TIMEOUT_S", 1.0)
    monkeypatch.setattr(jail_mod, "_ROUNDTRIP_TIMEOUT_S", 1.0)
    payload = b'{"ok":true,"host":"example.com","port":443}'
    frame_id = jail_mod.READY_FRAME_ID if frame == "ready" else 17

    class SlowSocket:
        def __init__(self):
            self.timeout = 1.0
            self.data = jail_mod.FRAME_HEADER.pack(len(payload), frame_id) + payload
            self.receives = 0

        def gettimeout(self):
            return self.timeout

        def settimeout(self, value):
            self.timeout = value

        def sendall(self, data):
            pass

        def recv(self, n):
            self.receives += 1
            # Each fragment fits the original socket timeout, but the
            # complete exchange exceeds its one-second budget.
            if self.timeout < 0.6:
                clock[0] += self.timeout
                raise socket.timeout("injected slow frame")
            clock[0] += 0.6
            result, self.data = self.data[:n], self.data[n:]
            return result

    class QuietPoll:
        def register(self, *args):
            pass

        def poll(self, *args):
            return []

    sock = SlowSocket()
    jail = jail_mod.ParserJail()
    if frame == "ready":
        with pytest.raises(socket.timeout):
            jail._read_ready_frame(sock)
    else:
        jail._sock = sock
        monkeypatch.setattr(jail, "_new_req_id", lambda: 17)
        monkeypatch.setattr(jail_mod.select, "poll", QuietPoll)
        with pytest.raises(OSError, match="round-trip timed out"):
            jail._roundtrip_locked(b"request")
    assert clock[0] == pytest.approx(1.0)
    assert sock.receives == 2
    assert sock.gettimeout() == 1.0


def test_recv_fragments_cannot_reset_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(jail_mod.time, "monotonic", lambda: clock[0])

    class FragmentSocket:
        timeout = 5.0
        received = 0

        def gettimeout(self):
            return self.timeout

        def settimeout(self, value):
            self.timeout = value

        def recv(self, n):
            if self.timeout < 0.4:
                clock[0] += self.timeout
                raise socket.timeout("injected fragmented frame")
            clock[0] += 0.4
            self.received += 1
            return b"x"

    sock = FragmentSocket()
    with pytest.raises(socket.timeout):
        jail_mod.ParserJail._recv_exact(sock, 4, deadline=1.0)
    assert clock[0] == pytest.approx(1.0)
    assert sock.received == 2
    assert sock.gettimeout() == 5.0


def test_high_descriptor_worker_still_parses(monkeypatch):
    from core.sandbox.tests.test_parser_jail import (
        _fake_subprocess, _READY_OK, _honest_responder,
    )
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard <= 2048:
        pytest.skip("host hard limit prevents high descriptor test")
    monkeypatch.setattr(jail_mod, "subprocess", _fake_subprocess(_READY_OK, _honest_responder))
    jail = jail_mod.ParserJail()
    try:
        jail.start()
        if soft != resource.RLIM_INFINITY and soft <= 2048:
            resource.setrlimit(resource.RLIMIT_NOFILE, (2049, hard))
        high_fd = fcntl.fcntl(jail._sock.fileno(), fcntl.F_DUPFD, 2048)
        high_sock = socket.socket(fileno=high_fd)
        high_sock.settimeout(jail_mod._ROUNDTRIP_TIMEOUT_S)
        jail._sock.close()
        jail._sock = high_sock
        assert jail.parse(b"CONNECT example.com:443 HTTP/1.1") == ParsedRequestLine(
            host="example.com", port=443,
        )
    finally:
        jail.stop()
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
