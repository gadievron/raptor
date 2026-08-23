"""CONNECT TLS-identity peek (domain-fronting defence).

The proxy authorises the plaintext CONNECT authority, dials the
vetted IP, then relays opaque bytes — pre-fix a child could send a
TLS ClientHello carrying a DIFFERENT SNI and reach another tenant
behind a shared front end. The peek closes the cheap version of that:
a complete first-record ClientHello whose SNI mismatches the
authorised CONNECT hostname closes the tunnel with a recorded
`denied_sni` event and nothing forwarded upstream.

Equally load-bearing is what must NOT change: matching-SNI tunnels
stay byte-identical (the peeked bytes are forwarded), and non-TLS,
SNI-less, or inconclusive first bytes pass through unchanged — the
layer is best-effort by design.

Harness: real EgressProxy + loopback backend, gate 2 stood down for
the loopback backend as in test_proxy_tcp_keepalive.py.
"""

from __future__ import annotations

import socket
import threading

import pytest

from core.sandbox import proxy as proxy_mod
from core.sandbox.proxy import _parse_tls_client_hello_sni


def _client_hello(sni: str | None) -> bytes:
    """Minimal TLS 1.2-style ClientHello record, optionally carrying
    a server_name extension."""
    ext = b""
    if sni is not None:
        name = sni.encode("ascii")
        entry = b"\x00" + len(name).to_bytes(2, "big") + name
        lst = len(entry).to_bytes(2, "big") + entry
        ext = b"\x00\x00" + len(lst).to_bytes(2, "big") + lst
    exts = len(ext).to_bytes(2, "big") + ext
    body = (b"\x03\x03" + bytes(32)      # client_version + random
            + b"\x00"                    # session_id (empty)
            + b"\x00\x02\x13\x01"        # cipher_suites
            + b"\x01\x00"                # compression_methods
            + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class _Backend:
    """Loopback TCP backend that records what it receives and can
    reply — proves both directions of the tunnel byte-for-byte."""

    def __init__(self, reply: bytes = b""):
        self._srv = socket.socket()
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self.port = self._srv.getsockname()[1]
        self.received = b""
        self.accepted = threading.Event()
        self._reply = reply
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        self.accepted.set()
        conn.settimeout(5)
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                self.received += chunk
                if self._reply:
                    conn.sendall(self._reply)
                    self._reply = b""
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self._srv.close()
        self._thread.join(timeout=5)


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


@pytest.fixture
def loopback_ok(monkeypatch):
    """Gate 2 blocks loopback by design; the captive backend in these
    tests lives on loopback, so stand the gate down for it."""
    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", lambda ip: False)


def _open_tunnel(proxy_port: int, target: str) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\n"
              f"Host: {target}\r\n\r\n".encode("latin-1"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    assert b" 200 " in buf.split(b"\r\n", 1)[0], buf
    return s


def _recv_until_eof(s: socket.socket, timeout: float = 5.0) -> bytes:
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except OSError:
        pass
    return out


class TestSniMismatchDenied:

    def test_fronted_client_hello_closes_tunnel(
        self, reset_proxy, loopback_ok,
    ):
        backend = _Backend()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            token = proxy.register_sandbox(caller_label="t")
            s = _open_tunnel(proxy.port, f"127.0.0.1:{backend.port}")
            fronted = _client_hello("other-tenant.example")
            s.sendall(fronted)
            # Tunnel must be closed on the client side...
            assert _recv_until_eof(s) == b""
            s.close()
            events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()
            backend.close()
        # ...with a recorded denial event...
        denied = [e for e in events if e["result"] == "denied_sni"]
        assert len(denied) == 1, f"expected one denied_sni event: {events}"
        assert "other-tenant.example" in denied[0]["reason"]
        # ...and nothing forwarded upstream.
        assert backend.received == b"", (
            "fronted ClientHello bytes reached the backend"
        )
        assert not [e for e in events if e["result"] == "allowed"]

    def test_sni_match_is_case_insensitive(self, reset_proxy, loopback_ok):
        backend = _Backend(reply=b"SRV")
        proxy = proxy_mod.EgressProxy(allowed_hosts={"localhost"})
        try:
            s = _open_tunnel(proxy.port, f"localhost:{backend.port}")
            hello = _client_hello("LOCALHOST")
            s.sendall(hello)
            s.settimeout(5)
            assert s.recv(3) == b"SRV"
            s.close()
        finally:
            proxy.stop()
            backend.close()
        assert backend.received == hello


class TestPassThroughUnchanged:

    def test_matching_sni_tunnel_is_byte_identical(
        self, reset_proxy, loopback_ok,
    ):
        backend = _Backend(reply=b"PONG")
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, f"127.0.0.1:{backend.port}")
            hello = _client_hello("127.0.0.1")
            s.sendall(hello)
            s.settimeout(5)
            assert s.recv(4) == b"PONG"      # u2c leg alive
            s.sendall(b"MORE-APP-BYTES")     # c2u continues past the peek
            deadline = 50
            while (backend.received != hello + b"MORE-APP-BYTES"
                   and deadline):
                import time
                time.sleep(0.1)
                deadline -= 1
            s.close()
        finally:
            proxy.stop()
            backend.close()
        assert backend.received == hello + b"MORE-APP-BYTES", (
            "peeked bytes were not forwarded byte-identically"
        )

    def test_non_tls_first_bytes_pass_through(
        self, reset_proxy, loopback_ok,
    ):
        backend = _Backend(reply=b"HTTP/1.0 200 OK\r\n\r\n")
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, f"127.0.0.1:{backend.port}")
            payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
            s.sendall(payload)
            s.settimeout(5)
            assert s.recv(8) == b"HTTP/1.0"
            s.close()
        finally:
            proxy.stop()
            backend.close()
        assert backend.received == payload

    def test_sni_less_client_hello_passes_through(
        self, reset_proxy, loopback_ok,
    ):
        backend = _Backend(reply=b"OK")
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, f"127.0.0.1:{backend.port}")
            hello = _client_hello(None)
            s.sendall(hello)
            s.settimeout(5)
            assert s.recv(2) == b"OK"
            s.close()
        finally:
            proxy.stop()
            backend.close()
        assert backend.received == hello

    def test_inconclusive_fragment_passes_after_peek_deadline(
        self, reset_proxy, loopback_ok, monkeypatch,
    ):
        """A truncated first record (never completed) is inconclusive:
        after the peek deadline the bytes must be forwarded and the
        tunnel proceed unchecked — the layer never blocks on doubt."""
        monkeypatch.setattr(proxy_mod, "_TLS_PEEK_TIMEOUT_S", 0.3)
        backend = _Backend(reply=b"ACK")
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, f"127.0.0.1:{backend.port}")
            fragment = _client_hello("whatever.example")[:7]
            s.sendall(fragment)
            s.settimeout(5)
            assert s.recv(3) == b"ACK"
            s.close()
        finally:
            proxy.stop()
            backend.close()
        assert backend.received == fragment


class TestClientHelloParser:
    """Unit coverage of the classifier — no sockets."""

    def test_complete_hello_with_sni(self):
        status, sni = _parse_tls_client_hello_sni(
            _client_hello("api.example.com"))
        assert (status, sni) == ("sni", "api.example.com")

    def test_hello_without_sni_passes(self):
        assert _parse_tls_client_hello_sni(
            _client_hello(None)) == ("pass", None)

    def test_empty_and_partial_are_incomplete(self):
        hello = _client_hello("h.example")
        assert _parse_tls_client_hello_sni(b"")[0] == "incomplete"
        assert _parse_tls_client_hello_sni(hello[:3])[0] == "incomplete"
        assert _parse_tls_client_hello_sni(hello[:-1])[0] == "incomplete"

    def test_non_tls_passes(self):
        assert _parse_tls_client_hello_sni(b"GET / HTTP/1.1\r\n") == \
            ("pass", None)
        assert _parse_tls_client_hello_sni(b"\x00\x01\x02\x03\x04") == \
            ("pass", None)

    def test_non_client_hello_record_passes(self):
        # Handshake record whose first handshake byte is ServerHello.
        rec = b"\x16\x03\x03\x00\x04" + b"\x02\x00\x00\x00"
        assert _parse_tls_client_hello_sni(rec) == ("pass", None)

    def test_fragmented_hello_passes(self):
        """Handshake length exceeding the first record's payload means
        the ClientHello spans records — inconclusive, pass."""
        hello = _client_hello("h.example")
        rec_len = int.from_bytes(hello[3:5], "big")
        first_half = rec_len // 2
        frag = (hello[:3] + first_half.to_bytes(2, "big")
                + hello[5:5 + first_half])
        assert _parse_tls_client_hello_sni(frag) == ("pass", None)

    def test_malformed_extension_lengths_pass(self):
        hello = bytearray(_client_hello("h.example"))
        hello[-4] = 0xFF  # corrupt a length field inside server_name
        assert _parse_tls_client_hello_sni(bytes(hello)) == ("pass", None)

    def test_oversize_record_length_passes(self):
        rec = b"\x16\x03\x01\xff\xff" + b"\x01" * 10
        assert _parse_tls_client_hello_sni(rec) == ("pass", None)
