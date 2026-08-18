"""Tests for TCP keepalive on established tunnel legs.

Corporate proxies, NAT gateways, and stateful firewalls drop
connection state for tunnels that go quiet — a thinking model can be
silent for minutes on a tunnel carrying zero bytes. Keepalive probes
refresh the per-TCP-leg state so the response still has a transport
to land on. Unix-socket lanes have no such middleboxes and are
skipped.
"""

from __future__ import annotations

import socket

import pytest

from core.sandbox.proxy import (
    _TCP_KEEPALIVE_IDLE_S,
    _enable_tcp_keepalive,
)


class _FakeWriter:
    """Just enough asyncio.StreamWriter for the helper: it only calls
    ``get_extra_info("socket")``."""

    def __init__(self, sock):
        self._sock = sock

    def get_extra_info(self, name):
        return self._sock if name == "socket" else None


@pytest.fixture
def tcp_pair():
    """A connected AF_INET socket pair (real kernel sockets — the
    keepalive options only make sense on those)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(server.getsockname())
    accepted, _ = server.accept()
    yield client, accepted
    client.close()
    accepted.close()
    server.close()


def test_enables_so_keepalive_on_tcp(tcp_pair):
    client, _ = tcp_pair
    assert client.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0
    _enable_tcp_keepalive(_FakeWriter(client))
    # POSIX only promises a non-zero value for an enabled boolean
    # option — macOS getsockopt returns the internal flag bit (8),
    # not 1, so assert truthiness rather than the literal.
    assert client.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0


@pytest.mark.skipif(
    not hasattr(socket, "TCP_KEEPIDLE"),
    reason="platform has no TCP_KEEPIDLE",
)
def test_sets_idle_time_on_linux(tcp_pair):
    client, _ = tcp_pair
    _enable_tcp_keepalive(_FakeWriter(client))
    assert client.getsockopt(
        socket.IPPROTO_TCP, socket.TCP_KEEPIDLE,
    ) == _TCP_KEEPALIVE_IDLE_S


def test_unix_socket_leg_is_skipped():
    """Sandbox lanes ride AF_UNIX — no middlebox, no keepalive, and
    the TCP options would error there."""
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        _enable_tcp_keepalive(_FakeWriter(left))  # must not raise
        assert left.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) == 0
    finally:
        left.close()
        right.close()


def test_missing_socket_info_is_tolerated():
    _enable_tcp_keepalive(_FakeWriter(None))  # must not raise


def test_setsockopt_failure_is_non_fatal(tcp_pair):
    client, _ = tcp_pair
    client.close()  # EBADF on setsockopt
    _enable_tcp_keepalive(_FakeWriter(client))  # must not raise


def test_established_tunnel_enables_keepalive_on_both_legs(monkeypatch):
    """End-to-end call-site check: a CONNECT that reaches the relay
    stage must arm keepalive on the client leg AND the upstream leg."""
    import threading

    from core.sandbox import proxy as proxy_mod

    armed = []
    real = proxy_mod._enable_tcp_keepalive

    def recording(writer):
        armed.append(writer)
        real(writer)

    monkeypatch.setattr(proxy_mod, "_enable_tcp_keepalive", recording)
    # Gate 2 blocks loopback IPs by design; the captive upstream in
    # this test lives on loopback, so stand the gate down for it.
    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", lambda ip: False)

    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.bind(("127.0.0.1", 0))
    upstream.listen(1)
    up_port = upstream.getsockname()[1]

    def serve_once():
        conn, _ = upstream.accept()
        conn.recv(16)
        conn.close()

    server_thread = threading.Thread(target=serve_once, daemon=True)
    server_thread.start()

    proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
    try:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5.0)
        try:
            s.sendall(
                f"CONNECT 127.0.0.1:{up_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{up_port}\r\n\r\n".encode("latin-1")
            )
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            assert b" 200 " in buf.split(b"\r\n", 1)[0]
            s.sendall(b"ping")
        finally:
            s.close()
        server_thread.join(timeout=5.0)
    finally:
        proxy.stop()
        upstream.close()

    assert len(armed) == 2, "keepalive must be armed on both tunnel legs"
