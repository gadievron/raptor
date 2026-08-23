"""Same-UID gate on the proxy's loopback TCP listeners.

Loopback is shared with every local user: without a peer-credential
check, any other account on the host could connect to the proxy's
main listener (or a TCP lane) and ride its allowlisted egress. TCP
has no SO_PEERCRED, so the proxy reads the peer's UID from its
/proc/net/tcp{,6} socket row and refuses cross-user connections.

Covers the /proc parsing helpers, the live same-UID accept path, and
the rejection path (via a monkeypatched foreign UID — tests cannot
mint a second local user).
"""

from __future__ import annotations

import os
import socket
import sys

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


class TestHexHelpers:

    def test_v4_localhost(self):
        assert proxy_mod._hex_v4("127.0.0.1") == "0100007F"

    def test_v6_localhost(self):
        assert proxy_mod._hex_v6("::1") == (
            "00000000" "00000000" "00000000" "01000000"
        )


@pytest.mark.skipif(sys.platform != "linux",
                    reason="/proc/net/tcp is Linux-only")
class TestLoopbackPeerUidLookup:

    def test_established_loopback_pair_reports_own_uid(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli = None
        conn = None
        try:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            cli = socket.create_connection(srv.getsockname(), timeout=5.0)
            conn, _ = srv.accept()
            # From the server's perspective: peer == the client's
            # (addr, port); sockname == the accepted socket's local end.
            uid = proxy_mod._loopback_peer_uid(
                conn.getpeername(), conn.getsockname(),
            )
            assert uid == os.geteuid()
        finally:
            for s in (conn, cli, srv):
                if s is not None:
                    s.close()

    def test_unknown_peer_returns_none(self):
        # A (peer, sockname) pair that matches no established socket.
        assert proxy_mod._loopback_peer_uid(
            ("127.0.0.1", 1), ("127.0.0.1", 2),
        ) is None

    def test_malformed_tuples_return_none(self):
        assert proxy_mod._loopback_peer_uid(None, None) is None
        assert proxy_mod._loopback_peer_uid((), ()) is None


def _connect_raw(port: int, timeout: float = 5.0) -> bytes:
    """Open a TCP connection to the proxy, send a CONNECT, return the
    raw response bytes ("" when the proxy dropped the connection)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(b"CONNECT denied-host.invalid:443 HTTP/1.1\r\n"
                  b"Host: denied-host.invalid:443\r\n\r\n")
        buf = b""
        try:
            while b"\r\n" not in buf:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        except OSError:
            pass
        return buf
    finally:
        s.close()


class TestProxyPeerGate:

    def test_same_uid_peer_is_served(self, reset_proxy):
        # A same-UID connection must get past the peer gate and reach
        # the policy gates (403 here — the host is not allowlisted —
        # which proves the connection was served, not dropped).
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _connect_raw(proxy.port)
            assert b"403" in buf.split(b"\r\n", 1)[0]
        finally:
            proxy.stop()

    def test_foreign_uid_peer_is_dropped(self, reset_proxy, monkeypatch):
        # Cannot mint a second local user in a test — simulate the
        # lookup verdict instead. The connection must be closed with
        # NO HTTP response (drop, not a policy 403).
        monkeypatch.setattr(
            proxy_mod, "_loopback_peer_uid",
            lambda peer, sockname: os.geteuid() + 1,
        )
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _connect_raw(proxy.port)
            assert buf == b"", (
                "cross-user loopback peer must be dropped without a "
                "response")
        finally:
            proxy.stop()

    def test_unknown_uid_fails_open(self, reset_proxy, monkeypatch):
        # None = "could not determine" — documented fail-open so
        # non-Linux hosts and kernel races don't break the proxy.
        monkeypatch.setattr(
            proxy_mod, "_loopback_peer_uid",
            lambda peer, sockname: None,
        )
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.example"})
        try:
            buf = _connect_raw(proxy.port)
            assert b"403" in buf.split(b"\r\n", 1)[0]
        finally:
            proxy.stop()
