"""Tunnel teardown / EOF propagation on the egress proxy.

Historically ``_relay`` returned on EOF without telling the other
direction anything: the sibling relay stayed parked on its read until
the idle timeout (300s), the two tunnel sockets lingered ESTABLISHED,
half-close protocols (client ``shutdown(SHUT_WR)``, server replies)
deadlocked, and the tunnel-cap slot was only released minutes after
both ends had hung up — sustained load wedged the proxy at its cap
with every real tunnel long dead.

These tests pin the repaired termination contract for every
interleaving:

  * EOF is PROPAGATED — one side's FIN becomes ``write_eof()`` on the
    other side, so half-close protocols keep working end to end.
  * Reset/abort TEARS DOWN the pair — both transports close promptly,
    unblocking whichever peer is still reading.
  * The cap slot is released exactly once per tunnel, promptly, under
    clean close, RST, and stop()-during-traffic alike.

Hermetic: loopback sockets + threads only, no external network, no
subprocess. Gate 2 is monkeypatched to permit loopback (its normal
job is to BLOCK private/loopback upstreams; the test backends live
there). All waits are bounded condition-polls with explicit deadlines
well below the 300s idle timeout, so a regression fails fast instead
of hanging.
"""

from __future__ import annotations

import contextlib
import ipaddress
import socket
import struct
import threading
import time
from typing import Callable

import pytest

from core.sandbox import proxy as proxy_mod

# Far below the proxy's 300s idle timeout (the pre-fix teardown time)
# and far above a loopback round-trip. Lower flakes on saturated CI
# runners (thread scheduling + two socket hops); higher just delays
# the failure report when a regression reintroduces the parked relay.
_DEADLINE = 5.0


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


@pytest.fixture
def loopback_permitted(monkeypatch):
    """Permit loopback upstreams through gate 2 for this test only.

    Everything non-loopback keeps the real verdict — the tests must
    not accidentally neuter the resolved-IP block they run beside.
    """
    orig = proxy_mod._ip_is_blocked

    def permit_loopback(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return True
        if ip.is_loopback:
            return False
        return orig(ip_str)

    monkeypatch.setattr(proxy_mod, "_ip_is_blocked", permit_loopback)


def _wait_until(cond: Callable[[], bool], msg: str,
                timeout: float = _DEADLINE) -> None:
    """Bounded condition-poll; fails the test at the deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return
        time.sleep(0.01)
    pytest.fail(msg)


def _active(proxy: proxy_mod.EgressProxy) -> int:
    with proxy._active_lock:
        return proxy._active_tunnels


def _serve_once(handler: Callable[[socket.socket], None]) -> int:
    """One-shot loopback backend: accept a single connection, run
    ``handler`` on it in a thread, close everything after. Returns
    the listening port."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    lsock.settimeout(_DEADLINE * 2)
    port = lsock.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = lsock.accept()
        except OSError:
            return
        finally:
            lsock.close()
        conn.settimeout(_DEADLINE * 2)
        try:
            handler(conn)
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _serve_echo_forever() -> "tuple[int, Callable[[], None]]":
    """Multi-connection echo backend; returns (port, close_fn)."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(64)
    port = lsock.getsockname()[1]

    def echo(conn: socket.socket) -> None:
        conn.settimeout(_DEADLINE * 2)
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(conn,),
                             daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return port, lsock.close


def _open_tunnel(proxy_port: int, backend_port: int,
                 expect: bytes = b" 200 ") -> socket.socket:
    """CONNECT through the proxy; assert the response status."""
    s = socket.create_connection(("127.0.0.1", proxy_port),
                                 timeout=_DEADLINE)
    s.settimeout(_DEADLINE)
    s.sendall(
        f"CONNECT 127.0.0.1:{backend_port} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{backend_port}\r\n\r\n".encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        assert chunk, f"proxy closed during CONNECT handshake: {buf!r}"
        buf += chunk
    status = buf.split(b"\r\n", 1)[0]
    assert expect in status, f"unexpected CONNECT status: {status!r}"
    return s


def _rst_close(s: socket.socket) -> None:
    """Abortive close: SO_LINGER(on, 0) turns close() into a RST."""
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                 struct.pack("ii", 1, 0))
    s.close()


def _recv_until_eof(s: socket.socket) -> bytes:
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            return buf
        buf += chunk


class TestEofPropagation:

    def test_half_close_protocol_continues(self, reset_proxy,
                                           loopback_permitted):
        """Client shutdown(SHUT_WR) → backend must SEE the EOF, and
        its late reply must still flow back (send-then-half-close
        protocols: git, some RPC). Pre-fix the FIN was swallowed —
        the backend waited on a read that could never end."""
        got: dict = {}
        served = threading.Event()

        def handler(conn: socket.socket) -> None:
            got["data"] = _recv_until_eof(conn)  # blocks until EOF
            conn.sendall(b"late-reply")
            served.set()

        backend_port = _serve_once(handler)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            s.shutdown(socket.SHUT_WR)
            reply = _recv_until_eof(s)
            assert got.get("data") == b"ping"
            assert served.is_set(), "backend never saw the client EOF"
            assert reply == b"late-reply", (
                f"reply after client half-close lost: {reply!r}")
            s.close()
            _wait_until(lambda: _active(proxy) == 0,
                        "tunnel slot not released after both ends done")
        finally:
            proxy.stop()

    def test_backend_close_propagates_eof_to_client(
            self, reset_proxy, loopback_permitted):
        """Backend replies and closes → the client must receive the
        reply AND the EOF promptly. Pre-fix the client's read hung
        until the idle timeout because the backend FIN was never
        forwarded."""

        def handler(conn: socket.socket) -> None:
            data = conn.recv(4)
            conn.sendall(data.upper())
            # handler returns → _serve_once closes → FIN to proxy

        backend_port = _serve_once(handler)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            reply = _recv_until_eof(s)  # raises timeout pre-fix
            assert reply == b"PING"
            s.close()
            _wait_until(lambda: _active(proxy) == 0,
                        "tunnel slot not released after backend close")
        finally:
            proxy.stop()


class TestResetTeardown:

    def test_client_rst_tears_down_backend_side(
            self, reset_proxy, loopback_permitted):
        """Client aborts (RST): the proxy must close the backend leg
        promptly — the backend's blocked read unblocks and the slot
        is released without the backend doing anything."""
        unblocked = threading.Event()

        def handler(conn: socket.socket) -> None:
            with contextlib.suppress(OSError):
                _recv_until_eof(conn)
            unblocked.set()

        backend_port = _serve_once(handler)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"x")
            _rst_close(s)
            _wait_until(unblocked.is_set,
                        "backend read never unblocked after client RST")
            _wait_until(lambda: _active(proxy) == 0,
                        "tunnel slot not released after client RST")
        finally:
            proxy.stop()

    def test_backend_rst_tears_down_client_side(
            self, reset_proxy, loopback_permitted):
        """Backend aborts (RST): the client's blocked read must end
        promptly (EOF or reset — the proxy translates the abort into
        a close of the client leg) and the slot must be released
        BEFORE the client closes its own socket."""

        def handler(conn: socket.socket) -> None:
            conn.recv(4)
            _rst_close(conn)

        backend_port = _serve_once(handler)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"ping")
            with contextlib.suppress(OSError):
                data = _recv_until_eof(s)
                assert data == b"", f"unexpected data after RST: {data!r}"
            # The strong assertion: teardown completes while the
            # client socket is still open — the proxy did it, not us.
            _wait_until(lambda: _active(proxy) == 0,
                        "tunnel slot not released after backend RST")
            s.close()
        finally:
            proxy.stop()


class TestCapAccounting:

    def test_cap_recovers_immediately_after_close(
            self, reset_proxy, loopback_permitted):
        """Fill a 2-slot proxy, verify 429 on the third, close both
        holders → a new tunnel must be admitted within the deadline.
        Pre-fix the slots stayed occupied for the 300s idle timeout
        and the proxy kept 429ing long after the holders hung up."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"},
                                      max_tunnels=2)
        try:
            t1 = _open_tunnel(proxy.port, backend_port)
            t2 = _open_tunnel(proxy.port, backend_port)
            rejected = _open_tunnel(proxy.port, backend_port,
                                    expect=b" 429 ")
            rejected.close()
            t1.close()
            t2.close()
            _wait_until(lambda: _active(proxy) == 0,
                        "slots not released after holders closed")
            t3 = _open_tunnel(proxy.port, backend_port)  # admitted
            t3.sendall(b"alive")
            assert t3.recv(5) == b"alive"
            t3.close()
        finally:
            proxy.stop()
            close_backend()

    def test_slot_released_exactly_once_under_mixed_churn(
            self, reset_proxy, loopback_permitted):
        """Every close style — clean close, half-close-then-close,
        RST — must release the slot exactly once. A leak leaves the
        counter positive; a double-decrement drives it negative;
        either way it fails the == 0 checks."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"},
                                      max_tunnels=8)
        try:
            for round_no in range(3):
                socks = [_open_tunnel(proxy.port, backend_port)
                         for _ in range(6)]
                for s in socks:
                    s.sendall(b"ping")
                    assert s.recv(4) == b"ping"
                for i, s in enumerate(socks):
                    if i % 3 == 0:
                        s.close()
                    elif i % 3 == 1:
                        s.shutdown(socket.SHUT_WR)
                        with contextlib.suppress(OSError):
                            _recv_until_eof(s)
                        s.close()
                    else:
                        _rst_close(s)
                _wait_until(
                    lambda: _active(proxy) == 0,
                    f"round {round_no}: active-tunnel counter did not "
                    f"return to 0 (leak if positive, double-decrement "
                    f"if negative)")
                assert _active(proxy) == 0
        finally:
            proxy.stop()
            close_backend()

    def test_stop_during_active_tunnel_releases_slot(
            self, reset_proxy, loopback_permitted):
        """Cancellation interleaving: stop() while a tunnel is mid-
        traffic must cancel the relays, decrement exactly once, and
        return within its drain budget — no hang, no negative count."""
        backend_port, close_backend = _serve_echo_forever()
        proxy = proxy_mod.EgressProxy(allowed_hosts={"127.0.0.1"})
        stopped = False
        try:
            s = _open_tunnel(proxy.port, backend_port)
            s.sendall(b"in-flight")
            assert _active(proxy) == 1
            t0 = time.monotonic()
            proxy.stop(drain_timeout=1.0)
            stopped = True
            assert time.monotonic() - t0 < _DEADLINE * 2, (
                "stop() exceeded its drain budget")
            assert _active(proxy) == 0, (
                "cancel-during-traffic broke slot accounting")
            s.close()
        finally:
            if not stopped:
                proxy.stop()
            close_backend()
