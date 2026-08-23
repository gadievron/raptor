"""CONNECT-handshake bounds (absolute deadline + header budgets).

The tunnel slot is charged before the request is parsed, and the slot
pool is process-wide — so the handshake itself must be bounded or a
client trickling header lines (one per just-under-the-per-line-timeout)
holds slots indefinitely and starves every other consumer of the
proxy singleton. Three bounds are under test:

- absolute deadline over request line + all headers
  (`_PROXY_HANDSHAKE_DEADLINE_S`) — breach responds 408 (or, when the
  deadline lands mid-line, falls through to the policy gates with
  whatever was parsed: either way the slot is released on schedule);
- aggregate header byte budget (`_PROXY_HANDSHAKE_MAX_HEADER_BYTES`)
  — breach responds 400;
- header count cap (`_PROXY_HANDSHAKE_MAX_HEADERS`) — breach
  responds 400.

Tests drive a real EgressProxy over loopback sockets — same harness
style as test_proxy_audit.py. Budgets are monkeypatched small so the
tests run in seconds.
"""

from __future__ import annotations

import socket
import time

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


def _read_status(sock: socket.socket, timeout: float) -> int | None:
    """First response status code, or None if the peer closed/stalled
    without sending one."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while b"\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
    except OSError:
        return None
    parts = buf.split(b"\r\n", 1)[0].split(None, 2)
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def _wait_no_active_tunnels(proxy, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with proxy._active_lock:
            if proxy._active_tunnels == 0:
                return
        time.sleep(0.05)
    with proxy._active_lock:
        active = proxy._active_tunnels
    assert active == 0, (
        f"tunnel slot not released after handshake bound fired "
        f"({active} still active)"
    )


class TestHandshakeDeadline:

    def test_trickled_headers_bounded_by_absolute_deadline(
        self, reset_proxy, monkeypatch,
    ):
        """A client dripping header lines — each well inside the
        per-line timeout — must be cut off at the ABSOLUTE deadline,
        releasing the slot. Pre-fix each line got a fresh full
        timeout and the slot was held for as long as the client kept
        trickling."""
        monkeypatch.setattr(proxy_mod, "_PROXY_HANDSHAKE_DEADLINE_S", 1.0)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            s = socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=5)
            try:
                s.sendall(b"CONNECT denied.test:443 HTTP/1.1\r\n")
                t0 = time.monotonic()
                status = None
                # Trickle fast so complete lines keep landing and the
                # loop-top deadline check is what fires (408). Stop
                # the moment the proxy responds.
                s.settimeout(0.02)
                while time.monotonic() - t0 < 6.0:
                    try:
                        s.sendall(b"X-Trickle: a\r\n")
                    except OSError:
                        break
                    try:
                        chunk = s.recv(256)
                    except socket.timeout:
                        continue
                    if chunk:
                        parts = chunk.split(b"\r\n", 1)[0].split(None, 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status = int(parts[1])
                    break
                elapsed = time.monotonic() - t0
                assert elapsed < 4.0, (
                    f"handshake not bounded: still trickling after "
                    f"{elapsed:.1f}s (deadline was 1.0s)"
                )
                # 408 when a completed line trips the loop-top check;
                # 403 when the deadline expired mid-line and the drain
                # fell through to the (denying) hostname gate. Both
                # terminate the handshake on schedule.
                assert status in (408, 403), (
                    f"expected 408/403 at the deadline, got {status!r}"
                )
            finally:
                s.close()
            _wait_no_active_tunnels(proxy)
        finally:
            proxy.stop()

    def test_deadline_breach_records_bad_request_event(
        self, reset_proxy, monkeypatch,
    ):
        monkeypatch.setattr(proxy_mod, "_PROXY_HANDSHAKE_DEADLINE_S", 0.5)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            token = proxy.register_sandbox(caller_label="t")
            s = socket.create_connection(
                ("127.0.0.1", proxy.port), timeout=5)
            try:
                s.sendall(b"CONNECT denied.test:443 HTTP/1.1\r\n")
                deadline = time.monotonic() + 5.0
                responded = False
                while time.monotonic() < deadline and not responded:
                    try:
                        s.sendall(b"X-T: a\r\n")
                    except OSError:
                        break
                    s.settimeout(0.02)
                    try:
                        responded = bool(s.recv(256))
                    except socket.timeout:
                        pass
            finally:
                s.close()
            _wait_no_active_tunnels(proxy)
            events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()
        terminal = [e for e in events
                    if e["result"] in ("bad_request", "denied_host")]
        assert terminal, (
            f"no terminal handshake event recorded, got: {events}"
        )


class TestHeaderBudgets:

    def _connect_with_headers(self, proxy, headers: bytes) -> int | None:
        s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
        try:
            s.sendall(b"CONNECT denied.test:443 HTTP/1.1\r\n" + headers)
            return _read_status(s, timeout=5.0)
        finally:
            s.close()

    def test_header_count_cap_responds_400(self, reset_proxy, monkeypatch):
        monkeypatch.setattr(proxy_mod, "_PROXY_HANDSHAKE_MAX_HEADERS", 5)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            headers = b"".join(b"X-%d: a\r\n" % i for i in range(10))
            status = self._connect_with_headers(proxy, headers)
            assert status == 400
            _wait_no_active_tunnels(proxy)
        finally:
            proxy.stop()

    def test_header_byte_budget_responds_400(self, reset_proxy, monkeypatch):
        monkeypatch.setattr(
            proxy_mod, "_PROXY_HANDSHAKE_MAX_HEADER_BYTES", 1024)
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            # 20 headers x ~110 bytes ≈ 2.2 KiB > the 1 KiB budget,
            # but comfortably under the (default 100) count cap.
            headers = b"".join(
                b"X-%d: " % i + b"a" * 100 + b"\r\n" for i in range(20))
            status = self._connect_with_headers(proxy, headers)
            assert status == 400
            _wait_no_active_tunnels(proxy)
        finally:
            proxy.stop()

    def test_normal_handshake_unaffected(self, reset_proxy):
        """A conventional CONNECT (request line + Host header + blank
        line, one burst) sails through the budgets and reaches the
        policy gate as before."""
        proxy = proxy_mod.EgressProxy(allowed_hosts={"allowed.test"})
        try:
            status = self._connect_with_headers(
                proxy,
                b"Host: denied.test:443\r\n"
                b"User-Agent: raptor-test\r\n\r\n")
            # 403 = the hostname gate denied it: the handshake itself
            # was accepted (no 400/408).
            assert status == 403
        finally:
            proxy.stop()
