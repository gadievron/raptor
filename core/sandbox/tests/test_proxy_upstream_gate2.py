"""Gate 2 (blocked-IP defense) on the upstream-proxy CONNECT path.

Pre-fix the upstream branch forwarded every allowlist-passing CONNECT
to the operator's HTTPS_PROXY with no IP vetting at all — gate 2 lived
only on the direct-connect path. A sandboxed child on a corporate-proxy
host could CONNECT to ``10.0.0.5:443`` / ``169.254.169.254:443`` and
the upstream (which legitimately reaches private address space) would
complete the internal-pivot gate 2 exists to stop.

These tests run a fake upstream proxy on loopback and assert:

  * a literal non-global IP target is denied with 403 and never
    reaches the upstream;
  * a hostname target that locally resolves to a blocked range
    (``localhost``) is denied the same way;
  * a hostname that does NOT resolve locally still proceeds to the
    upstream (documented fail-open: corporate resolvers often answer
    only at the upstream) — hermetic because the fake upstream is on
    loopback;
  * the deny stays ENFORCING in audit mode (blocking, not log-only).

No real network egress: every socket in these tests is loopback.
"""

from __future__ import annotations

import socket
import threading

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


class _FakeUpstream(threading.Thread):
    """Minimal CONNECT-accepting upstream proxy on 127.0.0.1."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.requests: list[bytes] = []
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                conn.settimeout(2.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                self.requests.append(data)
                conn.sendall(
                    b"HTTP/1.1 200 Connection established\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.join(timeout=2.0)


@pytest.fixture
def fake_upstream():
    up = _FakeUpstream()
    up.start()
    yield up
    up.stop()


def _send_connect(port: int, target: str, timeout: float = 5.0) -> tuple:
    """Send a CONNECT to a proxy at (127.0.0.1, port); return
    (status_code, raw_response)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        req = (f"CONNECT {target} HTTP/1.1\r\n"
               f"Host: {target}\r\n\r\n").encode("latin-1")
        s.sendall(req)
        buf = b""
        while b"\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 65536:
                break
        line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        parts = line.split(None, 2)
        status = (int(parts[1])
                  if len(parts) >= 2 and parts[1].isdigit() else 0)
        return status, buf
    finally:
        s.close()


def _make_proxy(fake_upstream, **kwargs):
    return proxy_mod.EgressProxy(
        allowed_hosts={
            "169.254.169.254", "10.0.0.5", "localhost",
            "does-not-exist.invalid",
        },
        upstream_proxy=f"http://127.0.0.1:{fake_upstream.port}",
        **kwargs,
    )


class TestUpstreamPathGate2:

    @pytest.mark.parametrize("target_ip", ["169.254.169.254", "10.0.0.5"])
    def test_literal_blocked_ip_denied_before_upstream(
            self, reset_proxy, fake_upstream, target_ip):
        proxy = _make_proxy(fake_upstream)
        try:
            token = proxy.register_sandbox(caller_label="test")
            try:
                status, _ = _send_connect(proxy.port, f"{target_ip}:443")
                assert status == 403, (
                    "upstream path must deny a literal non-global IP "
                    "target at gate 2")
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()
        assert fake_upstream.requests == [], (
            "denied CONNECT must never reach the upstream proxy")
        denied = [e for e in events
                  if e["result"] == "denied_resolved_ip"]
        assert len(denied) == 1, f"expected 1 deny event, got: {events}"
        assert "upstream path" in denied[0]["reason"]
        assert denied[0]["resolved_ip"] == target_ip

    def test_hostname_resolving_to_blocked_range_denied(
            self, reset_proxy, fake_upstream):
        # `localhost` resolves locally to 127.0.0.1/::1 — both blocked.
        proxy = _make_proxy(fake_upstream)
        try:
            status, _ = _send_connect(proxy.port, "localhost:443")
            assert status == 403
        finally:
            proxy.stop()
        assert fake_upstream.requests == []

    def test_unresolvable_hostname_proceeds_to_upstream(
            self, reset_proxy, fake_upstream):
        # Local NXDOMAIN (RFC 6761 .invalid) must NOT deny: corporate
        # networks often resolve external names only at the upstream.
        # The fake upstream answers 200, proving the CONNECT was
        # forwarded — all on loopback, no real egress.
        proxy = _make_proxy(fake_upstream)
        try:
            status, _ = _send_connect(
                proxy.port, "does-not-exist.invalid:443")
            assert status == 200, (
                "locally-unresolvable hostname should fall through to "
                "the upstream (documented fail-open)")
        finally:
            proxy.stop()
        assert len(fake_upstream.requests) == 1
        assert b"CONNECT does-not-exist.invalid:443" in \
            fake_upstream.requests[0]

    def test_audit_mode_still_blocks(self, reset_proxy, fake_upstream):
        # Gate 2 has no audit leniency — blocking, not log-only, on
        # the upstream path just like the direct path.
        proxy = _make_proxy(fake_upstream, audit_log_only=True)
        try:
            token = proxy.register_sandbox(caller_label="test")
            try:
                status, _ = _send_connect(
                    proxy.port, "169.254.169.254:443")
                assert status == 403, (
                    "audit mode must not downgrade the upstream-path "
                    "gate 2 to allow-and-log")
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()
        assert fake_upstream.requests == []
        assert any(e["result"] == "denied_resolved_ip" for e in events)
