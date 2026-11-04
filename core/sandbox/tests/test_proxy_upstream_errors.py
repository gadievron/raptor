"""Upstream-path error completeness: every failure between dialling
the upstream proxy and the relay taking ownership must (a) write a
status line whenever the client can still await one, and (b) close the
freshly-dialed upstream leg.

Pre-fix, two shapes escaped to the generic handler-error catch — an
upstream RST during the post-200 header drain, and any exception in
the post-200 client segment (200-ack drain, TLS peek). Both left the
client with an abrupt close instead of the documented 502, and both
stranded ``up_writer`` until proxy stop: a hostile child could pace
CONNECT-then-RST to grow the orchestrator's open-fd set unboundedly.

Hermetic: every socket is loopback; the local vet of ``.invalid``
CONNECT targets rides the stubbed resolver.
"""

from __future__ import annotations

import gc
import os
import socket
import struct
import threading
import time

import pytest

from core.sandbox import proxy as proxy_mod


@pytest.fixture
def reset_proxy():
    proxy_mod._reset_for_tests()
    yield
    proxy_mod._reset_for_tests()


class _RstUpstream(threading.Thread):
    """Upstream proxy that answers the CONNECT with a 200 status line
    (no terminating blank line) and then hard-resets the connection —
    the mid-header-drain death of a flaky corporate upstream."""

    def __init__(self, rst_delay: float = 0.15):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(16)
            self.sock.settimeout(0.2)
            self.port = self.sock.getsockname()[1]
            self.rst_delay = rst_delay
            self._stop = threading.Event()
        except BaseException:
            self.sock.close()
            raise

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
                # Status line only — the proxy parses it, then blocks
                # in the header-drain loop awaiting the blank line...
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n")
                time.sleep(self.rst_delay)
                # ...and gets an RST instead (SO_LINGER 0 close).
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack("ii", 1, 0))
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


class _HoldingUpstream(threading.Thread):
    """Upstream proxy that completes the CONNECT handshake fully and
    then holds the accepted connection open, exposing it so a test
    can observe whether the proxy closed its leg (EOF) or leaked it
    (recv blocks)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen(4)
            self.sock.settimeout(0.2)
            self.port = self.sock.getsockname()[1]
            self.held: list[socket.socket] = []
            self._stop = threading.Event()
        except BaseException:
            self.sock.close()
            raise

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
                conn.sendall(
                    b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.held.append(conn)
            except OSError:
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
        for conn in self.held:
            try:
                conn.close()
            except OSError:
                pass
        self.join(timeout=2.0)


def _send_connect(port: int, target: str, timeout: float = 5.0) -> tuple:
    """CONNECT to a proxy at (127.0.0.1, port) → (status, raw)."""
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


def _open_fds() -> int:
    return len(os.listdir("/proc/self/fd"))


class TestUpstreamHeaderDrainReset:
    def test_reset_during_header_drain_yields_502(
            self, reset_proxy, hermetic_invalid_dns):
        up = _RstUpstream()
        up.start()
        proxy = proxy_mod.EgressProxy(
            allowed_hosts={"drain-reset.invalid"},
            upstream_proxy=f"http://127.0.0.1:{up.port}",
        )
        try:
            token = proxy.register_sandbox(caller_label="test")
            try:
                status, _ = _send_connect(
                    proxy.port, "drain-reset.invalid:443")
                assert status == 502, (
                    f"upstream RST during header drain must surface "
                    f"as 502, got {status}")
            finally:
                events = proxy.unregister_sandbox(token)
        finally:
            proxy.stop()
            up.stop()

        failed = [e for e in events if e["result"] == "upstream_failed"]
        assert len(failed) == 1, \
            f"expected 1 upstream_failed event, got: {events}"
        assert "header drain" in failed[0]["reason"]

    @pytest.mark.skipif(not os.path.isdir("/proc/self/fd"),
                        reason="needs procfs fd listing")
    def test_repeated_resets_do_not_grow_fd_count(
            self, reset_proxy, hermetic_invalid_dns):
        """Each pre-fix drain-reset stranded the upstream transport
        (its fd stays registered with the event loop, so not even GC
        reaps it). Pace a dozen and require the fd count to settle
        back to baseline."""
        up = _RstUpstream(rst_delay=0.05)
        up.start()
        proxy = proxy_mod.EgressProxy(
            allowed_hosts={"drain-reset.invalid"},
            upstream_proxy=f"http://127.0.0.1:{up.port}",
        )
        try:
            gc.collect()
            baseline = _open_fds()
            for _ in range(12):
                _send_connect(proxy.port, "drain-reset.invalid:443")
            # Transport teardown is scheduled on the loop; poll
            # briefly instead of asserting an instant.
            deadline = time.monotonic() + 3.0
            slack = 3  # loop self-pipe/timer fds may flap by a few
            while time.monotonic() < deadline:
                if _open_fds() <= baseline + slack:
                    break
                time.sleep(0.05)
            grown = _open_fds() - baseline
            assert grown <= slack, (
                f"fd count grew by {grown} after 12 upstream resets "
                f"(baseline {baseline}) — upstream legs leaked")
        finally:
            proxy.stop()
            up.stop()


class TestPost200EscapeClosesUpstreamLeg:
    def test_escape_after_200_closes_upstream_leg(
            self, reset_proxy, monkeypatch, hermetic_invalid_dns):
        """Any exception between the 200 ack and the relay taking
        ownership (here: injected at the TLS peek) must close the
        freshly-dialed upstream leg — observed as prompt EOF on the
        upstream's held socket. No status assertion: the 200 is
        already committed on this path."""
        async def _peek_boom(self, reader):
            raise ConnectionResetError("client vanished at the peek")

        monkeypatch.setattr(proxy_mod.EgressProxy, "_peek_tls_identity",
                            _peek_boom)
        up = _HoldingUpstream()
        up.start()
        proxy = proxy_mod.EgressProxy(
            allowed_hosts={"post200.invalid"},
            upstream_proxy=f"http://127.0.0.1:{up.port}",
        )
        try:
            status, _ = _send_connect(proxy.port, "post200.invalid:443")
            assert status == 200  # tunnel was acknowledged first
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not up.held:
                time.sleep(0.02)
            assert up.held, "upstream never saw the CONNECT"
            conn = up.held[0]
            conn.settimeout(2.0)
            try:
                got = conn.recv(1)
            except socket.timeout:
                pytest.fail(
                    "upstream leg still open 2s after the tunnel "
                    "handler died — up_writer leaked")
            assert got == b"", "expected EOF on the upstream leg"
        finally:
            proxy.stop()
            up.stop()
