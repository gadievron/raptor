"""Containment of check probes that leave the WebClient chokepoint:
off-client lanes must not follow target-controlled redirects off-origin
and must bound what a hostile endpoint can feed them. Loopback fixtures
only."""

from __future__ import annotations

import http.server
import threading
from contextlib import contextmanager

import pytest

from packages.web.checks.information import VerboseHttpMethodsCheck


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    """Hermetic loopback fixtures: a host proxy env whose NO_PROXY does
    not cover 127.0.0.1 would otherwise route the probes off-box."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                 "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")


class _Response:
    def __init__(self, status: int = 200, text: str = "") -> None:
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers: dict = {}


class _StubClient:
    """In-scope WebClient double for the check's on-client leg."""

    verify_ssl = False
    reveal_secrets = False
    transport_errors = 0

    def get(self, path, params=None, headers=None, allow_redirects=True):
        return _Response(200, "ok")


@contextmanager
def _listener(handler_class):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _handler(status: int = 200, headers: dict | None = None):
    response_headers = dict(headers or {})

    class Handler(http.server.BaseHTTPRequestHandler):
        requests_seen: list = []

        def _serve(self):
            type(self).requests_seen.append((self.command, self.path))
            self.send_response(status)
            for name, value in response_headers.items():
                self.send_header(name, value)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = _serve
        do_OPTIONS = _serve

        def log_message(self, *args):
            pass

    return Handler


class TestOptionsProbeStaysOnOrigin:
    def test_redirecting_options_is_not_followed_off_origin(self):
        """A hostile in-scope target answering the raw OPTIONS probe
        with a 302 must not steer the scanner into an unpoliced fetch
        of a different host, nor let that host's Allow header become
        the finding's evidence."""
        off_origin = _handler(
            status=200, headers={"Allow": "TRACE, DELETE, PUT"},
        )
        with _listener(off_origin) as pivot_base:
            target = _handler(
                status=302, headers={"Location": f"{pivot_base}/pivot"},
            )
            with _listener(target) as target_base:
                findings = VerboseHttpMethodsCheck().run(
                    _StubClient(), target_base,
                )

        # The redirect was observed, never fetched: the off-origin host
        # saw no request, and its Allow header minted no finding.
        assert off_origin.requests_seen == []
        assert findings == []
        assert ("OPTIONS", "/") in target.requests_seen

    def test_first_response_allow_header_still_grades(self):
        """Containment must not cost the check its positive path: a
        dangerous Allow on the FIRST response still fires."""
        target = _handler(status=200, headers={"Allow": "GET, TRACE, PUT"})
        with _listener(target) as target_base:
            findings = VerboseHttpMethodsCheck().run(
                _StubClient(), target_base,
            )
        assert len(findings) == 1
        assert "TRACE" in findings[0].evidence


class TestRawExchangeIsBounded:
    """The smuggling probe's raw read loop faces a hostile endpoint
    with neither the WebClient response cap nor a request deadline —
    it must bound itself in BOTH bytes and wall time."""

    def _raw_server(self, feeder):
        import socket as socket_module

        server = socket_module.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def _serve():
            conn, _addr = server.accept()
            try:
                conn.recv(65536)
                feeder(conn)
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        return server, server.getsockname()[1]

    def test_flood_response_stops_at_the_byte_cap(self, monkeypatch):
        import time

        from packages.web.checks.cache import RequestSmugglingCheck

        block = b"x" * 65536

        def flood(conn):
            deadline = time.monotonic() + 10
            try:
                while time.monotonic() < deadline:
                    conn.sendall(block)
            except OSError:
                pass  # reader hung up: the cap fired

        server, port = self._raw_server(flood)
        try:
            data, _duration, truncated = RequestSmugglingCheck._raw_exchange(
                "127.0.0.1", port, False, "GET / HTTP/1.1\r\n\r\n",
            )
        finally:
            server.close()
        assert truncated is True
        # Bounded near the cap (may overshoot by one recv chunk).
        assert len(data) <= RequestSmugglingCheck._RAW_MAX_BYTES + 4096

    def test_drip_fed_response_hits_the_wall_clock_deadline(self, monkeypatch):
        import time

        from packages.web.checks.cache import RequestSmugglingCheck

        # Compressed clock: deadline semantics are under test, not the
        # production constant's literal value.
        monkeypatch.setattr(RequestSmugglingCheck, "_RAW_DEADLINE_S", 1.5)

        def drip(conn):
            # One byte per 0.3s for ~4s: each recv succeeds, so the
            # per-recv socket timeout alone never ends the loop.
            for _ in range(14):
                try:
                    conn.sendall(b"y")
                except OSError:
                    return
                time.sleep(0.3)

        server, port = self._raw_server(drip)
        start = time.monotonic()
        try:
            data, duration, truncated = RequestSmugglingCheck._raw_exchange(
                "127.0.0.1", port, False, "GET / HTTP/1.1\r\n\r\n",
            )
        finally:
            server.close()
        wall = time.monotonic() - start
        assert truncated is True
        assert wall < 3.5, f"read loop ran {wall:.1f}s past the deadline"
        assert data is not None

    def test_truncated_exchange_counts_as_degraded_coverage(self):
        from packages.web.checks.cache import RequestSmugglingCheck

        class _Client:
            transport_errors = 0

        check = RequestSmugglingCheck()
        check._raw_exchange = lambda *args: ("junk\r\n", 0.1, True)
        client = _Client()
        assert check.run(client, "https://t.example") == []
        assert client.transport_errors == 3  # one per probe variant
