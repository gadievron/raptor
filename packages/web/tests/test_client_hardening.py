"""WebClient transport-layer hardening: observed redirects, invalid
ports, per-hop rate limiting, buffered hop bodies, thread-safe DNS
pinning, and transport-error accounting. Loopback fixtures only."""

from __future__ import annotations

import http.server
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import requests

import packages.web.client as client_module
from packages.web.client import WebClient


class _Handler(http.server.BaseHTTPRequestHandler):
    response_status = 200
    response_headers: dict = {}
    response_body = b"ok"
    hits: list = []

    def do_GET(self):
        type(self).hits.append({"path": self.path, "headers": dict(self.headers)})
        self.send_response(type(self).response_status)
        for name, value in type(self).response_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, *args):  # pragma: no cover - keep tests quiet
        pass


@contextmanager
def _server(handler_class):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _base_url(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}"


def _handler(**attrs):
    return type("H", (_Handler,), {"hits": [], **attrs})


# -- observed (unfollowed) redirects ---------------------------------------


def test_no_follow_returns_offsite_redirect_for_observation():
    """A 3xx whose Location leaves the origin must be OBSERVABLE when
    following is off — checks grading redirect targets (host-header
    poisoning, OAuth redirect_uri) depend on seeing the raw 3xx."""
    handler = _handler(
        response_status=302,
        response_headers={"Location": "https://evil-probe.example.com/x"},
        response_body=b"",
    )
    with _server(handler) as target:
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)
        resp = client.get("/", allow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"] == "https://evil-probe.example.com/x"


def test_following_offsite_redirect_still_raises():
    handler = _handler(
        response_status=302,
        response_headers={"Location": "https://evil-probe.example.com/x"},
        response_body=b"",
    )
    with _server(handler) as target:
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)
        with pytest.raises(ValueError, match="outside configured target scope"):
            client.get("/")


# -- invalid ports ----------------------------------------------------------


def test_invalid_port_url_is_out_of_scope_not_a_crash():
    client = WebClient("https://example.test", block_private_ips=False)
    # urlparse defers the ValueError to .port access; scope checks must
    # classify such URLs out instead of blowing up the caller's phase.
    assert client._is_in_scope("http://h:99999/x") is False
    assert client._is_in_scope("http://h:8x/x") is False
    assert client._is_in_scope("https://example.test/ok") is True


# -- per-hop rate limiting ---------------------------------------------------


def test_redirect_hops_pass_through_the_rate_limiter():
    class RedirectOnce(_Handler):
        hits: list = []

        def do_GET(self):
            type(self).hits.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()
                self.wfile.write(b"")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"done")

    with _server(RedirectOnce) as target:
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)
        waits = []
        original = client._rate_limit_wait
        client._rate_limit_wait = lambda: waits.append(1) or original()
        resp = client.get("/start")
        assert resp.status_code == 200
        # One wait for the initial request + one per redirect hop.
        assert len(waits) == 2


def test_rate_limiter_reservation_is_thread_safe():
    client = WebClient("https://example.test", rate_limit=0.02)
    started = time.monotonic()

    threads = [
        threading.Thread(target=client._rate_limit_wait) for _ in range(5)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # 5 concurrent claims must be spaced out: at least 4 full intervals.
    assert time.monotonic() - started >= 4 * 0.02


# -- buffered redirect-hop bodies --------------------------------------------


def test_redirect_history_bodies_are_buffered_not_empty():
    class RedirectWithBody(_Handler):
        hits: list = []

        def do_GET(self):
            type(self).hits.append(self.path)
            if self.path == "/start":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.send_header("Content-Length", "13")
                self.end_headers()
                self.wfile.write(b"redirect body")
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"final body")

    with _server(RedirectWithBody) as target:
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)
        resp = client.get("/start")
        assert resp.content == b"final body"
        assert len(resp.history) == 1
        # The hop was opened streaming; its body must be read before the
        # connection is released, or redirect-chain evidence reads b"".
        assert resp.history[0].content == b"redirect body"


# -- thread-safe DNS pinning ---------------------------------------------------


def test_dns_pins_are_thread_local_and_never_leak():
    sentinel_a = [("A",)]
    sentinel_b = [("B",)]
    barrier = threading.Barrier(2)
    seen: dict[str, object] = {}

    def worker(name: str, sentinel):
        with WebClient._pinned_dns(("pin.example", 80, sentinel)):
            barrier.wait(timeout=5)
            seen[name] = socket.getaddrinfo("pin.example", 80)
            barrier.wait(timeout=5)

    threads = [
        threading.Thread(target=worker, args=("a", sentinel_a)),
        threading.Thread(target=worker, args=("b", sentinel_b)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    # Each thread saw ITS pin while both were live — with the old
    # global save/patch/restore one thread's pin shadowed the other's.
    assert seen["a"] == sentinel_a
    assert seen["b"] == sentinel_b
    # After both exits no pin remains on this thread: the wrapper is a
    # passthrough (loopback resolution still works, no stale closure).
    assert getattr(client_module._pin_local, "stack", None) in (None, [])
    assert socket.getaddrinfo("localhost", 80)


# -- transport-error accounting (degraded-vs-clean distinction) ---------------


def test_transport_failures_are_counted_and_scope_refusals_are_not():
    client = WebClient("https://example.test", block_private_ips=False, rate_limit=0)

    def _boom(*args, **kwargs):
        raise requests.ConnectionError("connection refused")

    client._send_scoped_request = _boom
    with pytest.raises(requests.ConnectionError):
        client.get("/")
    assert client.transport_errors == 1

    # Scope refusals are policy decisions, not target failures.
    with pytest.raises(ValueError, match="outside configured target scope"):
        client.get("http://example.invalid/x")
    assert client.transport_errors == 1
