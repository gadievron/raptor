"""Tests for WebClient target-scope enforcement."""

import http.server
import threading
from contextlib import contextmanager

import requests

import pytest

from packages.web.client import WebClient


class _Handler(http.server.BaseHTTPRequestHandler):
    response_status = 200
    response_headers = {}
    response_body = b"ok"
    hits = []

    def do_GET(self):
        type(self).hits.append({
            "path": self.path,
            "headers": dict(self.headers),
        })
        self.send_response(type(self).response_status)
        for name, value in type(self).response_headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(type(self).response_body)

    def log_message(self, *args):  # pragma: no cover - keep tests quiet
        pass


@contextmanager
def _server(status=200, headers=None, body=b"ok", handler_class=None):
    handler = handler_class or type(
        "ScopedTestHandler",
        (_Handler,),
        {
            "response_status": status,
            "response_headers": headers or {},
            "response_body": body,
            "hits": [],
        },
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _base_url(server):
    host, port = server.server_address
    return f"http://{host}:{port}"


def test_rejects_absolute_url_outside_base_origin():
    with _server() as (target, _):
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)

        with pytest.raises(ValueError, match="outside configured target scope"):
            client.get("http://example.invalid/off-scope")


def test_rejects_protocol_relative_url_outside_base_origin():
    with _server() as (target, _):
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)

        with pytest.raises(ValueError, match="outside configured target scope"):
            client.get("//example.invalid/off-scope")


def test_follows_same_origin_redirect():
    class SameOriginRedirectHandler(_Handler):
        hits = []

        def do_GET(self):
            type(self).hits.append({
                "path": self.path,
                "headers": dict(self.headers),
            })
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/final")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"redirected")

    with _server(handler_class=SameOriginRedirectHandler) as (server, handler):
        client = WebClient(_base_url(server), block_private_ips=False, rate_limit=0)

        response = client.get("/")

        assert response.status_code == 200
        assert response.text == "redirected"
        assert handler.hits[-1]["path"] == "/final"
        assert client.request_history[-1]["url"] == f"{_base_url(server)}/final"


def test_blocks_cross_origin_redirect_before_requesting_new_host():
    with _server() as (off_scope, off_scope_handler):
        redirect_headers = {"Location": f"{_base_url(off_scope)}/internal-metadata"}
        with _server(status=302, headers=redirect_headers) as (target, _):
            client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)

            with pytest.raises(ValueError, match="redirect outside configured target scope"):
                client.get("/")

        assert off_scope_handler.hits == []


def test_cross_origin_redirect_does_not_receive_configured_cookies():
    with _server() as (off_scope, off_scope_handler):
        redirect_headers = {"Location": f"{_base_url(off_scope)}/cookie-sink"}
        with _server(status=302, headers=redirect_headers) as (target, _):
            client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)
            client.set_cookies({"sessionid": "COOKIELEAKMARKER"})

            with pytest.raises(ValueError, match="redirect outside configured target scope"):
                client.get("/")

        assert off_scope_handler.hits == []


def test_same_origin_absolute_url_is_allowed():
    with _server() as (target, handler):
        client = WebClient(_base_url(target), block_private_ips=False, rate_limit=0)

        response = client.get(f"{_base_url(target)}/same-origin")

        assert response.status_code == 200
        assert handler.hits[-1]["path"] == "/same-origin"


def test_preserves_post_method_and_body_for_307_and_308_redirects():
    class PreserveMethodRedirectHandler(_Handler):
        hits = []

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            type(self).hits.append({
                "method": "POST",
                "path": self.path,
                "body": body,
                "headers": dict(self.headers),
            })
            if self.path in {"/temporary", "/permanent"}:
                self.send_response(307 if self.path == "/temporary" else 308)
                self.send_header("Location", "/final")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"preserved")

    for path in ("/temporary", "/permanent"):
        PreserveMethodRedirectHandler.hits = []
        with _server(handler_class=PreserveMethodRedirectHandler) as (server, handler):
            client = WebClient(_base_url(server), block_private_ips=False, rate_limit=0)

            response = client.post(path, data={"marker": "preserve-me"})

            assert response.status_code == 200
            assert response.text == "preserved"
            assert [hit["path"] for hit in handler.hits] == [path, "/final"]
            assert all(hit["method"] == "POST" for hit in handler.hits)
            assert handler.hits[1]["body"] == b"marker=preserve-me"
            assert client.request_history[-1]["url"] == f"{_base_url(server)}/final"


def test_raises_too_many_redirects_after_limit_is_exhausted():
    class RedirectLoopHandler(_Handler):
        hits = []

        def do_GET(self):
            type(self).hits.append({
                "path": self.path,
                "headers": dict(self.headers),
            })
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()

    with _server(handler_class=RedirectLoopHandler) as (server, handler):
        client = WebClient(_base_url(server), block_private_ips=False, rate_limit=0)

        with pytest.raises(requests.exceptions.TooManyRedirects, match="Exceeded"):
            client.get("/loop")

        assert len(handler.hits) == 11


def test_dns_pinning_prevents_rebind_toctou():
    """Verify that the resolved IP from validation is pinned for the request.

    Simulates a DNS rebinding attack: getaddrinfo is monkeypatched so
    that the first call (validation) returns the real server IP, but a
    second call would return 127.0.0.99 (a different loopback). Without
    pinning, requests' internal resolution would hit the rebinded address
    and either connect to the wrong host or fail. With pinning, the
    request uses the validated IP from the first resolution.
    """
    import socket as _socket
    with _server() as (target, handler):
        host, port = target.server_address
        client = WebClient(f"http://{host}:{port}", block_private_ips=False, rate_limit=0)

        _real_gai = _socket.getaddrinfo
        call_count = [0]

        def _rebinding_gai(h, p, *args, **kwargs):
            result = _real_gai(h, p, *args, **kwargs)
            call_count[0] += 1
            if call_count[0] > 1 and h == host:
                # Simulate rebind: return a different IP on subsequent
                # resolutions. With pinning this never reaches urllib3.
                return [
                    (fam, typ, proto, canon, ("127.0.0.99", sockaddr[1]))
                    for fam, typ, proto, canon, sockaddr in result
                ]
            return result

        _socket.getaddrinfo = _rebinding_gai
        try:
            resp = client.get("/pinned")
        finally:
            _socket.getaddrinfo = _real_gai

        assert resp.status_code == 200
        assert handler.hits[-1]["path"] == "/pinned"
