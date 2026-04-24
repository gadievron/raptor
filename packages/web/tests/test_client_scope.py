"""Tests for WebClient target-scope enforcement."""

import http.server
import threading
from contextlib import contextmanager

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
def _server(status=200, headers=None, body=b"ok"):
    handler = type(
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
        client = WebClient(_base_url(target))

        with pytest.raises(ValueError, match="outside configured target scope"):
            client.get("http://example.invalid/off-scope")


def test_rejects_protocol_relative_url_outside_base_origin():
    with _server() as (target, _):
        client = WebClient(_base_url(target))

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

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SameOriginRedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = WebClient(_base_url(server))

        response = client.get("/")

        assert response.status_code == 200
        assert response.text == "redirected"
        assert SameOriginRedirectHandler.hits[-1]["path"] == "/final"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_blocks_cross_origin_redirect_before_requesting_new_host():
    with _server() as (off_scope, off_scope_handler):
        redirect_headers = {"Location": f"{_base_url(off_scope)}/internal-metadata"}
        with _server(status=302, headers=redirect_headers) as (target, _):
            client = WebClient(_base_url(target))

            with pytest.raises(ValueError, match="redirect outside configured target scope"):
                client.get("/")

        assert off_scope_handler.hits == []


def test_cross_origin_redirect_does_not_receive_configured_cookies():
    with _server() as (off_scope, off_scope_handler):
        redirect_headers = {"Location": f"{_base_url(off_scope)}/cookie-sink"}
        with _server(status=302, headers=redirect_headers) as (target, _):
            client = WebClient(_base_url(target))
            client.set_cookies({"sessionid": "COOKIELEAKMARKER"})

            with pytest.raises(ValueError, match="redirect outside configured target scope"):
                client.get("/")

        assert off_scope_handler.hits == []


def test_same_origin_absolute_url_is_allowed():
    with _server() as (target, handler):
        client = WebClient(_base_url(target))

        response = client.get(f"{_base_url(target)}/same-origin")

        assert response.status_code == 200
        assert handler.hits[-1]["path"] == "/same-origin"
