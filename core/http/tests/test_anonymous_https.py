"""Captive HTTPS verification of anonymous requests; no external services.

The origin client uses its real urllib backend with an explicitly trusted
test pool. Proxy routing is covered separately by egress/proxy tests; no
production address checks are relaxed to reach this loopback fixture.
"""

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import shutil
import ssl
import subprocess

import pytest
import urllib3

from core.http import HttpError, SizeLimitExceeded
from core.http import anonymous
from core.http.anonymous import AnonymousOriginClient
from core.http.urllib_backend import UrllibClient, _HostCircuitBreaker
from packages.web.tests.http_server import start_http_server

pytestmark = pytest.mark.integration


@pytest.fixture
def https_endpoint(tmp_path):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is required for the captive HTTPS certificate")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:TRUE",
    ], check=True, capture_output=True, timeout=15, env={"PATH": os.defpath})
    key.chmod(0o600)
    hits, ports = [], []
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def do_GET(self):
            ports.append(self.client_address[1])
            hits.append((self.path, {name.lower(): value for name, value in self.headers.items()}))
            body = b"x" * (65 if self.path == "/large" else 5)
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "fixture=value; Path=/")
            if self.path == "/redirect":
                self.send_header("Location", "/followed")
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    with ExitStack() as cleanup:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cleanup.callback(server.server_close)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        start_http_server(server, cleanup.callback)
        yield f"https://127.0.0.1:{server.server_port}", str(cert), hits, ports


@pytest.fixture
def real_reader(https_endpoint, monkeypatch):
    origin, cert, hits, ports = https_endpoint
    pools = []
    def build(hosts):
        assert hosts == ["127.0.0.1"]
        pool = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=cert, retries=False)
        pools.append(pool)
        return UrllibClient(_http=pool, circuit_breaker=_HostCircuitBreaker())
    monkeypatch.setattr(anonymous, "EgressClient", build)
    try:
        yield origin, hits, ports
    finally:
        for pool in pools:
            pool.clear()


def test_wire_requests_have_no_implicit_credentials_or_cookies(real_reader, monkeypatch, tmp_path):
    origin, hits, ports = real_reader
    (tmp_path / ".netrc").write_text("machine 127.0.0.1 login fixture password fixture-secret\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    with AnonymousOriginClient([origin], max_bytes=64) as reader:
        assert reader.request("GET", origin + "/first").body == b"xxxxx"
        assert reader.request("GET", origin + "/second").body == b"xxxxx"
        with pytest.raises(HttpError):
            reader.request("GET", origin + "/rejected", headers={"X-Origin-Verify": "fixture"})
    assert [path for path, _ in hits] == ["/first", "/second"]
    assert len(set(ports)) == 1, "completed reads should reuse the TLS connection"
    for _, headers in hits:
        assert not {"authorization", "cookie", "proxy-authorization", "x-origin-verify"} & headers.keys()


def test_wire_redirect_is_returned_without_contacting_destination(real_reader):
    origin, hits, _ = real_reader
    with AnonymousOriginClient([origin], max_bytes=64) as reader:
        response = reader.request("GET", origin + "/redirect")
    assert response.status == 302
    assert response.headers["location"] == "/followed"
    assert [path for path, _ in hits] == ["/redirect"]


def test_wire_response_limit_is_enforced(real_reader):
    origin, _, _ = real_reader
    with AnonymousOriginClient([origin], max_bytes=64) as reader:
        with pytest.raises(SizeLimitExceeded):
            reader.request("GET", origin + "/large")
