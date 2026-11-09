"""Owned HTTP origins through the real CONNECT proxy; no external services."""

from contextlib import ExitStack, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event

from core.http.tests.test_anonymous_https import https_endpoint as _https_endpoint_fixture

import pytest

from core.http import HttpError, SizeLimitExceeded
from core.http.anonymous import AnonymousOriginClient
from core.http.egress_backend import EgressClient
from core.sandbox import proxy as proxy_mod
from core.testing.proxy_scope import isolated_proxy_scope
from packages.web.tests.http_server import start_http_server

https_endpoint = _https_endpoint_fixture
pytestmark = pytest.mark.integration


@pytest.fixture
def endpoint(request):
    hits, ports = [], []
    release_body = Event()
    request.addfinalizer(release_body.set)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def respond(self, *, head=False):
            size = int(self.headers.get("Content-Length", "0"))
            data = self.rfile.read(size) if size else b""
            hits.append((self.command, self.path,
                         {k.lower(): v for k, v in self.headers.items()}, data))
            ports.append(self.client_address[1])
            body = b"x" * 65 if self.path == "/large" else b"hello"
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "fixture=value; Path=/")
            if self.path == "/redirect":
                self.send_header("Location", "/followed")
            self.end_headers()
            if self.path == "/stall":
                self.wfile.flush()
                release_body.wait(3)
            if not head:
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):  # noqa: N802
            self.respond()

        def do_HEAD(self):  # noqa: N802
            self.respond(head=True)

        def do_POST(self):  # noqa: N802
            self.respond()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    start_http_server(server, lambda cb, *args: request.addfinalizer(lambda: cb(*args)))
    return f"http://127.0.0.1:{server.server_port}", hits, ports


@pytest.fixture
def proxy(monkeypatch, request):
    # Only the admitted fixture permits its own loopback origin. The denial
    # variant retains the production address check and must never hit it.
    if getattr(request, "param", True):
        blocked = proxy_mod._ip_is_blocked
        monkeypatch.setattr(proxy_mod, "_ip_is_blocked",
                            lambda ip: False if ip == "127.0.0.1" else blocked(ip))
    with isolated_proxy_scope():
        with ExitStack() as cleanup:
            instance = proxy_mod.EgressProxy(["127.0.0.1"])
            cleanup.callback(instance.stop)
            monkeypatch.setattr(proxy_mod, "get_proxy", lambda hosts: instance)
            yield instance


def test_http_round_trip_and_reuse_through_connect(endpoint, proxy):
    origin, hits, ports = endpoint
    client = EgressClient(["127.0.0.1"])
    try:
        assert client.get_bytes(origin + "/first?q=one", retries=0) == b"hello"
        assert client.get_bytes(origin + "/second", retries=0) == b"hello"
    finally:
        client.close()
    assert [h[1] for h in hits] == ["/first?q=one", "/second"]
    assert all(h[2]["host"] == origin.removeprefix("http://") for h in hits)
    assert len(set(ports)) == 1


def test_http_methods_and_limits(endpoint, proxy):
    origin, hits, _ = endpoint
    with closing(EgressClient(["127.0.0.1"])) as client:
        assert client.request("HEAD", origin, retries=0).body == b""
        assert client.request("POST", origin + "/post", body=b"\x00\xff", retries=0).body == b"hello"
        with pytest.raises(SizeLimitExceeded):
            client.get_bytes(origin + "/large", max_bytes=64, retries=0)
    assert hits[1][0] == "POST"
    assert hits[1][3] == b"\x00\xff"


def test_http_anonymous_origins_and_budgets(endpoint, proxy):
    origin, hits, _ = endpoint
    with AnonymousOriginClient([origin], max_bytes=64, max_requests=3,
                               max_total_bytes=128) as client:
        assert client.request("GET", origin).body == b"hello"
        assert client.request("GET", origin + "/redirect").status == 302
        with pytest.raises(HttpError, match="permissions"):
            client.request("GET", origin.replace("http:", "https:"))
        assert client.request("HEAD", origin).body == b""
        with pytest.raises(HttpError, match="request-count"):
            client.request("GET", origin)
        assert client.usage == {"requests": 3, "accounted_bytes": 10, "reserved_bytes": 0}
    assert len(hits) == 3
    assert all(not ({"authorization", "proxy-authorization", "cookie"} & h[2].keys()) for h in hits)
    assert all(h[1] != "/followed" for h in hits)


def test_http_host_denial_has_no_direct_fallback(endpoint, proxy):
    origin, hits, _ = endpoint
    with closing(EgressClient(["127.0.0.1"])) as client:
        with pytest.raises(HttpError):
            client.get_bytes(origin.replace("127.0.0.1", "localhost"), retries=0)
    assert hits == []


@pytest.mark.parametrize("proxy", [False], indirect=True)
def test_http_production_address_denial(endpoint, proxy):
    origin, hits, _ = endpoint
    with closing(EgressClient(["127.0.0.1"])) as client:
        with pytest.raises(HttpError):
            client.get_bytes(origin, retries=0)
    assert hits == []


def test_http_unavailable_proxy_has_no_direct_fallback(endpoint, proxy):
    origin, hits, _ = endpoint
    client = EgressClient(["127.0.0.1"])
    proxy.stop()
    try:
        with pytest.raises(HttpError):
            client.get_bytes(origin, retries=0, timeout=1)
    finally:
        client.close()
    assert hits == []


def test_http_proxy_credentials_stay_in_connect(endpoint, proxy):
    from core.http._connect import ConnectProxyManager
    from core.http.urllib_backend import UrllibClient, _new_proxy_manager
    origin, hits, _ = endpoint
    manager = _new_proxy_manager(
        f"http://fixture:secret@127.0.0.1:{proxy.port}", manager_class=ConnectProxyManager,
    )
    pool = manager.connection_from_url(origin)
    assert pool.proxy is None
    conn = pool._new_conn()
    assert conn._tunnel_headers["proxy-authorization"].startswith("Basic ")
    conn.close()
    with closing(UrllibClient(_http=manager)) as client:
        assert client.get_bytes(origin, retries=0) == b"hello"
    assert "proxy-authorization" not in hits[0][2]


def test_connect_manager_isolates_target_pools():
    import urllib3
    from core.http._connect import ConnectProxyManager
    manager = ConnectProxyManager("http://127.0.0.1:12345")
    normal = urllib3.PoolManager()
    try:
        one = manager.connection_from_url("http://one.example:80")
        assert manager.connection_from_url("http://one.example") is one
        assert manager.connection_from_url("http://two.example") is not one
        assert manager.connection_from_url("http://one.example:81") is not one
        assert manager.connection_from_url("https://one.example") is not one
        assert isinstance(manager.connection_from_url("https://one.example"), urllib3.HTTPSConnectionPool)
        assert type(normal.connection_from_url("http://one.example")) is urllib3.HTTPConnectionPool
    finally:
        manager.clear()
        normal.clear()


def test_http_lane_keeps_existing_port_restriction(endpoint, proxy, monkeypatch):
    from core.http import egress_backend
    origin, hits, _ = endpoint
    target_port = int(origin.rsplit(":", 1)[1])
    lane_port = proxy.bind_tcp_lane(
        label="http-test", allowed_hosts=["127.0.0.1"],
        allowed_ports=[1 if target_port != 1 else 2],
    )
    monkeypatch.setattr(egress_backend, "seatbelt_parent_proxy_url",
                        lambda: f"http://127.0.0.1:{lane_port}")
    with closing(EgressClient(["127.0.0.1"])) as client:
        with pytest.raises(HttpError):
            client.get_bytes(origin, retries=0)
    assert hits == []


def test_http_chained_connect_proxy(endpoint, proxy, monkeypatch):
    origin, hits, _ = endpoint
    downstream = proxy_mod.EgressProxy(
        ["127.0.0.1"], upstream_proxy=f"http://127.0.0.1:{proxy.port}",
    )
    try:
        monkeypatch.setattr(proxy_mod, "get_proxy", lambda hosts: downstream)
        with closing(EgressClient(["127.0.0.1"])) as client:
            assert client.get_bytes(origin, retries=0) == b"hello"
    finally:
        downstream.stop()
    assert len(hits) == 1


def test_http_total_deadline_cancels_tunnel(endpoint, proxy):
    origin, hits, _ = endpoint
    with closing(EgressClient(["127.0.0.1"])) as client:
        with pytest.raises(HttpError, match="[Tt]ime|deadline"):
            client.get_bytes(origin + "/stall", timeout=5, total_timeout=1, retries=0)
    assert len(hits) == 1


def test_https_still_verifies_certificate_through_connect(https_endpoint, proxy):
    from core.http._connect import ConnectProxyManager
    from core.http.urllib_backend import UrllibClient
    origin, cert, hits, _ = https_endpoint
    with closing(UrllibClient(_http=ConnectProxyManager(
        f"http://127.0.0.1:{proxy.port}", cert_reqs="CERT_REQUIRED", ca_certs=cert,
    ))) as client:
        assert client.get_bytes(origin, retries=0) == b"xxxxx"
    assert len(hits) == 1
    with closing(UrllibClient(_http=ConnectProxyManager(
        f"http://127.0.0.1:{proxy.port}", cert_reqs="CERT_REQUIRED",
    ))) as untrusted:
        with pytest.raises(HttpError):
            untrusted.get_bytes(origin, retries=0)
    assert len(hits) == 1
