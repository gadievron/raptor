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


# -- pin key canonicalisation (IDN / spelling variants) ------------------------
#
# The pin is only sound when it operates on the SAME normalized form
# the socket layer resolves. urllib3 resolves the IDNA2008 punycode
# form; keying the pin on urlparse's unicode form made it miss for
# every IDN hostname — a live second resolution, i.e. the rebinding
# TOCTOU the pin exists to close, plus an is_global verdict about a
# DIFFERENT registrable domain (legacy-codec 'faß.de' -> 'fass.de').


_GLOBAL_ADDR = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]
_REBOUND_ADDR = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]


@contextmanager
def _hostile_resolver(answers):
    """Swap the LIVE resolution the pin wrapper falls back to.

    ``answers(host)`` returns an addrinfo list or None (miss -> refuse
    with gaierror so no test resolution ever leaves the process).
    Installs the pin wrapper first so the swap sits UNDER it, exactly
    where a rebinding resolver sits in production.
    """
    calls: list = []
    client_module._ensure_pin_wrapper_installed()
    original = client_module._original_getaddrinfo

    def fake(host, port, *args, **kwargs):
        calls.append(host)
        answer = answers(host)
        if answer is None:
            raise socket.gaierror(f"test resolver has no answer for {host!r}")
        return [
            (family, type_, proto, cname, (addr, port))
            for family, type_, proto, cname, (addr, _p) in answer
        ]

    client_module._original_getaddrinfo = fake
    try:
        yield calls
    finally:
        client_module._original_getaddrinfo = original


def test_idn_pin_serves_the_punycode_lookup_and_blocks_the_rebind():
    """In-process rebind: validation-time DNS answers a global IP,
    connect-time DNS answers loopback. The connect-time lookup arrives
    as the IDNA2008 punycode form (what urllib3 resolves); the pin must
    serve it from the validated answer instead of letting the hostile
    second resolution through."""
    def answers(host):
        text = str(host)
        if "fa" in text and ("ß" in text or "xn--" in text):
            # First (validation) resolution: global. Any later live
            # resolution is the REBOUND answer — reaching it at all is
            # the vulnerability.
            return _GLOBAL_ADDR if len(calls) <= 1 else _REBOUND_ADDR
        return None

    with _hostile_resolver(answers) as calls:
        client = WebClient("http://faß.de", block_private_ips=True, rate_limit=0)
        pinned = client._resolve_and_validate("http://faß.de/x")
        assert pinned is not None
        # Validation resolved the SAME registrable domain the transport
        # connects to — the IDNA2008 form, never legacy 'fass.de'.
        assert calls == ["xn--fa-hia.de"]
        host_key, _port, addrs = pinned
        assert host_key == "xn--fa-hia.de"
        assert addrs[0][4][0] == "93.184.216.34"
        with WebClient._pinned_dns(pinned):
            served = socket.getaddrinfo("xn--fa-hia.de", 80)
        # Pin hit: the validated answer, and NO live second resolution.
        assert served[0][4][0] == "93.184.216.34"
        assert calls == ["xn--fa-hia.de"]


@pytest.mark.parametrize("lookup_spelling", [
    "xn--fa-hia.de",        # punycode (urllib3's form)
    "faß.de",               # unicode (CPython str-host form)
    "faß.de.",              # trailing-dot FQDN
    "XN--FA-HIA.DE",        # mixed case
    "faß。de",              # ideographic full stop U+3002
    "faß．de",              # fullwidth full stop U+FF0E
])
def test_pin_hit_for_every_spelling_of_the_pinned_host(lookup_spelling):
    sentinel = [("PINNED",)]
    with WebClient._pinned_dns(("faß.de", 80, sentinel)):
        assert socket.getaddrinfo(lookup_spelling, 80) == sentinel


def test_unpinned_hosts_still_resolve_live_inside_a_pin_window():
    sentinel = [("PINNED",)]
    with WebClient._pinned_dns(("faß.de", 80, sentinel)):
        assert socket.getaddrinfo("localhost", 80) != sentinel


def test_idna_invalid_hostname_fails_closed_not_open(monkeypatch):
    """A hostname with no valid IDNA2008 form cannot be validated or
    pinned — the guard must refuse it, not fall back to an unpinned
    live resolution."""
    client = WebClient("http://xn--valid.example", block_private_ips=True)
    with pytest.raises(ValueError, match="no valid IDNA2008 form"):
        client._resolve_and_validate("http://❤️.example/")


@pytest.mark.parametrize("literal", [
    "http://[::ffff:127.0.0.1]/",   # IPv4-mapped IPv6 spelling
    "http://[0:0:0:0:0:0:0:1]/",    # expanded loopback spelling
])
def test_ipv6_literal_spellings_of_loopback_are_blocked(literal):
    client = WebClient("http://target.example", block_private_ips=True)
    with pytest.raises(ValueError, match="non-global"):
        client._resolve_and_validate(literal)


# -- body-read wall-clock deadline (drip-fed responses) ------------------------


def test_drip_fed_body_is_cut_at_the_wall_clock_deadline(monkeypatch):
    """The request `timeout` is a PER-READ socket timeout: a server
    sending one byte per window keeps every read alive, and the
    buffered read inside iter_content does not yield until its chunk
    fills — so the byte cap alone never fires and get() stalls for as
    long as the server has patience. The watchdog must cut the read at
    the deadline and hand back the buffered prefix."""
    import socketserver

    monkeypatch.setattr(
        client_module, "_MAX_BODY_READ_SECONDS", 1.0, raising=False,
    )

    class DripHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "1000")
            self.end_headers()
            try:
                # One byte per 0.25s for up to 8s: each write succeeds,
                # nothing fills a 64 KiB read chunk, EOF never comes
                # inside the test window.
                for _ in range(32):
                    self.wfile.write(b"y")
                    self.wfile.flush()
                    time.sleep(0.25)
            except OSError:
                pass  # reader hung up: the deadline fired

    class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True

    server = _Server(("127.0.0.1", 0), DripHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = WebClient(
            _base_url(server), timeout=2, rate_limit=0,
            block_private_ips=False,
        )
        start = time.monotonic()
        response = client.get("/")
        wall = time.monotonic() - start
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert wall < 4.0, f"get() held for {wall:.1f}s past the deadline"
    assert response.status_code == 200
    # The buffered prefix (whatever dripped in) is what the caller sees.
    assert len(response.content) < 1000


@pytest.mark.parametrize("evasion_host", ["0x7f000001", "0177.0.0.1"])
def test_octal_hex_ipv4_forms_are_caught_at_the_resolution_gate(evasion_host):
    """Not IP literals for `ipaddress`, but glibc resolves them via
    inet_aton semantics — the post-resolution is_global loop must
    still block the loopback answer."""
    def answers(host):
        return _REBOUND_ADDR if str(host) == evasion_host else None

    with _hostile_resolver(answers):
        client = WebClient("http://target.example", block_private_ips=True)
        with pytest.raises(ValueError, match="non-global"):
            client._resolve_and_validate(f"http://{evasion_host}/")


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


# -- concurrency + clock domain of the client's shared counters -----------------


def test_transport_error_counting_is_atomic_under_threads():
    client = WebClient("http://t.example", rate_limit=0)
    threads = [
        threading.Thread(
            target=lambda: [client.note_transport_error() for _ in range(500)],
        )
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert client.transport_errors == 4000
    client.close()


def test_get_stats_snapshots_history_under_the_append_lock():
    client = WebClient("http://t.example", rate_limit=0)
    stop = threading.Event()

    def _appender():
        response = requests.Response()
        response.status_code = 200
        response._content = b""
        while not stop.is_set():
            client._log_request("GET", "http://t.example/", response, 0.01)

    thread = threading.Thread(target=_appender)
    thread.start()
    try:
        for _ in range(200):
            stats = client.get_stats()
            assert stats == {} or stats["total_requests"] > 0
    finally:
        stop.set()
        thread.join(timeout=10)
        client.close()


def test_rate_limiter_ignores_wall_clock_steps(monkeypatch):
    """Reservations on time.time() meant an NTP step parked
    last_request_time in the future and stalled the limiter; the
    monotonic clock is immune."""
    client = WebClient("http://t.example", rate_limit=0.05)
    sleeps: list[float] = []
    monkeypatch.setattr(
        client_module.time, "sleep", lambda s: sleeps.append(s),
    )
    real_time = time.time
    client._rate_limit_wait()
    # Simulate a backward NTP step of an hour between requests.
    monkeypatch.setattr(
        client_module.time, "time", lambda: real_time() - 3600,
    )
    client._rate_limit_wait()
    client.close()
    assert all(requested < 1.0 for requested in sleeps), sleeps
