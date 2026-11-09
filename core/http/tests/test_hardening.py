"""Boundary tests for budgets, pooled-body ownership and proxy configuration."""

from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import gzip
import io
import socket
import threading
import time
import traceback
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import urllib3

from core.http import HttpError, Response, SizeLimitExceeded, StreamWallclockExceeded
from core.http import _body, urllib_backend as backend
from core.http._body import BodyDeadline, response_body
from core.http.headers import anonymous_resource_headers, request_headers
from core.http.urllib_backend import UrllibClient, _HostCircuitBreaker
from core.testing.module_bindings import patch_module_attribute


def reader(body=b"content", *, status=200, headers=None):
    response = urllib3.response.HTTPResponse(
        body=io.BytesIO(body), status=status, headers=headers or {}, preload_content=False,
    )
    pool = Mock(spec=urllib3.PoolManager)
    pool.request.return_value = response
    return UrllibClient(_http=pool, circuit_breaker=_HostCircuitBreaker()), pool, response


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("key,value", [
    ("max_bytes", -1), ("max_bytes", None), ("max_bytes", True), ("max_bytes", 1.5),
    ("timeout", 0), ("timeout", -1), ("timeout", float("nan")),
    ("timeout", float("inf")), ("timeout", True), ("timeout", 10 ** 1000),
    ("total_timeout", -1), ("total_timeout", float("nan")),
    ("total_timeout", float("inf")), ("total_timeout", True),
    ("retries", -1), ("retries", True), ("retries", 0.5),
])
def test_invalid_limits_fail_before_transport(stream, key, value):
    client, pool, _ = reader()
    with pytest.raises(ValueError):
        if stream:
            client.stream_bytes("https://fixture.example/a", **{key: value})
        else:
            client.request("GET", "https://fixture.example/a", **{key: value})
    pool.request.assert_not_called()


@pytest.mark.parametrize("stream", [False, True])
def test_zero_byte_cap_accepts_only_empty_bodies(stream):
    for body in (b"", b"a"):
        client, _, _ = reader(body)
        def get():
            return b"".join(client.stream_bytes("https://fixture.example/a", max_bytes=0)) if stream else client.get_bytes("https://fixture.example/a", max_bytes=0)
        if body:
            with pytest.raises(SizeLimitExceeded):
                get()
        else:
            assert get() == b""


@pytest.mark.parametrize("stream", [False, True])
def test_gzip_is_decoded_exactly_once(stream):
    inner = gzip.compress(b"an application gzip file")
    client, _, _ = reader(gzip.compress(inner), headers={"Content-Encoding": "gzip"})
    actual = b"".join(client.stream_bytes("https://fixture.example/a")) if stream else client.get_bytes("https://fixture.example/a")
    assert actual == inner


@pytest.mark.parametrize("stream", [False, True])
def test_decoded_bytes_are_subject_to_cap(stream):
    client, _, actual = reader(gzip.compress(b"a" * 65), headers={"Content-Encoding": "gzip"})
    with pytest.raises(SizeLimitExceeded):
        if stream:
            list(client.stream_bytes("https://fixture.example/a", max_bytes=64))
        else:
            client.get_bytes("https://fixture.example/a", max_bytes=64)
    assert actual.closed


@pytest.mark.parametrize("stream", [False, True])
def test_deadline_includes_header_time_and_closes_response(stream, monkeypatch):
    client, pool, actual = reader()
    clock = [100.0]
    patch_module_attribute(monkeypatch, backend, "time", "monotonic", lambda: clock[0])
    def headers(*args, **kwargs):
        clock[0] += 5
        return actual
    pool.request.side_effect = headers
    with pytest.raises(StreamWallclockExceeded):
        if stream:
            list(client.stream_bytes("https://fixture.example/a", total_timeout=1))
        else:
            client.get_bytes("https://fixture.example/a", total_timeout=1)
    assert actual.closed


def test_retry_attempt_timeout_is_clipped_to_remaining_budget(monkeypatch):
    client, pool, _ = reader()
    client.get_bytes("https://fixture.example/a", timeout=30, total_timeout=1)
    assert 0 < pool.request.call_args.kwargs["timeout"].total <= 1


@pytest.mark.parametrize("url", [None, b"https://fixture.example", "", "\nhttps://fixture.example", "https://fixture.example/a\t", "https://fixture.example:0", "https:///missing?token=fixture-secret"])
def test_bad_urls_refused_without_echoing_query_values(url):
    client, pool, _ = reader()
    with pytest.raises(HttpError) as error:
        client.get_bytes(url)
    assert "fixture-secret" not in str(error.value)
    pool.request.assert_not_called()


@pytest.mark.parametrize("stream", [False, True])
def test_transport_error_traceback_does_not_repeat_credentials(stream):
    client, pool, _ = reader()
    pool.request.side_effect = urllib3.exceptions.ProtocolError(
        "failed https://fixture.example/a?access_token=fixture-secret"
    )
    with pytest.raises(HttpError) as error:
        if stream:
            list(client.stream_bytes("https://fixture.example/a", retries=0))
        else:
            client.get_bytes("https://fixture.example/a", retries=0)
    assert "fixture-secret" not in str(error.value)
    formatted = "".join(traceback.format_exception(error.value))
    assert "fixture-secret" not in formatted


@pytest.mark.parametrize("port,expected", [(443, False), (8443, True), (None, False)])
def test_no_proxy_honours_explicit_port(port, expected):
    assert backend._host_in_no_proxy("assets.example", ("assets.example:8443",), port) is expected


@pytest.mark.parametrize("entry,port,expected", [
    ("[::1]:8443", 8443, True), ("[::1]:8443", 443, False),
    ("[::1]", 443, True), ("::1", 443, True),
    ("[::1]:", 443, False), ("[::1]garbage", 443, False),
])
def test_no_proxy_ipv6(entry, port, expected):
    assert backend._host_in_no_proxy("::1", (entry,), port) is expected


def test_proxy_auth_unquotes_credentials_and_preserves_ipv6():
    pool = backend._new_proxy_manager("http://user%40example:p%3Ass@[::1]:3128")
    try:
        assert pool.proxy.host == "[::1]"
        assert pool.proxy.port == 3128
        encoded = pool.proxy_headers["proxy-authorization"].split()[1]
        assert base64.b64decode(encoded) == b"user@example:p:ss"
    finally:
        pool.clear()


def test_concurrent_lazy_proxy_pool_creation_is_owned_once(monkeypatch):
    pool = Mock(spec=urllib3.PoolManager)
    made = []
    def make(url):
        made.append(url)
        time.sleep(0.01)
        return pool
    monkeypatch.setattr(backend, "_new_proxy_manager", make)
    client, direct, _ = reader()
    client._proxy_map = {"https": "http://proxy.invalid:3128"}
    with ThreadPoolExecutor(max_workers=8) as workers:
        actual = list(workers.map(client._pool_for, ["https://fixture.example/a"] * 8))
    assert actual == [pool] * 8
    assert made == ["http://proxy.invalid:3128"]
    client.close()
    direct.clear.assert_called_once_with()
    pool.clear.assert_called_once_with()


def test_closing_shared_scheme_proxy_pool_clears_once():
    client, direct, _ = reader()
    proxy = Mock(spec=urllib3.ProxyManager)
    client._proxy_pools = {"http": proxy, "https": proxy}
    client.close()
    direct.clear.assert_called_once_with()
    proxy.clear.assert_called_once_with()


def test_deadline_cannot_release_connection_while_watchdog_owns_it():
    response = urllib3.response.HTTPResponse(body=io.BytesIO(b"ok"), preload_content=False)
    connection = Mock(spec=urllib3.connection.HTTPConnection)
    pool = Mock(spec=urllib3.HTTPConnectionPool)
    response._connection = connection
    response._pool = pool
    with BodyDeadline(response, 10, clock=lambda: 0):
        response.release_conn()
        pool._put_conn.assert_not_called()
        assert response._connection is connection
    assert response._pool is pool
    response.release_conn()
    pool._put_conn.assert_called_once_with(connection)
    response.close()


def test_body_watchdog_interrupts_owned_socket_and_joins_before_release():
    left, right = socket.socketpair()
    response = urllib3.response.HTTPResponse(body=io.BytesIO(b""), preload_content=False)
    response._connection = SimpleNamespace(sock=left, close=left.close)
    guard = BodyDeadline(response, time.monotonic() + 0.05)
    try:
        with pytest.raises(StreamWallclockExceeded):
            with guard:
                left.settimeout(2)
                assert left.recv(1) == b""
        assert guard._timer is not None and not guard._timer.is_alive()
    finally:
        response.close()
        left.close()
        right.close()


@pytest.mark.parametrize("after_start", [False, True])
def test_watchdog_setup_failure_restores_pool_and_stops_worker(monkeypatch, after_start):
    left, right = socket.socketpair()
    response = urllib3.response.HTTPResponse(body=io.BytesIO(b""), preload_content=False)
    response._connection = SimpleNamespace(sock=left, close=left.close)
    pool = Mock(spec=urllib3.HTTPConnectionPool)
    response._pool = pool
    real = threading.Timer
    made = []
    class FailedTimer(real):
        def start(self):
            made.append(self)
            if after_start:
                super().start()
            raise RuntimeError("owned timer start failure")
    patch_module_attribute(monkeypatch, _body, "threading", "Timer", FailedTimer)
    try:
        with pytest.raises(RuntimeError, match="owned timer start failure"):
            with response_body(response, time.monotonic() + 5, clock=time.monotonic):
                pytest.fail("timer setup should have failed")
        assert response._pool is pool
        assert made and all(not timer.is_alive() for timer in made)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("header", ["Set-Cookie", "Clear-Site-Data", "Alt-Svc", "Strict-Transport-Security", "Content-Length", "Transfer-Encoding", "X-Custom-State"])
def test_forwarded_resource_headers_exclude_origin_state(header):
    assert anonymous_resource_headers({header: "fixture", "Content-Type": "text/css"}) == {"content-type": "text/css"}


def test_connection_nominated_fields_are_not_forwarded():
    assert anonymous_resource_headers({"Connection": "ETag", "ETag": "fixture", "Content-Type": "text/css"}) == {"content-type": "text/css"}


@pytest.mark.parametrize("headers", [
    {"Content-Type": "text/css\ntext/plain"}, {"ETag": "first", "etag": "second"},
    {"Bad Name": "fixture"}, {"Content-Type": "text/css\r\n"},
])
def test_ambiguous_forwarded_headers_are_refused(headers):
    with pytest.raises(HttpError):
        anonymous_resource_headers(headers)


def test_resource_metadata_preserves_encoding_and_cors():
    supplied = {"Content-Encoding": "gzip", "Access-Control-Allow-Origin": "https://fixture.example"}
    assert anonymous_resource_headers(supplied) == {name.lower(): value for name, value in supplied.items()}


def test_circuit_state_is_bounded_across_hosts_and_failure_bursts():
    circuit = _HostCircuitBreaker(threshold=3, max_hosts=4)
    for host in range(20):
        for _ in range(10):
            circuit.record_failure(f"host-{host}.example", 443)
    assert len(circuit._tracked) == 4
    assert len(circuit._failures) == 4
    assert len(circuit._open_until) == 4
    assert all(len(events) <= 3 for events in circuit._failures.values())
    assert circuit.is_open("host-0.example", 443)[0] is False
    assert circuit.is_open("host-19.example", 443)[0] is True


def test_circuit_eviction_preserves_recently_observed_hosts():
    circuit = _HostCircuitBreaker(threshold=1, max_hosts=2)
    circuit.record_failure("first.example", 443)
    circuit.record_failure("second.example", 443)
    assert circuit.is_open("first.example", 443)[0]
    circuit.record_failure("third.example", 443)
    assert circuit.is_open("first.example", 443)[0]
    assert not circuit.is_open("second.example", 443)[0]
    circuit.record_success("first.example", 443)
    assert ("first.example", 443) not in circuit._tracked


@pytest.mark.parametrize("size", [0, -1, True, 0.5, None])
def test_buffered_response_chunk_size_is_validated(size):
    response = Response(status=200, headers={}, body=b"fixture", url="https://fixture.example")
    with pytest.raises(ValueError):
        list(response.iter_content(size))


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("headers", [
    {"Bad Name": "fixture"}, {"Authorization": "fixture\nsecret"},
    {"Cookie": "fixture\rsecret"}, {"X-Fixture": "fixture\x00secret"},
    {"Accept": "one", "accept": "two"}, {"Accept": None}, "not-a-mapping",
])
def test_bad_request_headers_are_refused_before_transport(stream, headers):
    client, pool, _ = reader()
    with pytest.raises(HttpError) as error:
        if stream:
            client.stream_bytes("https://fixture.example/a", headers=headers)
        else:
            client.get_bytes("https://fixture.example/a", headers=headers)
    pool.request.assert_not_called()
    assert "secret" not in str(error.value)


def test_request_header_overrides_are_case_insensitive_and_owned():
    defaults = {"User-Agent": "default", "Accept": "default"}
    supplied = {"user-agent": "fixture"}
    assert request_headers(defaults, supplied) == {"Accept": "default", "user-agent": "fixture"}
    assert defaults == {"User-Agent": "default", "Accept": "default"}
    assert supplied == {"user-agent": "fixture"}


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("character", ["\u0100", "\U0001f512", "\ud800"], ids=["bmp", "emoji", "surrogate"])
def test_unencodable_request_headers_fail_before_transport(stream, character):
    client, pool, _ = reader()
    supplied = {"Authorization": "fixture-private-value-" + character}
    with pytest.raises(HttpError, match="header") as error:
        if stream:
            client.stream_bytes("https://fixture.example/a", headers=supplied)
        else:
            client.get_bytes("https://fixture.example/a", headers=supplied)
    pool.request.assert_not_called()
    assert supplied["Authorization"] not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize("stream", [False, True])
def test_latin1_request_header_values_reach_transport_unchanged(stream):
    client, pool, _ = reader()
    supplied = {"X-Fixture": "caf\u00e9"}
    if stream:
        assert b"".join(client.stream_bytes("https://fixture.example/a", headers=supplied)) == b"content"
    else:
        assert client.get_bytes("https://fixture.example/a", headers=supplied) == b"content"
    assert pool.request.call_args.kwargs["headers"]["X-Fixture"] == supplied["X-Fixture"]
    assert supplied == {"X-Fixture": "caf\u00e9"}


@pytest.mark.parametrize("method", ["", "GET\n", "GET bad", None])
def test_invalid_methods_are_refused_before_transport(method):
    client, pool, _ = reader()
    with pytest.raises(HttpError, match="method"):
        client.request(method, "https://fixture.example/a")
    pool.request.assert_not_called()


def test_permanent_urllib_header_errors_are_not_retried():
    client, pool, _ = reader()
    pool.request.side_effect = urllib3.exceptions.InvalidHeader("fixture invalid header")
    with pytest.raises(HttpError):
        client.get_bytes("https://fixture.example/a")
    pool.request.assert_called_once()


@pytest.mark.parametrize("primary", [HttpError("fixture body error"), KeyboardInterrupt()])
def test_cleanup_failure_preserves_primary_exception(primary):
    response = Mock()
    response.close.side_effect = OSError("fixture close failure")
    with pytest.raises(type(primary)) as error:
        with response_body(response, 10, clock=lambda: 0):
            raise primary
    assert error.value is primary
    assert "HTTP response cleanup also failed" in error.value.__notes__
    response.release_conn.assert_not_called()


def test_cleanup_only_failure_uses_public_http_error_contract():
    response = Mock()
    response.close.side_effect = OSError("fixture close failure")
    with pytest.raises(HttpError, match="cleanup failed"):
        with response_body(response, 10, clock=lambda: 0):
            pass
    response.release_conn.assert_not_called()


def test_failed_real_response_close_retires_its_connection_slot(monkeypatch):
    response = urllib3.response.HTTPResponse(body=io.BytesIO(b"fixture"), preload_content=False)
    connection = Mock(spec=urllib3.connection.HTTPConnection)
    pool = Mock(spec=urllib3.HTTPConnectionPool)
    response._connection, response._pool = connection, pool
    monkeypatch.setattr(response, "close", Mock(side_effect=OSError("fixture close failure")))
    with pytest.raises(HttpError, match="cleanup failed"):
        with response_body(response, 10, clock=lambda: 0):
            pass
    connection.close.assert_called_once_with()
    pool._put_conn.assert_called_once_with(None)
    assert response._connection is None
