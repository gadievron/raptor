"""Exact permissions and anonymous reads, without starting a proxy or browser."""

from __future__ import annotations

import io
from unittest.mock import Mock
from concurrent.futures import ThreadPoolExecutor
import gzip
import threading
import traceback

import pytest
import urllib3

from core.http import HttpError, NotModified, SizeLimitExceeded
from core.http import anonymous
from core.http.anonymous import AnonymousOriginClient
from core.http.urllib_backend import UrllibClient, _HostCircuitBreaker


@pytest.fixture
def transport(monkeypatch):
    """Real bounded HTTP reader; only the network pool is replaced."""
    pool = Mock(spec=urllib3.PoolManager)
    created = []

    def build(hosts):
        created.append(tuple(hosts))
        backend = UrllibClient(_http=pool, circuit_breaker=_HostCircuitBreaker())
        return backend

    monkeypatch.setattr(anonymous, "EgressClient", build)
    return pool, created


def response(pool, body=b"asset", *, status=200, headers=None):
    actual = urllib3.response.HTTPResponse(
        body=io.BytesIO(body), status=status, headers=headers or {},
        preload_content=False,
    )
    pool.request.return_value = actual
    return actual


def client(**kwargs):
    return AnonymousOriginClient(["https://assets.example:8443"], max_bytes=32, **kwargs)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_permitted_reads_use_real_bounded_reader(transport, method):
    pool, created = transport
    response(pool)
    with client() as reader:
        actual = reader.request(method, "https://ASSETS.example:8443/a")
    assert created == [("assets.example",)]
    assert actual.body == (b"asset" if method == "GET" else b"")
    assert actual.status == 200
    call = pool.request.call_args
    assert call.args == (method, "https://ASSETS.example:8443/a")
    assert call.kwargs["headers"].get("accept-encoding") == "identity"
    assert call.kwargs["body"] is None
    assert call.kwargs["redirect"] is False
    assert call.kwargs["retries"] is False
    pool.clear.assert_called_once_with()


@pytest.mark.parametrize("url", [
    "https://assets.example/a", "http://assets.example:8443/a",
    "https://assets.example:9443/a", "https://sub.assets.example:8443/a",
    "https://other.example:8443/a", "https://assets.example:0/a",
    "https://assets.example:99999/a", "https://assets.example:bad/a",
    "https://[invalid/a", "//assets.example:8443/a", "/relative",
    "data:text/plain,hello", "file:///tmp/asset", "wss://assets.example:8443/a",
    "https://name:password@assets.example:8443/a",
    "https://@assets.example:8443/a", "https://assets.example:8443/a\n",
    " https://assets.example:8443/a", "https://assets.example:8443/a\x00",
    "https://assets.example:8443/" + "a" * 65536,
])
def test_refusal_happens_before_transport(transport, url):
    pool, _ = transport
    with client() as reader, pytest.raises(HttpError):
        reader.request("GET", url)
    pool.request.assert_not_called()


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS", "get", "GET\r\n"])
def test_other_methods_refused_before_transport(transport, method):
    pool, _ = transport
    with client() as reader, pytest.raises(HttpError):
        reader.request(method, "https://assets.example:8443/a")
    pool.request.assert_not_called()


@pytest.mark.parametrize("header", [
    "Authorization", "authorization", "Cookie", "Proxy-Authorization",
    "X-Api-Key", "X-Custom-Secret", "Referer", "Origin", "Host", "Accept-Encoding",
])
def test_only_explicit_anonymous_headers_allowed(transport, header):
    pool, _ = transport
    with client() as reader, pytest.raises(HttpError):
        reader.request("GET", "https://assets.example:8443/a", headers={header: "fixture"})
    pool.request.assert_not_called()


@pytest.mark.parametrize("name", ["Accept", "Accept-Language", "If-None-Match", "If-Modified-Since", "Range"])
def test_safe_headers_preserved_without_mutating_input(transport, name):
    pool, _ = transport
    response(pool)
    supplied = {name: "fixture"}
    with client() as reader:
        reader.request("GET", "https://assets.example:8443/a", headers=supplied)
    assert supplied == {name: "fixture"}
    assert pool.request.call_args.kwargs["headers"][name.lower()] == "fixture"


@pytest.mark.parametrize("headers", [
    {"Accept": "first", "accept": "second"}, {"Accept": "line\nbreak"},
    {"Accept": "line\rbreak"}, {"Accept": "nul\x00"}, {"Accept": "del\x7f"},
    {"Accept": None}, {None: "value"},
])
def test_bad_header_shapes_refused(transport, headers):
    pool, _ = transport
    with client() as reader, pytest.raises(HttpError):
        reader.request("GET", "https://assets.example:8443/a", headers=headers)
    pool.request.assert_not_called()


@pytest.mark.parametrize("origins", [
    [], "https://assets.example", ["http://assets.example"],
    ["https://assets.example/path"], ["https://assets.example/?query"],
    ["https://assets.example/#fragment"], ["https://*.example"],
    ["https://assets.example:0"], ["https://assets.example:65536"],
    ["https://user:secret@assets.example"], ["https://assets.example", "bad"],
    ["https://assets%2eexample"], ["https://assets.example\\other"],
    [None], [""], ["https://[broken"],
])
def test_invalid_declarations_do_not_register_hosts(transport, origins):
    _, created = transport
    with pytest.raises(ValueError):
        AnonymousOriginClient(origins, max_bytes=32)
    assert not created


@pytest.mark.parametrize("key", ["max_bytes", "timeout", "total_timeout"])
@pytest.mark.parametrize("value", [0, -1, True, False, 0.5, float("inf"), float("nan"), "10", None])
def test_invalid_limits_do_not_register_hosts(transport, key, value):
    _, created = transport
    kwargs = {"max_bytes": 32, key: value}
    with pytest.raises(ValueError):
        AnonymousOriginClient(["https://assets.example"], **kwargs)
    assert not created


def test_origins_are_snapshotted_normalised_and_immutable(transport):
    _, created = transport
    grants = ["https://ASSETS.example", "https://assets.example:443/", "https://assets.example:8443"]
    with AnonymousOriginClient(iter(grants), max_bytes=32) as reader:
        grants.append("https://other.example")
        assert reader.allowed_origins == frozenset({
            ("https", "assets.example", 443), ("https", "assets.example", 8443),
        })
    assert created == [("assets.example",)]


def test_idn_uses_the_transport_normalisation(transport):
    pool, created = transport
    response(pool)
    with AnonymousOriginClient(["https://b\u00fccher.example"], max_bytes=32) as reader:
        reader.request("GET", "https://xn--bcher-kva.example/a")
    assert created == [("xn--bcher-kva.example",)]


def test_ipv6_origin_keeps_port_and_registers_unbracketed_host(transport):
    _, created = transport
    with AnonymousOriginClient(["https://[2001:4860:4860::8888]:8443"], max_bytes=32) as reader:
        assert reader.allowed_origins == frozenset({("https", "2001:4860:4860::8888", 8443)})
    assert created == [("2001:4860:4860::8888",)]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_redirect_is_returned_without_following(transport, status):
    pool, _ = transport
    response(pool, status=status, headers={"Location": "https://other.example/a"})
    with client() as reader:
        actual = reader.request("GET", "https://assets.example:8443/a")
    assert actual.status == status
    assert actual.headers["location"] == "https://other.example/a"
    pool.request.assert_called_once()


def test_set_cookie_does_not_create_a_cookie_jar(transport):
    pool, _ = transport
    response(pool, headers={"Set-Cookie": "fixture=value; Path=/"})
    with client() as reader:
        reader.request("GET", "https://assets.example:8443/first")
        response(pool)
        reader.request("GET", "https://assets.example:8443/second")
    for call in pool.request.call_args_list:
        assert not {"cookie", "authorization"} & {name.lower() for name in call.kwargs["headers"]}


@pytest.mark.parametrize("size, accepted", [(31, True), (32, True), (33, False)])
def test_size_cap_is_enforced_by_the_real_reader(transport, size, accepted):
    pool, _ = transport
    actual = response(pool, b"a" * size)
    with client() as reader:
        if accepted:
            assert len(reader.request("GET", "https://assets.example:8443/a").body) == size
        else:
            with pytest.raises(SizeLimitExceeded):
                reader.request("GET", "https://assets.example:8443/a")
    assert actual.closed


def test_error_status_has_no_retry(transport):
    pool, _ = transport
    response(pool, status=503)
    with client() as reader:
        assert reader.request("GET", "https://assets.example:8443/a").status == 503
    pool.request.assert_called_once()


def test_existing_not_modified_signal_is_preserved(transport):
    pool, _ = transport
    response(pool, b"", status=304)
    with client() as reader, pytest.raises(NotModified):
        reader.request("GET", "https://assets.example:8443/a")


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_not_modified_releases_bytes_but_consumes_request_slot(transport, method):
    pool, _ = transport
    with client(max_total_bytes=32, max_requests=3) as reader:
        for count in (1, 2):
            response(pool, b"", status=304)
            with pytest.raises(NotModified):
                reader.request(method, "https://assets.example:8443/a", headers={"If-None-Match": '"fixture"'})
            assert reader.usage == {"requests": count, "accounted_bytes": 0, "reserved_bytes": 0}
        response(pool, b"body")
        assert reader.request("GET", "https://assets.example:8443/a").body == b"body"
        assert reader.usage == {"requests": 3, "accounted_bytes": 4, "reserved_bytes": 0}
        with pytest.raises(HttpError, match="request-count"):
            reader.request("GET", "https://assets.example:8443/a")
    assert pool.request.call_count == 3


def test_timeouts_are_passed_to_transport(transport):
    pool, _ = transport
    response(pool)
    with client(timeout=7, total_timeout=9) as reader:
        reader.request("GET", "https://assets.example:8443/a")
    assert pool.request.call_args.kwargs["timeout"].total == 7


def test_close_blocks_reuse_and_releases_only_owned_pool(transport):
    pool, _ = transport
    reader = client()
    reader.close()
    reader.close()
    assert pool.clear.call_count == 2
    with pytest.raises(HttpError, match="closed"):
        reader.request("GET", "https://assets.example:8443/a")
    with pytest.raises(HttpError, match="closed"):
        reader.__enter__()
    pool.request.assert_not_called()


def test_context_exit_closes_pool_when_request_fails(transport):
    pool, _ = transport
    pool.request.side_effect = RuntimeError("owned fixture failure")
    with pytest.raises(RuntimeError, match="owned fixture failure"):
        with client() as reader:
            reader.request("GET", "https://assets.example:8443/a")
    pool.clear.assert_called_once_with()


@pytest.mark.parametrize("key", ["max_requests", "max_total_bytes"])
@pytest.mark.parametrize("value", [0, -1, True, 0.5, "10"])
def test_invalid_aggregate_limits_do_not_register_hosts(transport, key, value):
    _, created = transport
    with pytest.raises(ValueError):
        client(**{key: value})
    assert not created


def test_request_budget_includes_http_errors_and_redirects(transport):
    pool, _ = transport
    with client(max_requests=2) as reader:
        response(pool, status=302, headers={"Location": "/next"})
        reader.request("GET", "https://assets.example:8443/a")
        response(pool, status=404)
        reader.request("GET", "https://assets.example:8443/b")
        with pytest.raises(HttpError, match="request-count"):
            reader.request("GET", "https://assets.example:8443/c")
        assert reader.usage["requests"] == 2
    assert pool.request.call_count == 2


def test_total_body_budget_releases_unused_reservations(transport):
    pool, _ = transport
    with client(max_total_bytes=10) as reader:
        response(pool, b"1234")
        reader.request("GET", "https://assets.example:8443/a")
        assert reader.usage == {"requests": 1, "accounted_bytes": 4, "reserved_bytes": 0}
        response(pool, b"123456")
        reader.request("GET", "https://assets.example:8443/b")
        with pytest.raises(HttpError, match="response-byte"):
            reader.request("GET", "https://assets.example:8443/c")
        response(pool, b"")
        reader.request("HEAD", "https://assets.example:8443/c")
        assert reader.usage == {"requests": 3, "accounted_bytes": 10, "reserved_bytes": 0}


def test_failed_request_conservatively_consumes_byte_reservation(transport):
    pool, _ = transport
    pool.request.side_effect = HttpError("fixture transport failure")
    with client(max_total_bytes=16) as reader:
        with pytest.raises(HttpError, match="fixture transport"):
            reader.request("GET", "https://assets.example:8443/a")
        assert reader.usage == {"requests": 1, "accounted_bytes": 16, "reserved_bytes": 0}
        with pytest.raises(HttpError, match="response-byte"):
            reader.request("GET", "https://assets.example:8443/a")
    pool.request.assert_called_once()


def test_concurrent_requests_cannot_spend_the_same_byte_budget(transport):
    pool, _ = transport
    entered, release = threading.Event(), threading.Event()
    def hold(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return urllib3.response.HTTPResponse(body=io.BytesIO(b"12"), status=200, preload_content=False)
    pool.request.side_effect = hold
    with client(max_total_bytes=5) as reader, ThreadPoolExecutor(max_workers=1) as workers:
        future = workers.submit(reader.request, "GET", "https://assets.example:8443/a")
        try:
            assert entered.wait(3)
            assert reader.usage["reserved_bytes"] == 5
            with pytest.raises(HttpError, match="response-byte"):
                reader.request("GET", "https://assets.example:8443/b")
        finally:
            release.set()
        assert future.result(timeout=3).body == b"12"
        assert reader.usage == {"requests": 1, "accounted_bytes": 2, "reserved_bytes": 0}


def test_anonymous_body_preserves_declared_encoding_for_forwarding(transport):
    pool, _ = transport
    body = gzip.compress(b"fixture resource")
    response(pool, body, headers={"Content-Encoding": "gzip"})
    with AnonymousOriginClient(["https://assets.example"], max_bytes=128) as reader:
        actual = reader.request("GET", "https://assets.example/a")
    assert actual.body == body
    assert actual.headers["content-encoding"] == "gzip"


def test_invalid_origin_traceback_does_not_echo_embedded_credentials(transport):
    _, created = transport
    invalid = "https://fixture:fixture-secret@" + chr(0xD800) + ".example"
    with pytest.raises(ValueError) as error:
        AnonymousOriginClient([invalid], max_bytes=32)
    assert "fixture-secret" not in str(error.value)
    assert "fixture-secret" not in "".join(traceback.format_exception(error.value))
    assert not created
