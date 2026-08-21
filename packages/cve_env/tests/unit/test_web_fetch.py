"""Tests for tools/web_fetch.py — SSRF-guarded research GET on the
core.http transport.

The transport is mocked at ``cve_env.tools.web_fetch._client`` with
scripted :class:`core.http.Response` objects / ``HttpError`` raises, so
no test touches the network. DNS is patched per-test (the SSRF guards
call ``socket.getaddrinfo``), which also makes the fetch-path tests
hermetic on hosts without resolvers.

Behavioural contract carried over from the pre-core.http
implementation: the guard set (scheme / literal / DNS-rebind pre-check /
post-redirect re-check), the ReasonClass mapping, truncation, selected
response headers, and the payload dict shape. Two deliberate
inversions, both design-record §4.5/§4.7 citizenship decisions:
operator proxy env is now HONOURED (core.http snapshots it; the old
code disabled proxies and hard-failed on proxy-only hosts), and
transient retries live inside core.http (Retry-After aware) instead of
a local sleep loop — ``enable_retry`` maps onto the client's retry
count.
"""

from __future__ import annotations

import socket
from typing import Any
from unittest.mock import patch

import pytest

from core.http import HttpError, Response, SizeLimitExceeded

from cve_env.tools import web_fetch as wf
from cve_env.tools.web_fetch import (
    FetchResult,
    _classify_http_status,
    _is_loopback_or_private,
    _resolve_hostname_safe,
    web_fetch,
    web_fetch_payload,
)

PUBLIC_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
PRIVATE_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
METADATA_ADDRINFO = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]


def _resp(status=200, body=b"<html>ok</html>", url="https://example.com/x",
          headers=None):
    hdrs = {"content-type": "text/html"}
    hdrs.update(headers or {})
    return Response(status=status, headers=hdrs, body=body, url=url)


class _FakeClient:
    """Scripted core.http client double. ``script`` entries are either a
    Response to return or an exception to raise, consumed in order."""

    def __init__(self, script: list[Any], stream_chunks: list[bytes] | None = None,
                 stream_exc: Exception | None = None):
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []
        self.stream_calls: list[dict[str, Any]] = []
        self._stream_chunks = stream_chunks or []
        self._stream_exc = stream_exc

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url, **kw})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def stream_bytes(self, url, **kw):
        self.stream_calls.append({"url": url, **kw})
        yield from self._stream_chunks
        if self._stream_exc is not None:
            raise self._stream_exc


def _fetch(fake, url="https://example.com/x", addrinfo=PUBLIC_ADDRINFO, **kw):
    with (
        patch.object(wf, "_client", lambda: fake),
        patch.object(wf.socket, "getaddrinfo", return_value=addrinfo),
    ):
        return web_fetch(url=url, **kw)


# ── guards (no transport involved) ───────────────────────────────────────


@pytest.mark.parametrize("host", [
    "localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9",
    "169.254.169.254", "metadata.google.internal", "::1", "0.0.0.0",
])
def test_is_loopback_or_private_blocks(host: str) -> None:
    assert _is_loopback_or_private(host) is True


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "raw.githubusercontent.com"])
def test_is_loopback_or_private_allows_public(host: str) -> None:
    assert _is_loopback_or_private(host) is False


def test_is_loopback_or_private_empty_hostname_is_false() -> None:
    assert _is_loopback_or_private("") is False


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x"])
def test_rejects_non_http_schemes(url: str) -> None:
    r = web_fetch(url=url)
    assert r.ok is False
    assert "not allowed" in r.reason
    assert r.reason_class == "not_found"


def test_rejects_missing_hostname() -> None:
    r = web_fetch(url="http:///nohost")
    assert r.ok is False
    assert r.reason_class == "not_found"


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/admin", "http://10.1.2.3/x", "http://localhost:8080/",
])
def test_rejects_loopback_and_private_urls(url: str) -> None:
    r = web_fetch(url=url)
    assert r.ok is False
    assert "SSRF" in r.reason
    assert r.reason_class == "not_found"


def test_ssrf_dns_rebinding_blocks_localhost_resolved_hostname() -> None:
    fake = _FakeClient([_resp()])
    r = _fetch(fake, url="https://evil.example.com/x", addrinfo=PRIVATE_ADDRINFO)
    assert r.ok is False
    assert "resolves to 127.0.0.1" in r.reason
    assert fake.calls == [], "transport must not be touched on a rebind block"


def test_ssrf_dns_rebinding_blocks_169_254_metadata() -> None:
    fake = _FakeClient([_resp()])
    r = _fetch(fake, url="https://evil.example.com/x", addrinfo=METADATA_ADDRINFO)
    assert r.ok is False
    assert "169.254.169.254" in r.reason
    assert fake.calls == []


def test_ssrf_public_ip_still_works() -> None:
    fake = _FakeClient([_resp()])
    r = _fetch(fake)
    assert r.ok is True


def test_resolve_hostname_safe_resolution_failure_blocks() -> None:
    with patch.object(wf.socket, "getaddrinfo", side_effect=OSError("no dns")):
        reason = _resolve_hostname_safe("cannot-resolve.example")
    assert reason is not None
    assert "fail closed" in reason


def test_resolve_hostname_safe_unicode_error_blocks() -> None:
    with patch.object(wf.socket, "getaddrinfo",
                      side_effect=UnicodeError("label too long")):
        assert _resolve_hostname_safe("x" * 300) is not None


def test_resolve_hostname_safe_empty_sockaddr_skipped() -> None:
    infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ()), *PUBLIC_ADDRINFO]
    with patch.object(wf.socket, "getaddrinfo", return_value=infos):
        assert _resolve_hostname_safe("example.com") is None


def test_resolve_hostname_safe_unparseable_ip_skipped() -> None:
    infos = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 0)),
             *PUBLIC_ADDRINFO]
    with patch.object(wf.socket, "getaddrinfo", return_value=infos):
        assert _resolve_hostname_safe("example.com") is None


# ── transport behaviour via the core.http double ─────────────────────────


def test_fetch_success() -> None:
    fake = _FakeClient([_resp(body=b"hello world")])
    r = _fetch(fake)
    assert r.ok is True
    assert r.status == 200
    assert r.body == "hello world"
    assert r.body_bytes == 11
    assert r.truncated is False
    assert r.content_type == "text/html"
    assert r.reason_class == "ok"


def test_fetch_uses_get_with_redirects_and_cap() -> None:
    fake = _FakeClient([_resp()])
    _fetch(fake, max_bytes=1234)
    call = fake.calls[0]
    assert call["method"] == "GET"
    assert call["max_bytes"] == 1234
    assert call["follow_redirects"] is True
    assert call["raise_on_status"] is False


def test_fetch_truncates_large_body() -> None:
    fake = _FakeClient(
        [SizeLimitExceeded("body exceeded 8 bytes")],
        stream_chunks=[b"12345678", b"OVERFLOW"],
        stream_exc=SizeLimitExceeded("cap"),
    )
    r = _fetch(fake, max_bytes=8)
    assert r.ok is True
    assert r.truncated is True
    assert r.body == "12345678"
    assert r.body_bytes == 8
    assert fake.stream_calls, "over-cap body must be recovered via stream"


def test_fetch_timeout_maps_to_transport() -> None:
    fake = _FakeClient([HttpError("GET https://example.com/x timed out")])
    r = _fetch(fake)
    assert r.ok is False
    assert r.reason_class == "transport"
    assert "timed out" in r.reason


def test_fetch_network_error_maps_to_transport() -> None:
    fake = _FakeClient([HttpError("connection refused")])
    r = _fetch(fake)
    assert r.ok is False
    assert r.reason_class == "transport"


def test_fetch_non_2xx_returns_body() -> None:
    fake = _FakeClient([_resp(status=500, body=b"oops")])
    r = _fetch(fake)
    assert r.ok is False
    assert r.status == 500
    assert r.body == "oops"
    assert r.reason == "HTTP 500"
    assert r.reason_class == "transport"


def test_fetch_429_classifies_rate_limited() -> None:
    """core.http retries 429 internally (Retry-After honoured); when the
    final answer is still 429 the classification surfaces to the agent."""
    fake = _FakeClient([_resp(status=429, body=b"slow down")])
    r = _fetch(fake)
    assert r.ok is False
    assert r.reason_class == "rate_limited"


@pytest.mark.parametrize("status,klass", [
    (404, "not_found"), (410, "not_found"),
    (401, "auth"), (403, "auth"),
])
def test_fetch_permanent_statuses_classify(status: int, klass: str) -> None:
    fake = _FakeClient([_resp(status=status)])
    r = _fetch(fake)
    assert r.ok is False
    assert r.reason_class == klass


def test_enable_retry_maps_to_client_retries() -> None:
    fake = _FakeClient([_resp(), _resp()])
    _fetch(fake)  # default enable_retry=True
    _fetch(fake, enable_retry=False)
    assert fake.calls[0]["retries"] == 1
    assert fake.calls[1]["retries"] == 0


def test_fetch_post_redirect_to_private_literal_rejected() -> None:
    fake = _FakeClient([_resp(url="http://127.0.0.1:8080/internal")])
    r = _fetch(fake)
    assert r.ok is False
    assert "post-redirect" in r.reason
    assert r.reason_class == "not_found"


def test_fetch_post_redirect_to_private_hostname_rejected() -> None:
    """A redirect target that LOOKS public but resolves inside must be
    rejected by the post-redirect re-resolve."""
    fake = _FakeClient([_resp(url="https://internal-lb.example.com/x")])

    def per_host(host, *a, **kw):
        if host == "internal-lb.example.com":
            return PRIVATE_ADDRINFO
        return PUBLIC_ADDRINFO

    with (
        patch.object(wf, "_client", lambda: fake),
        patch.object(wf.socket, "getaddrinfo", side_effect=per_host),
    ):
        r = web_fetch(url="https://example.com/x")
    assert r.ok is False
    assert "post-redirect" in r.reason


def test_fetch_final_url_without_hostname_skips_post_redirect_resolve() -> None:
    fake = _FakeClient([_resp(url="https:///weird")])
    r = _fetch(fake)
    assert r.ok is True  # no hostname to re-check; body path proceeds


def test_fetch_returns_selected_headers() -> None:
    fake = _FakeClient([_resp(headers={
        "etag": '"abc"', "last-modified": "yesterday",
        "x-secret-internal": "nope", "server": "nginx",
    })])
    r = _fetch(fake)
    assert r.headers == {
        "content-type": "text/html",
        "etag": '"abc"',
        "last-modified": "yesterday",
    }


def test_fetch_passes_caller_headers_to_client() -> None:
    fake = _FakeClient([_resp()])
    _fetch(fake, headers={"Authorization": "token x"})
    assert fake.calls[0]["headers"] == {"Authorization": "token x"}


def test_fetch_non_utf8_body_uses_replacement_decode() -> None:
    fake = _FakeClient([_resp(body=b"\xff\xfebad")])
    r = _fetch(fake)
    assert r.ok is True
    assert "�" in r.body


def test_operator_proxy_is_honoured_via_core_http() -> None:
    """Design inversion vs the requests-era BUG-004b test: the transport
    is core.http's UrllibClient, which snapshots the OPERATOR's proxy
    env at construction — proxy-only hosts must work. Child-process
    proxy hygiene is safe_subprocess_env's job, not this module's."""
    from core.http.urllib_backend import UrllibClient

    wf._client_singleton = None
    try:
        assert isinstance(wf._client(), UrllibClient)
    finally:
        wf._client_singleton = None


@pytest.mark.parametrize("status", [302, 400, 418, 451])
def test_classify_http_status_other_3xx_4xx_is_not_found(status: int) -> None:
    assert _classify_http_status(status) == "not_found"


# ── payload shape ─────────────────────────────────────────────────────────


def test_payload_includes_reason_class_field() -> None:
    fake = _FakeClient([_resp(body=b"x")])
    with (
        patch.object(wf, "_client", lambda: fake),
        patch.object(wf.socket, "getaddrinfo", return_value=PUBLIC_ADDRINFO),
    ):
        payload = web_fetch_payload(url="https://example.com/x")
    assert set(payload.keys()) == {
        "ok", "url", "status", "content_type", "body", "body_bytes",
        "truncated", "reason", "reason_class",
    }
    assert payload["reason_class"] == "ok"


def test_blocked_scheme_classifies_not_found() -> None:
    payload = web_fetch_payload(url="gopher://example.com/x")
    assert payload["ok"] is False
    assert payload["reason_class"] == "not_found"


def test_loopback_url_classifies_not_found() -> None:
    r: FetchResult = web_fetch(url="http://127.0.0.1/x")
    assert r.reason_class == "not_found"
