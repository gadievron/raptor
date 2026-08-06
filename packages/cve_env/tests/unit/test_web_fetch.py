"""Tests for :mod:`cve_env.tools.web_fetch`.

Mocks ``requests.get`` to exercise SSRF guards, size cap, timeout, and
post-redirect re-check without real network.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from cve_env.tools.web_fetch import (
    _classify_http_status,
    _is_loopback_or_private,
    _resolve_hostname_safe,
    web_fetch,
)


@pytest.fixture(autouse=True)
def _pin_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep these tests hermetic ("without real network", per the module
    docstring). The Phase-61.1 DNS-rebind guard calls ``socket.getaddrinfo``
    BEFORE the mocked ``requests.get``; sandboxed/CI resolvers can map
    ``example.com`` → 127.0.0.1, which the guard correctly rejects — short-
    circuiting before the mock and breaking the retry/status tests. Pin
    resolution to a PUBLIC IP so resolution is deterministic. The guard itself
    is covered by the IP-literal tests (127.0.0.1, ::1, 169.254.169.254, …),
    which reject before getaddrinfo and are unaffected."""
    monkeypatch.setattr(
        "cve_env.tools.web_fetch.socket.getaddrinfo",
        lambda *_a, **_k: [(2, 1, 6, "", ("93.184.216.34", 0))],
    )


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # AWS / cloud metadata
        "metadata.google.internal",
        "::1",
        "fc00::1",
    ],
)
def test_is_loopback_or_private_blocks(host: str) -> None:
    assert _is_loopback_or_private(host) is True


@pytest.mark.parametrize(
    "host",
    [
        "services.nvd.nist.gov",
        "api.github.com",
        "raw.githubusercontent.com",
        "8.8.8.8",
        "1.1.1.1",
    ],
)
def test_is_loopback_or_private_allows_public(host: str) -> None:
    assert _is_loopback_or_private(host) is False


def test_rejects_non_http_scheme() -> None:
    r = web_fetch(url="file:///etc/passwd")
    assert r.ok is False
    assert "scheme" in r.reason


def test_rejects_ftp_scheme() -> None:
    r = web_fetch(url="ftp://example.com")
    assert r.ok is False
    assert "scheme" in r.reason


def test_rejects_loopback_url() -> None:
    r = web_fetch(url="http://127.0.0.1:80/")
    assert r.ok is False
    assert "SSRF" in r.reason or "local" in r.reason


def test_rejects_private_range_url() -> None:
    r = web_fetch(url="http://192.168.1.1/")
    assert r.ok is False
    assert "local" in r.reason or "private" in r.reason


def test_rejects_missing_hostname() -> None:
    r = web_fetch(url="http:///path")
    assert r.ok is False
    assert "hostname" in r.reason


def _mk_stream_resp(
    *,
    status: int,
    body: bytes,
    content_type: str = "text/plain",
    final_url: str | None = None,
    ok: bool | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.ok = ok if ok is not None else (200 <= status < 400)
    resp.headers = {"Content-Type": content_type}
    resp.url = final_url or "https://example.com/x"
    resp.iter_content = MagicMock(return_value=[body])
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_success(mock_get: Any) -> None:
    mock_get.return_value = _mk_stream_resp(
        status=200, body=b"hello", content_type="text/plain"
    )
    r = web_fetch(url="https://example.com/x")
    assert r.ok is True
    assert r.status == 200
    assert r.body == "hello"
    assert r.body_bytes == 5
    assert r.truncated is False


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_truncates_large_body(mock_get: Any) -> None:
    big = b"x" * (300 * 1024)
    mock_get.return_value = _mk_stream_resp(status=200, body=big)
    r = web_fetch(url="https://example.com/", max_bytes=256 * 1024)
    assert r.ok is True
    assert r.truncated is True
    assert r.body_bytes == 256 * 1024


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_timeout(mock_get: Any, mock_sleep: Any) -> None:
    mock_get.side_effect = requests.exceptions.Timeout("slow")
    r = web_fetch(url="https://example.com/", timeout_seconds=1.0)
    assert r.ok is False
    assert "timeout" in r.reason.lower()
    assert r.reason_class == "transport"
    # Phase 0: a transient triggers exactly one retry (so 2 total calls).
    assert mock_get.call_count == 2


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_request_exception(mock_get: Any, mock_sleep: Any) -> None:
    mock_get.side_effect = requests.exceptions.ConnectionError("refused")
    r = web_fetch(url="https://example.com/")
    assert r.ok is False
    assert "request error" in r.reason
    assert r.reason_class == "transport"
    assert mock_get.call_count == 2


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_non_2xx_returns_body(mock_get: Any) -> None:
    mock_get.return_value = _mk_stream_resp(status=404, body=b"nope", ok=False)
    r = web_fetch(url="https://example.com/x")
    assert r.ok is False
    assert r.status == 404
    assert r.body == "nope"
    assert "404" in r.reason


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_post_redirect_to_private_rejected(mock_get: Any) -> None:
    # Server claims 200 OK but redirects to a private IP.
    mock_get.return_value = _mk_stream_resp(
        status=200,
        body=b"irrelevant",
        final_url="http://10.0.0.5/",
    )
    r = web_fetch(url="https://example.com/redirects")
    assert r.ok is False
    assert "local" in r.reason or "private" in r.reason


@patch("cve_env.tools.web_fetch.requests.get")
@patch("cve_env.tools.web_fetch.socket.getaddrinfo")
def test_fetch_post_redirect_to_private_hostname_rejected(
    mock_getaddrinfo: Any, mock_get: Any
) -> None:
    """RACE-2 defense-in-depth: a redirect to a public-LOOKING hostname whose
    DNS resolves to an internal IP must be rejected post-redirect (parity with
    the pre-request DNS-rebind guard). The IP-literal check alone misses this.
    """

    def _resolve(host: str, *_a: Any, **_k: Any) -> list[Any]:
        # Initial host resolves public; the redirect target resolves to 10.x.
        if "internal" in host:
            return [(None, None, None, "", ("10.0.0.5", 0))]
        return [(None, None, None, "", ("140.82.121.4", 0))]  # public

    mock_getaddrinfo.side_effect = _resolve
    mock_get.return_value = _mk_stream_resp(
        status=200,
        body=b"irrelevant",
        final_url="http://internal.corp.example/",  # public-looking name → 10.x
    )
    r = web_fetch(url="https://example.com/redirects")
    assert r.ok is False
    assert r.reason_class == "not_found"
    assert "post-redirect" in r.reason
    assert "10.0.0.5" in r.reason or "SSRF" in r.reason or "private" in r.reason


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_returns_selected_headers(mock_get: Any) -> None:
    resp = _mk_stream_resp(status=200, body=b"x", content_type="application/json")
    resp.headers = {
        "Content-Type": "application/json",
        "Server": "should-not-appear",
        "ETag": '"abc"',
    }
    mock_get.return_value = resp
    r = web_fetch(url="https://example.com/")
    assert "content-type" in [k.lower() for k in r.headers]
    assert "etag" in [k.lower() for k in r.headers]
    assert "server" not in [k.lower() for k in r.headers]


# Phase 0: reason_class + retry behavior --------------------------------------


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_429_retries_once_then_returns_rate_limited(
    mock_get: Any, mock_sleep: Any
) -> None:
    """A 429 fires exactly one retry (10s backoff) before surfacing."""
    mock_get.return_value = _mk_stream_resp(status=429, body=b"slow", ok=False)
    r = web_fetch(url="https://api.github.com/x")
    assert r.ok is False
    assert r.reason_class == "rate_limited"
    assert mock_get.call_count == 2  # original + 1 retry
    # The transient backoff for rate_limited is 10s.
    mock_sleep.assert_called_once_with(10.0)


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_404_does_not_retry(mock_get: Any, mock_sleep: Any) -> None:
    """A 404 is permanent; never retry."""
    mock_get.return_value = _mk_stream_resp(status=404, body=b"nope", ok=False)
    r = web_fetch(url="https://example.com/missing")
    assert r.ok is False
    assert r.reason_class == "not_found"
    assert mock_get.call_count == 1  # no retry
    assert mock_sleep.call_count == 0


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_403_does_not_retry(mock_get: Any, mock_sleep: Any) -> None:
    """A 403 is auth-class; never retry (won't help without credentials)."""
    mock_get.return_value = _mk_stream_resp(status=403, body=b"denied", ok=False)
    r = web_fetch(url="https://api.github.com/forbidden")
    assert r.ok is False
    assert r.reason_class == "auth"
    assert mock_get.call_count == 1
    assert mock_sleep.call_count == 0


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_503_retries_then_succeeds(mock_get: Any, mock_sleep: Any) -> None:
    """A 503 followed by a 200 on retry returns the 200."""
    mock_get.side_effect = [
        _mk_stream_resp(status=503, body=b"down", ok=False),
        _mk_stream_resp(status=200, body=b"recovered", content_type="text/plain"),
    ]
    r = web_fetch(url="https://example.com/x")
    assert r.ok is True
    assert r.status == 200
    assert r.reason_class == "ok"
    assert mock_get.call_count == 2
    mock_sleep.assert_called_once_with(5.0)  # transport backoff


@patch("cve_env.tools.web_fetch.time.sleep")
@patch("cve_env.tools.web_fetch.requests.get")
def test_enable_retry_false_skips_retry(mock_get: Any, mock_sleep: Any) -> None:
    """enable_retry=False (callers in retry-controlled contexts) suppresses retry."""
    mock_get.return_value = _mk_stream_resp(status=429, body=b"slow", ok=False)
    r = web_fetch(url="https://api.example.com/", enable_retry=False)
    assert r.reason_class == "rate_limited"
    assert mock_get.call_count == 1
    assert mock_sleep.call_count == 0


def test_payload_includes_reason_class_field() -> None:
    """The agent-tool payload exposes reason_class so the LLM can see it."""
    from cve_env.tools.web_fetch import web_fetch_payload

    with patch("cve_env.tools.web_fetch.requests.get") as mock_get:
        mock_get.return_value = _mk_stream_resp(status=200, body=b"hi")
        out = web_fetch_payload(url="https://example.com/x")
    assert "reason_class" in out
    assert out["reason_class"] == "ok"


def test_blocked_scheme_classifies_not_found() -> None:
    """A blocked scheme is permanent (no_retry) and classified not_found."""
    r = web_fetch(url="ftp://example.com/")
    assert r.ok is False
    assert r.reason_class == "not_found"


def test_loopback_url_classifies_not_found() -> None:
    """SSRF guard rejects + classifies as not_found (permanent)."""
    r = web_fetch(url="http://127.0.0.1/")
    assert r.ok is False
    assert r.reason_class == "not_found"


# Phase 61.1 — SSRF DNS-rebinding guard --------------------------------------


@patch("cve_env.tools.web_fetch.socket.getaddrinfo")
def test_phase61_ssrf_dns_rebinding_blocks_localhost_resolved_hostname(
    mock_getaddrinfo: Any,
) -> None:
    """A non-literal hostname that resolves to 127.0.0.1 must be blocked.

    Pre-fix: hostname check (ipaddress.ip_address) raises ValueError on a
    DNS name and falls through, allowing requests.get to follow attacker-
    controlled DNS to internal IPs. Post-fix: getaddrinfo is consulted
    BEFORE the request and the resolved IP is checked.
    """
    # Simulate evil.example.com → 127.0.0.1 via DNS.
    mock_getaddrinfo.return_value = [
        (None, None, None, "", ("127.0.0.1", 0)),
    ]
    with patch("cve_env.tools.web_fetch.requests.get") as mock_get:
        r = web_fetch(url="http://evil.example.com/")
    assert r.ok is False
    assert r.reason_class == "not_found"
    assert "SSRF" in r.reason or "private" in r.reason or "loopback" in r.reason
    # The request must NEVER have fired.
    assert mock_get.call_count == 0


@patch("cve_env.tools.web_fetch.socket.getaddrinfo")
def test_phase61_ssrf_dns_rebinding_blocks_169_254_metadata(
    mock_getaddrinfo: Any,
) -> None:
    """An attacker DNS pointing at 169.254.169.254 (cloud metadata) is blocked."""
    mock_getaddrinfo.return_value = [
        (None, None, None, "", ("169.254.169.254", 0)),
    ]
    with patch("cve_env.tools.web_fetch.requests.get") as mock_get:
        r = web_fetch(url="http://attacker.example.com/")
    assert r.ok is False
    assert r.reason_class == "not_found"
    assert mock_get.call_count == 0


@patch("cve_env.tools.web_fetch.socket.getaddrinfo")
@patch("cve_env.tools.web_fetch.requests.get")
def test_phase61_ssrf_public_ip_still_works(
    mock_get: Any, mock_getaddrinfo: Any
) -> None:
    """Sanity: a hostname resolving to a public IP must still fetch."""
    mock_getaddrinfo.return_value = [
        (None, None, None, "", ("140.82.121.4", 0)),  # api.github.com (public)
    ]
    mock_get.return_value = _mk_stream_resp(status=200, body=b"ok")
    r = web_fetch(url="https://api.github.com/")
    assert r.ok is True
    assert mock_get.call_count == 1


# ─── BUG-004b: env-based proxy injection defense ──────────────────────────


@patch("cve_env.tools.web_fetch.socket.getaddrinfo")
@patch("cve_env.tools.web_fetch.requests.get")
def test_BUG004b_web_fetch_passes_empty_proxies_kwarg(
    mock_get: Any, mock_getaddrinfo: Any
) -> None:
    """BUG-004b (port from bafb): web_fetch MUST pass
    proxies={"http": "", "https": ""} to requests.get to defeat env-based
    proxy injection (HTTP_PROXY / HTTPS_PROXY). Empty dict ({}) is a no-op
    in `requests` — env vars still merge — so the explicit empty-string
    sentinel is required.
    """
    mock_getaddrinfo.return_value = [
        (None, None, None, "", ("140.82.121.4", 0)),
    ]
    mock_get.return_value = _mk_stream_resp(status=200, body=b"ok")
    web_fetch(url="https://api.github.com/")
    assert mock_get.call_count == 1
    _args, kwargs = mock_get.call_args
    assert kwargs.get("proxies") == {"http": "", "https": ""}, (
        f"BUG-004b: web_fetch did not pass proxies={{'http':'','https':''}}; "
        f"got proxies={kwargs.get('proxies')!r}"
    )


# ─── Branch-coverage fill: pure-logic gaps ────────────────────────────────


@pytest.mark.parametrize(
    "status",
    [301, 302, 307, 400, 418],  # 3xx/4xx not in the explicit buckets
)
def test_classify_http_status_other_3xx_4xx_is_not_found(status: int) -> None:
    """Line 65: any 3xx/4xx outside the explicit buckets (429/401/403/404/410/5xx)
    falls through to the permanent ``not_found`` default."""
    assert _classify_http_status(status) == "not_found"


def test_is_loopback_or_private_empty_hostname_is_false() -> None:
    """Line 102: an empty hostname short-circuits to False (no SSRF verdict)."""
    assert _is_loopback_or_private("") is False


def test_resolve_hostname_safe_resolution_failure_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lines 133-138: getaddrinfo raising OSError blocks the request (fail
    closed) — returns a reason string, not None."""

    def _boom(*_a: Any, **_k: Any) -> list[Any]:
        raise OSError("DNS down")

    monkeypatch.setattr("cve_env.tools.web_fetch.socket.getaddrinfo", _boom)
    result = _resolve_hostname_safe("nope.example.com")
    assert result is not None
    assert "fail closed" in result.lower() or "resolution failed" in result.lower()


def test_resolve_hostname_safe_unicode_error_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lines 133-138: a UnicodeError from getaddrinfo (IDNA encoding failure)
    blocks the request (fail closed)."""

    def _boom(*_a: Any, **_k: Any) -> list[Any]:
        raise UnicodeError("bad idna")

    monkeypatch.setattr("cve_env.tools.web_fetch.socket.getaddrinfo", _boom)
    result = _resolve_hostname_safe("xn--bad.example.com")
    assert result is not None
    assert "fail closed" in result.lower() or "resolution failed" in result.lower()


def test_resolve_hostname_safe_empty_sockaddr_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Line 142: an addrinfo tuple with a falsy sockaddr is skipped; with only
    such entries the host is treated as having no unsafe IP (returns None)."""
    monkeypatch.setattr(
        "cve_env.tools.web_fetch.socket.getaddrinfo",
        lambda *_a, **_k: [(2, 1, 6, "", None)],
    )
    assert _resolve_hostname_safe("public.example.com") is None


def test_resolve_hostname_safe_unparseable_ip_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lines 146-147: a sockaddr[0] that is not a parseable IP raises ValueError
    in ipaddress.ip_address and is skipped (continue); returns None."""
    monkeypatch.setattr(
        "cve_env.tools.web_fetch.socket.getaddrinfo",
        lambda *_a, **_k: [(2, 1, 6, "", ("not-an-ip", 0))],
    )
    assert _resolve_hostname_safe("public.example.com") is None


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_passes_caller_headers_to_requests(mock_get: Any) -> None:
    """Line 201: caller-supplied headers are merged into the request headers
    (on top of the default User-Agent)."""
    mock_get.return_value = _mk_stream_resp(status=200, body=b"ok")
    web_fetch(url="https://example.com/x", headers={"X-Custom": "yes"})
    _args, kwargs = mock_get.call_args
    sent = kwargs.get("headers", {})
    assert sent.get("X-Custom") == "yes"
    assert "User-Agent" in sent  # default preserved


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_final_url_without_hostname_skips_post_redirect_resolve(
    mock_get: Any,
) -> None:
    """Branch 245->256: when the final URL has no hostname (e.g. an opaque
    scheme), the post-redirect DNS re-resolve is skipped and the body is read
    normally. The earlier IP-literal post-redirect check passes because
    ``hostname or ""`` → "" is not loopback/private."""
    mock_get.return_value = _mk_stream_resp(
        status=200, body=b"body-content", final_url="about:blank"
    )
    r = web_fetch(url="https://example.com/x")
    assert r.ok is True
    assert r.body == "body-content"
    assert r.url == "about:blank"


@patch("cve_env.tools.web_fetch.requests.get")
def test_fetch_non_utf8_body_uses_replacement_decode(mock_get: Any) -> None:
    """Lines 269-270: a body that fails strict utf-8 decode falls back to
    errors='replace' (lossy) rather than raising."""
    mock_get.return_value = _mk_stream_resp(status=200, body=b"\xff\xfe")
    r = web_fetch(url="https://example.com/x")
    assert r.ok is True
    assert r.body_bytes == 2
    # b"\xff\xfe" is invalid utf-8 → each byte maps to U+FFFD replacement char.
    assert r.body == "��"
