"""Tests for core.http.urllib_backend.UrllibClient (urllib3-backed)."""

from __future__ import annotations

import gzip
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# core/http/tests/test_urllib_backend.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.http import (
    DEFAULT_RETRIES,
    HttpError,
    Response,
    SizeLimitExceeded,
    default_client,
)
from core.http.urllib_backend import UrllibClient


def _stub_response(body: bytes, *, status: int = 200,
                   content_encoding: str = "",
                   reason: str = "OK",
                   extra_headers: Optional[dict] = None,
                   final_url: str = "") -> MagicMock:
    """Build a stub urllib3 HTTPResponse: stream() yields body in one chunk."""
    resp = MagicMock()
    resp.status = status
    resp.reason = reason
    headers = {"Content-Encoding": content_encoding} if content_encoding else {}
    if extra_headers:
        headers.update(extra_headers)
    resp.headers = headers
    resp.stream = lambda chunk_size, decode_content=True: iter([body])
    resp.read = lambda *a, **kw: body[:512]
    resp.release_conn = MagicMock()
    resp.geturl = lambda: final_url
    return resp


def _client_with_mock_pool(*responses):
    """Build a UrllibClient whose injected pool serves the given responses.

    Pass a single response → pool returns that for every call.
    Pass multiple positional args OR a single list → pool serves them
    sequentially via side_effect.
    """
    pool = MagicMock()
    # Unwrap a single-list arg so callers can write
    # _client_with_mock_pool([resp1, resp2, resp3])
    if len(responses) == 1 and isinstance(responses[0], list):
        responses = tuple(responses[0])
    if len(responses) == 1:
        pool.request.return_value = responses[0]
    else:
        pool.request.side_effect = list(responses)
    return UrllibClient(_http=pool), pool


# ---------------------------------------------------------------------------
# Successful paths
# ---------------------------------------------------------------------------

class TestSuccess:

    def test_get_json(self):
        client, pool = _client_with_mock_pool(_stub_response(b'{"a": 1}'))
        result = client.get_json("https://example.com/api")
        assert result == {"a": 1}
        # Verify it called pool.request once with method=GET
        assert pool.request.call_args.args[0] == "GET"

    def test_post_json_sends_serialised_body(self):
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.post_json("https://example.com/api", {"q": "deadbeef"})
        call = pool.request.call_args
        assert call.args[0] == "POST"
        assert call.kwargs["body"] == b'{"q": "deadbeef"}'
        assert call.kwargs["headers"]["Content-Type"] == "application/json"

    def test_get_bytes(self):
        client, pool = _client_with_mock_pool(_stub_response(b"\x01\x02\xff"))
        out = client.get_bytes("https://example.com/binary")
        assert out == b"\x01\x02\xff"

    def test_gzip_body_decompressed_as_defence_in_depth(self):
        """If urllib3's auto-decode misses (some servers send gzip without
        the header), the magic-byte sniffer in _fetch_once decodes it."""
        body = gzip.compress(b'{"hello": "world"}')
        # decode_content=True in urllib3 normally decompresses, but to
        # force the fallback path we lie via the stub: stream() returns
        # the raw gzipped bytes as if urllib3 didn't decode.
        client, _ = _client_with_mock_pool(_stub_response(body))
        result = client.get_json("https://example.com/api")
        assert result == {"hello": "world"}

    def test_release_conn_called(self):
        """Connection is returned to the pool after every request — this
        is the whole point of switching to urllib3."""
        resp = _stub_response(b'{"ok": true}')
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))
        client.get_json("https://example.com/api")
        resp.release_conn.assert_called_once()


class TestConnectionPooling:
    """Verify connection reuse — the headline win of switching to urllib3."""

    def test_repeat_calls_share_pool(self):
        """Multiple calls to the same client go through the same pool
        manager instance (so urllib3 can reuse the connection)."""
        pool = MagicMock()
        pool.request.return_value = _stub_response(b'{"a": 1}')
        client = UrllibClient(_http=pool)
        for _ in range(5):
            client.get_json("https://example.com/api")
        # All 5 calls hit the same pool object — urllib3 internally
        # reuses connections to the same host.
        assert pool.request.call_count == 5

    def test_pool_manager_uses_maxsize_default(self):
        """The default pool manager is constructed with maxsize > 1
        so concurrent calls to the same host don't serialise on a
        single connection."""
        from core.http.urllib_backend import _new_pool_manager, _DEFAULT_POOL_MAXSIZE
        pool = _new_pool_manager()
        # urllib3 stores maxsize on connection_pool_kw.
        assert pool.connection_pool_kw.get("maxsize") == _DEFAULT_POOL_MAXSIZE
        assert _DEFAULT_POOL_MAXSIZE > 1


# ---------------------------------------------------------------------------
# Caller-supplied headers + 304 Not Modified
# ---------------------------------------------------------------------------

class TestCallerHeaders:

    def test_get_json_merges_caller_headers(self):
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json(
            "https://example.com/api",
            headers={"Authorization": "Bearer abc123",
                     "X-Custom": "hello"},
        )
        sent = pool.request.call_args.kwargs["headers"]
        assert sent["Authorization"] == "Bearer abc123"
        assert sent["X-Custom"] == "hello"
        # Defaults still present.
        assert "User-Agent" in sent
        assert sent["Accept"] == "application/json"

    def test_caller_can_override_default_header(self):
        """Caller-supplied headers win over defaults — explicit override
        is allowed."""
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json(
            "https://example.com/api",
            headers={"User-Agent": "custom/1.0"},
        )
        sent = pool.request.call_args.kwargs["headers"]
        assert sent["User-Agent"] == "custom/1.0"

    def test_post_json_merges_caller_headers(self):
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.post_json(
            "https://example.com/api", {"x": 1},
            headers={"Authorization": "Bearer t"},
        )
        sent = pool.request.call_args.kwargs["headers"]
        assert sent["Authorization"] == "Bearer t"
        assert sent["Content-Type"] == "application/json"


class TestNotModified:
    """Conditional requests via If-None-Match / If-Modified-Since."""

    def test_304_raises_not_modified(self):
        from core.http import NotModified
        client, _ = _client_with_mock_pool(
            _stub_response(b"", status=304, reason="Not Modified"),
        )
        with pytest.raises(NotModified):
            client.get_json(
                "https://example.com/feed",
                headers={"If-None-Match": '"abc123"'},
            )

    def test_304_does_not_retry(self):
        """304 is a permanent (good) outcome — must not be retried."""
        from core.http import NotModified
        client, pool = _client_with_mock_pool(
            _stub_response(b"", status=304, reason="Not Modified"),
        )
        with pytest.raises(NotModified):
            client.get_json("https://example.com/feed")
        assert pool.request.call_count == 1

    def test_not_modified_is_subclass_of_http_error(self):
        """NotModified inherits from HttpError so existing
        `except HttpError:` handlers don't lose it; callers who want
        it specifically catch NotModified."""
        from core.http import HttpError, NotModified
        assert issubclass(NotModified, HttpError)


# ---------------------------------------------------------------------------
# total_timeout — wall-clock cap on the retry loop
# ---------------------------------------------------------------------------

class TestTotalTimeout:

    @patch("core.http.urllib_backend.time.monotonic")
    @patch("core.http.urllib_backend.time.sleep")
    def test_deadline_caps_retries(self, _mock_sleep, mock_monotonic):
        """If the wall-clock deadline elapses, raise immediately
        without continuing the backoff schedule. Worst case without
        this: ~1 hour spent in retries; with this, capped to total_timeout."""
        # Simulate clock jumping forward by 1000s on each call. With
        # default total_timeout=600, the deadline is exceeded before
        # the second iteration.
        ticks = iter([0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000])
        mock_monotonic.side_effect = lambda: next(ticks)
        client, pool = _client_with_mock_pool([
            _stub_response(b"", status=503),
            _stub_response(b"", status=503),
        ])
        with pytest.raises(HttpError, match="Total timeout"):
            client.get_json("https://example.com/api", total_timeout=600)

    def test_short_total_timeout_actually_fires_real_clock(self):
        """REGRESSION TEST. Before the fix, deadline was computed as
        ``time.monotonic() + max(total_timeout, timeout)``. With caller's
        total_timeout=1 (fail-fast for a health probe) and the default
        per-attempt timeout=30, ``max(1, 30) = 30`` — so the deadline
        was 30s away, not 1s. The cap never fired for short total_timeout.

        Mock-based tests didn't catch this: they advanced ``time.monotonic``
        with synthetic ticks and the bug only manifests when the deadline
        value is wrong AGAINST REAL WALL-CLOCK. This test uses a stub pool
        that returns 503 instantly and verifies elapsed wall-clock stays
        small (under 5s — the sleep clipping bounds the overshoot).
        """
        import time as _time
        pool = MagicMock()
        pool.request.return_value = _stub_response(b"", status=503)
        client = UrllibClient(_http=pool)

        t0 = _time.monotonic()
        with pytest.raises(HttpError):
            client.get_json("https://example.com/api", total_timeout=1)
        elapsed = _time.monotonic() - t0
        # Cap is 1s; allow generous slop for sleep granularity but well
        # under 5s (which is where the previous bug would have led with
        # default per-attempt timeout=30). The pre-fix max() would have
        # let this run through the full backoff schedule.
        assert elapsed < 5, (
            f"total_timeout=1 took {elapsed:.1f}s — "
            f"deadline computation may have regressed to max(total, timeout)"
        )


class TestHeadRequest:
    """REGRESSION TESTS for HEAD method support.

    urllib3 with ``preload_content=False`` does NOT auto-skip body reading
    for HEAD responses. If a server replies to HEAD with no body (correct
    per RFC 7231) and our code tries to ``resp.stream()`` the body, urllib3
    blocks waiting for bytes that won't come. The stress harness caught
    this against a real localhost server; mocks couldn't because they
    don't actually wait.

    Two-part fix in core.http.urllib_backend:
      1. ``preload_content=is_head`` — for HEAD we let urllib3 preload
         the (empty) body, sidestepping the streaming hang.
      2. Short-circuit ``resp.stream()`` loop in _fetch_once for HEAD —
         defence in depth in case (1) regresses or a future urllib3
         version changes behaviour.
    """

    def test_head_does_not_hang(self):
        """A HEAD response with no body returns cleanly, doesn't hang."""
        resp = MagicMock()
        resp.status = 200
        resp.headers = {"ETag": '"v1"', "Content-Length": "1234"}
        # If our code calls resp.stream() for HEAD, this would yield
        # nothing and urllib3 would block (in real life). The mock
        # would block too if we made it iterate forever — instead we
        # make stream() raise to prove the code DOESN'T call it.
        resp.stream = lambda *a, **kw: (_ for _ in ()).throw(
            AssertionError("stream() must not be called on HEAD response"),
        )
        resp.read = lambda *a, **kw: b""
        resp.release_conn = MagicMock()
        resp.geturl = lambda: ""
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))

        response = client.request("HEAD", "https://example.com/api")
        assert response.status == 200
        assert response.headers["etag"] == '"v1"'
        assert response.body == b""

    def test_head_uses_preload_content_true(self):
        """The pool.request call for HEAD must pass preload_content=True
        so urllib3 reads the (empty) body upfront and doesn't leave us
        with a half-finished response that hangs on .stream()."""
        pool = MagicMock()
        pool.request.return_value = _stub_response(b"", status=200)
        client = UrllibClient(_http=pool)
        client.request("HEAD", "https://example.com/api")
        assert pool.request.call_args.kwargs["preload_content"] is True

    def test_get_uses_preload_content_false(self):
        """Sanity: non-HEAD methods still use preload_content=False
        (so streaming + size cap work)."""
        pool = MagicMock()
        pool.request.return_value = _stub_response(b'{"x": 1}')
        client = UrllibClient(_http=pool)
        client.get_json("https://example.com/api")
        assert pool.request.call_args.kwargs["preload_content"] is False


# ---------------------------------------------------------------------------
# stream_bytes — chunked reads without buffering
# ---------------------------------------------------------------------------

class TestStreamBytes:

    def test_yields_chunks(self):
        """stream_bytes returns an iterator that yields the body in
        chunks. Caller can write straight to disk without RSS pressure."""
        # Stub stream() to yield known-size chunks.
        resp = MagicMock()
        resp.status = 200
        resp.headers = {}
        resp.stream = lambda cs, decode_content=True: iter(
            [b"chunk1", b"chunk2", b"chunk3"],
        )
        resp.release_conn = MagicMock()
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))

        chunks = list(client.stream_bytes("https://example.com/big"))
        assert chunks == [b"chunk1", b"chunk2", b"chunk3"]
        resp.release_conn.assert_called_once()

    def test_size_cap_enforced_mid_stream(self):
        """Cumulative size > max_bytes mid-stream raises SizeLimitExceeded."""
        resp = MagicMock()
        resp.status = 200
        resp.headers = {}
        resp.stream = lambda cs, decode_content=True: iter(
            [b"x" * 50, b"x" * 50, b"x" * 50, b"x" * 50],
        )
        resp.release_conn = MagicMock()
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))

        with pytest.raises(SizeLimitExceeded):
            for _ in client.stream_bytes("https://example.com/big", max_bytes=100):
                pass
        resp.release_conn.assert_called_once()  # finally fires on exception

    def test_url_validation_at_call_time(self):
        """URL validation must fail at call time, not deferred to
        first iteration — the generator-split must preserve fail-fast."""
        with pytest.raises(HttpError, match="scheme"):
            UrllibClient().stream_bytes("file:///etc/hostname")

    def test_304_raises_not_modified(self):
        """Streaming respects conditional requests too."""
        from core.http import NotModified
        resp = MagicMock()
        resp.status = 304
        resp.headers = {}
        resp.release_conn = MagicMock()
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))

        with pytest.raises(NotModified):
            list(client.stream_bytes("https://example.com/feed",
                                      headers={"If-None-Match": '"x"'}))
        resp.release_conn.assert_called_once()

    def test_retries_nonzero_rejected_at_call_time(self):
        """stream_bytes is single-attempt — retries=N for N != 0 must
        raise ValueError eagerly, before any HTTP call. Mid-stream
        failures aren't transparently resumable, so silently honouring
        retries would mislead callers about restart semantics."""
        client = UrllibClient(_http=MagicMock())
        with pytest.raises(ValueError, match="retries"):
            client.stream_bytes("https://example.com/x", retries=1)
        # Negative values are equally unsupported.
        with pytest.raises(ValueError, match="retries"):
            client.stream_bytes("https://example.com/x", retries=-1)
        # And no HTTP call should have been issued.
        assert client._http.request.call_count == 0


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

class TestErrors:

    def test_400_raises_immediately_no_retry(self):
        client, pool = _client_with_mock_pool(
            _stub_response(b'{"err":"bad"}', status=400, reason="Bad Request"),
        )
        with pytest.raises(HttpError) as ei:
            client.get_json("https://example.com/api")
        assert ei.value.status == 400
        assert pool.request.call_count == 1

    @patch("core.http.urllib_backend.time.sleep")
    def test_429_retries_with_backoff(self, _mock_sleep):
        # Two 429s, then success.
        client, pool = _client_with_mock_pool([
            _stub_response(b"", status=429, reason="Too Many"),
            _stub_response(b"", status=429, reason="Too Many"),
            _stub_response(b'{"ok": true}'),
        ])
        result = client.get_json("https://example.com/api")
        assert result == {"ok": True}
        assert pool.request.call_count == 3

    @patch("core.http.urllib_backend.time.sleep")
    def test_500_retries_then_raises(self, _mock_sleep):
        # Always 500 for every attempt — default = 1 initial + DEFAULT_RETRIES.
        attempts = DEFAULT_RETRIES + 1
        responses = [_stub_response(b"err", status=500, reason="Internal")
                     for _ in range(attempts)]
        client, pool = _client_with_mock_pool(responses)
        with pytest.raises(HttpError, match="Exhausted retries"):
            client.get_json("https://example.com/api")
        assert pool.request.call_count == attempts

    def test_size_limit_enforced(self):
        # Build a stub whose stream() yields 200 bytes; max_bytes=100.
        big_body = b"x" * 200
        resp = _stub_response(big_body)
        # Re-stub stream to yield in 50-byte chunks so size cap fires
        # MID-read, not just after the whole thing is buffered.
        resp.stream = lambda cs, decode_content=True: iter(
            [b"x" * 50, b"x" * 50, b"x" * 50, b"x" * 50],
        )
        client = UrllibClient(_http=MagicMock(request=MagicMock(return_value=resp)))
        with pytest.raises(SizeLimitExceeded):
            client.get_bytes("https://example.com/big", max_bytes=100)

    def test_invalid_json_raises(self):
        client, _ = _client_with_mock_pool(_stub_response(b"not json{"))
        with pytest.raises(HttpError, match="not valid JSON"):
            client.get_json("https://example.com/api")

    @patch("core.http.urllib_backend.time.sleep")
    def test_network_error_retries_then_raises(self, _mock_sleep):
        """Connection-level errors (urllib3 MaxRetryError, timeout etc.)
        are retried — same backoff schedule as 5xx."""
        from urllib3.exceptions import MaxRetryError
        pool = MagicMock()
        pool.request.side_effect = MaxRetryError(
            pool=None, url="https://example.com/api", reason="connection refused",
        )
        client = UrllibClient(_http=pool)
        with pytest.raises(HttpError, match="Exhausted retries"):
            client.get_json("https://example.com/api")
        assert pool.request.call_count == DEFAULT_RETRIES + 1

    def test_proxy_403_is_permanent_no_retry(self):
        """When the in-process proxy returns 403 (host not on allowlist),
        urllib3 surfaces it as a ProxyError. That's a permanent error
        — retrying through the full backoff schedule would waste many
        minutes. Must raise immediately with a clear message about
        the allowlist."""
        from urllib3.exceptions import ProxyError
        pool = MagicMock()
        pool.request.side_effect = ProxyError(
            "Cannot connect to proxy.",
            OSError("Tunnel connection failed: 403 Forbidden"),
        )
        client = UrllibClient(_http=pool)
        with pytest.raises(HttpError, match="not on the allowlist"):
            client.get_json("https://forbidden.example/api")
        # Single attempt — no retry storm.
        assert pool.request.call_count == 1

    @patch("core.http.urllib_backend.time.sleep")
    def test_other_proxy_errors_are_retried(self, _mock_sleep):
        """ProxyError that ISN'T a 403 (e.g., proxy unreachable) is
        transient and should retry like any other connection error."""
        from urllib3.exceptions import ProxyError
        pool = MagicMock()
        # No "403"/"Forbidden" in the message → treated as transient.
        pool.request.side_effect = ProxyError(
            "Cannot connect to proxy.",
            OSError("connection refused"),
        )
        client = UrllibClient(_http=pool)
        with pytest.raises(HttpError, match="Exhausted retries"):
            client.get_json("https://example.com/api")
        assert pool.request.call_count == DEFAULT_RETRIES + 1


# ---------------------------------------------------------------------------
# Retry-After parsing
# ---------------------------------------------------------------------------

class TestRetryAfter:

    @pytest.mark.parametrize("value,expected", [
        ("5", 5),           # plain seconds
        ("  10  ", 10),     # whitespace tolerated
        ("0", 1),           # clamped to min 1
        ("99999", 1800),    # clamped to max 30min
        ("Mon, 01 Jan 2030 00:00:00 GMT", None),   # HTTP-date — not supported
        (None, None),
        ("", None),
    ])
    def test_parses(self, value, expected):
        assert UrllibClient._parse_retry_after(value) == expected


# ---------------------------------------------------------------------------
# URL validation — adversarial input refused at entry
# ---------------------------------------------------------------------------

class TestUrlValidation:
    """The clients refuse non-http(s) schemes and URLs with credentials.

    These guards exist because:
      - urllib3 only handles http(s), but defence in depth — we don't
        rely on the underlying library refusing weird schemes; we
        refuse at our entry point.
      - URLs with userinfo would leak credentials into log lines and
        encourage anti-pattern auth flow; callers should pass
        Authorization headers instead.
    """

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "file:///etc/hostname",
        "ftp://example.com/file",
        "gopher://example.com/",
        "data:text/plain,hello",
        "javascript:alert(1)",
    ])
    def test_non_http_schemes_rejected(self, url):
        with pytest.raises(HttpError, match="scheme"):
            UrllibClient().get_bytes(url)

    @pytest.mark.parametrize("url", [
        # Standard userinfo forms
        "https://user:pass@example.com/api",
        "https://user@example.com/api",
        "http://admin:secret@example.com/",
        # Adversarial host-confusion attacks. urlsplit() resolves these
        # to (hostname=evil.com, username=<...>) — the *real* destination
        # is evil.com, with the leading "example.com" looking like a host
        # to a casual reader of the log line. Our `username is not None`
        # check catches the empty-string form too.
        "http://example.com@evil.com/",
        "http://@evil.com/",
        "http://@ftp://hostname/",
        "https://example.com:80@evil.com:443/",
    ])
    def test_userinfo_in_url_rejected(self, url):
        with pytest.raises(HttpError, match="credentials"):
            UrllibClient().get_json(url)

    def test_url_with_no_host_rejected(self):
        with pytest.raises(HttpError, match="no host"):
            UrllibClient().get_bytes("https:///path-but-no-host")

    def test_https_with_no_userinfo_accepted(self):
        client, _ = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json("https://api.example.com/v1/things?q=foo")

    def test_http_accepted_by_urllib_client(self):
        """UrllibClient accepts plain http:// — useful for local dev /
        test stubs hitting localhost. EgressClient narrows to https."""
        client, _ = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json("http://127.0.0.1:8080/health")

    def test_post_json_validates_too(self):
        """Validation hook fires from post_json + get_bytes too, not just get_json."""
        with pytest.raises(HttpError, match="scheme"):
            UrllibClient().post_json("file:///etc/hostname", {})


class TestSafeUrlForLog:
    """Defence in depth: even if a credential URL slipped past validation,
    log lines would still strip it."""

    def test_strips_userinfo(self):
        from core.http.urllib_backend import _safe_url_for_log
        result = _safe_url_for_log("https://user:pass@host.example/path")
        assert "pass" not in result
        assert "host.example/path" in result

    def test_preserves_port(self):
        from core.http.urllib_backend import _safe_url_for_log
        result = _safe_url_for_log("https://user:pass@host.example:8443/path")
        assert "pass" not in result
        assert "host.example:8443/path" in result

    def test_passthrough_for_clean_url(self):
        from core.http.urllib_backend import _safe_url_for_log
        url = "https://api.example.com/v1/x?q=1"
        assert _safe_url_for_log(url) == url


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestRequest:
    """Low-level request() — returns a Response object with status,
    headers, body, and final URL. Enables ETag-based conditional
    caching and arbitrary HTTP methods (DELETE/PUT/PATCH/HEAD)."""

    def test_returns_response_with_headers(self):
        client, _ = _client_with_mock_pool(
            _stub_response(b'{"ok": true}',
                           extra_headers={"ETag": '"v1.2.3"',
                                          "Cache-Control": "max-age=3600"},
                           final_url="https://example.com/api"),
        )
        resp = client.request("GET", "https://example.com/api")
        assert isinstance(resp, Response)
        assert resp.status == 200
        assert resp.body == b'{"ok": true}'
        # Header keys are lowercased on storage for predictable lookup.
        assert resp.headers["etag"] == '"v1.2.3"'
        assert resp.headers["cache-control"] == "max-age=3600"

    def test_response_json_parses_body(self):
        client, _ = _client_with_mock_pool(
            _stub_response(b'{"x": 42}'),
        )
        resp = client.request("GET", "https://example.com/api")
        assert resp.json() == {"x": 42}

    def test_response_json_raises_on_invalid(self):
        client, _ = _client_with_mock_pool(
            _stub_response(b"not json{"),
        )
        resp = client.request("GET", "https://example.com/api")
        with pytest.raises(HttpError, match="not valid JSON"):
            resp.json()

    def test_arbitrary_methods_accepted(self):
        """request() supports DELETE/PUT/PATCH/HEAD without explicit
        helper methods. Verify the method string is forwarded."""
        client, pool = _client_with_mock_pool(_stub_response(b""))
        for method in ("DELETE", "PUT", "PATCH", "HEAD"):
            client.request(method, "https://example.com/api")
            assert pool.request.call_args.args[0] == method


class TestRetriesOptOut:
    """retries=0 for fail-fast / non-idempotent POSTs / health probes."""

    def test_retries_zero_means_single_attempt(self):
        """retries=0 → one attempt then raise; no retry storm even on
        retryable errors."""
        client, pool = _client_with_mock_pool(
            _stub_response(b"", status=503),
        )
        with pytest.raises(HttpError):
            client.get_json("https://example.com/api", retries=0)
        assert pool.request.call_count == 1

    @patch("core.http.urllib_backend.time.sleep")
    def test_retries_three_means_four_attempts(self, _mock_sleep):
        """retries=3 → up to 4 total attempts (1 initial + 3 retries)."""
        responses = [_stub_response(b"", status=503) for _ in range(8)]
        client, pool = _client_with_mock_pool(responses)
        with pytest.raises(HttpError, match="Exhausted retries"):
            client.get_json("https://example.com/api", retries=3)
        assert pool.request.call_count == 4

    def test_no_sleep_after_final_attempt(self):
        """REGRESSION: each schedule slot owns the sleep AFTER its
        attempt. The final slot has no next attempt, so we MUST NOT
        sleep before raising 'Exhausted retries' — otherwise retries=0
        + 503 sleeps schedule[0] (1s), and a default-config full
        failure burns the trailing 300s slot for nothing.
        """
        import time as _time
        pool = MagicMock()
        pool.request.return_value = _stub_response(b"", status=503)
        client = UrllibClient(_http=pool)

        t0 = _time.monotonic()
        with pytest.raises(HttpError):
            client.get_json("https://example.com/api", retries=0)
        elapsed = _time.monotonic() - t0
        # Real wall-clock — well under schedule[0]=1s. Slop allows
        # for slow CI scheduling but well below the buggy 1s sleep.
        assert elapsed < 0.5, (
            f"retries=0 took {elapsed:.2f}s — likely slept the final "
            f"schedule slot before raising"
        )

    def test_post_json_documents_idempotency(self):
        """The post_json docstring tells callers about retry+idempotency
        risk for non-idempotent POSTs and recommends retries=0."""
        assert "idempotent" in UrllibClient.post_json.__doc__.lower()
        assert "retries=0" in UrllibClient.post_json.__doc__


class TestFollowRedirects:
    """follow_redirects=False surfaces 3xx responses to the caller
    instead of chasing them — security-scanning patterns need this."""

    def test_default_follows_redirects(self):
        """Default behaviour passes redirect=True to urllib3."""
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json("https://example.com/api")
        assert pool.request.call_args.kwargs["redirect"] is True

    def test_follow_redirects_false_passed_through(self):
        client, pool = _client_with_mock_pool(_stub_response(b'{"ok": true}'))
        client.get_json("https://example.com/api", follow_redirects=False)
        assert pool.request.call_args.kwargs["redirect"] is False

    def test_3xx_with_no_follow_raises(self):
        """3xx with follow_redirects=False reaches the >= 400 check via
        a different path — but actually 301/302 are < 400. The Response
        is returned. Verify we get a Response with the 301 status,
        not an exception."""
        # 302 with redirect=False: urllib3 doesn't auto-chase, returns
        # the 302 response. Our code only treats >=400 as error, so 302
        # comes back as a Response. Test via request().
        client, _ = _client_with_mock_pool(
            _stub_response(b"", status=302, reason="Found",
                           extra_headers={"Location": "https://other.example/"}),
        )
        resp = client.request(
            "GET", "https://example.com/api",
            follow_redirects=False,
        )
        assert resp.status == 302
        assert resp.headers["location"] == "https://other.example/"


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

class TestDefaultClient:

    def test_no_hosts_returns_urllib(self):
        c = default_client()
        assert isinstance(c, UrllibClient)


# ---------------------------------------------------------------------------
# requests-API compatibility shim
# ---------------------------------------------------------------------------

class TestRequestsCompatShim:
    """Consumers like ``core.oci.client`` were originally written
    against the ``requests.Response`` API. The Response dataclass
    exposes ``status_code`` / ``content`` / ``text`` / ``iter_content``
    / ``close`` aliases so they work without a rewrite."""

    def _resp(self, body=b"hello", status=200):
        from core.http import Response
        return Response(
            status=status, headers={}, body=body, url="https://x/",
        )

    def test_status_code_aliases_status(self):
        assert self._resp(status=404).status_code == 404

    def test_content_aliases_body(self):
        assert self._resp(body=b"abc").content == b"abc"

    def test_text_decodes_utf8_with_replace(self):
        # Invalid UTF-8 byte -> replacement char, not exception.
        r = self._resp(body=b"hello \xff world")
        assert "hello" in r.text and "world" in r.text

    def test_iter_content_chunks(self):
        r = self._resp(body=b"abcdefghij")
        assert list(r.iter_content(chunk_size=3)) == [
            b"abc", b"def", b"ghi", b"j",
        ]

    def test_iter_content_empty_body(self):
        r = self._resp(body=b"")
        assert list(r.iter_content()) == []

    def test_close_is_noop(self):
        # No-op for the buffered backend; doesn't raise.
        self._resp().close()


class TestStreamKwargAccepted:
    """``UrllibClient.request`` accepts ``stream=`` as a no-op so
    consumers written against ``requests.Session.request(stream=True)``
    keep working. Buffering behaviour is unchanged."""

    def test_request_accepts_stream_kwarg_via_inspect(self):
        # Inspect the signature directly — no network needed. We
        # only care that ``stream`` is an accepted parameter so the
        # OCI client's ``request(method, url, stream=True)`` calls
        # don't raise TypeError.
        import inspect
        sig = inspect.signature(UrllibClient.request)
        assert "stream" in sig.parameters
        assert sig.parameters["stream"].default is False

    def test_request_stream_kwarg_doesnt_change_buffering(self, monkeypatch):
        # The kwarg is accepted but ignored; buffering is unchanged.
        # We verify by mocking ``_fetch`` and confirming both calls
        # invoke it with identical arguments.
        client = UrllibClient()
        captured = []

        def fake_fetch(*args, **kwargs):
            captured.append(("call", args, kwargs))
            from core.http import Response
            return Response(
                status=200, headers={}, body=b"ok", url=args[0],
            )

        monkeypatch.setattr(client, "_fetch", fake_fetch)
        client.request("GET", "https://example.com/", stream=True)
        client.request("GET", "https://example.com/", stream=False)
        # Both calls reached _fetch with the same kwargs — stream=
        # was stripped by request() before dispatch.
        assert len(captured) == 2
        assert captured[0] == captured[1]
