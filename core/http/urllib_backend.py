"""urllib3-backed implementation of :class:`core.http.HttpClient`.

Why urllib3 not stdlib urllib:
  - **Connection pooling.** urllib3 reuses TCP+TLS connections across
    requests to the same host. SCA-shaped workloads (~100 calls across
    ~5 hosts) see ~4× speedup on the HTTP layer because handshakes
    amortise.
  - **No surprise no_proxy bypass.** stdlib urllib's ``ProxyHandler``
    silently honours ``no_proxy`` env vars and skips the proxy for
    matching hosts; verified empirically that ``no_proxy=*`` lets a
    request connect direct, defeating EgressClient's chokepoint.
    urllib3's ``ProxyManager`` does NOT read env vars at request
    time — every request goes through the configured proxy, full
    stop. One fewer security-critical workaround to maintain.
  - **Consistent TLS via certifi.** Stdlib urllib's CA store varies
    across distros / containers / OSes. urllib3 ships its own
    bundle and is configured CERT_REQUIRED + hostname-verified by
    default in 2.x.

Honours Retry-After on 429/503; exponential backoff on other transient
errors; bounded total retry duration; size caps on responses; gzip
decompression of responses that arrive compressed even when not
requested (some servers do this).

No allowlist — UrllibClient can reach any host on :443. For
allowlisted egress, use :class:`core.http.egress_backend.EgressClient`.
"""

from __future__ import annotations

import gzip
import json
import logging
import time
from typing import Any, Dict, Iterator, Optional
from urllib import parse as _urlparse

import urllib3
from urllib3.exceptions import (
    HTTPError as _U3HTTPError,
    MaxRetryError,
    ProxyError as _U3ProxyError,
    ReadTimeoutError,
    SSLError,
)

from core.http import (
    DEFAULT_MAX_BYTES,
    DEFAULT_RETRIES,
    DEFAULT_TIMEOUT,
    DEFAULT_TOTAL_TIMEOUT,
    DEFAULT_USER_AGENT,
    HttpError,
    NotModified,
    Response,
    SizeLimitExceeded,
)

logger = logging.getLogger(__name__)

# Backoff schedule for transient errors (5xx, 429). Length is chosen so
# the cumulative sleep (1+2+5+15+60+300 = 383s) fits comfortably under
# the default total_timeout of 600s — every slot can actually fire
# under default config. Callers needing longer retry budgets bump
# total_timeout AND retries together; the schedule auto-clips against
# the wall-clock deadline in _fetch so over-long sleeps can't blow past
# the caller's budget.
_BACKOFF_SECONDS = (1, 2, 5, 15, 60, 300)
# One schedule slot per attempt (initial + retries). Default attempt
# count is therefore len(schedule) and matches DEFAULT_RETRIES + 1 —
# the assert catches drift if either side is retuned without the other.
assert len(_BACKOFF_SECONDS) == DEFAULT_RETRIES + 1, (
    "_BACKOFF_SECONDS length must equal DEFAULT_RETRIES + 1 (one slot "
    "for the initial attempt + one per retry); update both together"
)


def _safe_url_for_log(url: str) -> str:
    """Strip credentials from a URL for log output.

    Delegates to ``core.security.redaction`` which handles userinfo,
    query-string secrets, and unparseable-URL fallback.
    """
    from core.security.redaction import redact_url_secrets_only
    return redact_url_secrets_only(url)


_DEFAULT_POOL_MAXSIZE = 10  # connections per (host, port) — see _new_pool_manager


def _new_pool_manager() -> urllib3.PoolManager:
    """Construct a urllib3.PoolManager with secure defaults.

    - retries=False — we run our own retry/backoff logic with
      Retry-After awareness; urllib3's default Retry would fight it.
    - cert_reqs='CERT_REQUIRED' + assert_hostname (urllib3 2.x default) —
      enforces TLS cert + hostname verification.
    - maxsize=10 — connections-per-host cap. urllib3's default is 1,
      which serialises concurrent calls to the same host (e.g. SCA
      hammering api.osv.dev with parallel queries would queue on a
      single connection). 10 lets up to 10 in-flight per host without
      thrashing kernel resources.
    """
    return urllib3.PoolManager(
        retries=False, cert_reqs="CERT_REQUIRED",
        maxsize=_DEFAULT_POOL_MAXSIZE,
    )


class UrllibClient:
    """urllib3-backed HttpClient (was stdlib urllib pre-pooling refactor).

    Subclasses (e.g. EgressClient) may inject a custom pool manager via
    the ``_http`` constructor arg — typically a ``urllib3.ProxyManager``
    pointing at a chokepoint proxy.

    Subclasses may also tighten ``_ALLOWED_SCHEMES`` to restrict
    accepted URL schemes — UrllibClient accepts http and https
    (the latter for production, the former for tests/dev paths
    hitting localhost stubs); EgressClient narrows to https only
    because its proxy is HTTPS-CONNECT-only and http requests
    can't be served through it cleanly.
    """

    _ALLOWED_SCHEMES = ("http", "https")

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        _http: Optional[urllib3.PoolManager] = None,
    ) -> None:
        self._ua = user_agent
        # Subclass / test hook. Lazy default avoids spinning up a pool
        # manager (and its certifi load) when the client is never used.
        self._http = _http or _new_pool_manager()

    def _validate_url(self, url: str) -> _urlparse.SplitResult:
        """Reject URLs that don't match (allowed-scheme)://host/...

        Without this guard, a caller-controlled URL could exfiltrate
        local files via ``file:///etc/passwd`` (urllib3 itself doesn't
        handle file://, but defence in depth) and the EgressClient
        proxy would be bypassed for non-http(s) schemes.

        Userinfo (``https://user:pass@host/...``) is also rejected — it
        would leak into log lines and is an anti-pattern; callers should
        pass credentials via Authorization headers instead. The
        ``is not None`` check catches the empty-string variant returned
        by urlsplit for adversarial forms like ``http://@evil.com/``.
        """
        parsed = _urlparse.urlsplit(url)
        if parsed.scheme not in self._ALLOWED_SCHEMES:
            permitted = "/".join(self._ALLOWED_SCHEMES)
            raise HttpError(
                f"Refused URL with scheme {parsed.scheme!r}: "
                f"only {permitted} permitted"
            )
        if not parsed.hostname:
            raise HttpError(f"Refused URL with no host: {url!r}")
        if parsed.username is not None or parsed.password is not None:
            raise HttpError(
                "Refused URL with embedded credentials; pass credentials via "
                "an Authorization header, not in the URL authority"
            )
        return parsed

    # -- public API -----------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
        stream: bool = False,
    ) -> Response:
        """Low-level HTTP request — returns a full :class:`Response` object.

        Use this when you need response metadata (status, headers, final
        URL after redirects). Typical case: capturing ``ETag`` /
        ``Last-Modified`` for a subsequent conditional request.

        For arbitrary HTTP methods (DELETE, PUT, PATCH, HEAD, etc.)
        callers can pass them via this method — the convenience methods
        (``get_json``, ``post_json``, ``get_bytes``) only cover the
        most common shapes.

        ``stream`` is accepted for ``requests``-API compatibility
        (consumers like :mod:`core.oci.client` were written against
        ``requests.Session.request(stream=True)``). The urllib
        backend buffers the response body either way, so the
        ``stream`` value is ignored. For true streaming downloads,
        use :meth:`stream_bytes`.
        """
        del stream                      # accepted for compat; no-op
        self._validate_url(url)
        merged = {"User-Agent": self._ua}
        if headers:
            merged.update(headers)
        return self._fetch(
            url, method=method, timeout=timeout, body=body,
            headers=merged, max_bytes=max_bytes,
            total_timeout=total_timeout,
            retries=retries,
            follow_redirects=follow_redirects,
        )

    def post_json(
        self,
        url: str,
        body: Dict[str, Any],
        timeout: int = DEFAULT_TIMEOUT,
        *,
        headers: Optional[Dict[str, str]] = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> Dict[str, Any]:
        """POST ``body`` as JSON, return decoded JSON response.

        NOTE on retry idempotency: ``post_json`` retries on transient
        5xx/429 the same as GET. This is safe for POSTs that are
        semantically idempotent (e.g. OSV's ``querybatch`` API —
        same input → same output). For non-idempotent POSTs (creating
        a record, charging a card, sending a message), pass
        ``retries=0`` so a 5xx after partial server-side processing
        doesn't retrigger the side effect.
        """
        self._validate_url(url)
        data = json.dumps(body).encode("utf-8")
        merged = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self._ua,
        }
        if headers:
            merged.update(headers)
        resp = self._fetch(url, method="POST", timeout=timeout, body=data,
                           headers=merged, max_bytes=DEFAULT_MAX_BYTES,
                           total_timeout=total_timeout, retries=retries,
                           follow_redirects=follow_redirects)
        return resp.json()

    def get_json(
        self,
        url: str,
        timeout: int = DEFAULT_TIMEOUT,
        *,
        headers: Optional[Dict[str, str]] = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> Dict[str, Any]:
        self._validate_url(url)
        merged = {"Accept": "application/json", "User-Agent": self._ua}
        if headers:
            merged.update(headers)
        resp = self._fetch(url, method="GET", timeout=timeout, body=None,
                           headers=merged, max_bytes=DEFAULT_MAX_BYTES,
                           total_timeout=total_timeout, retries=retries,
                           follow_redirects=follow_redirects)
        return resp.json()

    def get_bytes(
        self,
        url: str,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        *,
        headers: Optional[Dict[str, str]] = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> bytes:
        self._validate_url(url)
        merged = {"User-Agent": self._ua}
        if headers:
            merged.update(headers)
        resp = self._fetch(url, method="GET", timeout=timeout, body=None,
                           headers=merged, max_bytes=max_bytes,
                           total_timeout=total_timeout, retries=retries,
                           follow_redirects=follow_redirects)
        return resp.body

    def stream_bytes(
        self,
        url: str,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        headers: Optional[Dict[str, str]] = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = 0,
    ) -> Iterator[bytes]:
        """GET ``url``, yield response body chunks without buffering.

        Use for large downloads (multi-100MB+) where ``get_bytes`` would
        balloon RSS. Cumulative size cap is enforced across yielded
        chunks; exceeding ``max_bytes`` raises :class:`SizeLimitExceeded`
        mid-stream.

        ``timeout`` caps the per-attempt connect+read window. The
        ``total_timeout`` parameter is accepted for **API symmetry**
        with the buffered methods but only enforced on connection
        setup — once the iterator yields its first chunk, the body
        read is bounded by ``timeout`` alone (urllib3 has no clean
        knob for "wall-clock cap on streamed reads").

        ``retries`` is accepted for API symmetry but **must be 0** —
        mid-stream failures aren't transparently retryable (would
        need range-resumed restart). Non-zero values raise
        :class:`ValueError`. Caller can wrap the iterator in their
        own retry loop if needed.

        Caller must fully consume the iterator OR call ``.close()`` on
        it to release the connection back to the pool. A common
        pattern::

            with open(dest, "wb") as f:
                for chunk in client.stream_bytes(url):
                    f.write(chunk)
        """
        if retries != 0:
            raise ValueError(
                "stream_bytes does not support retries (mid-stream "
                "failures aren't transparently resumable). "
                "Pass retries=0 or wrap the iterator in your own "
                "retry loop."
            )
        self._validate_url(url)
        merged = {"User-Agent": self._ua}
        if headers:
            merged.update(headers)
        # Cap per-attempt timeout by remaining total_timeout so a caller
        # tightening total_timeout actually shortens the connect window.
        effective_timeout = min(timeout, total_timeout)
        # Validation runs at call time; the generator below runs at
        # iteration time. Splitting them ensures URL errors fail fast
        # instead of waiting for the first .next() call.
        return self._stream(url, merged, effective_timeout, max_bytes)

    def _stream(
        self,
        url: str,
        headers: Dict[str, str],
        timeout: int,
        max_bytes: int,
    ) -> Iterator[bytes]:
        resp = self._http.request(
            "GET", url,
            headers=headers,
            timeout=urllib3.Timeout(total=float(timeout)),
            preload_content=False,
            decode_content=True,
            redirect=True,
            retries=False,
        )
        try:
            if resp.status == 304:
                raise NotModified(
                    f"304 Not Modified for {_safe_url_for_log(url)}",
                )
            if resp.status >= 400:
                snippet = resp.read(512, decode_content=True) or b""
                reason = resp.reason or "?"
                raise HttpError(
                    f"HTTP {resp.status} from {_safe_url_for_log(url)}: "
                    f"{reason} {snippet!r}"[:200],
                    status=resp.status,
                )
            total = 0
            for chunk in resp.stream(64 * 1024, decode_content=True):
                total += len(chunk)
                if total > max_bytes:
                    raise SizeLimitExceeded(
                        f"Stream from {_safe_url_for_log(url)} "
                        f"exceeded {max_bytes} bytes",
                    )
                yield chunk
        finally:
            # Released whether the generator was fully consumed,
            # garbage-collected mid-stream, or .close()-d explicitly.
            resp.release_conn()

    # -- internals ------------------------------------------------------

    def _fetch(
        self,
        url: str,
        method: str,
        timeout: int,
        max_bytes: int,
        body: Optional[bytes],
        headers: Dict[str, str],
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> Response:
        # Wall-clock deadline for the whole retry loop. Without this,
        # the full backoff schedule (~1h worst case) can dominate
        # agentic budgets. Caller's total_timeout is authoritative —
        # if they pass total_timeout=2 (fail-fast for a health probe)
        # we honour that even when total_timeout < timeout (per-attempt).
        deadline = time.monotonic() + total_timeout
        # Caller-cap on the retry count. retries=0 means "single attempt,
        # don't retry anything" — useful for non-idempotent POSTs and
        # health probes. The slice gives the same backoff schedule but
        # truncated; a max() guards against negative values.
        max_attempts = max(1, min(retries + 1, len(_BACKOFF_SECONDS)))
        schedule = _BACKOFF_SECONDS[:max_attempts]
        last_exc: Optional[Exception] = None
        for attempt, delay in enumerate(schedule):
            if time.monotonic() >= deadline:
                raise HttpError(
                    f"Total timeout ({total_timeout}s) exceeded for "
                    f"{_safe_url_for_log(url)}",
                ) from last_exc
            # Each schedule slot represents one attempt and the sleep
            # AFTER it (before the next attempt). On the final slot
            # there is no next attempt, so we skip the post-failure
            # sleep entirely — otherwise retries=0 against a 503
            # would sleep schedule[0] seconds (1s) before raising
            # "Exhausted retries", and a default-config full failure
            # would burn the trailing 300s slot for no reason.
            is_last_attempt = attempt + 1 == len(schedule)
            try:
                return self._fetch_once(
                    url, method=method, timeout=timeout, max_bytes=max_bytes,
                    body=body, headers=headers,
                    follow_redirects=follow_redirects,
                )
            except HttpError as e:
                # Retry only on transient status codes (429, 5xx).
                # Everything else — non-retryable 4xx, SizeLimitExceeded
                # (status=None), JSON-decode errors, etc. — propagates.
                is_transient = (
                    e.status == 429
                    or (e.status is not None and 500 <= e.status < 600)
                )
                if not is_transient:
                    raise
                last_exc = e
                if is_last_attempt:
                    continue
                # Retry-After honoured by _fetch_once if present.
                sleep_for = e.retry_after or delay
                logger.info(
                    "core.http: %s %s -> %d; sleeping %ds (retry %d)",
                    method, _safe_url_for_log(url), e.status,
                    sleep_for, attempt + 1,
                )
                # Clip sleep to remaining deadline so a long backoff
                # doesn't blow past total_timeout.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HttpError(
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}",
                    ) from last_exc
                time.sleep(min(sleep_for, remaining))
                continue
            except _U3ProxyError as e:
                # Distinguish "proxy denied CONNECT" (permanent, our
                # chokepoint refused the host as off-allowlist) from
                # "proxy unreachable" (transient). urllib3 surfaces
                # both as ProxyError with a message; we string-match
                # for the 403/Forbidden marker the in-process proxy
                # emits at core/sandbox/proxy.py for off-allowlist
                # hosts. Permanent errors must NOT loop through the
                # backoff schedule (minutes of wasted sleep); raise now.
                # Lower-case the haystack so a future urllib3 release
                # changing the message casing doesn't silently turn
                # "off-allowlist" into a transient-retry storm.
                msg = str(e).lower()
                if "403" in msg or "forbidden" in msg:
                    host = _urlparse.urlsplit(url).hostname or "?"
                    raise HttpError(
                        f"Egress proxy refused {host!r}: host not on the "
                        f"allowlist. If you're using EgressClient, add "
                        f"this host to allowed_hosts at construction — "
                        f"the chokepoint allowlist supersedes any "
                        f"no_proxy env var by design (closing it would "
                        f"reintroduce the bypass urllib3 was chosen to "
                        f"prevent). Underlying: {e}",
                    ) from e
                last_exc = e
                if is_last_attempt:
                    continue
                logger.info(
                    "core.http: %s %s proxy error: %s; backoff %ds",
                    method, _safe_url_for_log(url), e, delay,
                )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HttpError(
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}",
                    ) from last_exc
                time.sleep(min(delay, remaining))
                continue
            except (MaxRetryError, ReadTimeoutError, SSLError, _U3HTTPError,
                    TimeoutError, ConnectionError) as e:
                last_exc = e
                if is_last_attempt:
                    continue
                logger.info(
                    "core.http: %s %s network error: %s; backoff %ds",
                    method, _safe_url_for_log(url), e, delay,
                )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HttpError(
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}",
                    ) from last_exc
                time.sleep(min(delay, remaining))
                continue
        # Exhausted retries
        raise HttpError(
            f"Exhausted retries fetching {_safe_url_for_log(url)}: {last_exc}",
        ) from last_exc

    def _fetch_once(
        self,
        url: str,
        method: str,
        timeout: int,
        max_bytes: int,
        body: Optional[bytes],
        headers: Dict[str, str],
        follow_redirects: bool = True,
    ) -> Response:
        # urllib3.Timeout(total=N) caps both connect and read; matches
        # the per-call semantics our public API exposes.
        # preload_content=False normally so we can stream-read for
        # size-cap enforcement before buffering the whole response —
        # but for HEAD requests we use preload_content=True since HEAD
        # responses have no body. urllib3 with preload_content=False
        # on a HEAD response can hang reading body bytes that won't
        # arrive (no clean way to signal "drain zero bytes").
        # decode_content=True so urllib3 transparently decompresses
        # gzip/deflate responses from servers that send them whether
        # or not we asked.
        # redirect default True follows up to 10 redirects (urllib3 default).
        # follow_redirects=False lets callers inspect 3xx responses —
        # useful for security scanning patterns that need to see
        # Location headers without chasing them.
        is_head = method.upper() == "HEAD"
        resp = self._http.request(
            method, url,
            body=body,
            headers=headers,
            timeout=urllib3.Timeout(total=float(timeout)),
            preload_content=is_head,   # True for HEAD, False otherwise
            decode_content=True,
            redirect=follow_redirects,
            retries=False,
        )
        try:
            # 304 Not Modified — caller used If-None-Match / If-Modified-Since
            # and the server says the cached value is still fresh. Surface
            # via NotModified exception so caller can fall back to cache.
            # Important: 304 is NOT >= 400, so this needs to come first
            # before the generic error threshold below.
            if resp.status == 304:
                raise NotModified(
                    f"304 Not Modified for {_safe_url_for_log(url)}",
                )
            if resp.status in (429, 503):
                raise HttpError(
                    f"HTTP {resp.status} from {_safe_url_for_log(url)}",
                    status=resp.status,
                    retry_after=self._parse_retry_after(
                        resp.headers.get("Retry-After"),
                    ),
                )
            # Treat 4xx/5xx as HttpError. The exception is non-retryable
            # for 4xx (we don't loop on auth/validation errors) and
            # retried by _fetch for 5xx via the is_transient check.
            # 3xx-with-follow_redirects=False reaches here too — surface
            # the Location header in the exception for caller inspection.
            if resp.status >= 400:
                # Drain enough body for the error message — bounded.
                snippet = resp.read(512, decode_content=True) or b""
                reason = resp.reason or "?"
                raise HttpError(
                    f"HTTP {resp.status} from {_safe_url_for_log(url)}: "
                    f"{reason} {snippet!r}"[:200],
                    status=resp.status,
                )

            # Stream-read the body, enforcing the size cap as we go so
            # an unexpectedly-huge response doesn't first balloon RSS.
            # HEAD responses have no body — urllib3 with preload_content=False
            # would block on resp.stream() waiting for bytes that never
            # arrive, so short-circuit there.
            if method.upper() == "HEAD":
                raw = b""
            else:
                buf = bytearray()
                for chunk in resp.stream(64 * 1024, decode_content=True):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise SizeLimitExceeded(
                            f"Response from {_safe_url_for_log(url)} "
                            f"exceeded {max_bytes} bytes",
                        )
                raw = bytes(buf)

            # Defence in depth: some servers send Content-Encoding: gzip
            # but urllib3 may not always auto-decode (depends on
            # decode_content honouring). If body still looks gzip
            # (magic bytes 1f 8b), decode here. Fall back to the raw
            # bytes if gzip.decompress raises — the magic-byte check
            # has a ~1/65k false-positive rate on arbitrary binary
            # bodies, and we'd rather hand the caller raw data than
            # corrupt a payload that wasn't actually gzip.
            if raw.startswith(b"\x1f\x8b"):
                try:
                    raw = gzip.decompress(raw)
                except (OSError, EOFError):
                    pass

            # Lowercase header keys for predictable case-insensitive
            # lookup — servers send mixed case, callers shouldn't have
            # to remember whether a particular server uses "ETag" or
            # "etag".
            # urllib3's geturl() returns the post-redirect URL, or the
            # request URL when no redirect happened. It can return None
            # (or empty string) if the response object hasn't recorded
            # the URL yet — fall back to the request URL so callers
            # always see something parseable. Documented contract on
            # Response.url.
            final_url = resp.geturl() or url
            return Response(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=raw,
                url=final_url,
            )
        finally:
            # Return the connection to the pool. Without this, repeated
            # requests would each open a fresh connection — exactly the
            # cost we're switching to urllib3 to avoid.
            resp.release_conn()

    @staticmethod
    def _parse_retry_after(value: Optional[str]) -> Optional[int]:
        """Parse Retry-After header (seconds form only; HTTP-date form ignored)."""
        if not value:
            return None
        try:
            n = int(value.strip())
            return max(1, min(n, 1800))  # clamp 1s..30min
        except ValueError:
            return None


__all__ = ["UrllibClient"]
