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
import io
import json
import logging
import re
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple
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
# count is therefore len(schedule) and matches DEFAULT_RETRIES + 1.
#
# Pre-fix this was an `assert` statement. `python -O` (production
# deployments that disable assertions for perf) strips assert
# statements at bytecode-compile time — so the drift guard simply
# wasn't there in optimised builds. A future maintainer who tuned
# `DEFAULT_RETRIES` without touching `_BACKOFF_SECONDS` (or vice
# versa) would see local dev tests pass (assert fires, they fix the
# tuple) but production silently use a mismatched schedule:
# `_BACKOFF_SECONDS[attempt]` IndexError on the over-budget retry,
# or a schedule slot never reached. Lift to an explicit RuntimeError
# so the gate fires regardless of `-O`.
if len(_BACKOFF_SECONDS) != DEFAULT_RETRIES + 1:
    raise RuntimeError(
        f"_BACKOFF_SECONDS length ({len(_BACKOFF_SECONDS)}) must equal "
        f"DEFAULT_RETRIES + 1 ({DEFAULT_RETRIES + 1}) — one slot for the "
        f"initial attempt + one per retry; update both together"
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
    # Pre-fix `cert_reqs="CERT_REQUIRED"` enabled validation but
    # didn't pin `ca_certs=`. urllib3 then falls back to the
    # system bundle (or worse, a stale OS-bundled CA list on
    # ancient minimal containers). Pin to certifi's bundle so:
    #
    #   * Validation always uses the latest Mozilla CA list
    #     (certifi ships releases tracking root-store changes;
    #     system bundles can lag months behind on minimal
    #     containers / appliances).
    #   * Operators on hosts with NO system CA bundle (Alpine
    #     minimal images without ca-certificates installed)
    #     still get TLS validation — pre-fix they got
    #     "SSL: CERTIFICATE_VERIFY_FAILED" with no system
    #     trust anchors.
    #   * Pinning to the certifi-shipped bundle gives us
    #     audit-able provenance: the cert set is whatever
    #     `certifi.where()` returns at install time.
    try:
        import certifi
        ca_certs = certifi.where()
    except ImportError:
        # certifi not installed (rare — it's a transitive dep
        # of requests / urllib3-extras typically). Fall back to
        # urllib3's default behaviour. Operator sees the
        # CERTIFICATE_VERIFY_FAILED if the system bundle is
        # missing; that's the right diagnostic.
        ca_certs = None
    return urllib3.PoolManager(
        retries=False, cert_reqs="CERT_REQUIRED",
        ca_certs=ca_certs,
        maxsize=_DEFAULT_POOL_MAXSIZE,
    )


class _HostCircuitBreaker:
    """Per-(host, port) rate-limit circuit breaker.

    After ``threshold`` 429/5xx events from the same host within
    ``window`` seconds, the circuit opens — subsequent requests
    for that host fail-fast for ``cooldown`` seconds instead of
    retrying through the full backoff schedule (1+2+5+15+60+300 =
    383s per request).

    Why this exists: anonymous Docker Hub pulls hit a hard rate
    limit (100 / 6h per IP) that no amount of in-process backoff
    can recover from. With 8 worker threads each retrying every
    rate-limited fetch through the full schedule, a multi-image
    project (istio: 87 unique image refs) can spend 5-7 minutes
    burning sleep cycles for fetches that are guaranteed to fail.
    The circuit breaker bounds that to ``cooldown`` seconds total
    instead of ``unique_failed_fetches × 383s``.

    Successful responses to the host clear both the failure
    history and the open-state, so a host that recovers (e.g.
    rate-limit window resets) is immediately tried again.

    Thread-safe: SCA's OCI fetcher uses an 8-worker ThreadPool
    against a shared HttpClient, so concurrent record_failure /
    is_open calls from different threads must serialise.
    """

    def __init__(
        self, *,
        threshold: int = 2,
        window: float = 60.0,
        cooldown: float = 120.0,
    ) -> None:
        self._threshold = threshold
        self._window = window
        self._cooldown = cooldown
        self._failures: Dict[Tuple[str, int], List[float]] = {}
        self._open_until: Dict[Tuple[str, int], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(host: str, port: int) -> Tuple[str, int]:
        return (host.lower(), port)

    def is_open(self, host: str, port: int) -> Tuple[bool, float]:
        """Return ``(is_open, seconds_remaining)``. When ``is_open``
        is True the caller should raise without making the request."""
        key = self._key(host, port)
        with self._lock:
            now = time.monotonic()
            until = self._open_until.get(key, 0.0)
            if now < until:
                return True, until - now
            # Cooldown elapsed — drop the open-state record so a
            # successful retry fully resets to closed.
            if until:
                self._open_until.pop(key, None)
            return False, 0.0

    def record_failure(self, host: str, port: int) -> bool:
        """Record a 429/5xx for the host. Returns True iff the
        circuit transitioned to open as a result of this call.

        Returning the transition lets the caller emit a single
        log line rather than one per blocked attempt downstream.
        """
        key = self._key(host, port)
        with self._lock:
            now = time.monotonic()
            failures = self._failures.setdefault(key, [])
            failures[:] = [t for t in failures if now - t < self._window]
            failures.append(now)
            if len(failures) >= self._threshold:
                was_open = (now < self._open_until.get(key, 0.0))
                self._open_until[key] = now + self._cooldown
                return not was_open
            return False

    def record_success(self, host: str, port: int) -> None:
        """Reset state for the host on a 2xx response."""
        key = self._key(host, port)
        with self._lock:
            self._failures.pop(key, None)
            self._open_until.pop(key, None)


# Module-level singleton circuit breaker — shared across all
# UrllibClient (and subclass) instances created without an explicit
# breaker. Lazy-initialised so module import doesn't pay the cost
# when nobody constructs a default client. Tests that need state
# isolation pass a fresh ``_HostCircuitBreaker()`` via the
# ``circuit_breaker`` kwarg.
_DEFAULT_CIRCUIT_BREAKER: Optional["_HostCircuitBreaker"] = None
_DEFAULT_CIRCUIT_BREAKER_LOCK = threading.Lock()


def _default_circuit_breaker() -> "_HostCircuitBreaker":
    global _DEFAULT_CIRCUIT_BREAKER
    if _DEFAULT_CIRCUIT_BREAKER is None:
        with _DEFAULT_CIRCUIT_BREAKER_LOCK:
            if _DEFAULT_CIRCUIT_BREAKER is None:
                _DEFAULT_CIRCUIT_BREAKER = _HostCircuitBreaker()
    return _DEFAULT_CIRCUIT_BREAKER


def reset_default_circuit_breaker() -> None:
    """Reset module-level breaker state — for tests + long-running
    daemons that want a clean slate without restarting the process."""
    global _DEFAULT_CIRCUIT_BREAKER
    with _DEFAULT_CIRCUIT_BREAKER_LOCK:
        _DEFAULT_CIRCUIT_BREAKER = None


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
        *,
        circuit_breaker: Optional[_HostCircuitBreaker] = None,
    ) -> None:
        self._ua = user_agent
        # Subclass / test hook. Lazy default avoids spinning up a pool
        # manager (and its certifi load) when the client is never used.
        self._http = _http or _new_pool_manager()
        # Per-host rate-limit circuit breaker. Defaults to a module-
        # level singleton so state persists ACROSS HttpClient
        # instances within one process — important for sweep-style
        # callers (calibration corpus collect, stress test) that
        # construct a fresh client per sample. Without sharing,
        # docker.io's rate-limit window stays exhausted (it's
        # IP-scoped on their side) while each per-sample breaker
        # has to re-trip from scratch, burning ~90s of retry budget
        # per sample. Tests pass a fresh breaker explicitly via the
        # kwarg to keep state isolated.
        if circuit_breaker is None:
            circuit_breaker = _default_circuit_breaker()
        self._circuit_breaker = circuit_breaker

    # Hard cap on URL length. Browsers cap at ~2-8 KB depending on
    # vendor; HTTP RFC has no explicit limit but server / proxy /
    # log-aggregator stacks (nginx default 8 KB request line, AWS
    # ALB 16 KB, common log shippers truncating at 4-16 KB) all
    # break down past low-tens-of-KB. Pre-fix RAPTOR had no
    # client-side cap, so a caller bug (URL built from an unbounded
    # template, attacker-influenced query string concatenated
    # without truncation) could send multi-megabyte URLs that
    # urllib3 would happily build into a request — DoS the
    # destination, get truncated mid-line by intermediaries
    # (causing parser confusion at the server), or simply waste
    # the local connection slot. 64 KB is comfortably above any
    # legitimate use (typical OAuth callback URLs with state +
    # PKCE are ~1.5 KB) and well below the smallest infra cap.
    _MAX_URL_BYTES = 64 * 1024

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
        # Length cap BEFORE urlsplit so a giant input doesn't burn
        # CPU through the parser before the rejection lands. Compare
        # encoded bytes (ASCII + percent-encoded) since wire-length
        # is the operationally-meaningful unit.
        if len(url.encode("utf-8", errors="ignore")) > self._MAX_URL_BYTES:
            raise HttpError(
                f"Refused URL exceeding {self._MAX_URL_BYTES}-byte cap "
                f"(input was {len(url)} chars)"
            )
        # Pre-fix `_urlparse.urlsplit(url)` raised ValueError
        # directly for malformed inputs:
        #
        #   * IPv6 with bad brackets: `http://[invalid::ipv6/`
        #   * URL containing NUL byte: `http://a\x00b/`
        #   * URL with port out of range: `http://h:99999/`
        #     (`int(port)` raises ValueError downstream).
        #
        # Callers expect _validate_url to raise HttpError ONLY,
        # so they can catch a single exception class. The leaked
        # ValueError bypassed caller error-handling and surfaced
        # as an opaque traceback. Wrap urlsplit so the
        # contract holds.
        try:
            parsed = _urlparse.urlsplit(url)
        except ValueError as exc:
            raise HttpError(
                f"Refused malformed URL: {exc}"
            ) from exc
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
        raise_on_status: bool = True,
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

        ``raise_on_status`` (default True) raises ``HttpError`` on
        4xx/5xx responses — the standard behaviour every consumer
        relies on. Pass ``raise_on_status=False`` when you need to
        inspect a 4xx response yourself (notably the OCI client's
        401 → token-exchange retry path, where the WWW-Authenticate
        header on the 401 IS the signal to act on, not a failure to
        propagate). With ``raise_on_status=False`` the Response is
        returned for any status; transient 5xx still triggers
        backoff retry, but the final Response (whatever its status)
        is handed back instead of raising.
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
            raise_on_status=raise_on_status,
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
        it to release the connection back to the pool.

        A common pattern (NOTE the explicit ``max_bytes``)::

            with open(dest, "wb") as f:
                for chunk in client.stream_bytes(url, max_bytes=100 * 1024 * 1024):
                    f.write(chunk)

        Always pass an explicit ``max_bytes`` ceiling. Pre-fix
        the example here omitted ``max_bytes``, leading
        callers to hit the method's default and write
        attacker-served content straight to disk. Even a
        modest 1 GB serve from a hostile mirror can fill a
        constrained ``/tmp`` partition before the operator
        notices. ``max_bytes`` enforces the cap by raising
        :class:`SizeLimitExceeded` mid-stream — your
        ``with open(...)`` block then sees the partial-write
        file, which the caller should ``os.unlink`` in the
        except handler.
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
        return self._stream(url, merged, effective_timeout, max_bytes,
                            wallclock_cap=total_timeout)

    def _stream(
        self,
        url: str,
        headers: Dict[str, str],
        timeout: int,
        max_bytes: int,
        wallclock_cap: int = None,
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
            # Pre-fix the loop honoured ``timeout`` for the
            # initial connect+read but had NO wall-clock cap on
            # the streamed body. A slowloris-style server that
            # trickled bytes (1 byte every 5 seconds, never
            # idle long enough to trip the per-read timeout)
            # held the connection open indefinitely. Operators
            # waiting on the iterator saw "stream stalled"
            # with no signal to abort.
            #
            # Apply ``wallclock_cap`` (passed from the caller's
            # ``total_timeout``) as a hard ceiling on total
            # generator lifetime. Aborts with TimeoutError if
            # the stream takes longer than the cap, matching
            # the documented contract that ``total_timeout``
            # bounds the END-TO-END operation.
            import time as _time
            _start = _time.monotonic()
            total = 0
            for chunk in resp.stream(64 * 1024, decode_content=True):
                total += len(chunk)
                if total > max_bytes:
                    raise SizeLimitExceeded(
                        f"Stream from {_safe_url_for_log(url)} "
                        f"exceeded {max_bytes} bytes",
                    )
                if (wallclock_cap is not None
                        and _time.monotonic() - _start > wallclock_cap):
                    raise TimeoutError(
                        f"Stream from {_safe_url_for_log(url)} exceeded "
                        f"wallclock cap of {wallclock_cap}s "
                        f"(slowloris defence)"
                    )
                yield chunk
        finally:
            # Same drain-then-release pattern as `_fetch_once`: a
            # SizeLimitExceeded / TimeoutError raised mid-stream
            # leaves bytes in the socket buffer. Releasing without
            # draining poisons the pool — the next request that
            # picks up the connection sees the leftover bytes
            # prepended to its OWN response. Drain (urllib3 caps
            # internally at ~64KB), then release.
            try:
                if hasattr(resp, "drain_conn"):
                    resp.drain_conn()
            except Exception:
                pass
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
        raise_on_status: bool = True,
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

        # Per-host circuit-breaker fast-fail. If we recently saw enough
        # 429/5xx from this host to open the circuit, skip the request
        # entirely — saves the full backoff schedule (~383s) on a host
        # that's already known-bad-this-window. Most common case: Docker
        # Hub anonymous-pull rate limit during a multi-image scan.
        parsed_for_cb = _urlparse.urlsplit(url)
        cb_host = (parsed_for_cb.hostname or "").lower()
        cb_port = parsed_for_cb.port or (
            443 if parsed_for_cb.scheme == "https" else 80
        )
        is_open, seconds_left = self._circuit_breaker.is_open(
            cb_host, cb_port,
        )
        if is_open:
            raise HttpError(
                f"Circuit open for {cb_host}:{cb_port} "
                f"(cooldown {seconds_left:.0f}s remaining); "
                f"recent 429/5xx history. Skipping request to avoid "
                f"retry-storm: {_safe_url_for_log(url)}",
            )

        last_exc: Optional[Exception] = None
        for attempt, delay in enumerate(schedule):
            # Deadline gate. Pre-fix the check was unconditional and
            # used `>=`, which fired BEFORE the first attempt when
            # `total_timeout == 0` (deadline = monotonic() + 0, then
            # `monotonic() >= deadline` is immediately True at the
            # top of the first iteration). The caller saw a "total
            # timeout exceeded" error without any attempt being
            # made — useless, since 0 here is most meaningfully read
            # as "single attempt, no retry budget", not "no time at
            # all". Skip the gate on attempt==0 so the first try
            # always runs; check on subsequent iterations only.
            if attempt > 0 and time.monotonic() >= deadline:
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
                response = self._fetch_once(
                    url, method=method, timeout=timeout, max_bytes=max_bytes,
                    body=body, headers=headers,
                    follow_redirects=follow_redirects,
                    raise_on_status=raise_on_status,
                )
                # Successful response (or a 4xx-with-raise_on_status=False
                # that we want to surface). Reset the host's circuit
                # breaker — a successful fetch means the rate-limit
                # window reset, the registry came back, etc.
                self._circuit_breaker.record_success(cb_host, cb_port)
                return response
            except HttpError as e:
                # Retry only on transient status codes (429, 5xx).
                # Everything else — non-retryable 4xx, SizeLimitExceeded
                # (status=None), JSON-decode errors, etc. — propagates.
                is_transient = (
                    e.status == 429
                    or (e.status is not None and 500 <= e.status < 600)
                )
                if is_transient:
                    transitioned = self._circuit_breaker.record_failure(
                        cb_host, cb_port,
                    )
                    if transitioned:
                        logger.warning(
                            "core.http: opening circuit breaker for "
                            "%s:%d (recent 429/5xx threshold reached); "
                            "subsequent requests will fail-fast for the "
                            "cooldown window",
                            cb_host, cb_port,
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
                # both as ProxyError with a message; we have to
                # pattern-match the message because ProxyError
                # doesn't expose the upstream status code structurally.
                #
                # Pre-fix the test was `"403" in msg or "forbidden"
                # in msg`. Two false-positive shapes:
                #   * Proxy unreachable error containing "403" in
                #     the URL fragment of the connect target
                #     (`https://example.com/v1/403/something`) —
                #     misclassified as permanent, retry skipped.
                #   * Proxy connectivity message naming the status
                #     code in prose: `"upstream returned 403 (after
                #     N retries)"` for a server that legitimately
                #     emitted 403 NOT from the chokepoint allowlist
                #     enforcement — also misclassified.
                #
                # Tighten by anchoring to a status-code pattern:
                # `403`/`Forbidden` must appear next to a plausible
                # HTTP-status context word, not just as a bare
                # substring. The chokepoint message at
                # core/sandbox/proxy.py emits
                # "Tunnel connection failed: 403 Forbidden" — both
                # the status word and a leading ":" or status
                # context are present, so tighten to require BOTH.
                msg = str(e).lower()
                _has_403_status = bool(
                    re.search(r'(?:status|http|tunnel|response)[^\n]{0,40}\b403\b',
                              msg)
                )
                _has_forbidden_status = bool(
                    re.search(r'\b403\s+forbidden\b', msg)
                )
                if _has_403_status or _has_forbidden_status:
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
        raise_on_status: bool = True,
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
            # Treat 4xx/5xx as HttpError unless caller opted out via
            # ``raise_on_status=False`` (e.g. OCI client's 401 →
            # token-exchange retry needs to inspect WWW-Authenticate
            # on the 401 response). When opting out we still bound
            # the body read by max_bytes — a 4xx response can carry
            # an arbitrary body.
            if resp.status >= 400 and raise_on_status:
                # Drain enough body for the error message — bounded.
                snippet = resp.read(512, decode_content=True) or b""
                reason = resp.reason or "?"
                # Pre-fix the snippet was interpolated into the
                # exception message via `repr()` only — no secret
                # redaction. 4xx responses commonly echo the
                # request token / API key back in the error body
                # ("Invalid API key abc-XXX...", "Permission denied
                # for token xxx"), which then landed verbatim in
                # caller logs / scorecards / crash dumps. Defang
                # via redact_secrets so any token-shaped substring
                # in the body gets masked before it reaches the log
                # surface. `errors='replace'` for the decode so
                # a non-UTF-8 body (rare but possible for binary
                # error responses) doesn't itself crash here.
                from core.security.redaction import redact_secrets
                snippet_text = snippet.decode("utf-8", errors="replace")
                snippet_safe = redact_secrets(snippet_text, reveal_secrets=False)
                raise HttpError(
                    f"HTTP {resp.status} from {_safe_url_for_log(url)}: "
                    f"{reason} {snippet_safe!r}"[:200],
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
                # Pre-fix `gzip.decompress(raw)` had no output cap.
                # A decompression bomb (gzip ratio >>1000:1, e.g.
                # 100KB compressed → 10GB decompressed) consumed
                # the parent process's full RAM before
                # decompression finished. The size cap on the
                # response above (`max_bytes`) bounded the
                # COMPRESSED bytes but not the decompressed
                # output.
                #
                # Use streaming decompression with a per-call
                # cap matching `max_bytes` (or 50MB if not set
                # — pathological-but-bounded ceiling for the
                # rare un-capped path). Abort and keep the raw
                # compressed bytes on cap-overflow rather than
                # raising — the existing fallback semantics
                # are "if decode fails, hand the caller the
                # raw bytes".
                _decomp_cap = max_bytes if max_bytes is not None and max_bytes > 0 else 50 * 1024 * 1024
                try:
                    decompressor = gzip.GzipFile(fileobj=io.BytesIO(raw), mode='rb')
                    out = bytearray()
                    while True:
                        block = decompressor.read(64 * 1024)
                        if not block:
                            break
                        out.extend(block)
                        if len(out) > _decomp_cap:
                            # Decompression bomb. Keep raw,
                            # don't materialise the bomb output.
                            out = None
                            break
                    if out is not None:
                        raw = bytes(out)
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
            #
            # Re-validate the post-redirect URL via _validate_url
            # (same scheme/userinfo/host gates as the initial
            # request). Pre-fix urllib3 would happily follow a 302
            # `Location: http://attacker.com/...` from an https://
            # request — a downgrade-to-cleartext that bypasses the
            # caller's TLS expectation. Even if the host is the
            # same, the scheme drop leaks the full request +
            # response body in cleartext to anyone on the network
            # path.
            #
            # If post-redirect URL fails validation, raise HttpError
            # rather than returning the response — caller's expected
            # contract (validated URL) was violated by the server's
            # redirect, and silently returning a downgraded response
            # would mask the violation.
            final_url = resp.geturl() or url
            # Only revalidate when the URL actually changed AND
            # is a real string (test fixtures may mock geturl
            # to return a MagicMock; defensively skip the
            # validator in that case rather than crashing
            # urlparse).
            if isinstance(final_url, str) and final_url != url:
                # urllib3's ``geturl()`` may return a relative path
                # (no scheme + no host) for the original
                # response when the server's response shape includes
                # a ``Location:`` header even on a non-redirect 200
                # response — observed in the wild against
                # ``https://api.osv.dev/v1/querybatch`` which returns
                # ``Location: /v1/querybatch`` alongside its 200.
                # Pre-fix the validator rejected the relative URL
                # ("no scheme") and the entire successful response
                # was discarded as a "refused redirect", silently
                # turning every successful querybatch call into an
                # empty-result error. Resolve relative paths against
                # the original request URL before validating.
                from urllib.parse import urlparse, urljoin
                if not urlparse(final_url).scheme:
                    final_url = urljoin(url, final_url)
                try:
                    self._validate_url(final_url)
                except HttpError as exc:
                    raise HttpError(
                        f"refused redirect from {_safe_url_for_log(url)} "
                        f"to {_safe_url_for_log(final_url)}: {exc}"
                    ) from exc
            # Pre-fix `{k.lower(): v for k, v in resp.headers.items()}`
            # silently dropped duplicate-name headers (last value
            # wins). The operationally-significant case is
            # `Set-Cookie`: an HTTP response can legitimately carry
            # multiple Set-Cookie headers (one per cookie), and the
            # dict comprehension collapsed them to a single value
            # per key — caller saw only the LAST cookie set, the
            # others lost. Other headers (Vary, Link, X-Foo) can
            # also legitimately repeat per RFC 9110 §5.3.
            #
            # Aggregate via getlist() so multi-value headers become
            # newline-joined values. Caller can split on `\n` for
            # the multi-value cases (Set-Cookie commonly does this);
            # single-value headers still come back as the bare
            # string. urllib3's HTTPHeaderDict.getlist returns the
            # full list preserving order and casing-insensitive.
            collapsed_headers: Dict[str, str] = {}
            for key in resp.headers:
                values = resp.headers.getlist(key) if hasattr(resp.headers, "getlist") else [resp.headers[key]]
                # Already lower-cased after collection — last lowercase wins
                # if the server somehow sent the same header in multiple cases
                # (very rare; if so the values are joined together too).
                lk = key.lower()
                if lk in collapsed_headers and values:
                    collapsed_headers[lk] = collapsed_headers[lk] + "\n" + "\n".join(values)
                else:
                    collapsed_headers[lk] = "\n".join(values) if values else ""
            return Response(
                status=resp.status,
                headers=collapsed_headers,
                body=raw,
                url=final_url,
            )
        finally:
            # Drain THEN release. Pre-fix the finally only called
            # `resp.release_conn()`. release_conn returns the
            # connection to the pool WITHOUT draining any
            # remaining body bytes from the socket buffer. The
            # next request that picks up the connection then saw
            # the leftover bytes prepended to its OWN response —
            # parser confusion, wrong status codes, occasional
            # data leaks across requests sharing the pool.
            #
            # Two failure paths that left bytes in the buffer:
            #   * 4xx snippet branch reads only 512 bytes but a
            #     larger error body has more in flight.
            #   * SizeLimitExceeded raises mid-stream with the
            #     remainder of the body still on the socket.
            #
            # `drain_conn()` reads remaining bytes (up to a small
            # cap inside urllib3, ~64KB by default) so the socket
            # buffer is empty when release_conn returns the conn
            # to the pool. If drain itself fails we fall through
            # to release — better to leak a single connection
            # than to crash the cleanup path.
            try:
                if hasattr(resp, "drain_conn"):
                    resp.drain_conn()
            except Exception:
                pass
            resp.release_conn()

    @staticmethod
    def _parse_retry_after(value: Optional[str]) -> Optional[int]:
        """Parse Retry-After header. Both delta-seconds and HTTP-date forms.

        RFC 7231 §7.1.3 defines two grammars: a non-negative integer
        (``Retry-After: 120``) or an HTTP-date
        (``Retry-After: Fri, 31 Dec 1999 23:59:59 GMT``). Pre-fix the
        seconds-only path silently returned None on the date form,
        which caused the caller's retry loop to fall back to its
        default backoff schedule — typically much shorter than what
        the upstream actually wanted. For a 503 from Cloudflare /
        Akamai (commonly date-form), this triggered the retry storm
        the header is supposed to prevent.

        Both forms get clamped to [1, 1800] so a malicious /
        misconfigured upstream can't tie up our connection slot for
        an arbitrary delay. Negative deltas (legacy behaviour bug)
        and past dates both clamp to 1.
        """
        if not value:
            return None
        s = value.strip()
        try:
            n = int(s)
            return max(1, min(n, 1800))
        except ValueError:
            pass
        # HTTP-date form — RFC 7231 says the value is in the IMF-fixdate
        # / obs-date subset of RFC 5322. Use email.utils.parsedate_to_datetime
        # which handles all three IMF/RFC 850/asctime variants.
        try:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone
            target = parsedate_to_datetime(s)
            if target is None:
                return None
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            delta = (target - datetime.now(timezone.utc)).total_seconds()
            return max(1, min(int(delta), 1800))
        except (TypeError, ValueError):
            return None


__all__ = ["UrllibClient"]
