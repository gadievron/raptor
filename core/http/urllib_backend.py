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

Operator proxy env: when constructed WITHOUT an injected pool
manager, UrllibClient snapshots ``https_proxy`` / ``http_proxy`` /
``all_proxy`` (+ ``no_proxy``) at construction time and routes
requests through the operator's proxy — mandatory-egress-proxy hosts
otherwise have no route at all for the direct client (urllib3 never
reads env at request time). This does NOT weaken the EgressClient
chokepoint: EgressClient injects its own ``ProxyManager`` via
``_http``, which disables the env snapshot entirely, so ``no_proxy``
still cannot bypass the chokepoint. The snapshot is
construction-time, matching the sandbox egress proxy's
capture-once semantics.

Honours Retry-After on 429/503; exponential backoff on other transient
errors; bounded total retry duration; size caps on responses; gzip
decompression only when the response DECLARES Content-Encoding: gzip
(never by sniffing body magic — content-addressed payloads like OCI
layer blobs legitimately ARE gzip files and must arrive verbatim).
Callers can pin ``Accept-Encoding: identity`` to disable transport
decompression entirely and receive raw bytes.

No allowlist — UrllibClient can reach any host on :443. For
allowlisted egress, use :class:`core.http.egress_backend.EgressClient`.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import logging
import re
import threading
import time
from collections.abc import Iterator
from typing import Any
from urllib import parse as _urlparse

import urllib3
from urllib3.exceptions import (
    HTTPError as _U3HTTPError,
)
from urllib3.exceptions import (
    LocationValueError as _U3LocationValueError,
)
from urllib3.exceptions import (
    MaxRetryError,
    ReadTimeoutError,
    SSLError,
)
from urllib3.exceptions import (
    ProxyError as _U3ProxyError,
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

# Permanent classes inside the urllib3 ``HTTPError`` umbrella that
# we do NOT want the transient-retry loop to retry. Pre-fix the
# blanket ``_U3HTTPError`` catch retried every subclass — including
# config-error shapes like ``LocationValueError`` (raised on a
# malformed URL the operator can't fix by waiting). Multiplied
# latency on permanent failures without any chance of recovery.
_U3_PERMANENT_HTTPERROR = (_U3LocationValueError,)


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
    msg = (
        f"_BACKOFF_SECONDS length ({len(_BACKOFF_SECONDS)}) must equal "
        f"DEFAULT_RETRIES + 1 ({DEFAULT_RETRIES + 1}) — one slot for the "
        f"initial attempt + one per retry; update both together"
    )
    raise RuntimeError(msg)


def _caller_header(headers: dict[str, str] | None, name: str) -> str:
    """Case-insensitive lookup in a caller-supplied header dict."""
    if not headers:
        return ""
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v or ""
    return ""


def _wants_identity(headers: dict[str, str] | None) -> bool:
    """True when the caller pinned ``Accept-Encoding: identity`` —
    the raw-bytes contract for content-addressed consumers (OCI
    blobs). Transport decompression is then disabled end to end so
    the caller hashes exactly the bytes the server stored."""
    value = _caller_header(headers, "accept-encoding")
    return value.strip().lower() == "identity"


def _declared_gzip(resp) -> bool:
    """True when the response's ``Content-Encoding`` names gzip."""
    headers = getattr(resp, "headers", None) or {}
    get = getattr(headers, "get", None)
    if get is None:
        return False
    ce = get("Content-Encoding") or get("content-encoding") or ""
    return any(
        token.strip() in ("gzip", "x-gzip")
        for token in ce.lower().split(",")
    )


# Byte budget for draining a response before returning its connection
# to the pool. Enough to clear real-world leftovers (error bodies,
# the tail after a 512-byte snippet read); a remainder larger than
# this is not worth reading — the connection is closed instead.
_DRAIN_BUDGET_BYTES = 64 * 1024


def _drain_bounded_or_close(resp) -> None:
    """Clear at most ``_DRAIN_BUDGET_BYTES`` from ``resp`` so its
    connection can be reused; close the connection when more remains.

    Reusing a connection with unread bytes poisons the pool (the next
    request sees the leftovers prepended to its own response), so the
    remainder must be dealt with — but urllib3's ``drain_conn()``
    reads to EOF with NO cap, which turned every abort path
    (SizeLimitExceeded, timeout, 4xx snippet) into an unbounded read
    of whatever the hostile peer still had to send, AFTER the
    advertised limit had already fired. Budgeted drain first; if the
    body still isn't exhausted, closing the connection (the pool
    replaces closed connections) is strictly cheaper than reading a
    hostile remainder.

    Failures here only cost one pooled connection — never crash the
    cleanup path.
    """
    try:
        remaining = _DRAIN_BUDGET_BYTES
        while remaining > 0:
            # No decode_content override: urllib3 2.x refuses to
            # switch decode modes mid-response.
            chunk = resp.read(min(16 * 1024, remaining))
            if not chunk:
                return          # EOF — fully drained, safe to reuse
            if not isinstance(chunk, (bytes, bytearray)) or not len(chunk):
                # Non-bytes / zero-length-but-truthy reads mean an
                # unknown response implementation (test doubles) —
                # don't risk spinning; close instead of reusing.
                resp.close()
                return
            remaining -= len(chunk)
        resp.close()
    except Exception:  # noqa: BLE001 — transport/state errors alike
        with contextlib.suppress(Exception):
            resp.close()


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


def _env_proxy_settings() -> tuple[dict[str, str], tuple[str, ...]]:
    """Snapshot proxy env for the direct client.

    Returns ``({scheme: proxy_url}, no_proxy_entries)``. Lowercase
    names win (matching curl/requests precedence), ``all_proxy`` is
    the per-scheme fallback. Empty mapping when no proxy configured.
    """
    import os

    def _get(*names: str) -> str | None:
        for n in names:
            v = os.environ.get(n)
            if v:
                return v
        return None

    fallback = _get("all_proxy", "ALL_PROXY")
    mapping: dict[str, str] = {}
    https_p = _get("https_proxy", "HTTPS_PROXY") or fallback
    http_p = _get("http_proxy", "HTTP_PROXY") or fallback
    if https_p:
        mapping["https"] = https_p
    if http_p:
        mapping["http"] = http_p
    raw = _get("no_proxy", "NO_PROXY") or ""
    entries = tuple(e.strip() for e in raw.split(",") if e.strip())
    return mapping, entries


def _host_in_no_proxy(host: str, entries: tuple[str, ...]) -> bool:
    """Suffix-match ``host`` against no_proxy entries.

    Standard semantics: ``*`` matches everything; entries match the
    exact host or any subdomain (leading dots optional); a ``:port``
    suffix on an entry is ignored (we match on host only).
    """
    host = host.lower().rstrip(".")
    for entry in entries:
        e = entry.lower()
        if e == "*":
            return True
        # Strip a :port suffix — but not an IPv6 colon. no_proxy
        # entries with bracketed IPv6 are rare; handle the common
        # host[:port] shape and leave bare IPv6 entries intact.
        if e.count(":") == 1:
            e = e.split(":", 1)[0]
        e = e.lstrip(".")
        if not e:
            continue
        if host == e or host.endswith("." + e):
            return True
    return False


def _new_proxy_manager(proxy_url: str) -> urllib3.ProxyManager:
    """ProxyManager with the same secure defaults as the direct pool.

    Basic-auth userinfo in the proxy URL (``http://user:pass@corp:8080``)
    is extracted into ``Proxy-Authorization`` headers — urllib3 does
    not parse it from the URL itself.
    """
    try:
        import certifi
        ca_certs = certifi.where()
    except ImportError:
        ca_certs = None
    parsed = _urlparse.urlsplit(proxy_url)
    proxy_headers = None
    if parsed.username is not None:
        auth = parsed.username
        if parsed.password is not None:
            auth = f"{parsed.username}:{parsed.password}"
        proxy_headers = urllib3.make_headers(proxy_basic_auth=auth)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        proxy_url = _urlparse.urlunsplit(
            (parsed.scheme, netloc, parsed.path, parsed.query,
             parsed.fragment)
        )
    return urllib3.ProxyManager(
        proxy_url,
        retries=False, cert_reqs="CERT_REQUIRED",
        ca_certs=ca_certs,
        maxsize=_DEFAULT_POOL_MAXSIZE,
        proxy_headers=proxy_headers,
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
        self._failures: dict[tuple[str, int], list[float]] = {}
        self._open_until: dict[tuple[str, int], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(host: str, port: int) -> tuple[str, int]:
        return (host.lower(), port)

    def is_open(self, host: str, port: int) -> tuple[bool, float]:
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
_DEFAULT_CIRCUIT_BREAKER: _HostCircuitBreaker | None = None
_DEFAULT_CIRCUIT_BREAKER_LOCK = threading.Lock()


def _default_circuit_breaker() -> _HostCircuitBreaker:
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
        _http: urllib3.PoolManager | None = None,
        *,
        circuit_breaker: _HostCircuitBreaker | None = None,
    ) -> None:
        self._ua = user_agent
        # Subclass / test hook. An injected pool manager (EgressClient's
        # chokepoint ProxyManager, test doubles) is used exclusively —
        # the operator-proxy env snapshot below is then disabled, so
        # no_proxy can never bypass the chokepoint.
        if _http is not None:
            self._http = _http
            self._proxy_map: dict[str, str] = {}
            self._no_proxy: tuple[str, ...] = ()
        else:
            self._http = _new_pool_manager()
            # Proxy env is SNAPSHOTTED here but the ProxyManagers are
            # built lazily on first proxied request. Eager
            # construction meant a malformed proxy env (schemeless
            # ``proxy:3128``, unsupported ``socks5://``) raised
            # ProxySchemeUnknown out of EVERY UrllibClient(),
            # including loopback/no_proxy-only uses that never touch
            # the proxy.
            self._proxy_map, self._no_proxy = _env_proxy_settings()
        # One ProxyManager per distinct proxy URL (http and https
        # usually share one) — schemes map onto the shared pool.
        # Built on demand by _pool_for; a construction failure is
        # cached so every proxied request gets the same clear error
        # without re-raising from an unrelated code path.
        self._proxy_pools: dict[str, urllib3.ProxyManager] = {}
        self._proxy_pool_errors: dict[str, str] = {}
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

    def _pool_for(self, url: str) -> urllib3.PoolManager:
        """Pick the pool for ``url``: the operator-proxy pool when one
        was detected at construction and the host isn't no_proxy'd,
        else the direct pool (which is also the injected pool for
        EgressClient — see ``__init__``).

        Proxy pools are constructed lazily HERE, so a malformed proxy
        env only fails the requests that would actually use the proxy
        — with a clear :class:`HttpError` naming the bad value —
        while direct/no_proxy traffic is unaffected.
        """
        if not self._proxy_map:
            return self._http
        parsed = _urlparse.urlsplit(url)
        purl = self._proxy_map.get(parsed.scheme)
        if purl is None:
            return self._http
        host = (parsed.hostname or "").lower()
        if host and _host_in_no_proxy(host, self._no_proxy):
            return self._http
        pool = self._proxy_pools.get(parsed.scheme)
        if pool is not None:
            return pool
        prior_error = self._proxy_pool_errors.get(purl)
        if prior_error is not None:
            raise HttpError(prior_error)
        try:
            # Share one manager across schemes pointing at the same
            # proxy URL.
            shared = next(
                (p for s, p in self._proxy_pools.items()
                 if self._proxy_map.get(s) == purl),
                None,
            )
            pool = shared if shared is not None else _new_proxy_manager(purl)
        except Exception as exc:
            from core.security.redaction import redact_secrets
            msg = (
                f"invalid proxy configuration for scheme "
                f"{parsed.scheme!r}: {redact_secrets(str(exc))} — fix "
                f"the https_proxy/http_proxy/all_proxy value (must be "
                f"an http(s):// URL) or add the host to no_proxy"
            )
            self._proxy_pool_errors[purl] = msg
            raise HttpError(msg) from exc
        self._proxy_pools[parsed.scheme] = pool
        return pool

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
            msg = (
                f"Refused URL exceeding {self._MAX_URL_BYTES}-byte cap "
                f"(input was {len(url)} chars)"
            )
            raise HttpError(msg)
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
            msg = f"Refused malformed URL: {exc}"
            raise HttpError(msg) from exc
        if parsed.scheme not in self._ALLOWED_SCHEMES:
            permitted = "/".join(self._ALLOWED_SCHEMES)
            msg = (
                f"Refused URL with scheme {parsed.scheme!r}: "
                f"only {permitted} permitted"
            )
            raise HttpError(msg)
        if not parsed.hostname:
            msg = f"Refused URL with no host: {url!r}"
            raise HttpError(msg)
        if parsed.username is not None or parsed.password is not None:
            msg = (
                "Refused URL with embedded credentials; pass credentials via "
                "an Authorization header, not in the URL authority"
            )
            raise HttpError(msg)
        return parsed

    # -- public API -----------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
        stream: bool = False,
        raise_on_status: bool = True,
    ) -> Response:
        """Low-level HTTP request — returns a full :class:`Response` object.

        Use this when you need response metadata (status, headers,
        final URL). Typical case: capturing ``ETag`` /
        ``Last-Modified`` for a subsequent conditional request.

        Redirects are NOT followed by this backend — a 3xx response
        is returned to the caller as-is (status + ``Location``
        header), regardless of ``follow_redirects``. This is
        deliberate: the post-response URL revalidation checks only
        the generic URL gates (scheme, userinfo, host presence), not
        caller-level address policy (e.g. the OCI registry SSRF
        policy), so transparently following a redirect would let any
        policy-passing host bounce a request at endpoints the caller
        never validated. Callers that need to follow a redirect must
        read ``Location``, re-validate the target through their own
        policy, and issue a new request. ``follow_redirects`` is
        retained for interface compatibility only.

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
        body: dict[str, Any],
        timeout: int = DEFAULT_TIMEOUT,
        *,
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
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
        headers: dict[str, str] | None = None,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        follow_redirects: bool = True,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> dict[str, Any]:
        self._validate_url(url)
        merged = {"Accept": "application/json", "User-Agent": self._ua}
        if headers:
            merged.update(headers)
        resp = self._fetch(url, method="GET", timeout=timeout, body=None,
                           headers=merged, max_bytes=max_bytes,
                           total_timeout=total_timeout, retries=retries,
                           follow_redirects=follow_redirects)
        return resp.json()

    def get_bytes(
        self,
        url: str,
        timeout: int = DEFAULT_TIMEOUT,
        max_bytes: int = DEFAULT_MAX_BYTES,
        *,
        headers: dict[str, str] | None = None,
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
        headers: dict[str, str] | None = None,
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
            msg = (
                "stream_bytes does not support retries (mid-stream "
                "failures aren't transparently resumable). "
                "Pass retries=0 or wrap the iterator in your own "
                "retry loop."
            )
            raise ValueError(msg)
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
        headers: dict[str, str],
        timeout: int,
        max_bytes: int,
        wallclock_cap: int | None = None,
    ) -> Iterator[bytes]:
        # Same raw-bytes contract as _fetch_once: an explicit
        # ``Accept-Encoding: identity`` disables transport
        # decompression so content-addressed downloads hash the
        # bytes the server stored.
        decode = not _wants_identity(headers)
        resp = self._pool_for(url).request(
            "GET", url,
            headers=headers,
            timeout=urllib3.Timeout(total=float(timeout)),
            preload_content=False,
            decode_content=decode,
            # Never follow redirects — same deliberate pin as
            # `_fetch_once` (see its comment): with retries=False
            # urllib3 already zeroed the redirect budget, so the old
            # ``redirect=True`` here was dead weight one retry-
            # plumbing refactor away from silently chasing 3xx into
            # endpoints no caller-level address policy ever saw.
            redirect=False,
            retries=False,
        )
        try:
            # Re-validate the final URL BEFORE yielding any body
            # bytes — same scheme/userinfo/host gates as the initial
            # request. Defence in depth now that redirects are
            # pinned off (it would catch a backend regression that
            # starts following again), and it still resolves the
            # relative-path shape urllib3's geturl() can return on
            # 200 responses that carry a ``Location:`` header (same
            # handling as `_fetch_once`).
            final_url = resp.geturl() or url
            if isinstance(final_url, str) and final_url != url:
                from urllib.parse import urljoin, urlparse
                if not urlparse(final_url).scheme:
                    final_url = urljoin(url, final_url)
                try:
                    self._validate_url(final_url)
                except HttpError as exc:
                    msg = (
                        f"refused redirect from {_safe_url_for_log(url)} "
                        f"to {_safe_url_for_log(final_url)}: {exc}"
                    )
                    raise HttpError(msg) from exc
            if resp.status == 304:
                msg = f"304 Not Modified for {_safe_url_for_log(url)}"
                raise NotModified(msg)
            if resp.status >= 400:
                # Bounded read for the error message, secrets
                # redacted — same defang as `_fetch_once`'s 4xx
                # branch (4xx bodies commonly echo the request
                # token back).
                snippet = resp.read(512, decode_content=decode) or b""
                reason = resp.reason or "?"
                from core.security.redaction import redact_secrets
                snippet_text = snippet.decode("utf-8", errors="replace")
                snippet_safe = redact_secrets(snippet_text, reveal_secrets=False)
                raise HttpError(
                    f"HTTP {resp.status} from {_safe_url_for_log(url)}: "
                    f"{reason} {snippet_safe!r}"[:200],
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
            for chunk in resp.stream(64 * 1024, decode_content=decode):
                total += len(chunk)
                if total > max_bytes:
                    msg = (
                        f"Stream from {_safe_url_for_log(url)} "
                        f"exceeded {max_bytes} bytes"
                    )
                    raise SizeLimitExceeded(msg)
                if (wallclock_cap is not None
                        and _time.monotonic() - _start > wallclock_cap):
                    msg = (
                        f"Stream from {_safe_url_for_log(url)} exceeded "
                        f"wallclock cap of {wallclock_cap}s "
                        f"(slowloris defence)"
                    )
                    raise TimeoutError(msg)
                yield chunk
        finally:
            # Same bounded-drain-then-release pattern as
            # `_fetch_once`: a SizeLimitExceeded / TimeoutError
            # raised mid-stream leaves bytes in the socket buffer,
            # and releasing without clearing them poisons the pool.
            # urllib3's own drain_conn() reads to EOF UNBOUNDED, so
            # a hostile remainder would be consumed after the abort
            # fired — drain under a byte budget and close the
            # connection instead when more remains.
            _drain_bounded_or_close(resp)
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
        body: bytes | None,
        headers: dict[str, str],
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
            msg = (
                f"Circuit open for {cb_host}:{cb_port} "
                f"(cooldown {seconds_left:.0f}s remaining); "
                f"recent 429/5xx history. Skipping request to avoid "
                f"retry-storm: {_safe_url_for_log(url)}"
            )
            raise HttpError(
                msg,
                circuit_break=True,
            )

        last_exc: Exception | None = None
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
                msg = (
                    f"Total timeout ({total_timeout}s) exceeded for "
                    f"{_safe_url_for_log(url)}"
                )
                raise HttpError(msg) from last_exc
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
                            "core.http: circuit breaker opened for "
                            "%s:%d — fail-fast for cooldown",
                            cb_host, cb_port,
                        )
                    if self._circuit_breaker.is_open(cb_host, cb_port)[0]:
                        msg = (
                            f"Circuit open for {cb_host}:{cb_port}; "
                            f"aborting retry: "
                            f"{_safe_url_for_log(url)}"
                        )
                        raise HttpError(
                            msg,
                            circuit_break=True,
                        ) from e
                if not is_transient:
                    raise
                last_exc = e
                if is_last_attempt:
                    continue
                sleep_for = e.retry_after or delay
                logger.debug(
                    "core.http: %s %s -> %d; sleeping %ds (retry %d)",
                    method, _safe_url_for_log(url), e.status,
                    sleep_for, attempt + 1,
                )
                # Clip sleep to remaining deadline so a long backoff
                # doesn't blow past total_timeout.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    msg = (
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}"
                    )
                    raise HttpError(msg) from last_exc
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
                    msg_0 = (
                        f"Egress proxy refused {host!r}: host not on the "
                        f"allowlist. If you're using EgressClient, add "
                        f"this host to allowed_hosts at construction — "
                        f"the chokepoint allowlist supersedes any "
                        f"no_proxy env var by design (closing it would "
                        f"reintroduce the bypass urllib3 was chosen to "
                        f"prevent). Underlying: {e}"
                    )
                    raise HttpError(msg_0) from e
                # CONNECT-level 5xx from the (upstream) proxy is the
                # other hard-refusal shape: the proxy itself answered
                # and said no (host blocked by upstream policy, or the
                # upstream cannot reach it). Retrying with backoff just
                # multiplies a policy decision into minutes of wall
                # clock — observed as registry probes burning the full
                # total_timeout per blocked host. Same anchored-pattern
                # discipline as the 403 branch above.
                _has_tunnel_5xx = bool(
                    re.search(r'(?:tunnel|status|http|response)'
                              r'[^\n]{0,40}\b50[234]\b', msg)
                )
                if _has_tunnel_5xx:
                    host = _urlparse.urlsplit(url).hostname or "?"
                    msg_0 = (
                        f"Upstream proxy could not tunnel to {host!r} "
                        f"(CONNECT-level 5xx — upstream policy or "
                        f"reachability, not transient). Underlying: {e}"
                    )
                    raise HttpError(msg_0) from e
                last_exc = e
                if is_last_attempt:
                    continue
                logger.debug(
                    "core.http: %s %s proxy error: %s; backoff %ds",
                    method, _safe_url_for_log(url), e, delay,
                )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    msg_0 = (
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}"
                    )
                    raise HttpError(msg_0) from last_exc
                time.sleep(min(delay, remaining))
                continue
            except _U3_PERMANENT_HTTPERROR as e:
                # Permanent — config error (malformed URL, etc.).
                # Don't retry; fail fast so the caller sees the
                # immediate cause instead of an "exhausted retries"
                # wrapper.
                msg_0 = (
                    f"core.http: permanent error fetching "
                    f"{_safe_url_for_log(url)}: {e}"
                )
                raise HttpError(msg_0) from e
            except (MaxRetryError, ReadTimeoutError, SSLError, _U3HTTPError,
                    TimeoutError, ConnectionError) as e:
                last_exc = e
                if is_last_attempt:
                    continue
                logger.debug(
                    "core.http: %s %s network error: %s; backoff %ds",
                    method, _safe_url_for_log(url), e, delay,
                )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    msg_0 = (
                        f"Total timeout ({total_timeout}s) exceeded for "
                        f"{_safe_url_for_log(url)}"
                    )
                    raise HttpError(msg_0) from last_exc
                time.sleep(min(delay, remaining))
                continue
        # Exhausted retries
        msg_0 = f"Exhausted retries fetching {_safe_url_for_log(url)}: {last_exc}"
        raise HttpError(msg_0) from last_exc

    def _fetch_once(
        self,
        url: str,
        method: str,
        timeout: int,
        max_bytes: int,
        body: bytes | None,
        headers: dict[str, str],
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
        # redirect=False — redirects are never followed by this
        # backend. Pre-fix the code passed redirect=follow_redirects
        # (default True) and non-following was ACCIDENTAL: with
        # retries=False urllib3 zeroes the redirect budget
        # (Retry.__init__ sets redirect=0, raise_on_redirect=False
        # when total is False), so the 3xx came back unfollowed no
        # matter what redirect= said. One refactor of the retry
        # plumbing away from silently starting to follow — and the
        # post-redirect revalidation below re-checks only generic
        # URL gates (scheme/userinfo/host), never caller-level
        # address policy (e.g. the OCI registry SSRF policy). Pin
        # the intended behaviour explicitly; 3xx responses surface
        # to the caller with their Location header intact.
        is_head = method.upper() == "HEAD"
        # ``Accept-Encoding: identity`` from the caller is the
        # raw-bytes contract (content-addressed consumers hash the
        # exact stored bytes): disable transport decompression for
        # the whole request instead of letting urllib3 second-guess.
        decode = not _wants_identity(headers)
        resp = self._pool_for(url).request(
            method, url,
            body=body,
            headers=headers,
            timeout=urllib3.Timeout(total=float(timeout)),
            preload_content=is_head,   # True for HEAD, False otherwise
            decode_content=decode,
            redirect=False,            # never follow — see comment above
            retries=False,
        )
        try:
            # 304 Not Modified — caller used If-None-Match / If-Modified-Since
            # and the server says the cached value is still fresh. Surface
            # via NotModified exception so caller can fall back to cache.
            # Important: 304 is NOT >= 400, so this needs to come first
            # before the generic error threshold below.
            if resp.status == 304:
                msg = f"304 Not Modified for {_safe_url_for_log(url)}"
                raise NotModified(msg)
            if resp.status in (429, 503):
                msg = f"HTTP {resp.status} from {_safe_url_for_log(url)}"
                raise HttpError(
                    msg,
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
            if resp.status >= 500 and not raise_on_status:
                msg = f"HTTP {resp.status} from {_safe_url_for_log(url)}"
                raise HttpError(
                    msg,
                    status=resp.status,
                )
            if resp.status >= 400 and raise_on_status:
                # Drain enough body for the error message — bounded.
                snippet = resp.read(512, decode_content=decode) or b""
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
                for chunk in resp.stream(64 * 1024, decode_content=decode):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        msg = (
                            f"Response from {_safe_url_for_log(url)} "
                            f"exceeded {max_bytes} bytes"
                        )
                        raise SizeLimitExceeded(msg)
                raw = bytes(buf)

            # Defence in depth: a server that DECLARES
            # Content-Encoding: gzip may still hand us compressed
            # bytes when urllib3's auto-decode misses; decode here.
            # The declaration gate matters: pre-fix this sniffed the
            # 1f8b magic alone and gunzipped ANY body that happened
            # to be a gzip stream — OCI layer blobs ARE gzip files,
            # so a blob whose decompressed size fit the cap was
            # transparently mutated, breaking sha256 verification of
            # the content address and inviting decompression
            # amplification. Content that merely IS gzip (no
            # Content-Encoding) now passes through untouched. Fall
            # back to the raw bytes if decompression raises.
            if decode and _declared_gzip(resp) \
                    and raw.startswith(b"\x1f\x8b"):
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
            # urllib3's geturl() returns the URL the response was
            # actually served from (the request URL, since redirects
            # are pinned off above). It can return None (or empty
            # string) if the response object hasn't recorded the URL
            # yet — fall back to the request URL so callers always
            # see something parseable. Documented contract on
            # Response.url.
            #
            # Re-validate any changed final URL via _validate_url
            # (same scheme/userinfo/host gates as the initial
            # request). With redirect=False this is defence in
            # depth: if a backend regression ever starts following
            # again, an https -> http downgrade redirect
            # (`Location: http://attacker.com/...`) still gets
            # refused here instead of silently leaking the request
            # and response in cleartext.
            #
            # If the final URL fails validation, raise HttpError
            # rather than returning the response — caller's expected
            # contract (validated URL) was violated, and silently
            # returning the response would mask the violation.
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
                from urllib.parse import urljoin, urlparse
                if not urlparse(final_url).scheme:
                    final_url = urljoin(url, final_url)
                try:
                    self._validate_url(final_url)
                except HttpError as exc:
                    msg = (
                        f"refused redirect from {_safe_url_for_log(url)} "
                        f"to {_safe_url_for_log(final_url)}: {exc}"
                    )
                    raise HttpError(msg) from exc
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
            collapsed_headers: dict[str, str] = {}
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
            # Bounded drain THEN release. Two failure paths leave
            # bytes in the socket buffer:
            #   * 4xx snippet branch reads only 512 bytes but a
            #     larger error body has more in flight.
            #   * SizeLimitExceeded raises mid-stream with the
            #     remainder of the body still on the socket.
            # Releasing without clearing them poisons the pool (the
            # next request sees the leftovers prepended to its own
            # response). urllib3's drain_conn() reads to EOF with NO
            # cap, which handed a hostile peer an unbounded read
            # AFTER the advertised limit aborted — so the drain runs
            # under a byte budget and the connection is closed
            # (pool replaces it) when more remains.
            _drain_bounded_or_close(resp)
            resp.release_conn()

    @staticmethod
    def _parse_retry_after(value: str | None) -> int | None:
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
            from datetime import datetime, timezone
            from email.utils import parsedate_to_datetime
            target = parsedate_to_datetime(s)
            if target is None:
                return None
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            delta = (target - datetime.now(timezone.utc)).total_seconds()
            return max(1, min(int(delta), 1800))
        except (TypeError, ValueError, OverflowError):
            # OverflowError catches absurd dates a hostile server can
            # send (e.g. year=9999999) where parsedate_to_datetime
            # constructs a datetime that overflows ``int(delta)``.
            return None


__all__ = ["UrllibClient"]
