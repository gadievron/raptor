"""
Secure HTTP Client for Web Testing

Handles HTTP requests with safety features:
- Request/response logging
- Automatic rate limiting
- Session management
- Header manipulation
- Authentication handling
"""

import contextlib
import ipaddress
import socket
import threading
import time
from types import TracebackType
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    from packages.web.execution_policy import WebExecutionPolicy

import requests
import urllib3
from typing_extensions import Self

from core.logging import get_logger
from core.security.redaction import redact_secrets

from packages.web.origin import origin_of

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 10


class ScopeRedirectBlockedError(ValueError):
    """A redirect Location pointed outside the configured target scope.

    Subclasses ValueError so existing handlers keep working; carries
    the blocked destination so callers can explain WHERE the target
    tried to send the scan (preflight uses this to tell the operator
    "the target lives at https://... — scan that origin" instead of a
    generic unreachable error).
    """

    def __init__(self, message: str, next_url: str) -> None:
        super().__init__(message)
        self.next_url = next_url

# What closing a Response/Session can legitimately raise: socket/SSL
# teardown (OSError family) plus the requests/urllib3 error trees a
# hostile server can force mid-stream. TypeError/AttributeError here
# would be a wiring bug and must propagate.
_CLOSE_ERRORS = (
    OSError,
    requests.RequestException,
    urllib3.exceptions.HTTPError,
)

# Caps on the buffered response body — hostile endpoints attack in
# BOTH directions. Memory: multi-GB responses OOM the scanner; 128 MiB
# is generous for real HTML / API responses (typical pages <1 MiB).
# Time: the request `timeout` is a PER-READ socket timeout, so a
# chunked-encoding slowloris sending one byte per window keeps every
# read alive and stalls the sequential check pipeline indefinitely —
# the byte cap alone never fires against it. The wall-clock deadline
# runs from the start of the body read; 60s lets a well-behaved
# endpoint deliver the full 128 MiB at ~2 MiB/s while cutting a
# dripping endpoint off in bounded time (raising it tolerates slower
# legitimate servers at the cost of longer hostile stalls per request;
# lowering it truncates slow-but-real large bodies).
_MAX_RESPONSE_BYTES = 128 * 1024 * 1024
_MAX_BODY_READ_SECONDS = 60.0

# Cap on request_history length — without this, long-running scans
# against large targets accumulate hundreds of MB (full request +
# response captured per call) until process exit.
_MAX_REQUEST_HISTORY = 1024

logger = get_logger()

# Thread-safe DNS pinning. A per-request save/patch/restore of the
# process-global socket.getaddrinfo races under concurrent callers
# (thread B can save thread A's patch as its "original" and restore it
# permanently). Instead one wrapper is installed exactly once and
# consults a THREAD-LOCAL pin stack: requests/urllib3 resolve on the
# calling thread, so the pin is visible exactly where it is needed and
# invisible everywhere else. With no pins on the current thread the
# wrapper is a pure passthrough.
_pin_install_lock = threading.Lock()
_pin_local = threading.local()
_original_getaddrinfo = None

# Trailing label separators (ASCII dot plus the IDNA/UTS46 dot
# variants U+3002, U+FF0E, U+FF61): a fully-qualified spelling of a
# hostname names the same host, so pins must fold it away.
_HOST_DOT_VARIANTS = ".。．｡"


def _canonical_pin_host(host: object) -> str:
    """Fold a hostname into the one canonical form pins are keyed on.

    The pin is only sound when it is keyed on the SAME form the socket
    layer later resolves. urllib3 hands ``getaddrinfo`` the IDNA2008
    punycode form of the URL host, while ``urlparse().hostname`` yields
    the unicode form — keying the pin on the latter made it miss for
    every non-ASCII hostname (live second resolution: the exact
    rebinding TOCTOU the pin exists to close). Both the pin key and the
    wrapper's lookup key go through this fold, so any spelling of the
    same host (mixed case, trailing FQDN dot, unicode dot variants,
    unicode vs punycode) lands on one key.

    Total: never raises. Returns "" for values that cannot name a
    resolvable host (``None``, non-ASCII bytes, IDNA-invalid unicode) —
    "" never appears as a pin key, so the wrapper treats it as a miss.
    """
    if host is None:
        return ""
    if isinstance(host, (bytes, bytearray)):
        try:
            text = bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return ""
    else:
        text = str(host)
    text = text.rstrip(_HOST_DOT_VARIANTS).lower()
    if not text or text.isascii():
        return text
    try:
        import idna
        return idna.encode(text, uts46=True).decode("ascii")
    except Exception:
        # IDNA2008-invalid unicode hostname: no canonical ASCII form
        # exists, so no pin can be keyed for it. Callers that VALIDATE
        # (block_private_ips) fail closed on ""; the lookup wrapper
        # falls through to live resolution, which the transport layer
        # rejects for the same reason.
        return ""


def _pinning_getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
    pins = getattr(_pin_local, "stack", None)
    if pins:
        key = _canonical_pin_host(host)
        if key:
            for mapping in reversed(pins):
                addrs = mapping.get(key)
                if addrs is not None:
                    return addrs
    return _original_getaddrinfo(host, port, *args, **kwargs)


def _shutdown_response_socket(response: requests.Response) -> None:
    """Best-effort shutdown of a streamed response's underlying socket.

    Used by the body-read watchdog: a thread blocked in ``recv`` is NOT
    woken by ``close()`` on the socket object — only ``shutdown()``
    makes the pending read return. Walks the requests -> urllib3 ->
    http.client -> SocketIO private chain defensively; when any hop is
    missing (mocked responses, future library layouts) it silently
    does nothing and the caller's ``close()`` remains the fallback.
    """
    raw = getattr(response, "raw", None)
    http_response = getattr(raw, "_fp", None)
    sock_file = getattr(http_response, "fp", None)
    sock = getattr(getattr(sock_file, "raw", None), "_sock", None)
    if sock is None:
        connection = getattr(raw, "_connection", None)
        sock = getattr(connection, "sock", None)
    if sock is not None:
        with contextlib.suppress(OSError, ValueError):
            sock.shutdown(socket.SHUT_RDWR)


def _ensure_pin_wrapper_installed() -> None:
    global _original_getaddrinfo
    with _pin_install_lock:
        if _original_getaddrinfo is None:
            _original_getaddrinfo = socket.getaddrinfo
            socket.getaddrinfo = _pinning_getaddrinfo


class WebClient:
    """Secure HTTP client for web application testing."""

    def __init__(self, base_url: str, timeout: int = 30, rate_limit: float = 0.5,
                 verify_ssl: bool = True, reveal_secrets: bool = False,
                 block_private_ips: bool = True,
                 execution_policy: "WebExecutionPolicy | None" = None) -> None:
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.rate_limit = rate_limit  # Seconds between requests
        self.last_request_time = 0.0
        # Serialises the rate limiter's check-then-set: concurrent
        # callers (e.g. the common-paths thread pool) otherwise all
        # read a stale last_request_time and burst past the limit.
        self._rate_lock = threading.Lock()
        # Monotonic count of transport-level request failures (timeouts,
        # connection errors — NOT scope refusals). Checks swallow their
        # own probe exceptions by design, which makes "target died
        # mid-scan" indistinguishable from "ran clean"; the scanner
        # diffs this counter around each check so a dead/rate-limited/
        # WAF-banned target surfaces as degraded coverage instead of a
        # clean compliant report. Per-check delta attribution assumes
        # checks run sequentially over this client (they do: both check
        # phases iterate one check at a time); concurrent client use
        # elsewhere (the discovery thread pool) happens outside any
        # check window.
        self.transport_errors = 0
        self.verify_ssl = verify_ssl
        self.reveal_secrets = reveal_secrets
        self.block_private_ips = block_private_ips
        self.execution_policy = execution_policy

        # Session for cookie management
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RAPTOR Security Scanner (Authorized Testing)',
        })

        # Loopback / private-IP scan targets are on the local segment
        # by definition — routing them through a corporate proxy
        # (requests honours proxy env; host NO_PROXY rarely covers
        # loopback) breaks every request. Disable proxy-env pickup
        # for those targets; internet targets keep trust_env so
        # mandatory-proxy hosts can reach them.
        _host = (urlparse(self.base_url).hostname or '').lower()
        _local = _host in ('localhost',)
        if not _local:
            try:
                _ip = ipaddress.ip_address(_host)
                _local = _ip.is_loopback or _ip.is_private
            except ValueError:
                pass
        if _local:
            self.session.trust_env = False
            logger.info(
                "Web client: %s is a loopback/private target — "
                "proxy env bypassed for this session", _host,
            )

        # Request history — bounded ring buffer. Pre-cap, long scans
        # accumulated full request/response dicts (hundreds of MB on
        # large targets) until process exit.
        from collections import deque
        self.request_history: deque[dict[str, Any]] = deque(
            maxlen=_MAX_REQUEST_HISTORY,
        )

        logger.info("Web client initialized for %s (verify_ssl=%s)", base_url, verify_ssl)

    def _origin(self, url: str) -> tuple[str, str, int]:
        """Return normalized (scheme, host, port) tuple for URL scope checks."""
        return origin_of(url)

    def _is_in_scope(self, url: str) -> bool:
        """Check whether URL stays within the configured base origin."""
        return self._origin(url) == self._origin(self.base_url)

    def _resolve_and_validate(self, url: str):
        """Resolve URL hostname, reject non-global IPs, return pinned addrs.

        Returns (hostname, port, addr_list) where addr_list is the
        validated getaddrinfo result, or None if validation is disabled
        or the URL uses a literal IP.  The caller pins socket.getaddrinfo
        to addr_list for the actual request, eliminating the DNS-rebinding
        TOCTOU (resolve-then-connect with a second resolution).
        """
        if not self.block_private_ips:
            return None
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return None
        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            # Not an IP literal — a hostname; resolve and validate below.
            # (Deciding this by substring-matching the exception message
            # mis-blocked any hostname whose text collided with our own
            # error wording.)
            ip_obj = None
        if ip_obj is not None:
            if not ip_obj.is_global:
                msg = (
                    f"Blocked request to non-global IP {hostname} — "
                    f"set block_private_ips=False to scan internal targets"
                )
                raise ValueError(msg)
            return None
        default_port = 443 if parsed.scheme == "https" else 80
        port = parsed.port or default_port
        # Canonicalise ONCE (IDNA2008 punycode) and use the ASCII form
        # for BOTH the validation resolution and the pin key. Resolving
        # the unicode form judged a DIFFERENT registrable domain than
        # the one the transport connects to (CPython's str-host path
        # uses the legacy IDNA2003 codec: 'faß.de' -> 'fass.de', while
        # urllib3 connects to 'xn--fa-hia.de'), and keying the pin on
        # the unicode form made it miss the socket layer's punycode
        # lookup — a live second resolution for every IDN hostname.
        pin_key = _canonical_pin_host(hostname)
        if not pin_key:
            msg = (
                f"Blocked request: hostname {hostname!r} has no valid "
                f"IDNA2008 form, so its resolution cannot be validated "
                f"or pinned"
            )
            raise ValueError(msg)
        try:
            addrs = socket.getaddrinfo(pin_key, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            msg = f"DNS resolution failed for {hostname}: {exc}"
            raise ValueError(msg) from exc
        for _family, _type, _proto, _canonname, sockaddr in addrs:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if not ip_obj.is_global:
                msg = (
                    f"DNS for {hostname} resolved to non-global IP {ip_str} — "
                    f"blocked to prevent SSRF (set block_private_ips=False "
                    f"to scan internal targets)"
                )
                raise ValueError(msg)
        return (pin_key, port, addrs)

    @staticmethod
    @contextlib.contextmanager
    def _pinned_dns(pinned):
        """Pin DNS resolution to pre-validated results for one request.

        Eliminates the DNS-rebinding TOCTOU: requests/urllib3 internally
        calls getaddrinfo, which would re-resolve the hostname. By
        returning our already-validated addresses, the connection goes
        to the IP we checked — not a rebinded one.

        The pin rides a THREAD-LOCAL stack consulted by a single
        process-wide wrapper (installed once, never removed). The old
        per-request save/patch/restore of socket.getaddrinfo raced
        under concurrent callers and could permanently leave a stale
        pinning closure installed process-wide.
        """
        if pinned is None:
            yield
            return
        hostname, _port, addrs = pinned
        _ensure_pin_wrapper_installed()
        stack = getattr(_pin_local, "stack", None)
        if stack is None:
            stack = []
            _pin_local.stack = stack
        # Same fold as the wrapper's lookup side: pin key and lookup
        # key must be computed by ONE function or they drift apart
        # (the pre-fix bug class).
        stack.append({_canonical_pin_host(hostname) or hostname: addrs})
        try:
            yield
        finally:
            stack.pop()

    def _build_url(self, path: str) -> str:
        """Build a request URL and reject paths that leave the target origin."""
        url = urljoin(self.base_url + '/', path)
        if not self._is_in_scope(url):
            msg = f"URL outside configured target scope: {url}"
            raise ValueError(msg)
        if self.execution_policy is not None:
            # Same guardrail external tools get: every live request is an
            # authorized, audited decision — not just an origin check.
            self.execution_policy.authorize(
                tool_id="raptor-http",
                url=url,
                risk="passive",
                action="http_request",
            )
        return url

    def _resolve_redirect(self, current_url: str, response: requests.Response) -> str | None:
        """Resolve and scope-check a redirect Location header."""
        location = response.headers.get('Location')
        if not location:
            return None
        next_url = urljoin(current_url, location)
        if not self._is_in_scope(next_url):
            msg = f"Blocked redirect outside configured target scope: {next_url}"
            raise ScopeRedirectBlockedError(msg, next_url)
        if self.execution_policy is not None:
            self.execution_policy.authorize(
                tool_id="raptor-http",
                url=next_url,
                risk="passive",
                action="follow_redirect",
            )
        return next_url

    def _rate_limit_wait(self) -> None:
        """Enforce rate limiting between requests.

        Reservation-based and lock-guarded: each caller atomically
        claims the next send slot, then sleeps until it. Concurrent
        threads therefore space out at the configured rate instead of
        all reading a stale ``last_request_time`` and bursting.
        """
        now = time.time()
        with self._rate_lock:
            scheduled = max(now, self.last_request_time + self.rate_limit)
            self.last_request_time = scheduled
        if scheduled > now:
            time.sleep(scheduled - now)

    def _redact_for_logging(self, value: object) -> str:
        """Apply this client's secret-redaction policy to log/display text."""
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def _log_request(self, method: str, url: str, response: requests.Response,
                     duration: float) -> None:
        """Log request details."""
        log_url = self._redact_for_logging(url)
        self.request_history.append({
            'method': method,
            'url': log_url,
            'status_code': response.status_code,
            'duration': duration,
            'content_length': len(response.content),
            'timestamp': time.time(),
        })

        logger.debug("%s %s -> %s (%.2fs)", method, log_url, response.status_code, duration)

    def _send_scoped_request(self, method: str, url: str,
                             follow_redirects: bool = True,
                             **kwargs) -> requests.Response:
        """Send a request while enforcing target scope across redirects.

        ``follow_redirects=False`` returns the FIRST response verbatim,
        including 3xx responses whose Location points off-origin — the
        redirect is observed, never fetched, so no scope check applies
        to the Location value. Checks that grade redirect targets
        (host-header poisoning, OAuth redirect_uri) need this: with
        internal following, an out-of-scope Location raises before the
        check ever sees the 3xx, structurally killing their positive
        path.
        """
        history: list[requests.Response] = []
        current_url = url
        current_method = method.upper()
        request_kwargs = dict(kwargs)

        for hop in range(_MAX_REDIRECTS + 1):
            if hop:
                # Redirect hops are real requests against the target:
                # without a per-hop wait a redirecting endpoint
                # multiplies the effective rate past the configured
                # limit exactly where targets are most fragile.
                self._rate_limit_wait()
            pinned = self._resolve_and_validate(current_url)
            with self._pinned_dns(pinned):
                response = self.session.request(
                    current_method,
                    current_url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_ssl,
                    stream=True,  # so we can size-cap before reading
                    **request_kwargs,
                )
            response.history = history[:]

            # Bound the buffered response body. requests' default is
            # unbounded; a hostile in-scope endpoint can serve multi-GB
            # responses (or chunked-encoding slowloris) and OOM the
            # scanner. Forcibly stream the body up to the cap; close
            # the connection if the upstream tries to exceed.
            if response.status_code not in _REDIRECT_STATUSES or not follow_redirects:
                self._enforce_response_cap(response)
                return response

            next_url = self._resolve_redirect(current_url, response)
            if not next_url:
                self._enforce_response_cap(response)
                return response

            # Buffer the hop body (size-capped) BEFORE closing: the
            # hop was opened with stream=True, so without a read its
            # `.content` would silently be empty for every consumer of
            # redirect-chain evidence (history[i].content). Redirect
            # bodies are typically tiny; the cap bounds the hostile
            # case. Then eagerly close the intermediate response's
            # underlying urllib3 connection back to the pool — on long
            # redirect chains an unclosed hop kept its connection
            # checked out until garbage collection and exhausted the
            # pool. After the buffered read, status_code, headers, and
            # `.content` / `.text` remain accessible on the history
            # entry.
            self._enforce_response_cap(response)
            with contextlib.suppress(*_CLOSE_ERRORS):
                response.close()

            history.append(response)
            current_url = next_url

            # Match browser/requests behavior for common redirect status codes:
            # 303 always becomes GET; 301/302 switch POST to GET.
            if response.status_code == 303 or (response.status_code in {301, 302} and current_method == 'POST'):
                current_method = 'GET'
                request_kwargs.pop('data', None)
                request_kwargs.pop('json', None)

            # Query params/body should not be replayed to redirect
            # targets. Per-call headers (including Authorization,
            # Cookie, X-API-Key) DO survive redirects — the scope
            # check above already enforces strict scheme+host+port
            # equality on every redirect target, so headers only
            # cross to same-origin endpoints. This is what
            # authenticated scanning needs: OAuth callback chains,
            # API-versioning redirects, streaming-API load-balancer
            # redirects, and cookie-based session state all require
            # the credentials to follow the redirect within the
            # configured origin.
            request_kwargs.pop('params', None)

        msg = f"Exceeded {_MAX_REDIRECTS} redirects within configured target scope"
        raise requests.exceptions.TooManyRedirects(msg)

    def _enforce_response_cap(self, response: requests.Response) -> None:
        """Read the streamed body into ``response._content`` up to
        :data:`_MAX_RESPONSE_BYTES` and within
        :data:`_MAX_BODY_READ_SECONDS`. If the body exceeds either
        bound, truncate and close the connection — the caller sees a
        body capped near the byte limit (it may overshoot by up to one
        64 KiB read chunk) rather than the process OOMing on a hostile
        multi-GB response, and a drip-fed body (each read succeeding
        inside the per-read socket timeout, forever) hands back what
        arrived instead of stalling the scan pipeline.
        """
        chunks: list[bytes] = []
        # Watchdog, not an in-loop clock check: a dripping server keeps
        # the SINGLE blocking read inside iter_content alive (each byte
        # restarts the per-recv socket timeout and the buffered read
        # does not yield until its chunk fills), so loop-body code
        # never runs while the stall lasts. Closing the response from
        # the timer thread unblocks the read; the buffered prefix is
        # kept.
        expired = threading.Event()

        def _expire() -> None:
            expired.set()
            # shutdown() BEFORE close(): closing a socket object does
            # not wake a thread blocked in recv on it — shutdown does
            # (the read returns EOF immediately).
            _shutdown_response_socket(response)
            with contextlib.suppress(*_CLOSE_ERRORS):
                response.close()

        watchdog = threading.Timer(_MAX_BODY_READ_SECONDS, _expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            total = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= _MAX_RESPONSE_BYTES:
                    logger.warning(
                        "WebClient: response body exceeded %d-byte cap "
                        "at %s; truncating",
                        _MAX_RESPONSE_BYTES,
                        self._redact_for_logging(response.url or "<unknown>"),
                    )
                    with contextlib.suppress(*_CLOSE_ERRORS):
                        response.close()
                    break
            response._content = b"".join(chunks)
        except (requests.exceptions.RequestException, *_CLOSE_ERRORS,
                ValueError):
            # Let the caller see whatever was buffered; do not raise
            # from the cap-enforcer. The extra classes are what the
            # watchdog's close() makes the blocked read raise
            # (protocol errors, closed-file ValueError).
            response._content = b"".join(chunks) if chunks else b""
        finally:
            watchdog.cancel()
            if expired.is_set():
                logger.warning(
                    "WebClient: response body still streaming after "
                    "%.0fs at %s; truncated (drip-fed/slowloris shape)",
                    _MAX_BODY_READ_SECONDS,
                    self._redact_for_logging(response.url or "<unknown>"),
                )

    def get(self, path: str, params: dict | None = None,
            headers: dict | None = None,
            allow_redirects: bool = True) -> requests.Response:
        """Send GET request.

        ``allow_redirects=False`` returns the first response even when
        it is a 3xx with an off-origin Location (observed, not
        followed) — see ``_send_scoped_request``.
        """
        self._rate_limit_wait()

        url = self._build_url(path)
        start_time = time.time()

        try:
            response = self._send_scoped_request(
                'GET',
                url,
                follow_redirects=allow_redirects,
                params=params,
                headers=headers or {},
            )

            duration = time.time() - start_time
            self._log_request('GET', response.url or url, response, duration)

            return response

        except requests.exceptions.Timeout:
            self.transport_errors += 1
            logger.warning("Timeout on GET %s", self._redact_for_logging(url))
            raise
        except requests.exceptions.RequestException as e:
            self.transport_errors += 1
            logger.error("Request failed: %s", self._redact_for_logging(e))
            raise

    def post(self, path: str, data: dict | None = None,
             json_data: dict | None = None,
             headers: dict | None = None,
             allow_redirects: bool = True) -> requests.Response:
        """Send POST request."""
        self._rate_limit_wait()

        url = self._build_url(path)
        start_time = time.time()

        try:
            response = self._send_scoped_request(
                'POST',
                url,
                follow_redirects=allow_redirects,
                data=data,
                json=json_data,
                headers=headers or {},
            )

            duration = time.time() - start_time
            self._log_request('POST', response.url or url, response, duration)

            return response

        except requests.exceptions.RequestException as e:
            self.transport_errors += 1
            logger.error("POST request failed: %s", self._redact_for_logging(e))
            raise

    def set_auth(self, username: str, password: str) -> None:
        """Set basic authentication."""
        self.session.auth = (username, password)
        logger.info("Authentication set for user: %s", username)

    def set_bearer_token(self, token: str) -> None:
        """Set bearer token authentication."""
        self.session.headers['Authorization'] = f'Bearer {token}'
        logger.info("Bearer token authentication configured")

    def get_cookies(self) -> dict[str, str]:
        """Get current session cookies."""
        return {
            name: value
            for name, value in self.session.cookies.get_dict().items()
            if value is not None
        }

    def set_cookies(self, cookies: dict[str, str]) -> None:
        """Set session cookies."""
        self.session.cookies.update(cookies)

    def get_stats(self) -> dict[str, Any]:
        """Get request statistics."""
        if not self.request_history:
            return {}

        total_requests = len(self.request_history)
        total_duration = sum(r['duration'] for r in self.request_history)
        status_codes: dict[int, int] = {}

        for req in self.request_history:
            code = req['status_code']
            status_codes[code] = status_codes.get(code, 0) + 1

        return {
            'total_requests': total_requests,
            'total_duration': total_duration,
            'avg_duration': total_duration / total_requests if total_requests > 0 else 0,
            'status_codes': status_codes,
        }

    def close(self) -> None:
        """Close the underlying ``requests.Session`` and free its
        connection pool. Idempotent.

        Without this, long-lived scanner processes that instantiate
        ``WebClient`` per target accumulate one urllib3 connection
        pool (sockets + SSL contexts) per scan until process exit.
        """
        with contextlib.suppress(*_CLOSE_ERRORS):
            self.session.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()
