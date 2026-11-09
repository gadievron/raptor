"""Opt-in, anonymous HTTPS reads restricted to exact caller-declared origins.

This client owns a fresh EgressClient, never a browser or authenticated
session. It has no cookie jar, accepts only a small set of request headers,
and returns redirects without following them. The existing egress proxy
owns address validation and upstream-proxy routing; no direct fallback or
environment mutation is introduced here.

The caller owns asset types, redirect policy, budget choices, receipts
and browser integration. Response headers are returned unchanged: consumers
which fulfil a browser request must decide which response headers to copy.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import threading
from typing import Self

from urllib3.exceptions import LocationParseError
from urllib3.util import parse_url

from core.http import DEFAULT_TIMEOUT, DEFAULT_TOTAL_TIMEOUT, HttpError, NotModified, Response, SizeLimitExceeded
from core.http.egress_backend import EgressClient

Origin = tuple[str, str, int]
_REQUEST_HEADERS = frozenset({
    "accept", "accept-language", "if-none-match", "if-modified-since", "range",
})


def _origin(url: str, *, declaration: bool = False) -> Origin:
    # Reject controls before a URL parser can discard or normalise them.
    if not isinstance(url, str) or not url or len(url) > 65536 or any(
        ord(character) <= 32 or ord(character) == 127 for character in url
    ):
        raise ValueError("expected an absolute HTTPS URL without whitespace or controls")
    # Inspect the authority before urllib3 normalises percent-escaped hosts
    # or treats a backslash as a path separator (behaviour differs by version).
    authority = url.partition("://")[2].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "%" in authority or "\\" in authority:
        raise ValueError("origin must name one exact host")
    try:
        parsed = parse_url(url)
    except (LocationParseError, ValueError):
        raise ValueError("invalid HTTPS URL") from None
    if parsed.scheme != "https" or not parsed.host or parsed.auth is not None:
        raise ValueError("expected an absolute HTTPS URL without embedded credentials")
    host = parsed.host.removeprefix("[").removesuffix("]")
    if any(character in host for character in ("%", "\\", "*")):
        raise ValueError("origin must name one exact host")
    port = 443 if parsed.port is None else parsed.port
    if not 1 <= port <= 65535:
        raise ValueError("origin port must be between 1 and 65535")
    if declaration and (
        parsed.path not in (None, "", "/")
        or parsed.query is not None or parsed.fragment is not None
    ):
        raise ValueError("declare an origin without a path, query or fragment")
    return "https", host, port


def _positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


class AnonymousOriginClient:
    """Read-only, credential-free requests to an immutable set of HTTPS origins.

    ``max_bytes`` is a required per-response cap. Requests have no automatic
    retries and never follow redirects; callers re-authorise each hop by
    making another request. Body bytes preserve Content-Encoding so a browser
    consumer can retain that header without double-decoding the response.

    ``max_requests`` and ``max_total_bytes`` are optional lifetime budgets;
    callers handling hostile pages should choose both explicitly. Concurrent
    reads reserve bytes before transport work and fail fast if the available
    budget is already reserved. Failed reads conservatively consume their
    reservation. These bounds do not include a renderer's decoded memory.

    Exact origins are an application-layer boundary. The process-wide proxy
    still has its documented union-of-hosts semantics; this is not a sandbox
    lane or a new kernel containment boundary. Close only after all users
    have finished; concurrent close/request is unsupported.
    """

    def __init__(
        self,
        allowed_origins: Iterable[str],
        *,
        max_bytes: int,
        timeout: int = DEFAULT_TIMEOUT,
        total_timeout: int = DEFAULT_TOTAL_TIMEOUT,
        max_requests: int | None = None,
        max_total_bytes: int | None = None,
    ) -> None:
        if isinstance(allowed_origins, (str, bytes)):
            raise ValueError("allowed_origins must be an iterable of origin URLs")
        origins = frozenset(_origin(url, declaration=True) for url in allowed_origins)
        if not origins:
            raise ValueError("at least one exact HTTPS origin is required")
        _positive_integer(max_bytes, "max_bytes")
        _positive_integer(timeout, "timeout")
        _positive_integer(total_timeout, "total_timeout")
        if timeout > threading.TIMEOUT_MAX or total_timeout > threading.TIMEOUT_MAX:
            raise ValueError("timeout exceeds the platform's supported wait interval")
        if max_requests is not None:
            _positive_integer(max_requests, "max_requests")
        if max_total_bytes is not None:
            _positive_integer(max_total_bytes, "max_total_bytes")
        self._origins = origins
        self._max_bytes = max_bytes
        self._timeout = timeout
        self._total_timeout = total_timeout
        self._closed = False
        self._budget_lock = threading.Lock()
        self._max_requests = max_requests
        self._remaining_bytes = max_total_bytes
        self._requests = 0
        self._accounted_bytes = 0
        self._reserved_bytes = 0
        # Validate every declaration and limit before registering proxy hosts.
        self._client = EgressClient(sorted({host for _, host, _ in origins}))

    @property
    def allowed_origins(self) -> frozenset[Origin]:
        """Canonical permissions for callers to record separately from scan scope."""
        return self._origins

    @property
    def usage(self) -> dict[str, int]:
        """Snapshot requests, accounted body bytes and in-flight reservations.

        Failed requests consume their reservation because their partial body
        length is unknown. NotModified consumes a request slot but no body
        bytes. This conservative body budget is not a count of
        wire bytes, TLS overhead or decompressed browser memory.
        """
        with self._budget_lock:
            return {
                "requests": self._requests,
                "accounted_bytes": self._accounted_bytes,
                "reserved_bytes": self._reserved_bytes,
            }

    def request(
        self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
    ) -> Response:
        """Return one bounded response, including 3xx and HTTP error responses.

        The backend's existing NotModified signal for HTTP 304 is preserved.
        Unknown headers are refused rather than silently dropping credentials.
        """
        if self._closed:
            raise HttpError("anonymous origin client is closed")
        if method not in ("GET", "HEAD"):
            raise HttpError("anonymous origin client permits only GET and HEAD")
        try:
            origin = _origin(url)
        except ValueError:
            raise HttpError("invalid anonymous request URL") from None
        if origin not in self._origins:
            raise HttpError("request origin is outside the declared permissions")
        selected = {"accept-encoding": "identity"}
        for name, value in (headers or {}).items():
            if not isinstance(name, str) or name.lower() not in _REQUEST_HEADERS:
                raise HttpError("request header is not permitted for anonymous reads")
            if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise HttpError("invalid anonymous request header value")
            key = name.lower()
            if key in selected:
                raise HttpError("duplicate anonymous request header")
            selected[key] = value
        with self._budget_lock:
            if self._max_requests is not None and self._requests >= self._max_requests:
                raise HttpError("anonymous request-count budget exhausted")
            cap = 0 if method == "HEAD" else self._max_bytes
            if self._remaining_bytes is not None:
                cap = min(cap, self._remaining_bytes)
                if cap == 0 and method != "HEAD":
                    raise HttpError("anonymous response-byte budget exhausted")
                self._remaining_bytes -= cap
            self._requests += 1
            self._reserved_bytes += cap
        charged = cap
        try:
            result = self._client.request(
                method, url, headers=selected,
                max_bytes=cap, timeout=self._timeout,
                total_timeout=self._total_timeout,
                retries=0, follow_redirects=False, raise_on_status=False,
            )
            if len(result.body) > cap:
                raise SizeLimitExceeded("anonymous response exceeded its reserved body budget")
            try:
                result_origin = _origin(result.url)
            except ValueError:
                raise HttpError("anonymous response has an invalid origin") from None
            if result_origin != origin:
                raise HttpError("anonymous response unexpectedly changed origin")
            charged = len(result.body)
            return result
        except NotModified:
            charged = 0
            raise
        finally:
            with self._budget_lock:
                self._reserved_bytes -= cap
                self._accounted_bytes += charged
                if self._remaining_bytes is not None:
                    self._remaining_bytes += cap - charged

    def close(self) -> None:
        """Release this client's connection pool, leaving the shared proxy running."""
        self._closed = True
        self._client.close()

    def __enter__(self) -> Self:
        if self._closed:
            raise HttpError("anonymous origin client is closed")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
