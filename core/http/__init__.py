"""HTTP client interface — single chokepoint for outbound HTTP from RAPTOR.

Two backends ship today:

  - :class:`~core.http.urllib_backend.UrllibClient` — urllib3-backed
    with connection pooling, bounded size, gzip-decompress, and
    exponential backoff. No host allowlist; reaches anywhere. Use
    only where the egress proxy isn't appropriate (tests, dev paths
    without sandbox).

  - :class:`~core.http.egress_backend.EgressClient` — routes via the
    in-process HTTPS proxy at ``core.sandbox.proxy``. Hostname
    allowlist enforced by the proxy; refuses CONNECT to anything
    outside the registered hosts. Use this for any production HTTP
    call where the threat model includes "compromised parser
    exfiltrates to attacker host".

Callers depend on the :class:`HttpClient` Protocol only — concrete
backend swap is one factory call, no consumer churn.

Constants below are defaults. Callers may override per-call timeouts
and per-call max_bytes; the user-agent is fixed at client construction
(``UrllibClient(user_agent=...)``) but not per-call.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Mapping, Optional, Protocol

# Default size limits — caps protect parser code paths from decompression
# bombs and pathological response shapes.
DEFAULT_MAX_BYTES = 50 * 1024 * 1024   # 50MB; covers wheels and source archives
DEFAULT_TIMEOUT = 30                   # seconds (per-attempt connect+read)
DEFAULT_TOTAL_TIMEOUT = 600            # seconds (whole-call deadline incl retries)
# Default count of retries beyond the first attempt — i.e. the default
# call makes up to (1 + DEFAULT_RETRIES) total attempts. Sized so the
# default exactly fills the urllib backend's backoff schedule (one slot
# per attempt, including the initial). Kept here (not in the backend)
# so the Protocol signature doesn't drift when the schedule is retuned.
# Backends MUST cap the effective attempt count at their own schedule
# length, and the urllib backend asserts the relationship at import.
DEFAULT_RETRIES = 5
DEFAULT_USER_AGENT = "raptor/0.1 (+https://github.com/gadievron/raptor)"


class HttpError(Exception):
    """Raised when an HTTP call fails after retries."""

    def __init__(
        self,
        message: str,
        status: Optional[int] = None,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        # Seconds the server asked us to wait (Retry-After header). The
        # backend's retry loop reads this when honouring 429/503; None
        # means "no Retry-After advertised, use our backoff schedule".
        self.retry_after = retry_after


class SizeLimitExceeded(HttpError):
    """Raised when a response exceeds max_bytes before we finish reading."""


@dataclass(frozen=True)
class Response:
    """Lightweight HTTP response wrapper.

    Returned by the low-level :meth:`HttpClient.request` and used
    internally by the JSON/bytes convenience methods. Bridges between
    consumer code and the underlying urllib3 response so callers don't
    depend on urllib3 types directly.

    Use the convenience methods (``get_json``, ``post_json``,
    ``get_bytes``) when you only need the body. Drop down to
    ``request()`` when you need response headers — typical case is
    capturing ``ETag`` / ``Last-Modified`` for a subsequent
    conditional request via ``If-None-Match`` / ``If-Modified-Since``.

    Header keys are **lowercased on storage** so callers can do
    ``resp.headers["etag"]`` regardless of how the server cased it.
    Servers send mixed case (``ETag``, ``Etag``, ``etag``); the
    HTTP spec says headers are case-insensitive, and forcing one
    casing keeps caller code simple.

    ``url`` is the final URL after any redirects (or the request URL
    if redirects were disabled / the backend couldn't determine the
    final URL).
    """

    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str

    def json(self) -> Any:
        """Parse body as JSON. Raises HttpError on parse failure."""
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise HttpError(f"Response is not valid JSON: {e}") from e


class NotModified(HttpError):
    """Raised when a server returns 304 Not Modified.

    Use with conditional requests — pass ``If-None-Match`` (with a
    cached ETag) or ``If-Modified-Since`` (with a cached Last-Modified
    timestamp) via the ``headers`` kwarg, then catch this exception to
    fall back to your cached value:

        try:
            data = client.get_json(
                url, headers={"If-None-Match": cached_etag},
            )
            store(url, data)
        except NotModified:
            data = cache[url]   # still fresh

    Bandwidth + latency win for resources that change rarely (KEV feed,
    EPSS data, GitHub raw files). Status is always 304.
    """

    def __init__(self, message: str = "304 Not Modified") -> None:
        super().__init__(message, status=304)


class HttpClient(Protocol):
    """Interface every HTTP-using module in RAPTOR depends on.

    Callers type-hint this Protocol so the concrete backend can be
    swapped (UrllibClient ↔ EgressClient ↔ test mock) with no
    consumer-side changes.

    All methods accept these adoption-friendly kwargs:

      - ``headers``: caller-supplied headers (e.g. Authorization,
        If-None-Match, Accept-Language). Merged with backend defaults.
      - ``retries``: maximum **additional** attempts after the first,
        on transient errors (429, 5xx, network). ``retries=0`` for
        fail-fast / non-idempotent POSTs / health probes. Backends
        cap the effective attempt count at their own backoff
        schedule length, so values larger than the schedule are
        silently equivalent to "use the whole schedule".
      - ``follow_redirects``: True (default) follows up to 10 redirects;
        False surfaces 3xx as ``HttpError`` for caller inspection.
      - ``total_timeout``: wall-clock cap on the whole retry loop in
        seconds (default 600).
    """

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
    ) -> "Response":
        """Low-level request — returns :class:`Response` with status, headers, body.

        Use for arbitrary HTTP methods (DELETE/PUT/PATCH/HEAD) and when
        response metadata (ETag, Last-Modified) is needed for the next
        conditional request.
        """
        ...

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
        """POST ``body`` as JSON, return decoded JSON response."""
        ...

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
        """GET ``url``, parse response as JSON."""
        ...

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
        """GET ``url``, return raw bytes capped at ``max_bytes``."""
        ...

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
        """GET ``url``, yield body chunks without buffering the whole response.

        Single attempt — ``retries`` is accepted for API symmetry but
        non-zero values raise :class:`ValueError` (mid-stream failures
        aren't transparently resumable). Cumulative size cap is
        enforced across yielded chunks; exceeding ``max_bytes`` raises
        :class:`SizeLimitExceeded` mid-stream.
        """
        ...


def default_client(
    allowed_hosts: Optional[List[str]] = None,
) -> HttpClient:
    """Construct the right HttpClient backend for the caller.

    - ``allowed_hosts=None`` (default) → :class:`UrllibClient`.
      No allowlist, unrestricted. For tests + paths where the
      sandbox proxy is unavailable.

    - ``allowed_hosts=[...]`` → :class:`EgressClient`. Routes through
      the in-process egress proxy with the given hosts on its
      allowlist. Production paths SHOULD pass an allowlist.
    """
    if allowed_hosts is not None:
        from core.http.egress_backend import EgressClient
        return EgressClient(allowed_hosts)
    from core.http.urllib_backend import UrllibClient
    return UrllibClient()


__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_RETRIES",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TOTAL_TIMEOUT",
    "DEFAULT_USER_AGENT",
    "HttpClient",
    "HttpError",
    "NotModified",
    "Response",
    "SizeLimitExceeded",
    "default_client",
]
