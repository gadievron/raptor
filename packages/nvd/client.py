"""NVD API v2.0 client with retry and caching.

Fetches CVE records from the NVD REST API.  Supports:

- Per-process in-memory cache + optional disk cache via
  :class:`core.json.cache.JsonCache`
- Exponential backoff on 429 (NVD public quota: 5 req / 30 s)
- Optional ``NVD_API_KEY`` environment variable for higher rate limits
- Pluggable ``on_rate_limit`` callback for telemetry / status reporting
"""

from __future__ import annotations

import functools
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING
from urllib.parse import quote

from core.http import HttpError
from core.http.urllib_backend import UrllibClient
from core.json.cache import JsonCache
from core.run.retry import RetryPolicy, retry_call

if TYPE_CHECKING:
    from collections.abc import Callable

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "cve-diff" / "nvd"
DEFAULT_TIMEOUT_S = 30

_CACHE_TTL = 86400 * 7  # 7 days
_RETRY_MAX = 4
_RETRY_BASE_S = 1.0

# NVD API keys are RFC 4122 UUID strings — `xxxxxxxx-xxxx-
# xxxx-xxxx-xxxxxxxxxxxx`. Used to validate operator-supplied
# NVD_API_KEY before sending; placeholder strings like
# `"YOUR_KEY_HERE"` get rejected at validation rather than
# triggering 401/403 retry storms.
_NVD_KEY_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)

_NVD_CACHE_MISSING: dict[str, str] = {"_sentinel": "nvd_missing"}

# In-process marker for a TRANSIENT lookup failure (quota exhaustion,
# outage, network error). Distinct from a definitive miss so callers
# minting verdicts can tell "NVD says this CVE does not exist" apart
# from "the lookup failed". Never written to the disk cache.
_NVD_TRANSIENT_MISS: dict[str, str] = {"_sentinel": "nvd_transient"}


class NvdLookupError(Exception):
    """A per-CVE lookup failed for a NON-definitive reason.

    Raised (opt-in, see :meth:`NvdClient.get_payload`) for network
    failures, quota exhaustion, and non-resource-missing HTTP errors —
    everything where "NVD has no record" would be the wrong conclusion.
    A definitive miss (4xx resource-missing classes) stays ``None``:
    that IS NVD's authoritative "no such record".

    Never disk-cached: transient failures are remembered in-process
    only, so an outage can't be replayed as an authoritative answer.
    """

# CVE ids are `CVE-<year>-<4+ digits>`. `cve_id` values reach this
# client from advisory-derived data, not just operator input — validate
# the shape before the value joins a cache key or the request URL, so a
# crafted "id" can't smuggle extra query parameters, path separators,
# or control bytes into either. ``re.ASCII`` pins ``\d`` to 0-9 (keep
# in sync with the core/cve epss / vulnrichment / cwe regexes) — a
# non-ASCII decimal digit would otherwise mint a junk cache key and
# URL. ``\A..\Z`` instead of ``^..$``: ``$`` tolerates a trailing
# newline (regex hygiene; ``get_payload`` strips before matching).
_CVE_ID_RE = re.compile(r"\ACVE-\d{4}-\d{4,}\Z", re.IGNORECASE | re.ASCII)

_SENTINEL_USE_DEFAULT = object()


@functools.lru_cache(maxsize=1)
def _default_http() -> UrllibClient:
    return UrllibClient(user_agent="raptor-nvd/0.1")


@dataclass
class NvdClient:
    """Thin client over the NVD v2.0 ``/cves`` endpoint.

    ``on_rate_limit`` is called (no args) each time a 429 is received,
    before sleeping for the retry delay.  Consumers that track API health
    (e.g. ``cve_diff.infra.api_status``) can plug in here without the
    shared client depending on them.
    """

    timeout_s: int = DEFAULT_TIMEOUT_S
    cache_enabled: bool = True
    disk_cache_dir: Path | None = field(default=_SENTINEL_USE_DEFAULT)  # type: ignore[assignment]
    on_rate_limit: Callable[[], None] | None = None
    _cache: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    _disk: JsonCache | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.disk_cache_dir is _SENTINEL_USE_DEFAULT:
            self.disk_cache_dir = DEFAULT_CACHE_DIR
        if self.cache_enabled and self.disk_cache_dir is not None and self._disk is None:
            self._disk = JsonCache(self.disk_cache_dir)

    def get_payload(
        self, cve_id: str, *, raise_on_transient: bool = False,
    ) -> dict[str, Any] | None:
        """Return the full NVD 2.0 JSON for *cve_id*, or ``None``.

        With ``raise_on_transient=True``, non-definitive failures
        (network error, quota exhaustion, non-resource-missing HTTP
        errors) raise :class:`NvdLookupError` instead of degrading to
        ``None`` — callers minting verdicts must not read a transient
        outage as "NVD has no record". The default keeps the historical
        swallow-to-``None`` shape for aggregating callers.
        """
        cve_id = (cve_id or "").strip()
        if not _CVE_ID_RE.match(cve_id):
            # Not a CVE id — never let the value reach the cache keys
            # or the request URL. Definitive: the id shape itself is
            # wrong, retrying can't help.
            return None
        # Case-fold AFTER the shape check: CVE ids are case-
        # insensitive, and raw-case keys split both the in-memory and
        # 7-day disk caches — duplicate fetches against NVD's public
        # 5-req/30s quota, and a definitive miss negative-cached under
        # one spelling only. Same normalisation as the core/cve
        # sibling clients.
        cve_id = cve_id.upper()
        if self.cache_enabled and cve_id in self._cache:
            hit = self._cache[cve_id]
            if hit is _NVD_TRANSIENT_MISS:
                if raise_on_transient:
                    msg = f"NVD lookup for {cve_id} failed earlier this run (transient)"
                    raise NvdLookupError(msg)
                return None
            return hit
        if self.cache_enabled and self._disk is not None:
            hit = self._disk.get(f"nvd/{cve_id}", ttl_seconds=_CACHE_TTL)
            if hit is not None:
                payload = None if hit == _NVD_CACHE_MISSING else hit
                self._cache[cve_id] = payload
                return payload
        payload, definitive = self._fetch_with_retry(cve_id)
        if self.cache_enabled:
            if payload is not None or definitive:
                self._cache[cve_id] = payload
                if self._disk is not None:
                    value = payload if payload is not None else _NVD_CACHE_MISSING
                    self._disk.put(f"nvd/{cve_id}", value, ttl_seconds=_CACHE_TTL)
            else:
                # Transient failure (quota exhaustion, outage, network
                # error): remember only in-process so one batch doesn't
                # hammer a downed NVD, but never write the 7-day disk
                # sentinel — that would misreport the CVE as nonexistent
                # to every later run sharing the cache until TTL expiry.
                self._cache[cve_id] = _NVD_TRANSIENT_MISS
        if payload is None and not definitive and raise_on_transient:
            msg = f"NVD lookup for {cve_id} failed (transient)"
            raise NvdLookupError(msg)
        return payload

    def _fetch_with_retry(self, cve_id: str) -> tuple[dict[str, Any] | None, bool]:
        """Fetch *cve_id*; return ``(payload, definitive)``.

        ``definitive`` is True when a ``None`` payload means "NVD says
        this does not exist" (4xx resource-missing classes) rather than
        "the lookup failed" (rate limit, outage, network error, mangled
        body) — only definitive misses may be negative-cached.
        """
        # API key validation. Pre-fix any non-empty NVD_API_KEY
        # was sent verbatim — placeholders (`"must-set-this-please"`,
        # `"YOUR_KEY_HERE"`, copy-paste with leading whitespace
        # already stripped but trailing junk preserved) reached
        # the server, were rejected with 401/403, and the
        # operator saw "no NVD result" without knowing the key
        # was malformed. NVD API keys are 36-char UUIDs
        # (8-4-4-4-12 hex with hyphens). Reject obvious
        # placeholders silently — empty header is better than
        # invalid header (the latter triggers 403 retries that
        # exhaust the budget).
        api_key = os.environ.get("NVD_API_KEY", "").strip()
        if api_key and not _NVD_KEY_RE.match(api_key):
            api_key = ""
        headers = {"apiKey": api_key} if api_key else {}
        # get_payload validated the id shape; percent-encode anyway
        # (mirrors the OSV client) so the value can never terminate the
        # query parameter early.
        url = f"{BASE_URL}?cveId={quote(cve_id, safe='')}"

        # Transient = 429 (NVD quota) or 5xx, whether raised as
        # HttpError or returned as an error-status response. 502/503/
        # 504 retry like 429 — a brief NVD outage should not fail a
        # whole CVE-diff batch. Everything else (404, auth) surfaces
        # immediately. The transport's own retries stay disabled
        # (retries=0) so the policy here is the only one.
        def _attempt():
            try:
                return _default_http().request(
                    "GET", url, headers=headers,
                    timeout=self.timeout_s, retries=0,
                )
            except HttpError as exc:
                if (exc.status or 0) == 429 and self.on_rate_limit is not None:
                    # Every 429 counts for telemetry, retried or not.
                    self.on_rate_limit()
                raise

        def _is_transient(exc: Exception) -> bool:
            status = getattr(exc, "status", None) or 0
            return status == 429 or 500 <= status < 600

        def _honour_retry_after(exc: Exception, scheduled: float) -> float:
            if getattr(exc, "status", None) == 429:
                return max(float(getattr(exc, "retry_after", None) or 0),
                           scheduled)
            return scheduled

        policy = RetryPolicy(
            attempts=_RETRY_MAX + 1,
            retryable=_is_transient,
            base_delay=_RETRY_BASE_S,
            multiplier=2.0,
        )
        try:
            resp = retry_call(
                _attempt,
                policy=policy,
                retry_result=lambda r: 500 <= r.status < 600,
                delay_override=_honour_retry_after,
            )
        except HttpError as exc:
            # 400/404/410 are the server's answer ("no such resource") —
            # definitive. Anything else (429 retry exhaustion, 403
            # auth/quota, 5xx, status-less network errors) is transient.
            return None, (exc.status or 0) in (400, 404, 410)
        if resp.status != 200:
            return None, False
        try:
            # Response.json raises HttpError on a non-JSON body — a
            # proxy error page, not an NVD answer: transient.
            return resp.json(), True
        except HttpError:
            return None, False
