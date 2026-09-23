"""CISA Known-Exploited Vulnerabilities (KEV) lookup.

The full KEV catalog is one ~150 KB JSON document fetched from CISA. We
download it once per run (24h cache), build an in-memory set of
exploited CVE IDs, and answer ``contains(cve_id)`` in O(1).

Failure modes:
  * Network down + cold cache → ``KevClient.is_loaded()`` is False;
    ``contains`` always returns False (degraded but harmless: KEV is a
    bonus signal layered on top of any underlying CVE match).
  * Stale cache + offline (or the refresh fetch fails) → load the
    stale cache anyway, with a loud warning; the KEV list rarely
    changes day-to-day. Only catalogs written by this client are
    eligible (they carry a no-expiry envelope the stale arm can
    re-read); a legacy finite-TTL envelope re-serves after one
    online refresh.

Originally written for ``packages/sca`` — lifted to ``core/cve`` so other
consumers (``/agentic`` finding ranking, ``/validate`` Stage D severity,
``/exploit`` prioritisation, SARIF report badges) can layer the
KEV-listed flag on any CVE-tagged finding.
"""

from __future__ import annotations

import logging

from core.http import HttpClient, HttpError
from core.json import MISSING, TTL_FOREVER
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from core.json import JsonCache

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_DEFAULT_TTL = 24 * 3600
_CACHE_KEY = "kev"


class KevClient:
    """In-memory KEV lookup; lazy-loads on first call.

    Caller-supplied ``HttpClient`` (so tests inject a stub) and
    ``JsonCache`` (for the 24h catalog persistence). ``offline=True``
    suppresses the network — fresh-cache load still succeeds; cold
    cache leaves ``contains`` returning False.
    """

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache,
        *,
        offline: bool = False,
        ttl_seconds: int = _DEFAULT_TTL,
    ) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline
        self._ttl = ttl_seconds
        self._loaded = False
        self._cve_set: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def contains(self, cve_id: str) -> bool:
        """True if ``cve_id`` is in CISA's KEV list (case-insensitive)."""
        if not cve_id:
            return False
        if not self._loaded:
            self._load()
        return cve_id.upper() in self._cve_set

    def is_loaded(self) -> bool:
        return self._loaded

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        record = self._cache.get(_CACHE_KEY, ttl_seconds=self._ttl)
        if record is not None and not _extract_cves(record):
            # A cached envelope that is not catalog-shaped predates
            # the shape gate below (or was hand-corrupted) — evict it
            # and treat this as a cache miss so a real catalog can be
            # fetched instead of serving an empty signal.
            self._cache.invalidate(_CACHE_KEY)
            record = None
        if record is None and not self._offline:
            try:
                record = self._http.get_json(KEV_URL)
            except HttpError as e:
                record = self._stale_cached_catalog()
                if record is None:
                    logger.warning(
                        "core.cve.kev: fetch failed (%s); KEV unavailable", e,
                    )
                    self._loaded = True
                    return
                logger.warning(
                    "core.cve.kev: fetch failed (%s); serving the stale "
                    "cached catalog — the KEV list rarely changes "
                    "day-to-day", e,
                )
            else:
                if _extract_cves(record):
                    # Stored with TTL_FOREVER so the stale-if-offline
                    # arm can re-read past the freshness window
                    # (JsonCache honours min(stored, caller) TTL); the
                    # ordinary load above still enforces day-to-day
                    # freshness via the caller-side TTL.
                    self._cache.put(
                        _CACHE_KEY, record, ttl_seconds=TTL_FOREVER,
                    )
                else:
                    # A 200 whose body carries no CVE entries is not a
                    # KEV catalog (CDN/proxy error page shaped as JSON,
                    # hostile feed — the real catalog has 1000+
                    # entries). Storing it with TTL_FOREVER would make
                    # one junk fetch the eternal "catalog" the stale
                    # arm re-serves on every later failure, with
                    # is_loaded() True hiding the loss. Same epistemic
                    # state as a failed fetch: never cached, stale real
                    # catalog preferred.
                    stale = self._stale_cached_catalog()
                    if stale is None:
                        logger.warning(
                            "core.cve.kev: fetch returned a non-catalog "
                            "payload; KEV unavailable",
                        )
                        self._loaded = True
                        return
                    logger.warning(
                        "core.cve.kev: fetch returned a non-catalog "
                        "payload; serving the stale cached catalog",
                    )
                    record = stale
        elif record is None:
            # Offline + fresh-cache miss: a stale catalog beats
            # silently answering False for everything (an offline
            # scan would otherwise lose the KEV signal entirely and
            # --fail-on-kev could never fire).
            record = self._stale_cached_catalog()
            if record is not None:
                logger.warning(
                    "core.cve.kev: offline with a stale cached catalog "
                    "— serving it anyway; the KEV list rarely changes "
                    "day-to-day",
                )
        if record is None:
            # Cold cache and no way to fetch.
            self._loaded = True
            return

        self._cve_set = _extract_cves(record)
        self._loaded = True

    def _stale_cached_catalog(self) -> dict[str, Any] | None:
        """Best-effort re-read of the cached catalog IGNORING freshness.

        Only envelopes written by this client (TTL_FOREVER) are
        eligible: ``JsonCache`` honours the minimum of the caller and
        stored TTLs, so a legacy finite-TTL envelope stays expired and
        re-serves only after one successful online refresh. Catalog-
        shape-invalid payloads (a junk entry written before the shape
        gate at the cache write) are refused — degraded-unavailable is
        honest; "serving the stale cached catalog" over junk is not.
        """
        value = self._cache.try_get(_CACHE_KEY, ttl_seconds=TTL_FOREVER)
        if value is MISSING or not _extract_cves(value):
            return None
        return value


def _extract_cves(record: object) -> set[str]:
    """Pull the CVE-id set from a KEV catalog payload.

    Schema (relevant slice): ``{"vulnerabilities": [{"cveID": "CVE-..."},
    ...]}``. Anything else is silently ignored; a corrupt feed yields an
    empty set rather than a crash.
    """
    if not isinstance(record, dict):
        return set()
    vulns = record.get("vulnerabilities")
    if not isinstance(vulns, list):
        return set()
    out: set[str] = set()
    for entry in vulns:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cveID") or entry.get("cve_id")
        if isinstance(cve, str) and cve:
            out.add(cve.upper())
    return out


__all__ = ["KEV_URL", "KevClient"]
