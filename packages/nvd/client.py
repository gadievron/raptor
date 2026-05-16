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
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.http import HttpError
from core.http.urllib_backend import UrllibClient
from core.json.cache import JsonCache

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

    def get_payload(self, cve_id: str) -> dict[str, Any] | None:
        """Return the full NVD 2.0 JSON for *cve_id*, or ``None``."""
        if self.cache_enabled and cve_id in self._cache:
            return self._cache[cve_id]
        if self.cache_enabled and self._disk is not None:
            hit = self._disk.get(f"nvd/{cve_id}", ttl_seconds=_CACHE_TTL)
            if hit is not None:
                payload = None if hit == _NVD_CACHE_MISSING else hit
                self._cache[cve_id] = payload
                return payload
        payload = self._fetch_with_retry(cve_id)
        if self.cache_enabled:
            self._cache[cve_id] = payload
            if self._disk is not None:
                value = payload if payload is not None else _NVD_CACHE_MISSING
                self._disk.put(f"nvd/{cve_id}", value, ttl_seconds=_CACHE_TTL)
        return payload

    def _fetch_with_retry(self, cve_id: str) -> dict[str, Any] | None:
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
        url = f"{BASE_URL}?cveId={cve_id}"
        delay_s = _RETRY_BASE_S
        for attempt in range(_RETRY_MAX + 1):
            try:
                resp = _default_http().request(
                    "GET", url, headers=headers,
                    timeout=self.timeout_s, retries=0,
                )
            except HttpError as exc:
                status = exc.status or 0
                if status == 429:
                    if self.on_rate_limit is not None:
                        self.on_rate_limit()
                    if attempt < _RETRY_MAX:
                        retry_after_val = exc.retry_after
                        wait_s = max(float(retry_after_val or 0), delay_s)
                        if wait_s > 0:
                            time.sleep(wait_s)
                        delay_s *= 2
                        continue
                # 5xx server errors are transient — retry like
                # 429. Pre-fix only 429 was retried; 502/503/504
                # gave up immediately, so a brief NVD outage
                # caused the whole CVE-diff batch to fail when
                # a 1-2 retry would have succeeded.
                if 500 <= status < 600:
                    if attempt < _RETRY_MAX:
                        time.sleep(delay_s)
                        delay_s *= 2
                        continue
                return None
            if resp.status != 200:
                # 5xx on the response path (no exception raised
                # but error status returned) — same retry rule.
                if 500 <= resp.status < 600 and attempt < _RETRY_MAX:
                    time.sleep(delay_s)
                    delay_s *= 2
                    continue
                return None
            try:
                return resp.json()
            except Exception:
                return None
        return None
