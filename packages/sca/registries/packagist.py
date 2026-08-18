"""Packagist (PHP / Composer) registry client.

Fetches ``https://repo.packagist.org/p2/<vendor>/<package>.json`` and
returns the available versions newest-first, with dev-suffixed and
pre-release versions filtered out.

Packagist names are ``vendor/package``. The hostname is the *static*
content host (``repo.packagist.org``), not the v1 API
(``packagist.org``) — the v2 metadata endpoints are documented as the
preferred long-term API.
"""

from __future__ import annotations

import logging
import re
import urllib.parse

from core.http import HttpClient
from core.json import MISSING, JsonCache

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "packagist-versions"
_DEFAULT_TTL = 24 * 3600


def _key_component(value: str) -> str:
    """Percent-encode one cache-key component so the key identity is
    injective — Composer names legitimately contain ``/``, and a raw
    name with ``..`` segments could otherwise alias another package's
    cache file after JsonCache path sanitisation. Old raw-name entries
    re-fetch once."""
    return urllib.parse.quote(value, safe="")

# Composer pre-release tags (hyphen-prefixed or dev- prefix forms).
_PRERELEASE_RE = re.compile(
    r"(?:^dev-|-(?:dev|alpha|beta|rc|patch)(?:[._-]?\d+)?(?:$|[^a-z]))",
    re.IGNORECASE,
)


class PackagistClient:
    """List versions from Packagist's p2 metadata."""

    ecosystem = "Packagist"

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache | None = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL,
        offline: bool = False,
    ) -> None:
        self._http = http
        self._cache = cache
        self._ttl = ttl_seconds
        self._offline = offline

    def list_versions(self, name: str) -> list[str]:
        if "/" not in name:
            logger.debug("sca.registries.packagist: name %r missing vendor/",
                          name)
            return []

        cache_key = f"{_CACHE_KEY_PREFIX}:{_key_component(name)}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        data = self.get_metadata(name)
        if data is None:
            return []
        versions = _extract_versions(data, name)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions

    def get_metadata(self, name: str) -> dict | None:
        """Return the raw /p2 packagist response for a package.

        Used by the transitive-drop detector to inspect per-version
        ``require`` / ``require-dev`` / ``suggest`` blocks across
        versions. Cached separately from the version list so callers
        needing the dep blocks don't double-fetch."""
        if "/" not in name:
            return None
        cache_key = f"packagist-meta:{_key_component(name)}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://repo.packagist.org/p2/{name}.json",
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.packagist", name, e)
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data


def _extract_versions(data: dict, name: str) -> list[str]:
    """Pull versions from the Packagist p2 response.

    Shape (abridged):
        {
          "packages": {
            "vendor/pkg": [
              {"version": "1.2.3", "version_normalized": "...", ...},
              {"version": "1.2.2", ...},
              ...
            ]
          }
        }
    """
    if not isinstance(data, dict):
        return []
    packages = data.get("packages") or {}
    if not isinstance(packages, dict):
        return []
    raw = packages.get(name) or []
    if not isinstance(raw, list):
        return []
    seen: set = set()
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        ver = entry.get("version")
        if not isinstance(ver, str) or ver in seen:
            continue
        # Drop dev/alpha/beta/rc/patch tags.
        if _PRERELEASE_RE.search(ver):
            continue
        seen.add(ver)
        out.append(ver)
    # Packagist returns newest-first; preserve.
    return out


__all__ = ["PackagistClient"]
