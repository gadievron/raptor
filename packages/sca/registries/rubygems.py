"""RubyGems registry client.

Fetches ``https://rubygems.org/api/v1/versions/<name>.json`` and returns
published versions, sorted newest-first, with yanked and pre-release
versions filtered out.

Same shape as the other registry clients.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "rubygems-versions"
_DEFAULT_TTL = 24 * 3600


class RubyGemsClient:
    """List versions from RubyGems.org."""

    ecosystem = "RubyGems"

    def __init__(
        self,
        http: HttpClient,
        cache: Optional[JsonCache] = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL,
        offline: bool = False,
    ) -> None:
        self._http = http
        self._cache = cache
        self._ttl = ttl_seconds
        self._offline = offline

    def list_versions(self, name: str) -> List[str]:
        cache_key = f"{_CACHE_KEY_PREFIX}:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                f"https://rubygems.org/api/v1/versions/{name}.json")
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.rubygems: fetch failed for %r: %s",
                           name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions

    def get_metadata(self, name: str) -> Optional[dict]:
        """Aggregate metadata via ``/api/v1/gems/<name>.json``.

        Used by ``_latest_stable_version`` in the transitive-drop
        detector (turns the gem name into a releases list)."""
        cache_key = f"rubygems-meta:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://rubygems.org/api/v1/gems/{name}.json",
            )
        except Exception as e:                # noqa: BLE001
            logger.warning(
                "sca.registries.rubygems: meta fetch failed for "
                "%r: %s", name, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        # Adapt to a ``releases`` shape so _latest_stable_version
        # finds versions consistently across ecosystems.
        if isinstance(data, dict):
            data = {**data, "releases": {data.get("version"): []}}
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_version_metadata(
        self, name: str, version: str,
    ) -> Optional[dict]:
        """Fetch per-version metadata via
        ``/api/v2/rubygems/<name>/versions/<ver>.json``.

        Returns the version's structured data including
        ``dependencies: {runtime: [...], development: [...]}``.
        Used by the transitive-drop detector to diff dep state
        across versions."""
        cache_key = f"rubygems-vmeta:{name}:{version}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://rubygems.org/api/v2/rubygems/{name}/"
                f"versions/{version}.json",
            )
        except Exception as e:                # noqa: BLE001
            logger.warning(
                "sca.registries.rubygems: version-meta fetch failed "
                "for %r==%r: %s", name, version, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data


def _extract_versions(data) -> List[str]:
    """Pull stable, non-yanked versions from the RubyGems response.

    Shape: a JSON array of objects, each with ``number``, ``prerelease``,
    ``created_at``, ``yanked``.
    """
    if not isinstance(data, list):
        return []
    out: List[str] = []
    seen: set = set()
    for v in data:
        if not isinstance(v, dict):
            continue
        num = v.get("number")
        if not isinstance(num, str) or num in seen:
            continue
        if v.get("yanked"):
            continue
        if v.get("prerelease"):
            continue
        seen.add(num)
        out.append(num)
    # The API already returns newest-first by ``created_at``; preserve.
    return out


__all__ = ["RubyGemsClient"]
