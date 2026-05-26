"""Debian registry client.

Fetches ``https://sources.debian.org/api/src/<package>/`` — the canonical
"all known versions of this Debian source package" endpoint. Returns
versions newest-first.

Note: the Debian Sources API lists *source-package* versions, not the
binary-package versions you'd see in ``apt list``. For most cases the
two track each other (binary nginx ↔ source nginx). When they diverge
the source list is the conservative choice — every binary derives from
some source version.

Suite-aware queries (which versions are in which release) are deferred:
the simple "list versions" endpoint is sufficient for harden's
pick-latest-safe semantic.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "debian-versions"
_DEFAULT_TTL = 24 * 3600


class DebianClient:
    """List versions from the Debian Sources API."""

    ecosystem = "Debian"

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
                f"https://sources.debian.org/api/src/{name}/")
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.debian: fetch failed for %r: %s",
                           name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull versions from the Debian Sources response.

    Shape:
        {
          "package": "nginx",
          "versions": [
            {"version": "1.22.1-9", "suites": ["bookworm"], ...},
            {"version": "1.18.0-6.1+deb11u3", "suites": ["bullseye"], ...}
          ]
        }
    """
    raw = data.get("versions") or []
    if not isinstance(raw, list):
        return []
    seen: set = set()
    out: List[str] = []
    for v in raw:
        if not isinstance(v, dict):
            continue
        ver = v.get("version")
        if not isinstance(ver, str) or ver in seen:
            continue
        seen.add(ver)
        out.append(ver)
    # The API returns roughly newest-first; preserve.
    return out


__all__ = ["DebianClient"]
