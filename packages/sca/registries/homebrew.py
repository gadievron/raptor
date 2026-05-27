"""Homebrew registry client.

Fetches ``https://formulae.brew.sh/api/formula/<name>.json`` and returns
the latest stable version.

Homebrew's model differs from versioned-package registries: a formula
tracks one stable version at any point in time. Older versions live as
``foo@<n>`` formulae (e.g., ``python@3.11``) — those are *separate*
formulae, not historical versions. So ``list_versions("python")``
returns just the current stable; ``list_versions("python@3.11")``
returns the stable for that pinned-major formula.

For harden's "pick latest safe" semantic this is fine — we always want
the newest stable, which is the only one Homebrew exposes.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "brew-versions"
_DEFAULT_TTL = 24 * 3600


class HomebrewClient:
    """List versions from Homebrew's formulae.brew.sh API."""

    ecosystem = "Homebrew"

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
                f"https://formulae.brew.sh/api/formula/{name}.json")
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.homebrew", name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull the stable version from the Homebrew response.

    Shape (abridged):
        {
          "name": "semgrep",
          "versions": {"stable": "1.161.0", "head": "HEAD", "bottle": true},
          ...
        }

    We only return the stable version; head/bottle aren't versioned
    pins an operator would want to harden to.
    """
    versions = data.get("versions")
    if not isinstance(versions, dict):
        return []
    stable = versions.get("stable")
    if not isinstance(stable, str) or not stable:
        return []
    return [stable]


__all__ = ["HomebrewClient"]
