"""crates.io registry client.

Fetches ``https://crates.io/api/v1/crates/<name>`` and returns published
versions, sorted newest-first, with yanked and pre-release versions
filtered out.

Same shape as ``PyPIClient`` / ``NpmClient`` — same ``RegistryClient``
Protocol. Caching: ``crates-versions:<name>`` with a 24h TTL by default.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "crates-versions"
_DEFAULT_TTL = 24 * 3600


class CratesClient:
    """List versions from crates.io."""

    # Internal canonical name; OSV-side translation (``Cargo`` →
    # ``crates.io``) lives at the OSV query boundary, not here.
    ecosystem = "Cargo"

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
        data = self.get_metadata(name)
        if data is None:
            return []
        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions

    def get_metadata(self, name: str) -> Optional[dict]:
        """Return the raw crates.io aggregate response."""
        cache_key = f"crates-meta:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://crates.io/api/v1/crates/{name}",
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.crates", name, e)
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_version_dependencies(
        self, name: str, version: str,
    ) -> Optional[list]:
        """Fetch per-version deps from
        ``/api/v1/crates/<crate>/<version>/dependencies``.

        Returns the deps list (each row carries ``crate_id``,
        ``kind``, ``optional``, ``features``, ``default_features``,
        etc.); None on miss / offline. Used by the
        transitive-drop detector."""
        cache_key = f"crates-deps:{name}:{version}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://crates.io/api/v1/crates/{name}/"
                f"{version}/dependencies",
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(
                logger, "sca.registries.crates", f"{name}@{version}", e)
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        deps = data.get("dependencies") if isinstance(data, dict) else None
        if not isinstance(deps, list):
            return None
        if self._cache is not None:
            self._cache.put(cache_key, deps, ttl_seconds=self._ttl)
        return deps


def _extract_versions(data: dict) -> List[str]:
    """Pull stable, non-yanked versions from the crates.io response.

    Shape:
        {
          "crate": {...},
          "versions": [
            {"num": "1.2.3", "yanked": false, "created_at": "...", ...},
            ...
          ]
        }
    """
    versions = data.get("versions") or []
    if not isinstance(versions, list):
        return []
    out: List[str] = []
    for v in versions:
        if not isinstance(v, dict):
            continue
        num = v.get("num")
        if not isinstance(num, str):
            continue
        if v.get("yanked"):
            continue
        # crates.io semver: pre-release is anything with ``-`` (e.g.
        # ``1.0.0-alpha.1``).
        if "-" in num:
            continue
        out.append(num)
    # Sort newest-first using semver-ish ordering: lex-sort works for
    # zero-padded numbers; for safety we use a tuple-of-ints key when we
    # can, falling back to string compare.
    out.sort(key=_semver_key, reverse=True)
    return out


def _semver_key(v: str):
    """Best-effort semver tuple. Non-numeric segments sort last."""
    parts = v.split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return tuple(out)


__all__ = ["CratesClient"]
