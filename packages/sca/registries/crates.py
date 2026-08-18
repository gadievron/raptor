"""crates.io registry client.

Fetches ``https://crates.io/api/v1/crates/<name>`` and returns published
versions, sorted newest-first, with yanked and pre-release versions
filtered out.

Same shape as ``PyPIClient`` / ``NpmClient`` — same ``RegistryClient``
Protocol. Caching: ``crates-versions:<name>`` with a 24h TTL by default.
"""

from __future__ import annotations

import logging
import urllib.parse

from core.http import HttpClient
from core.json import MISSING, JsonCache

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "crates-versions"
_DEFAULT_TTL = 24 * 3600


def _key_component(value: str) -> str:
    """Percent-encode one cache-key component so the key identity is
    injective — a raw name containing ``/`` or ``..`` could otherwise
    alias another package's cache file after JsonCache path
    sanitisation. Old raw-name entries re-fetch once."""
    return urllib.parse.quote(value, safe="")


class CratesClient:
    """List versions from crates.io."""

    # Internal canonical name; OSV-side translation (``Cargo`` →
    # ``crates.io``) lives at the OSV query boundary, not here.
    ecosystem = "Cargo"

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
        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions

    def get_metadata(self, name: str) -> dict | None:
        """Return the raw crates.io aggregate response."""
        cache_key = f"crates-meta:{_key_component(name)}"
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
    ) -> list | None:
        """Fetch per-version deps from
        ``/api/v1/crates/<crate>/<version>/dependencies``.

        Returns the deps list (each row carries ``crate_id``,
        ``kind``, ``optional``, ``features``, ``default_features``,
        etc.); None on miss / offline. Used by the
        transitive-drop detector."""
        cache_key = (f"crates-deps:{_key_component(name)}:"
                     f"{_key_component(version)}")
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                if cached is None:
                    return None
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


def _extract_versions(data: dict) -> list[str]:
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
    if not isinstance(data, dict):
        return []
    versions = data.get("versions") or []
    if not isinstance(versions, list):
        return []
    out: list[str] = []
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
