"""PyPI registry client.

Fetches ``https://pypi.org/pypi/<name>/json`` and returns published
versions, sorted newest-first, with pre-releases and yanked releases
filtered out.

Caching: keyed on ``pypi:versions:<name>`` with a 24h TTL by default.
The cache layer is the same ``JsonCache`` used by OSV/KEV/EPSS — no
parallel cache.

Failure policy: any network/parse error returns an empty list and logs a
warning. Callers (``harden`` etc.) treat empty as "no candidates" and
leave the dep alone rather than failing the whole run.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from packaging.version import InvalidVersion, Version

from core.json import JsonCache
from core.http import HttpClient

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "pypi-versions"
_DEFAULT_TTL = 24 * 3600


class PyPIClient:
    """List versions from PyPI's JSON API."""

    ecosystem = "PyPI"

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
        # Private-registry override — operator pointed PIP_INDEX_URL
        # at an Artifactory / Nexus / GHE PyPI mirror. We rebase
        # request URLs onto that host and (when set) thread an
        # Authorization header on every call.
        from ..private_registry import get as _get_override
        over = _get_override("PyPI")
        self._base_url = (
            over.base_url.rstrip("/") if over and over.base_url
            else "https://pypi.org"
        )
        self._auth_header = over.auth_header if over else None

    def _build_url(self, name: str) -> str:
        """Build a JSON-API URL pointed at the configured base.

        PyPI's JSON API lives at ``<base>/pypi/<name>/json``. Mirrors
        following the standard pip layout (Artifactory's PyPI repo,
        Nexus's pypi-proxy) generally honour the same path; mirrors
        that diverge can be reached by setting PIP_INDEX_URL to the
        ``/pypi/`` parent so the path concatenation lands correctly.
        """
        # Strip trailing ``/simple/`` if present — PIP_INDEX_URL
        # usually points at the simple-index path, but the JSON API
        # is one level up.
        base = self._base_url
        if base.endswith("/simple"):
            base = base[: -len("/simple")]
        if base.endswith("/simple/"):
            base = base[: -len("/simple/")]
        return f"{base}/pypi/{name}/json"

    def _request_headers(self) -> Optional[dict]:
        if self._auth_header:
            return {"Authorization": self._auth_header}
        return None

    def get_metadata(self, name: str) -> Optional[dict]:
        """Return the raw PyPI JSON for a package — or ``None`` on miss.

        Cached separately from the version list so callers needing publish
        timestamps / maintainer info don't pay an extra round-trip.
        """
        canon = _canonical_name(name)
        cache_key = f"pypi-meta:{canon}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                self._build_url(canon),
                headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.pypi: meta fetch failed for %r: %s",
                           canon, e)
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_version_metadata(
        self, name: str, version: str,
    ) -> Optional[dict]:
        """Return the version-specific PyPI JSON.

        ``/pypi/<name>/<version>/json`` returns metadata as
        published with THAT specific version — including the
        version's actual ``requires_dist``, which the aggregate
        ``/pypi/<name>/json`` only carries for the latest release.
        Used by the transitive-drop detector to compare requires_dist
        across versions (e.g. did this dep move behind an extras
        marker between 1.14.x and 1.15.x?).

        Cached separately from the aggregate metadata; same TTL.
        """
        canon = _canonical_name(name)
        cache_key = f"pypi-meta:{canon}:{version}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return cached
        if self._offline:
            return None
        url = f"{self._build_url(canon).rsplit('/', 1)[0]}/{version}/json"
        try:
            data = self._http.get_json(
                url, headers=self._request_headers(),
            )
        except Exception as e:                            # noqa: BLE001
            logger.warning(
                "sca.registries.pypi: version-meta fetch failed for "
                "%r==%r: %s", canon, version, e,
            )
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def list_versions(self, name: str) -> List[str]:
        canon = _canonical_name(name)
        cache_key = f"{_CACHE_KEY_PREFIX}:{canon}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return list(cached)

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                self._build_url(canon),
                headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.pypi: fetch failed for %r: %s",
                           canon, e)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _canonical_name(name: str) -> str:
    """PEP 503 normalisation."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_versions(data: dict) -> List[str]:
    """Pull the version list from PyPI's JSON shape, drop pre-releases and
    versions with all yanked artefacts.

    PyPI shape:
        {
          "info": {...},
          "releases": {
            "1.0": [{"yanked": false, ...}],
            "1.0a1": [{...}],
            ...
          }
        }
    """
    releases = data.get("releases") or {}
    if not isinstance(releases, dict):
        return []
    out: List[str] = []
    for ver, files in releases.items():
        if not isinstance(files, list):
            continue
        # Drop versions where every artefact was yanked.
        if files and all(f.get("yanked") for f in files
                          if isinstance(f, dict)):
            continue
        # Some entries appear with no files at all (rare; skip).
        if not files:
            continue
        try:
            parsed = Version(ver)
        except InvalidVersion:
            continue
        # Skip pre-releases by default — operators don't want
        # ``pip install requests==2.31.0a1`` from a hardening pass.
        if parsed.is_prerelease or parsed.is_devrelease:
            continue
        out.append(ver)
    # Sort newest-first using PEP 440 ordering.
    out.sort(key=Version, reverse=True)
    return out


__all__ = ["PyPIClient"]
