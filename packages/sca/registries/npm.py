"""npm registry client.

Fetches ``https://registry.npmjs.org/<name>`` and returns published
versions, sorted newest-first, with pre-releases and deprecated
versions filtered out.

Same shape as ``PyPIClient`` — same ``RegistryClient`` Protocol.
Caching: ``npm-versions:<name>`` with a 24h TTL by default.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "npm-versions"
_DEFAULT_TTL = 24 * 3600

# Cap raised above the global 50 MB default. Popular scoped
# namespaces like ``@grafana/runtime`` / ``@grafana/ui`` ship
# cumulative version metadata that exceeds the global default;
# the May 2026 200-project sweep against Grafana surfaced this
# as a silent meta-fetch failure across 3+ packages. 200 MB
# absorbs every namespace observed in OSS-corpus practice
# without inviting registry-bomb concerns at the transport
# layer.
_NPM_META_MAX_BYTES = 200 * 1024 * 1024

# Fields stripped from per-version dicts before cache write. None of
# RAPTOR's SCA passes (license, yanked, transitive_drop, evaluator,
# install-hook review, bump) read these — they're either npm registry
# internals, non-security metadata, or build-time-only data. Stripping
# at fetch saves disk + cuts cold-parse cost on subsequent reads.
# Conservative list — when in doubt, leave it in.
#
# ``devDependencies`` is the single biggest win: on a representative
# 31 MB envelope (next.js, 3768 versions) it accounted for 16 MB (52%).
# RAPTOR scans the runtime ``dependencies`` graph for vulns, not the
# dev-tooling graph, so dropping devDeps is safe.
_NPM_VERSION_STRIP_FIELDS = frozenset((
    "devDependencies",
    "_defaultsLoaded", "_engineSupported", "_id", "_nodeVersion",
    "_npmJsonOpts", "_npmOperationalInternal", "_npmVersion",
    "author", "bugs", "description", "directories", "engines",
    "keywords", "main", "maintainers", "repository", "taskr",
))

# Top-level fields with no RAPTOR consumer.
_NPM_TOP_STRIP_FIELDS = frozenset((
    "_id", "_rev", "_attachments", "readme", "readmeFilename",
    "homepage", "author", "bugs", "contributors", "description",
    "keywords", "repository", "users", "maintainers",
))


def _strip_npm_metadata(data: object) -> object:
    """Strip security-irrelevant fields from an npm registry envelope.

    Returns ``data`` unchanged when it isn't a dict (404 sentinel ``None``
    or upstream schema drift). In-place mutation on a defensive shallow
    copy of the outer dict; per-version dicts are mutated in place since
    the caller doesn't retain references.
    """
    if not isinstance(data, dict):
        return data
    out = dict(data)
    for k in _NPM_TOP_STRIP_FIELDS:
        out.pop(k, None)
    versions = out.get("versions")
    if isinstance(versions, dict):
        for v_meta in versions.values():
            if isinstance(v_meta, dict):
                for k in _NPM_VERSION_STRIP_FIELDS:
                    v_meta.pop(k, None)
    return out


# Loose semver matcher; the registry's keys are canonical semver but we
# guard against pre-release tags being treated as stable. Pre-releases
# follow the ``-`` convention: ``1.0.0-rc.1``, ``1.0.0-beta``, etc.
_PRERELEASE_RE = re.compile(r"-")


class NpmClient:
    """List versions from the npm registry."""

    ecosystem = "npm"

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
        # Private-registry override (NPM_CONFIG_REGISTRY).
        from ..private_registry import get as _get_override
        over = _get_override("npm")
        self._base_url = (
            over.base_url.rstrip("/") if over and over.base_url
            else "https://registry.npmjs.org"
        )
        self._auth_header = over.auth_header if over else None

    def _request_headers(self) -> Optional[dict]:
        if self._auth_header:
            return {"Authorization": self._auth_header}
        return None

    def get_metadata(self, name: str) -> Optional[dict]:
        """Return the raw npm registry document for a package.

        Uses ``_NPM_META_MAX_BYTES`` (200 MB) as the cap because
        popular scoped namespaces like ``@grafana/runtime`` ship
        cumulative version metadata above the global 50 MB default.

        Negative caching: a 404 / fetch failure caches ``None`` for
        the same TTL as a successful response. Pre-fix the failure
        path returned None without caching, so monorepos with
        hundreds of internal workspace packages (e.g. Grafana's
        200+ unpublished ``@grafana/*`` and ``@grafana-plugins/*``
        entries) re-queried the npm registry on every detector that
        called ``get_metadata``. The May 2026 200-project sweep
        showed thousands of duplicate 404s for the same set of
        names. ``try_get`` + ``MISSING`` distinguishes "not cached"
        from "cached as None" so the negative entry serves.
        """
        encoded = urllib.parse.quote(name, safe="@")
        cache_key = f"npm-meta:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                # Includes both successful payloads and the cached
                # negative (None) — the caller treats both correctly.
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"{self._base_url}/{encoded}",
                headers=self._request_headers(),
                max_bytes=_NPM_META_MAX_BYTES,
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.npm", name, e)
            if self._cache is not None:
                # Cache the failure for the same TTL so subsequent
                # detectors don't re-query the same dead name.
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        # Strip security-irrelevant fields before caching: devDeps,
        # npm internals, non-security metadata. See
        # ``_strip_npm_metadata`` for the rationale. Returns the
        # stripped envelope so subsequent in-process callers don't
        # see a different shape than the cache.
        data = _strip_npm_metadata(data)
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def list_versions(self, name: str) -> List[str]:
        # npm scoped names: ``@anthropic-ai/claude-code`` is URL-encoded
        # as ``@anthropic-ai%2Fclaude-code`` (or sometimes as-is — the
        # registry accepts both). We use ``urllib.parse.quote`` so the
        # ``/`` is encoded.
        encoded = urllib.parse.quote(name, safe="@")
        cache_key = f"{_CACHE_KEY_PREFIX}:{name}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if cached is not None:
                return list(cached)

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                f"{self._base_url}/{encoded}",
                headers=self._request_headers(),
                max_bytes=_NPM_META_MAX_BYTES,
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.npm", name, e)
            if self._cache is not None:
                # Negative-cache the empty result so re-queries on the
                # same TTL window don't re-hit the registry. Same
                # rationale as ``get_metadata``: workspace-internal
                # names that 404 on every call would otherwise burn
                # the same lookup once per detector. The empty list
                # collides cleanly with the cached-empty-result path
                # below — both surface as ``[]``.
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull stable versions from the npm registry document.

    Shape:
        {
          "versions": {"1.0.0": {...}, "1.0.0-rc.1": {...}, ...},
          "time": {"created": "...", "modified": "...",
                   "1.0.0": "<iso>", "<ver>": "<iso>", ...},
          "dist-tags": {"latest": "1.0.0"}
        }

    We sort by publish time (newest-first) using ``time``; if absent,
    fall back to the ``versions`` map order.
    """
    versions = data.get("versions") or {}
    if not isinstance(versions, dict):
        return []
    times = data.get("time") or {}
    if not isinstance(times, dict):
        times = {}

    candidates: List[str] = []
    for ver, meta in versions.items():
        # Drop deprecated versions: npm marks these by setting the
        # ``deprecated`` field on the package metadata.
        if isinstance(meta, dict) and meta.get("deprecated"):
            continue
        # Drop pre-releases (any version with a ``-`` suffix).
        if _PRERELEASE_RE.search(ver):
            continue
        candidates.append(ver)

    # Sort by publish time descending; fall back to lexical sort if
    # ``time`` is missing.
    def _sort_key(v: str):
        return times.get(v, "")
    candidates.sort(key=_sort_key, reverse=True)
    return candidates


__all__ = ["NpmClient"]
