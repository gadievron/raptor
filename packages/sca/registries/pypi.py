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
import urllib.parse

from packaging.version import InvalidVersion, Version

from core.http import HttpClient
from core.json import MISSING, JsonCache

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "pypi-versions"
_DEFAULT_TTL = 24 * 3600


def _key_component(value: str) -> str:
    """Percent-encode one cache-key component so the key identity is
    injective — a raw name containing ``/`` or ``..`` could otherwise
    alias another package's cache file after JsonCache path
    sanitisation. Old raw-name entries re-fetch once."""
    return urllib.parse.quote(value, safe="")


# Top-level fields with no RAPTOR consumer.
#   - ``ownership``: package-ownership history (security irrelevant).
#   - ``urls``: same content as ``releases[latest]`` (redundant).
#   - ``vulnerabilities``: PyPI's own advisory feed; RAPTOR uses OSV +
#     NVD as the canonical sources, not this.
#   - ``last_serial``: PyPI-internal counter, no consumer.
_PYPI_TOP_STRIP_FIELDS = frozenset((
    "ownership", "urls", "vulnerabilities", "last_serial",
))

# Per-release-file fields RAPTOR doesn't read.
#   - ``md5_digest``: redundant with the sha256 in ``digests``.
#   - ``has_sig``: deprecated; PyPI dropped GPG signature support.
#   - ``comment_text``: rarely populated; no consumer.
#   - ``upload_time``: redundant with ``upload_time_iso_8601``;
#     RAPTOR's age checks use the ISO field.
#   - ``downloads``: always ``-1`` (deprecated stats).
_PYPI_RELEASE_FILE_STRIP_FIELDS = frozenset((
    "md5_digest", "has_sig", "comment_text", "upload_time", "downloads",
))

# Cosmetic ``info`` fields. RAPTOR reads ``license``,
# ``license_expression``, ``requires_dist``, ``requires_python``,
# ``yanked``, ``yanked_reason``, ``version``, ``name`` — and a small
# few via the per-version block. Everything else in ``info`` is
# author/project metadata with no security consumer.
#
# ``classifiers`` is INTENTIONALLY KEPT (not stripped): older PyPI
# packages encode their license only in the trove classifier
# ``License :: OSI Approved :: <name>``, and ``_spdx_from_pypi``
# falls back to scanning classifiers when ``info.license`` and
# ``info.license_expression`` are both empty. The 2026-05-20
# initial strip omitted it — that regression flagged 5 mainstream
# Python packages (jinja2, markdown-it-py, annotated-types, mdurl,
# playwright) as ``license_unknown`` despite their classifiers
# carrying the SPDX. Surfaced 2026-05-21 by the dogfood scan.
_PYPI_INFO_STRIP_FIELDS = frozenset((
    "author", "author_email", "bugtrack_url",
    "description", "description_content_type", "docs_url",
    "download_url", "downloads", "dynamic", "home_page", "keywords",
    "maintainer", "maintainer_email", "package_url", "platform",
    "project_url", "project_urls", "provides_extra", "release_url",
    "summary",
))


def _strip_pypi_metadata(data: object) -> object:
    """Strip security-irrelevant fields from a PyPI envelope.

    Returns ``data`` unchanged when it isn't a dict (404 sentinel
    ``None`` or upstream schema drift). Mutates a defensive shallow
    copy of the outer dict; nested ``releases`` and ``info`` blocks
    are mutated in place since the caller doesn't retain references.
    """
    if not isinstance(data, dict):
        return data
    out = dict(data)
    for k in _PYPI_TOP_STRIP_FIELDS:
        out.pop(k, None)
    releases = out.get("releases")
    if isinstance(releases, dict):
        for files in releases.values():
            if isinstance(files, list):
                for f in files:
                    if isinstance(f, dict):
                        for k in _PYPI_RELEASE_FILE_STRIP_FIELDS:
                            f.pop(k, None)
    info = out.get("info")
    if isinstance(info, dict):
        for k in _PYPI_INFO_STRIP_FIELDS:
            info.pop(k, None)
    return out


class PyPIClient:
    """List versions from PyPI's JSON API."""

    ecosystem = "PyPI"

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
        base = base.removesuffix("/simple")
        base = base.removesuffix("/simple/")
        return f"{base}/pypi/{name}/json"

    def _request_headers(self) -> dict | None:
        if self._auth_header:
            return {"Authorization": self._auth_header}
        return None

    def get_metadata(self, name: str) -> dict | None:
        """Return the raw PyPI JSON for a package — or ``None`` on miss.

        Cached separately from the version list so callers needing publish
        timestamps / maintainer info don't pay an extra round-trip.

        Negative caching: a 404 / fetch failure caches ``None`` for
        the same TTL so workspace-internal / private package names
        don't re-query on every detector call.
        """
        canon = _canonical_name(name)
        cache_key = f"pypi-meta:{_key_component(canon)}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                self._build_url(canon),
                headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.pypi", canon, e)
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        # Strip security-irrelevant fields before caching. See
        # ``_strip_pypi_metadata`` for the rationale.
        data = _strip_pypi_metadata(data)
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_version_metadata(
        self, name: str, version: str,
    ) -> dict | None:
        """Return the version-specific PyPI JSON.

        ``/pypi/<name>/<version>/json`` returns metadata as
        published with THAT specific version — including the
        version's actual ``requires_dist``, which the aggregate
        ``/pypi/<name>/json`` only carries for the latest release.
        Used by the transitive-drop detector to compare requires_dist
        across versions (e.g. did this dep move behind an extras
        marker between 1.14.x and 1.15.x?).

        Cached separately from the aggregate metadata; same TTL.
        Same negative-caching policy as ``get_metadata``.
        """
        canon = _canonical_name(name)
        cache_key = (f"pypi-meta:{_key_component(canon)}:"
                     f"{_key_component(version)}")
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        url = f"{self._build_url(canon).rsplit('/', 1)[0]}/{version}/json"
        try:
            data = self._http.get_json(
                url, headers=self._request_headers(),
            )
        except Exception as e:                            # noqa: BLE001
            # A 404 here is expected and non-fatal: yanked releases (e.g.
            # codecov 2.0.22) have no per-version JSON, and the caller treats
            # None as "no data". Keep it at debug so a routine miss doesn't
            # spam the run log — yank detection is the yanked-versions stage's.
            logger.debug(
                "sca.registries.pypi: version-meta fetch failed for "
                "%r==%r: %s", canon, version, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def list_versions(self, name: str) -> list[str]:
        canon = _canonical_name(name)
        cache_key = f"{_CACHE_KEY_PREFIX}:{_key_component(canon)}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                self._build_url(canon),
                headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.pypi", canon, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _canonical_name(name: str) -> str:
    """PEP 503 normalisation."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_versions(data: dict) -> list[str]:
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
    if not isinstance(data, dict):
        return []
    releases = data.get("releases") or {}
    if not isinstance(releases, dict):
        return []
    out: list[str] = []
    for ver, files in releases.items():
        if not isinstance(files, list):
            continue
        # Drop versions where every artefact was yanked.
        dict_files = [f for f in files if isinstance(f, dict)]
        if dict_files and all(f.get("yanked") for f in dict_files):
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
