"""NuGet (.NET) registry client.

Fetches the ``api.nuget.org`` flat-container index for a package — the
simplest endpoint that returns just a version list with no pagination:

    https://api.nuget.org/v3-flatcontainer/<lowercase_id>/index.json

Returns versions newest-first with pre-releases (any version containing
``-``) filtered out.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


# defusedxml is required for safe ``.nuspec`` parsing. NuGet
# responses come over HTTPS so the attacker model is registry-
# compromise or MITM — lower risk than target-repo XML, but
# defense-in-depth says use defusedxml. Refuse to parse without it.
try:
    from defusedxml.ElementTree import fromstring as _safe_xml_fromstring
    _DEFUSEDXML_AVAILABLE = True
except ImportError:                                  # pragma: no cover
    _safe_xml_fromstring = None                      # type: ignore[assignment]
    _DEFUSEDXML_AVAILABLE = False
    logger.warning(
        "sca.registries.nuget: 'defusedxml' not installed — NuGet "
        "license / metadata fetches will be skipped. `pip install "
        "defusedxml` to enable.",
    )


_CACHE_KEY_PREFIX = "nuget-versions"
_DEFAULT_TTL = 24 * 3600


class NugetClient:
    """List versions from NuGet's flat-container."""

    ecosystem = "NuGet"

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
        # NuGet IDs are case-insensitive but the URL path requires
        # lowercase.
        canon = name.lower()
        cache_key = f"{_CACHE_KEY_PREFIX}:{canon}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        try:
            data = self._http.get_json(
                f"https://api.nuget.org/v3-flatcontainer/{canon}/index.json")
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.nuget", name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull versions from the NuGet flat-container response.

    Shape:
        {"versions": ["1.0.0", "1.1.0", "1.2.0-rc.1", ...]}
    """
    raw = data.get("versions") or []
    if not isinstance(raw, list):
        return []
    out = [v for v in raw if isinstance(v, str) and "-" not in v]
    # Newest-first using semver-ish ordering.
    out.sort(key=_semver_key, reverse=True)
    return out


def _semver_key(v: str):
    """Best-effort semver tuple."""
    parts = v.split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return tuple(out)


def _add_nuspec_methods():
    """Attach ``get_metadata`` + ``get_nuspec`` to NugetClient."""

    def get_metadata(self, name: str) -> Optional[dict]:
        versions = self.list_versions(name)
        if not versions:
            return None
        return {
            "releases": {v: [] for v in versions},
            "info": {"version": versions[0]},
        }

    def get_nuspec(self, pkg: str, version: str) -> Optional[dict]:
        """Fetch + parse a .nuspec XML.

        ``api.nuget.org/v3-flatcontainer/<id>/<ver>/<id>.nuspec``;
        case-insensitive (caller normalises). Returns
        ``{dependency_groups: [{targetFramework, dependencies}]}``."""
        cache_key = f"nuget-nuspec:{pkg.lower()}:{version}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        lower = pkg.lower()
        url = (f"https://api.nuget.org/v3-flatcontainer/{lower}/"
                f"{version}/{lower}.nuspec")
        try:
            resp = self._http.request(
                "GET", url, raise_on_status=False,
            )
        except Exception as e:                              # noqa: BLE001
            logger.warning(
                "sca.registries.nuget: nuspec fetch failed for "
                "%s@%s: %s", pkg, version, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if resp.status_code != 200:
            return None
        if not _DEFUSEDXML_AVAILABLE:
            return None
        try:
            root = _safe_xml_fromstring(resp.content)
        except Exception as e:                              # noqa: BLE001
            logger.warning(
                "sca.registries.nuget: nuspec parse failed for "
                "%s@%s: %s", pkg, version, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}", 1)[0] + "}"
        meta = root.find(f"{ns}metadata") or root
        deps_root = meta.find(f"{ns}dependencies") if meta is not None else None
        groups: List[dict] = []
        if deps_root is not None:
            inner_groups = list(deps_root.findall(f"{ns}group"))
            if inner_groups:
                for g in inner_groups:
                    tfm = g.get("targetFramework", "")
                    deps = [
                        {"id": d.get("id", ""),
                         "version": d.get("version", "")}
                        for d in g.findall(f"{ns}dependency")
                    ]
                    groups.append({
                        "targetFramework": tfm,
                        "dependencies": deps,
                    })
            else:
                deps = [
                    {"id": d.get("id", ""),
                     "version": d.get("version", "")}
                    for d in deps_root.findall(f"{ns}dependency")
                ]
                groups = [{"targetFramework": "", "dependencies": deps}]
        result = {"dependency_groups": groups}
        if self._cache is not None:
            self._cache.put(cache_key, result, ttl_seconds=self._ttl)
        return result

    NugetClient.get_metadata = get_metadata
    NugetClient.get_nuspec = get_nuspec


_add_nuspec_methods()


__all__ = ["NugetClient"]
