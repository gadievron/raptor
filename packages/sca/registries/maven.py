"""Maven Central registry client.

Fetches ``https://search.maven.org/solrsearch/select?q=g:<group>+AND+a:<artifact>&core=gav&rows=200&wt=json``
and returns versions newest-first, with non-stable / classifier-only
artifacts filtered out.

Maven artifacts are keyed on ``groupId:artifactId``. Callers pass that
combined form via ``list_versions("group:artifact")``.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

logger = logging.getLogger(__name__)


# defusedxml is required for safe POM XML parsing. Maven Central's
# responses come over HTTPS, so the attacker model is registry-
# compromise or MITM — lower risk than target-repo XML, but
# defense-in-depth says use defusedxml. Refuse to parse without it.
try:
    from defusedxml.ElementTree import fromstring as _safe_xml_fromstring
    _DEFUSEDXML_AVAILABLE = True
except ImportError:                                  # pragma: no cover
    _safe_xml_fromstring = None                      # type: ignore[assignment]
    _DEFUSEDXML_AVAILABLE = False
    logger.warning(
        "sca.registries.maven: 'defusedxml' not installed — Maven POM "
        "metadata fetches will be skipped. `pip install defusedxml` "
        "to enable.",
    )


_CACHE_KEY_PREFIX = "maven-versions"
_DEFAULT_TTL = 24 * 3600


class MavenClient:
    """List versions from Maven Central's solrsearch API."""

    ecosystem = "Maven"

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
        # Private-registry override (RAPTOR_SCA_MAVEN_REGISTRY).
        # Maven mirrors typically expose ``/solrsearch/select`` and
        # ``/maven2/`` paths (the same shape as Maven Central). When
        # the operator's mirror diverges (Artifactory's pattern is
        # ``/artifactory/api/search/...``), the env var should
        # contain a base URL whose ``/solrsearch/select?q=...``
        # path resolves correctly.
        from ..private_registry import get as _get_override
        over = _get_override("Maven")
        self._base_url = (
            over.base_url.rstrip("/") if over and over.base_url
            else "https://search.maven.org"
        )
        self._auth_header = over.auth_header if over else None

    def _request_headers(self) -> Optional[dict]:
        if self._auth_header:
            return {"Authorization": self._auth_header}
        return None

    def list_versions(self, name: str) -> List[str]:
        if ":" not in name:
            logger.debug("sca.registries.maven: name %r missing group:artifact",
                          name)
            return []
        group, artifact = name.split(":", 1)

        cache_key = f"{_CACHE_KEY_PREFIX}:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        # ``core=gav`` returns one row per group:artifact:version (versus
        # ``core=ga`` which collapses to the latest). 200 rows is enough
        # for almost every artifact; very long histories will be capped.
        q = (f"g:{urllib.parse.quote(group)}+AND+"
             f"a:{urllib.parse.quote(artifact)}")
        url = (f"{self._base_url}/solrsearch/select?q={q}"
               f"&core=gav&rows=200&wt=json")
        try:
            data = self._http.get_json(
                url, headers=self._request_headers(),
            )
        except Exception as e:                # noqa: BLE001
            logger.warning("sca.registries.maven: fetch failed for %r: %s",
                           name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(data)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _extract_versions(data: dict) -> List[str]:
    """Pull versions from the Maven Central solr response.

    Shape (abridged):
        {
          "response": {
            "docs": [
              {"v": "2.17.1", "g": "...", "a": "...", "timestamp": ...},
              ...
            ]
          }
        }
    """
    docs = (data.get("response") or {}).get("docs") or []
    if not isinstance(docs, list):
        return []
    seen: set = set()
    out: List[str] = []
    for d in docs:
        if not isinstance(d, dict):
            continue
        v = d.get("v")
        if not isinstance(v, str) or v in seen:
            continue
        # Drop pre-release-style artifacts (alpha, beta, rc, snapshot).
        # Maven coords are looser than semver; we use a substring sniff
        # rather than a strict parse.
        lo = v.lower()
        if any(tag in lo for tag in (
                "snapshot", "alpha", "beta", "-rc", ".rc",
                "-cr", ".cr", "milestone", "-m", ".m")):
            # The trailing "-m" / ".m" check would false-positive on
            # legitimate versions with an "m" suffix; gate on a
            # following digit.
            if any(t in lo for t in ("snapshot", "alpha", "beta",
                                       "milestone")):
                continue
            import re as _re
            if _re.search(r"[-.](rc|cr|m)\d+", lo):
                continue
        seen.add(v)
        out.append(v)
    # Solr returns newest-first by default; preserve.
    return out


def _add_pom_methods():
    """Attach ``get_pom`` and ``get_metadata`` to MavenClient.

    Separated for readability — these methods serve the
    transitive-drop detector, not the version-listing path."""

    def get_metadata(self, name: str) -> Optional[dict]:
        """Aggregate-shape adapter — returns ``{releases: {<ver>: []}}``
        keyed off ``list_versions`` so the transitive-drop
        detector's ``_latest_stable_version`` finds the latest."""
        versions = self.list_versions(name)
        if not versions:
            return None
        return {
            "releases": {v: [] for v in versions},
            "info": {"version": versions[0]},
        }

    def get_pom(self, coord: str, version: str) -> Optional[dict]:
        """Fetch + parse a POM XML file from Maven Central.

        ``coord`` is ``groupId:artifactId``. Returns a dict with
        ``dependencies: [{groupId, artifactId, version, scope,
        optional}, ...]``. Properties (``${...}``) are NOT
        substituted; parent-POM inheritance is NOT resolved
        (separate detector handles those gaps). Returns None on
        404 / parse failure / offline.
        """
        if ":" not in coord:
            return None
        group, artifact = coord.split(":", 1)
        cache_key = f"maven-pom:{coord}:{version}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached
        if self._offline:
            return None
        group_path = group.replace(".", "/")
        url = (f"https://repo1.maven.org/maven2/{group_path}/"
                f"{artifact}/{version}/{artifact}-{version}.pom")
        try:
            resp = self._http.request(
                "GET", url, raise_on_status=False,
            )
        except Exception as e:                              # noqa: BLE001
            logger.warning(
                "sca.registries.maven: POM fetch failed for "
                "%s@%s: %s", coord, version, e,
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
                "sca.registries.maven: POM parse failed for "
                "%s@%s: %s", coord, version, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None

        ns = "{http://maven.apache.org/POM/4.0.0}"
        deps_node = root.find(f"{ns}dependencies")
        deps: List[dict] = []
        if deps_node is not None:
            for d in deps_node.findall(f"{ns}dependency"):
                gid = (d.findtext(f"{ns}groupId") or "").strip()
                aid = (d.findtext(f"{ns}artifactId") or "").strip()
                ver = (d.findtext(f"{ns}version") or "").strip()
                scope = (d.findtext(f"{ns}scope") or "").strip()
                optional = (d.findtext(f"{ns}optional") or "").strip()
                deps.append({
                    "groupId": gid, "artifactId": aid,
                    "version": ver, "scope": scope,
                    "optional": optional,
                })
        # ``raw_xml`` lets downstream consumers (the POM inheritance
        # resolver, primarily) re-parse the document to inspect
        # ``<parent>``, ``<properties>``, and full ``<dependencyManagement>``
        # — fields the dependency-only summary above doesn't carry.
        # Decoded to ``str`` for cache portability across JSON-backed
        # cache backends; ``errors='replace'`` to survive malformed
        # encoding declarations in old POMs.
        try:
            raw_xml = resp.content.decode("utf-8", errors="replace")
        except Exception:                                       # noqa: BLE001
            raw_xml = None
        result = {"dependencies": deps, "raw_xml": raw_xml}
        if self._cache is not None:
            self._cache.put(cache_key, result, ttl_seconds=self._ttl)
        return result

    MavenClient.get_metadata = get_metadata
    MavenClient.get_pom = get_pom


_add_pom_methods()


__all__ = ["MavenClient"]
