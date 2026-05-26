"""Debian registry client.

Lists the versions of a Debian *binary* package across the active Debian
suites via the ftp-master ``madison`` service:
``https://api.ftp-master.debian.org/madison?package=<name>&f=json``.

Why madison and not ``sources.debian.org/api/src/<name>/``: the Sources
API is keyed by *source*-package name and lists every historical version
back to the distribution's origins. Querying it by *binary* name silently
mis-resolves —

  - ``gcc`` hits an ancient standalone source package (newest ``2.95.2-20``
    from woody, ~2002); the modern binary builds from ``gcc-defaults``,
  - ``g++`` 404s (there is no source named ``g++``),
  - ``make`` is really the source ``make-dfsg``,

and even when names coincide it returns long-dead releases unsorted.
madison is *binary-package-aware* (no binary→source mapping needed), only
covers *active* suites (oldstable…experimental, plus -security/-backports/
-proposed-updates), and we sort newest-first with the dpkg version
comparator (:mod:`packages.sca.versions.debian`).

Note on use: RAPTOR's own ``harden`` deliberately does NOT pin or bump apt
deps — an exact ``pkg=version`` pin is fragile (Debian keeps only the
current version per suite, so the pin breaks the build once it's
superseded). See the ``pinning_deferred`` gate in ``harden._plan_one``.
This client exists so the version data is *correct* for direct inspection
and for any consumer that explicitly opts in.
"""

from __future__ import annotations

import functools
import logging
import urllib.parse
from typing import Any, List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ..versions.debian import compare as _debian_compare

logger = logging.getLogger(__name__)


_MADISON_URL = "https://api.ftp-master.debian.org/madison"
# ``-madison`` (was ``debian-versions``) so any entries cached by the old
# source-API client are bypassed rather than served stale for a TTL window
# — those held the wrong (source-by-binary, unsorted) version lists.
_CACHE_KEY_PREFIX = "debian-madison"
_DEFAULT_TTL = 24 * 3600


class DebianClient:
    """List binary-package versions from the Debian madison service."""

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
        """All versions across the active suites, newest-first.

        For direct inspection / SBOM use. ``apt`` pinning wants a single
        suite — see :meth:`versions_in_suite`.
        """
        return self._query(name, suite=None)

    def versions_in_suite(self, name: str, suite: str) -> List[str]:
        """Versions of ``name`` available in a single suite, newest-first.

        ``suite`` is whatever a Dockerfile ``FROM`` yields — a codename
        (``bookworm``), an alias (``stable``), or a pocket
        (``bookworm-security``). madison resolves codenames to their
        current alias server-side, so no (drifting) codename↔alias table
        is needed here.
        """
        return self._query(name, suite=suite)

    def _query(self, name: str, *, suite: Optional[str]) -> List[str]:
        cache_key = (f"{_CACHE_KEY_PREFIX}:{name}" if suite is None
                     else f"{_CACHE_KEY_PREFIX}:{name}:{suite}")
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        # madison's query string treats ``+`` as a space, so a binary name
        # like ``g++`` MUST be percent-encoded (``safe=""`` encodes ``+``,
        # ``&``, ``=`` …). This is also the injection guard for names (and
        # suites) that originate from a scanned manifest.
        url = (f"{_MADISON_URL}?package={urllib.parse.quote(name, safe='')}"
               f"&f=json")
        if suite is not None:
            url += f"&s={urllib.parse.quote(suite, safe='')}"
        try:
            data = self._http.get_json(url)
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


def _extract_versions(data: Any) -> List[str]:
    """Pull versions from a madison ``f=json`` response, newest-first.

    Shape (a one-element list; ``[]`` for an unknown package)::

        [ { "<pkg>": { "<suite>": { "<version>": {<metadata>}, ... },
                       "<suite>-security": { ... }, ... } } ]

    The same version recurs across suites (e.g. ``oldstable`` and its
    ``oldstable-debug`` shadow); collect across every suite, dedup, then
    sort with the dpkg comparator so the newest version is first (matching
    the other registry clients' contract).
    """
    if not isinstance(data, list):
        return []
    seen: set = set()
    out: List[str] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        for suites in entry.values():
            if not isinstance(suites, dict):
                continue
            for versions in suites.values():
                if not isinstance(versions, dict):
                    continue
                for ver in versions:
                    if isinstance(ver, str) and ver not in seen:
                        seen.add(ver)
                        out.append(ver)
    out.sort(key=functools.cmp_to_key(_debian_compare), reverse=True)
    return out


__all__ = ["DebianClient"]
