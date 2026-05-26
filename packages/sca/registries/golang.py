"""Go module proxy client.

Fetches ``https://proxy.golang.org/<module>/@v/list`` (a plain-text
newline-separated list of available versions) and returns them sorted
newest-first, with pre-releases filtered out.

The Go module proxy returns version *tags*, not metadata — yanked /
deprecated state isn't surfaced through this endpoint. For a deeper
view (pseudo-versions, retracted modules) the ``deps.dev`` API would
be needed; current scope is the simple list.

Same shape as the other registry clients.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import List, Optional

from core.json import JsonCache, MISSING
from core.http import HttpClient

from ._negative_cache import log_fetch_failure

logger = logging.getLogger(__name__)


_CACHE_KEY_PREFIX = "go-versions"
_DEFAULT_TTL = 24 * 3600


class GoClient:
    """List versions from the Go module proxy."""

    ecosystem = "Go"

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
        # Module path encoding: capital letters are encoded as ``!<lower>``
        # (Go's case-insensitive mapping). Slashes and dots are passed
        # through.
        encoded = _encode_module_path(name)
        cache_key = f"{_CACHE_KEY_PREFIX}:{name}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return list(cached) if cached else []

        if self._offline:
            return []

        url = f"https://proxy.golang.org/{encoded}/@v/list"
        try:
            raw = self._http.get_bytes(url)
            text = raw.decode("utf-8", errors="replace")
        except Exception as e:                # noqa: BLE001
            log_fetch_failure(logger, "sca.registries.golang", name, e)
            if self._cache is not None:
                self._cache.put(cache_key, [], ttl_seconds=self._ttl)
            return []

        versions = _extract_versions(text)
        if self._cache is not None:
            self._cache.put(cache_key, versions, ttl_seconds=self._ttl)
        return versions


def _encode_module_path(name: str) -> str:
    """Apply Go's case-insensitive module-path encoding.

    See https://pkg.go.dev/golang.org/x/mod/module#EscapePath — capital
    letters become ``!<lower>``. The path is otherwise passed through
    URL-encoded (slashes preserved).
    """
    out = []
    for ch in name:
        if ch.isupper():
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return urllib.parse.quote("".join(out), safe="/!@.-_")


def _extract_versions(text: str) -> List[str]:
    """Parse the proxy's newline-delimited version list.

    Lines are tags like ``v1.2.3``, ``v1.2.3-rc.1``, or pseudo-versions
    like ``v0.0.0-20210101120000-abcdef123456``. We drop pre-releases
    and pseudo-versions, leaving only stable tagged releases.
    """
    out: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not line.startswith("v"):
            continue
        # Pseudo-version detection: ``vX.Y.Z-<timestamp>-<sha>`` or
        # ``vX.Y.Z-<pre>.0.<timestamp>-<sha>`` — both have a ``-`` in the
        # tag (and so will be filtered as pre-release below).
        if "-" in line:
            continue
        out.append(line)
    out.sort(key=_semver_key, reverse=True)
    return out


def _semver_key(v: str):
    """Best-effort semver tuple for ordering."""
    bare = v.lstrip("v")
    parts = bare.split(".")
    out = []
    for p in parts:
        try:
            out.append((0, int(p)))
        except ValueError:
            out.append((1, p))
    return tuple(out)


__all__ = ["GoClient"]
