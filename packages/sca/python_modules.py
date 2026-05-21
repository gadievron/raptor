"""On-demand wheel-metadata fetch for Python distribution → module mapping.

Used as the third tier of dist→module resolution (after the curated
``_DIST_TO_MODULES`` map and the PEP 503 / PEP 8 lowercase fallback)
when reachability triage hits a CVE-bearing dep we still can't resolve.

Strategy: don't download the whole ``.whl`` (multi-100MB for things
like PyTorch). Use HTTP Range to fetch:

  1. The last ~64 KB of the wheel — contains the End-Of-Central-
     Directory record + part of the central directory.
  2. Whatever we still need from the central directory if the EOCD
     points further back.
  3. Just the bytes of ``<dist>-<ver>.dist-info/top_level.txt``,
     decompressed via ``zipfile``.

A wheel where the metadata is in the first kilobyte is a 3-request
fetch totalling <100 KB; the alternative — full download — would be
the entire wheel. Servers that don't honour Range requests (returning
``200 OK`` with the whole body) are detected and the result is
discarded; we fall back to ``None`` (no module mapping; reachability
becomes ``not_evaluated`` for that dep).

Caching: the result is cached forever under
``python_modules/<name>/<version>`` because PyPI versions are
immutable. Re-resolving on every run would be both wasteful and a
needless registry hit.
"""

from __future__ import annotations

import io
import logging
import zipfile
from typing import Iterable, List, Optional, Tuple

from core.http import HttpClient, HttpError
from core.json import JsonCache, TTL_FOREVER

logger = logging.getLogger(__name__)

# Hard cap on wheel size we'll touch. Anything bigger is a heavyweight
# package (PyTorch, TensorFlow) where the .dist-info we actually need
# is still tiny — but the cap defends against absurdly-sized index
# entries that might be hostile or buggy.
_DEFAULT_MAX_WHEEL_BYTES = 200 * 1024 * 1024
# Initial Range fetch covers the End-Of-Central-Directory record (22
# bytes minimum, up to ~65 KB with a tail comment) plus a generous
# slice of the central directory itself. 64 KB is the conventional
# "first guess" — covers small-to-medium wheels in one round-trip.
_TAIL_PROBE_BYTES = 64 * 1024

# ZIP magic numbers
_EOCD_SIGNATURE = b"PK\x05\x06"
_EOCD_MAX_LEN = 65557           # 22 fixed + 65535 max comment


def resolve_modules(
    dist_name: str, version: str,
    *,
    http: HttpClient, cache: Optional[JsonCache] = None,
    max_wheel_bytes: int = _DEFAULT_MAX_WHEEL_BYTES,
) -> Optional[Tuple[str, ...]]:
    """Resolve ``(dist_name, version)`` to a tuple of module names.

    Returns ``None`` when:
      - the version has no wheel on PyPI (sdist-only release),
      - every wheel exceeds ``max_wheel_bytes``,
      - the server doesn't honour Range requests,
      - the wheel parses cleanly but has no ``top_level.txt`` entry,
      - any HTTP error along the way.

    Caches a successful result forever. Caches a None forever too —
    a release without a wheel today won't grow one tomorrow, since
    PyPI versions are immutable.
    """
    if cache is not None:
        cache_key = f"python_modules/{dist_name}/{version}"
        cached = cache.get(cache_key, ttl_seconds=TTL_FOREVER)
        if cached is not None:
            return tuple(cached) if cached else None

    modules = _resolve_modules_uncached(
        dist_name, version, http=http,
        max_wheel_bytes=max_wheel_bytes,
    )
    if cache is not None:
        cache.put(cache_key, list(modules) if modules else [],
                  ttl_seconds=TTL_FOREVER)
    return modules


def _resolve_modules_uncached(
    dist_name: str, version: str, *,
    http: HttpClient, max_wheel_bytes: int,
) -> Optional[Tuple[str, ...]]:
    pypi_url = f"https://pypi.org/pypi/{dist_name}/{version}/json"
    try:
        meta = http.get_json(pypi_url, retries=0)
    except HttpError as e:
        logger.debug("python_modules: pypi metadata fetch failed: %s", e)
        return None

    wheel = _pick_smallest_wheel(meta.get("urls", []), max_wheel_bytes)
    if wheel is None:
        return None
    wheel_url, wheel_size = wheel

    try:
        ranged = _RangedHTTPFile(http, wheel_url, wheel_size)
        with zipfile.ZipFile(ranged) as zf:
            top_level_paths = [
                n for n in zf.namelist()
                if n.endswith(".dist-info/top_level.txt")
            ]
            if not top_level_paths:
                return None
            raw = zf.read(top_level_paths[0])
    except (zipfile.BadZipFile, HttpError, _RangeNotSupported) as e:
        logger.debug("python_modules: wheel parse failed for %s %s: %s",
                     dist_name, version, e)
        return None

    return _parse_top_level(raw)


def _pick_smallest_wheel(
    urls: Iterable[dict], max_bytes: int,
) -> Optional[Tuple[str, int]]:
    """Pick the smallest wheel under the size cap from a PyPI ``urls``
    list. Returns ``(url, size)`` or ``None`` if no wheel qualifies.
    """
    candidates: List[Tuple[int, str]] = []
    for entry in urls:
        if entry.get("packagetype") != "bdist_wheel":
            continue
        size = entry.get("size")
        url = entry.get("url")
        if not url or not isinstance(size, int):
            continue
        if size <= 0 or size > max_bytes:
            continue
        candidates.append((size, url))
    if not candidates:
        return None
    candidates.sort()           # smallest first
    size, url = candidates[0]
    return (url, size)


def _parse_top_level(raw: bytes) -> Optional[Tuple[str, ...]]:
    """Each non-empty, non-comment line in ``top_level.txt`` is a
    module name. Returns ``None`` for an empty file (caller falls
    back to PEP 503 guess)."""
    lines = raw.decode("utf-8", errors="replace").splitlines()
    modules = tuple(
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith("#")
    )
    return modules if modules else None


# ---------------------------------------------------------------------------
# Ranged HTTP file
# ---------------------------------------------------------------------------

class _RangeNotSupported(Exception):
    """Raised when a server returns 200 to a Range request — we can't
    proceed with a partial-fetch parse."""


class _RangedHTTPFile:
    """File-like wrapper that satisfies ``zipfile.ZipFile`` reads via
    HTTP Range requests against a single URL.

    ``zipfile`` calls ``seek(...)`` to position itself, then ``read(N)``
    to consume bytes. We intercept and translate to ``Range: bytes=X-Y``.

    Lifecycle: not thread-safe; one instance per ``ZipFile``.
    """

    def __init__(self, http: HttpClient, url: str, size: int) -> None:
        self._http = http
        self._url = url
        self._size = size
        self._pos = 0

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self._pos = offset
        elif whence == io.SEEK_CUR:
            self._pos += offset
        elif whence == io.SEEK_END:
            self._pos = self._size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        # Clamp into [0, size]; zipfile probes EOF with negative seeks.
        if self._pos < 0:
            self._pos = 0
        if self._pos > self._size:
            self._pos = self._size
        return self._pos

    def read(self, n: int = -1) -> bytes:
        if n < 0:
            n = self._size - self._pos
        if n <= 0 or self._pos >= self._size:
            return b""
        end = min(self._pos + n, self._size) - 1
        headers = {"Range": f"bytes={self._pos}-{end}"}
        resp = self._http.request(
            "GET", self._url,
            headers=headers,
            retries=0,
        )
        # 206 Partial Content is what we expect. 200 means the server
        # ignored the Range header — we're now holding the whole
        # wheel in memory and the caller's offset assumptions are
        # wrong; abort.
        if resp.status == 200:
            raise _RangeNotSupported(
                f"server returned 200 to Range request for {self._url} "
                f"— partial-fetch parse not possible"
            )
        body = resp.body
        self._pos += len(body)
        return body


__all__ = ["resolve_modules"]
