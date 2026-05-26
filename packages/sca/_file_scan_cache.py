"""Per-file scan-result cache shared across the Python AST walkers.

The reachability scan and the ``python_imports`` supply-chain check
both AST-walk every ``.py`` file under ``target``. On cprofile,
those walks together account for ~8s of an ~28s mechanical scan
against /home/raptor/raptor — a sizeable chunk of the wallclock,
all of it wasted on files that haven't changed since the previous
scan.

This module wraps :class:`core.json.JsonCache` with a per-file
keying convention so each consumer's per-file result is cached
under ``sca:<consumer>:<sha256-of-file-content>``. Cache invalidation
is by content hash — if the file changes, its sha256 changes, the
old entry is orphaned (TTL_FOREVER means it lingers but is never
served), the new content gets a fresh compute + cache.

Why content hash, not mtime: build tools and editors often touch
files (rewrite-in-place, format-on-save) without changing semantic
content. mtime-based invalidation forces unnecessary recomputes.
sha256 over the file bytes is the right strict invariant.

The helper is consumer-shape-agnostic: each consumer passes its
own ``compute()`` callable that produces the cacheable result. The
cache stores the JSON-serialisable representation; consumers
serialise/deserialise as appropriate.
"""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Optional

from core.json import JsonCache, TTL_FOREVER


def file_sha256(text: str) -> str:
    """Hex sha256 over the file's UTF-8 byte representation. Used as
    the cache-key suffix; consumers don't need to compute it
    independently."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def cached_per_file(
    cache: Optional[JsonCache],
    consumer: str,
    text: str,
    compute: Callable[[], Any],
) -> Any:
    """Cache a per-file scan result keyed by SHA-256 of file content.

    Cache miss → call ``compute()``, persist its return value under
    ``sca:<consumer>:<sha256>``, return it.
    Cache hit  → return the deserialised cached value (no compute).
    No cache (``cache is None``) → just call ``compute()`` (legacy
    behaviour preserved for callers that opt out of caching).

    The result must be JSON-serialisable (lists/dicts/ints/strs).
    Consumers caching dataclass-shaped findings are responsible for
    flattening to dicts before passing to this helper and rebuilding
    on retrieval.
    """
    if cache is None:
        return compute()
    # Duck-type check: tests sometimes pass a sentinel ``object()``
    # to satisfy a parameter contract without supplying a real cache.
    # Falling through to compute is the safe legacy behaviour.
    if not hasattr(cache, "get") or not hasattr(cache, "put"):
        return compute()
    key = f"sca:{consumer}:{file_sha256(text)}"
    cached = cache.get(key, ttl_seconds=TTL_FOREVER)
    if cached is not None:
        return cached
    result = compute()
    cache.put(key, result, ttl_seconds=TTL_FOREVER)
    return result


__all__ = ["cached_per_file", "file_sha256"]
