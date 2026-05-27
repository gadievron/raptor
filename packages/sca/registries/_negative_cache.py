"""Shared negative-caching helper for registry clients.

Every registry client (npm / PyPI / Maven / Cargo / RubyGems / NuGet
/ Packagist / Go / Debian / GHA / Homebrew) follows the same shape:

  1. Look up ``key`` in ``JsonCache``; return on hit.
  2. HTTP-fetch the upstream registry.
  3. On success, ``cache.put(key, payload)`` and return payload.
  4. On failure (404, network, parse, etc.), log a warning and
     return a sentinel value (``None`` for full-metadata endpoints,
     ``[]`` for version-list endpoints).

Pre-fix step 4 returned the sentinel but did NOT cache it.
Workspace-internal package names that always 404 (e.g. Grafana's
200+ ``@grafana/*`` / ``@grafana-plugins/*`` packages that aren't
published to npm) re-queried the registry on every detector call.
The May 2026 200-project sweep saw thousands of duplicate 404s
for the same names.

This helper makes negative caching the default. The cached
sentinel is returned without re-hitting the registry until the
TTL expires.

``try_get`` + ``MISSING`` distinguishes "no entry" from "entry
holds the sentinel" so the negative entry serves correctly.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from core.json import JsonCache, MISSING

logger = logging.getLogger(__name__)

# HTTP statuses that mean "the registry has no such package/version" — an
# expected, non-fatal outcome (the caller falls back to a sentinel). Distinct
# from a network/timeout/5xx error, which is a real (often transient) problem.
_NOT_FOUND_STATUSES = frozenset({404, 410})


def log_fetch_failure(
    log: logging.Logger, log_prefix: str, item_name: str, exc: Exception,
) -> None:
    """Log a registry fetch failure at the level its cause warrants.

    A 404/410 (the package or version simply isn't in the registry) is
    routine and non-fatal — log it at DEBUG so it doesn't drown the run log
    (a single SCA scan can legitimately miss hundreds of private/yanked
    names). Anything else (timeout, connection error, 5xx, parse failure) is a
    real problem worth a WARNING. ``exc`` is inspected for a ``status``
    attribute (set by :class:`core.http.HttpError`); absent it, WARNING.
    """
    status = getattr(exc, "status", None)
    level = logging.DEBUG if status in _NOT_FOUND_STATUSES else logging.WARNING
    if item_name:
        log.log(level, "%s: fetch failed for %r: %s", log_prefix, item_name, exc)
    else:
        log.log(level, "%s: fetch failed: %s", log_prefix, exc)


def fetch_or_negative_cache(
    cache: Optional[JsonCache],
    key: str,
    ttl_seconds: int,
    fetch: Callable[[], Any],
    *,
    negative_value: Any = None,
    log_prefix: str = "sca.registries",
    item_name: str = "",
) -> Any:
    """Cached-fetch helper with negative caching.

    Args:
      cache: optional ``JsonCache`` instance. ``None`` disables caching
        entirely (fetch always runs, no negatives stored).
      key: cache key.
      ttl_seconds: same TTL applies to both successful and negative
        entries. Callers wanting a shorter negative TTL can call
        :meth:`JsonCache.put` separately with the desired window.
      fetch: zero-arg callable that returns the upstream payload.
        Raised exceptions are caught and treated as negative.
      negative_value: value returned (and cached) on fetch failure.
        Defaults to ``None``; pass ``[]`` for version-list endpoints.
      log_prefix / item_name: shape the WARNING log line on failure.
    """
    if cache is not None:
        cached = cache.try_get(key, ttl_seconds=ttl_seconds)
        if cached is not MISSING:
            return cached
    try:
        data = fetch()
    except Exception as e:                                # noqa: BLE001
        log_fetch_failure(logger, log_prefix, item_name, e)
        if cache is not None:
            cache.put(key, negative_value, ttl_seconds=ttl_seconds)
        return negative_value
    if cache is not None:
        cache.put(key, data, ttl_seconds=ttl_seconds)
    return data


__all__ = ["fetch_or_negative_cache", "log_fetch_failure"]
