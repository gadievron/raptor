"""Helm repository index upstream-latest lookup.

A Helm chart's ``Chart.yaml`` ``dependencies:`` block points at
chart repos by URL:

    dependencies:
      - name: postgresql
        version: 13.4.4
        repository: https://charts.bitnami.com/bitnami

To find the latest stable version of ``postgresql`` in that
repo, we GET ``<repository>/index.yaml`` — a YAML map of chart
names → ordered list of versions:

    apiVersion: v1
    entries:
      postgresql:
        - version: 13.4.4
          created: "2026-01-15T..."
          digest: sha256:...
        - version: 13.4.3
        ...

This module fetches that index (cached 24h), filters to
stable-semver, and returns the highest.

Same uniform interface as ``github_releases`` /
``oci_tags`` — injected ``HttpClient`` + optional
``JsonCache`` — so the bumper's orchestrator handles all
three registries uniformly."""

from __future__ import annotations

import logging
from typing import Any, List, Optional

from core.http import HttpClient, HttpError
from core.json import JsonCache

from ._version_filter import highest_stable
from .github_releases import (
    NoStableVersionsFound,
    UpstreamLookupError,
)

logger = logging.getLogger(__name__)

_DEFAULT_TTL_SECONDS = 24 * 3600


def latest_chart_version(
    repository: str,
    chart_name: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
) -> str:
    """Return the highest stable-semver version of ``chart_name``
    in the Helm repo at ``repository``.

    ``repository`` is the base URL — we append ``/index.yaml``
    (or accept a URL already pointing at the index file).
    ``chart_name`` is the entry key in ``index.yaml``'s ``entries``
    map.

    Raises:
      * :class:`UpstreamLookupError` — fetch failed, malformed
        YAML, or chart name not in the index.
      * :class:`NoStableVersionsFound` — chart exists in the index
        but no version matches the stable-semver shape.
    """
    index = _fetch_index_cached(
        repository, http=http, cache=cache, ttl_seconds=ttl_seconds,
    )
    entries = index.get("entries") if isinstance(index, dict) else None
    if not isinstance(entries, dict):
        raise UpstreamLookupError(
            f"Helm index at {repository} missing entries map"
        )
    versions = entries.get(chart_name)
    if not isinstance(versions, list):
        raise UpstreamLookupError(
            f"Helm index at {repository} has no entry for "
            f"chart {chart_name!r}"
        )
    raw_versions: List[str] = []
    for entry in versions:
        if not isinstance(entry, dict):
            continue
        v = entry.get("version")
        if isinstance(v, str) and v.strip():
            raw_versions.append(v.strip())
    if not raw_versions:
        raise UpstreamLookupError(
            f"Helm index entry {chart_name!r} at {repository} "
            f"has no version field"
        )
    winner = highest_stable(raw_versions)
    if winner is None:
        raise NoStableVersionsFound(
            f"no stable-semver versions of {chart_name} in "
            f"{repository}"
        )
    return winner


def _fetch_index_cached(
    repository: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache],
    ttl_seconds: int,
) -> Any:
    """Fetch + cache the index.yaml as a parsed dict.

    Cache key keyed on the normalized index URL — if two charts
    in the same repo are queried in the same run, the second
    one is a cache hit (no second HTTP call).
    """
    url = _normalize_index_url(repository)
    cache_key = f"upstream_latest:helm:{url}"
    if cache is not None and ttl_seconds > 0:
        cached = cache.get(cache_key, ttl_seconds=ttl_seconds)
        if cached is not None:
            return cached
    try:
        raw = http.get_bytes(url)
    except HttpError as exc:
        raise UpstreamLookupError(
            f"Helm index fetch failed for {url}: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UpstreamLookupError(
            f"Helm index at {url} not UTF-8: {exc}"
        ) from exc
    try:
        import yaml          # type: ignore[import-untyped]
    except ImportError as exc:
        raise UpstreamLookupError(
            f"PyYAML not installed; cannot parse Helm index"
        ) from exc
    try:
        # ``CSafeLoader`` is faster + immune to the same arbitrary-
        # code-execution path that ``Loader`` exposes via Python
        # tags. Fall back to ``SafeLoader`` when libyaml not
        # built; both are safe.
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        data = yaml.load(text, Loader=loader)   # noqa: S506
    except yaml.YAMLError as exc:
        raise UpstreamLookupError(
            f"Helm index at {url} not parseable YAML: {exc}"
        ) from exc
    if cache is not None and ttl_seconds > 0:
        cache.put(cache_key, data, ttl_seconds=ttl_seconds)
    return data


def _normalize_index_url(repository: str) -> str:
    """Append ``/index.yaml`` if the URL doesn't already end with
    it. Tolerate trailing slashes — many Chart.yaml entries write
    ``https://charts.example.com`` without the trailing slash."""
    repository = repository.rstrip("/")
    if repository.endswith(".yaml") or repository.endswith(".yml"):
        return repository
    return f"{repository}/index.yaml"
