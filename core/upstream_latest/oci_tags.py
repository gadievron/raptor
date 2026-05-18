"""OCI registry tag-listing upstream-latest lookup.

Given an image reference (``docker.io/library/python:3.12``,
``ghcr.io/anthropic/claude-code:latest``, etc.), return the
highest stable-semver tag available for that repository on its
registry.

Two entry points:

* :func:`latest_tag` — list tags via OCI Distribution Spec
  ``/v2/<repo>/tags/list``, filter to stable-semver, pick the
  highest. Use when the image upstream tags releases with
  numeric semver shapes (``3.12.1``, ``v1.2.3``, etc.).
* :func:`list_all_tags` — return the unfiltered list (rarely
  needed; exposed for diagnostic / future-detector use).

Why not just trust the ``latest`` tag: ``latest`` is a moving
alias that the publisher can re-point at any time. Auto-bumping
to ``latest`` is the renovate/dependabot anti-pattern this whole
substrate is designed to avoid. We pin to specific stable-semver
tags instead.

Out-of-scope shapes silently filter out (filter lives in
``_version_filter``):

  * Variant tags (``3.12-bookworm``, ``3.12-slim``)
  * Date tags (``2024-01-15``)
  * Branch / commit refs (``main``, ``deadbeef``)
  * Pre-releases / dev shapes
"""

from __future__ import annotations

import logging
from typing import List, Optional

from core.http import HttpClient
from core.json import JsonCache
from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref

from ._version_filter import highest_stable
from .github_releases import (
    NoStableVersionsFound,
    UpstreamLookupError,
)

logger = logging.getLogger(__name__)

_DEFAULT_TTL_SECONDS = 24 * 3600


def latest_tag(
    image_ref: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    client: Optional[OciRegistryClient] = None,
    per_page: int = 100,
) -> str:
    """Return the highest stable-semver tag for the OCI image.

    ``image_ref`` is a Docker / OCI reference string —
    ``docker.io/library/python``, ``ghcr.io/anthropic/claude-code``,
    or short-form ``python`` (which expands to
    ``docker.io/library/python``). Tag / digest portions are
    ignored; we're looking at the whole repository's tag list.

    Caller can pass an existing ``OciRegistryClient`` (for
    credential-lookup overrides / token reuse across calls).
    Without one, a fresh client is constructed from ``http``.

    Raises:

    * :class:`NoStableVersionsFound` — no tag in the repo's tag
      list matches the stable-semver shape (caller should fall
      back to e.g. GitHub releases or skip the bump).
    * :class:`UpstreamLookupError` — registry returned a non-200
      / shape-regression / network failure.
    """
    tags = _list_tags_cached(
        image_ref, http=http, cache=cache, ttl_seconds=ttl_seconds,
        client=client, per_page=per_page,
    )
    winner = highest_stable(tags)
    if winner is None:
        raise NoStableVersionsFound(
            f"no stable-semver tags found for {image_ref}"
        )
    return winner


def list_all_tags(
    image_ref: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    client: Optional[OciRegistryClient] = None,
    per_page: int = 100,
) -> List[str]:
    """Return the full tag list, unfiltered.

    Useful for diagnostic / future-detector use cases (e.g. "list
    every patch on the current minor"). The bumper's auto-bump
    path uses :func:`latest_tag` instead — it doesn't want to see
    pre-release / variant tags.
    """
    return list(_list_tags_cached(
        image_ref, http=http, cache=cache, ttl_seconds=ttl_seconds,
        client=client, per_page=per_page,
    ))


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _list_tags_cached(
    image_ref: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache],
    ttl_seconds: int,
    client: Optional[OciRegistryClient],
    per_page: int,
) -> List[str]:
    """Cached wrapper around ``OciRegistryClient.list_tags``.

    Cache key includes the parsed registry + repository (not the
    tag — the tags-list endpoint is registry-wide for a repo
    regardless of what tag the caller asked about).
    """
    ref = parse_image_ref(image_ref)
    cache_key = (
        f"upstream_latest:oci:{ref.registry}/{ref.repository}"
        f":n={per_page}"
    )
    if cache is not None and ttl_seconds > 0:
        cached = cache.get(cache_key, ttl_seconds=ttl_seconds)
        if cached is not None and isinstance(cached, list):
            return cached
    registry_client = client or OciRegistryClient(http=http)
    try:
        tags = registry_client.list_tags(ref, per_page=per_page)
    except RegistryError as exc:
        raise UpstreamLookupError(
            f"OCI tag list failed for {image_ref}: {exc}"
        ) from exc
    if cache is not None and ttl_seconds > 0:
        cache.put(cache_key, tags, ttl_seconds=ttl_seconds)
    return tags


__all__ = ["latest_tag", "list_all_tags"]
