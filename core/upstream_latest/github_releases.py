"""GitHub releases / tags upstream-latest lookup.

Two entry points:

* :func:`latest_release` — calls ``GET /repos/{owner}/{repo}/
  releases/latest``. GitHub already filters this to the most
  recent non-draft, non-pre-release release. Use this when the
  upstream cuts proper GitHub releases (semgrep, codeql,
  most CLI tools that ship via release assets).
* :func:`latest_tag` — calls ``GET /repos/{owner}/{repo}/tags``,
  filters to stable semver (rejecting ``-rc``, ``-beta``,
  ``.dev0`` etc.), returns the highest. Use this when the
  upstream tags releases but doesn't publish a ``releases/latest``
  marker (claude-code, some quieter projects).

Both functions take an injected ``HttpClient`` (so the egress
allowlist and the project's circuit-breaker apply) and an
optional ``JsonCache`` (24h TTL by default — the registry
state changes slowly relative to a scan cadence).

Adapted from https://github.com/gadievron/raptor/pull/467 by
Natalie Somersall — her devcontainer auto-update workflow ships
the same patterns inline; this module generalises them so other
SCA consumers (bumper subcommand, GHA freshness scanner,
cve-diff upstream resolver) share one implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from core.http import HttpClient, HttpError
from core.json import JsonCache

from ._version_filter import highest_stable

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
_DEFAULT_TTL_SECONDS = 24 * 3600


class UpstreamLookupError(Exception):
    """Raised when an upstream-latest lookup fails irrecoverably.

    Distinct from ``HttpError`` so callers (the bumper) can
    distinguish "GitHub returned 404 / 403 / 5xx" from "no usable
    tag found in the response". The bumper treats both as
    "skip this surface" — but logs them differently."""


class NoStableVersionsFound(UpstreamLookupError):
    """Raised when ``latest_tag`` finds no stable-semver tags in
    the tag list. Either the project doesn't cut tags, OR every
    tag is pre-release / non-semver shape. Caller should fall
    back to ``latest_release`` (if applicable) or skip the bump.
    """


def latest_release(
    repo: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    github_token: Optional[str] = None,
) -> str:
    """Return the ``tag_name`` of the latest stable GitHub release.

    ``repo`` is the ``owner/name`` slug.  Returns the tag verbatim
    (caller decides whether to strip a leading ``v``).

    GitHub's ``releases/latest`` endpoint already filters drafts
    + pre-releases, so we trust its choice and don't re-filter.
    If the project doesn't cut proper releases, this returns
    HTTP 404 — caller should fall back to ``latest_tag``.
    """
    url = f"{GITHUB_API_BASE}/repos/{repo}/releases/latest"
    data = _fetch_cached_json(
        url, http=http, cache=cache, ttl_seconds=ttl_seconds,
        github_token=github_token,
    )
    if not isinstance(data, dict):
        raise UpstreamLookupError(
            f"GitHub /releases/latest for {repo} returned non-object"
        )
    tag = data.get("tag_name")
    if not isinstance(tag, str) or not tag.strip():
        raise UpstreamLookupError(
            f"GitHub /releases/latest for {repo} missing tag_name"
        )
    return tag.strip()


def resolve_tag_to_sha(
    repo: str,
    tag: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    github_token: Optional[str] = None,
) -> str:
    """Resolve a tag to its 40-char commit SHA.

    Hits ``GET /repos/{repo}/git/refs/tags/{tag}``. The
    response carries ``object.sha`` which is either:
      * The commit SHA directly (lightweight tag), or
      * A tag-object SHA (annotated tag) — in which case we
        chase one more redirect via ``GET /repos/{repo}/git/
        tags/{sha}`` to get the underlying commit SHA.

    Caches the result per (repo, tag) — tag-to-SHA mappings
    are typically stable once published (the SCA git_tag_drift
    detector catches the rare cases where a tag is re-pointed).

    Used by the bumper's SHA-pinned GHA-uses path (Phase 3.b.2)
    to construct the target SHA when proposing a bump from
    ``<sha-A>  # was v6`` to ``<sha-B>  # was v7``.
    """
    url = f"{GITHUB_API_BASE}/repos/{repo}/git/refs/tags/{tag}"
    data = _fetch_cached_json(
        url, http=http, cache=cache, ttl_seconds=ttl_seconds,
        github_token=github_token,
    )
    if not isinstance(data, dict):
        raise UpstreamLookupError(
            f"GitHub /git/refs/tags/{tag} for {repo} returned non-object"
        )
    obj = data.get("object") or {}
    sha = obj.get("sha")
    obj_type = obj.get("type")
    if not isinstance(sha, str) or len(sha) != 40:
        raise UpstreamLookupError(
            f"GitHub /git/refs/tags/{tag} for {repo} missing sha"
        )
    if obj_type == "tag":
        # Annotated tag — chase the tag object to get the
        # underlying commit SHA.
        tag_url = f"{GITHUB_API_BASE}/repos/{repo}/git/tags/{sha}"
        tag_data = _fetch_cached_json(
            tag_url, http=http, cache=cache, ttl_seconds=ttl_seconds,
            github_token=github_token,
        )
        if not isinstance(tag_data, dict):
            raise UpstreamLookupError(
                f"GitHub /git/tags/{sha} for {repo} returned non-object"
            )
        inner_obj = tag_data.get("object") or {}
        inner_sha = inner_obj.get("sha")
        if not isinstance(inner_sha, str) or len(inner_sha) != 40:
            raise UpstreamLookupError(
                f"GitHub /git/tags/{sha} for {repo} missing inner sha"
            )
        return inner_sha
    return sha


def latest_tag(
    repo: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache] = None,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    github_token: Optional[str] = None,
    per_page: int = 100,
) -> str:
    """Return the highest stable-semver tag in the repo.

    Filters out pre-releases (``-rc.1``, ``-beta.2``, ``.dev0``)
    so an auto-bumper never lands a pre-release into a pin.
    Raises :class:`NoStableVersionsFound` if no tag matches the
    stable-semver shape.

    Use this when ``latest_release`` 404s (project doesn't ship
    GitHub Releases, only tags).
    """
    url = (
        f"{GITHUB_API_BASE}/repos/{repo}/tags?per_page={per_page}"
    )
    data = _fetch_cached_json(
        url, http=http, cache=cache, ttl_seconds=ttl_seconds,
        github_token=github_token,
    )
    if not isinstance(data, list):
        raise UpstreamLookupError(
            f"GitHub /tags for {repo} returned non-list"
        )
    names = [
        entry["name"] for entry in data
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    ]
    winner = highest_stable(names)
    if winner is None:
        raise NoStableVersionsFound(
            f"no stable-semver tags found for {repo}"
        )
    return winner


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _fetch_cached_json(
    url: str,
    *,
    http: HttpClient,
    cache: Optional[JsonCache],
    ttl_seconds: int,
    github_token: Optional[str],
) -> Any:
    """Cached GET-JSON wrapper.

    Cache miss → live HTTP call → store in cache.  Cache hit →
    return cached value without HTTP. Operators wanting to force
    a refresh pass ``ttl_seconds=0``.
    """
    cache_key = f"upstream_latest:gh:{url}"
    if cache is not None and ttl_seconds > 0:
        cached = cache.get(cache_key, ttl_seconds=ttl_seconds)
        if cached is not None:
            return cached
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "raptor-sca",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    try:
        data = http.get_json(url, headers=headers)
    except HttpError as exc:
        # Surface the original error with a more actionable wrapper
        # (the caller cares "did this work" / "did it 404 / 403 /
        # 5xx" — same fail-soft fallthrough either way).
        raise UpstreamLookupError(
            f"GitHub fetch failed for {url}: {exc}"
        ) from exc
    if cache is not None and ttl_seconds > 0:
        cache.put(cache_key, data, ttl_seconds=ttl_seconds)
    return data
