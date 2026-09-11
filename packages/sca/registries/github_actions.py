"""GitHub Actions metadata client.

Queries the GitHub Releases API for a given action's latest stable
release tag. Used by the ``gha_freshness`` supply-chain detector to
flag actions that are multiple majors behind the current release.

API surface used:

  * ``GET /repos/{owner}/{repo}/releases/latest`` — returns the
    most recent non-prerelease, non-draft release. Most-maintained
    actions ship one. 404 means either the repo has no Releases at
    all (some action repos rely on tags only) or the repo doesn't
    exist; the caller treats both as "no freshness info".

We deliberately don't use the unauthenticated ``/repos/{owner}/{
repo}/tags`` fallback here — it returns every tag (potentially
hundreds), bloats the cache, and the caller-side semver-major
comparison is still the right thing. When ``releases/latest``
returns nothing, the freshness check just doesn't fire for that
action.

Auth: anonymous works (60/hr per-IP rate limit). Operators can
optionally set ``GITHUB_TOKEN`` in the environment for the 5000/hr
authenticated quota — this client reads the env var at construction
(or takes an explicit ``github_token``) and sends it as a Bearer
Authorization header. Whether a token is present also changes what
a 404 MEANS on the branch-protection endpoint — see
:meth:`get_branch_protection`.

Cache TTL: 24h. Latest-release info changes rarely; over-caching
just delays a freshness alert by a day, never produces a wrong one.
"""

from __future__ import annotations

import logging
import os

from core.json import MISSING, JsonCache

from ._negative_cache import should_negative_cache
from ._url import (
    UnsafeUrlComponentError,
    quote_path,
    quote_segment,
    registry_cache_key,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.http import HttpClient

logger = logging.getLogger(__name__)


_DEFAULT_TTL = 24 * 3600
_CACHE_KEY_PREFIX = "ghactions-latest"


class GitHubActionsClient:
    """Resolve the latest release tag for a ``<owner>/<repo>``."""

    ecosystem = "GitHub Actions"

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache | None = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL,
        offline: bool = False,
        github_token: str | None = None,
    ) -> None:
        self._http = http
        self._cache = cache
        self._ttl = ttl_seconds
        self._offline = offline
        # Explicit token wins; fall back to the conventional env var
        # so pipeline callers don't need new plumbing to benefit from
        # the authenticated quota (and so the branch-protection
        # detector knows whether its 404s are meaningful).
        self._github_token = github_token or os.environ.get("GITHUB_TOKEN")

    def _request_headers(self) -> dict[str, str] | None:
        if self._github_token:
            return {"Authorization": f"Bearer {self._github_token}"}
        return None

    @staticmethod
    def _encode_repo(owner_repo: str) -> str:
        """Validate + encode an ``owner/repo`` slug for URL-path use.

        Exactly two segments; each rejects traversal shapes (``..``),
        empties, whitespace, and control characters, so a hostile
        slug from a scanned workflow can't steer the API request at
        a different endpoint. Raises UnsafeUrlComponentError."""
        return quote_path(owner_repo, expected_segments=2)

    def get_latest_tag(self, owner_repo: str) -> str | None:
        """Return the ``tag_name`` of the latest non-prerelease
        release for ``<owner>/<repo>``, or None on any failure.

        Sub-action paths (``actions/cache/restore``) are reduced to
        the parent repo automatically — releases live on the repo,
        not on subdirectories.
        """
        repo = self._parent_repo(owner_repo)
        if not repo:
            return None
        try:
            encoded = self._encode_repo(repo)
        except UnsafeUrlComponentError:
            return None
        cache_key = registry_cache_key(_CACHE_KEY_PREFIX, repo)
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                # Cache stores the dict — extract tag. ``None`` from
                # a negative-cached failure surfaces as no tag.
                return (
                    cached.get("tag_name")
                    if isinstance(cached, dict) else None
                )
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{encoded}/releases/latest",
                headers=self._request_headers(),
            )
        except Exception as e:                      # noqa: BLE001
            # 404, 403 (rate-limited), network — treat all as "no
            # freshness info available" rather than escalating.
            logger.debug(
                "sca.registries.github_actions: releases/latest failed for "
                "%s: %s", repo, e,
            )
            if self._cache is not None and should_negative_cache(e):
                # Authoritative 404 (no releases / no repo) only —
                # a rate-limit 403 or network blip must not read as
                # "no releases" for a whole TTL window.
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if not isinstance(data, dict):
            return None
        # Cache the whole shape so a future caller wanting more than
        # the tag_name pays no extra round-trip.
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        tag = data.get("tag_name")
        return tag if isinstance(tag, str) else None

    @staticmethod
    def _parent_repo(name: str) -> str | None:
        """``actions/cache/restore`` → ``actions/cache``;
        ``actions/checkout`` → ``actions/checkout``. Returns None
        for malformed names without an ``owner/repo`` prefix."""
        if "/" not in name:
            return None
        parts = name.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        return f"{parts[0]}/{parts[1]}"

    def get_repo_info(self, owner_repo: str) -> dict | None:
        """Return the ``GET /repos/{owner}/{repo}`` response, or None.

        Used by the branch-protection detector to discover the
        repo's default branch (most repos use ``main`` but
        ``master``, ``develop``, ``trunk`` etc. are also in the
        wild — the API tells us authoritatively).

        Cached for 24h alongside the rest of this client's data.
        """
        if "/" not in owner_repo:
            return None
        try:
            encoded = self._encode_repo(owner_repo)
        except UnsafeUrlComponentError:
            return None
        cache_key = registry_cache_key("ghactions-repo", owner_repo)
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached if isinstance(cached, dict) else None
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{encoded}",
                headers=self._request_headers(),
            )
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "sca.registries.github_actions: repo info failed for "
                "%s: %s", owner_repo, e,
            )
            if self._cache is not None and should_negative_cache(e):
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if not isinstance(data, dict):
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_branch_protection(
        self, owner_repo: str, branch: str,
    ) -> dict | None:
        """Return the ``GET /repos/{owner}/{repo}/branches/{branch}/
        protection`` response, or None on any failure.

        Returns:
            * dict — branch has protection configured; the dict's
              ``required_signatures.enabled`` key tells us whether
              signed-commits is enforced.
            * ``{"_sentinel": "not_found"}`` — an AUTHENTICATED
              request got a 404: GitHub affirmatively says there is
              no protection rule for this branch. This is itself a
              finding — surfaced by the caller.
            * None — no answer available. Covers:
                - 404 on an ANONYMOUS request: the branch-protection
                  API requires the ``administration:read`` (or legacy
                  ``repo``) scope and returns 404 to every anonymous
                  caller regardless of the branch's actual posture —
                  such a 404 says nothing about protection and MUST
                  NOT become an "unprotected branch" finding.
                - 403: token lacks the scope for this repo. Genuine
                  permission gap; we can't tell the posture.
                - network / rate-limit / 5xx: transient; left
                  uncached so a later call retries.
              The caller layer treats None as "no answer available"
              and emits no finding — better silent than wrong.
        """
        if "/" not in owner_repo or not branch:
            return None
        try:
            encoded_repo = self._encode_repo(owner_repo)
            # Branches legitimately contain ``/`` (``release/1.0``);
            # confine to one percent-encoded segment.
            encoded_branch = quote_segment(branch, encode_slash=True)
        except UnsafeUrlComponentError:
            return None
        cache_key = registry_cache_key(
            "ghactions-branch-prot", owner_repo, branch,
        )
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached if isinstance(cached, dict) else None
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{encoded_repo}"
                f"/branches/{encoded_branch}/protection",
                headers=self._request_headers(),
            )
        except Exception as e:                      # noqa: BLE001
            # A 404 is only meaningful when we asked WITH a token —
            # anonymous requests 404 unconditionally on this endpoint,
            # so an anonymous 404 must not produce (or cache) the
            # "no protection rule" sentinel the caller turns into a
            # medium finding. ``status`` attr first (core.http
            # HttpError); message sniff kept for stub exceptions.
            err_str = str(e)
            is_404 = (
                getattr(e, "status", None) == 404
                or "404" in err_str or "Not Found" in err_str
            )
            authoritative_404 = is_404 and bool(self._github_token)
            sentinel = (
                {"_sentinel": "not_found"} if authoritative_404 else None
            )
            logger.debug(
                "sca.registries.github_actions: branch-protection "
                "failed for %s/%s: %s%s", owner_repo, branch, e,
                "" if self._github_token else
                " (anonymous request — 404 is not authoritative)",
            )
            if self._cache is not None and authoritative_404:
                self._cache.put(
                    cache_key, sentinel, ttl_seconds=self._ttl,
                )
            return sentinel
        if not isinstance(data, dict):
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data


__all__ = ["GitHubActionsClient"]
