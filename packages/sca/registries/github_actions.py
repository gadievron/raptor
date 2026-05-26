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
authenticated quota — the underlying ``HttpClient`` reads the env
var when present.

Cache TTL: 24h. Latest-release info changes rarely; over-caching
just delays a freshness alert by a day, never produces a wrong one.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.http import HttpClient
from core.json import JsonCache, MISSING

logger = logging.getLogger(__name__)


_DEFAULT_TTL = 24 * 3600
_CACHE_KEY_PREFIX = "ghactions-latest"


class GitHubActionsClient:
    """Resolve the latest release tag for a ``<owner>/<repo>``."""

    ecosystem = "GitHub Actions"

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

    def get_latest_tag(self, owner_repo: str) -> Optional[str]:
        """Return the ``tag_name`` of the latest non-prerelease
        release for ``<owner>/<repo>``, or None on any failure.

        Sub-action paths (``actions/cache/restore``) are reduced to
        the parent repo automatically — releases live on the repo,
        not on subdirectories.
        """
        repo = self._parent_repo(owner_repo)
        if not repo:
            return None
        cache_key = f"{_CACHE_KEY_PREFIX}:{repo}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                # Cache stores the dict — extract tag. ``None`` from
                # a negative-cached failure surfaces as no tag.
                tag = (
                    cached.get("tag_name")
                    if isinstance(cached, dict) else None
                )
                return tag
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{repo}/releases/latest",
            )
        except Exception as e:                      # noqa: BLE001
            # 404, 403 (rate-limited), network — treat all as "no
            # freshness info available" rather than escalating.
            logger.debug(
                "sca.registries.github_actions: releases/latest failed for "
                "%s: %s", repo, e,
            )
            if self._cache is not None:
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
    def _parent_repo(name: str) -> Optional[str]:
        """``actions/cache/restore`` → ``actions/cache``;
        ``actions/checkout`` → ``actions/checkout``. Returns None
        for malformed names without an ``owner/repo`` prefix."""
        if "/" not in name:
            return None
        parts = name.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        return f"{parts[0]}/{parts[1]}"

    def get_repo_info(self, owner_repo: str) -> Optional[dict]:
        """Return the ``GET /repos/{owner}/{repo}`` response, or None.

        Used by the branch-protection detector to discover the
        repo's default branch (most repos use ``main`` but
        ``master``, ``develop``, ``trunk`` etc. are also in the
        wild — the API tells us authoritatively).

        Cached for 24h alongside the rest of this client's data.
        """
        if "/" not in owner_repo:
            return None
        cache_key = f"ghactions-repo:{owner_repo}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached if isinstance(cached, dict) else None
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{owner_repo}",
            )
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "sca.registries.github_actions: repo info failed for "
                "%s: %s", owner_repo, e,
            )
            if self._cache is not None:
                self._cache.put(cache_key, None, ttl_seconds=self._ttl)
            return None
        if not isinstance(data, dict):
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data

    def get_branch_protection(
        self, owner_repo: str, branch: str,
    ) -> Optional[dict]:
        """Return the ``GET /repos/{owner}/{repo}/branches/{branch}/
        protection`` response, or None on any failure.

        Returns:
            * dict — branch has protection configured; the dict's
              ``required_signatures.enabled`` key tells us whether
              signed-commits is enforced.
            * None — failures take three shapes that we don't
              distinguish here:
                - 404 Not Found: no protection rule for this branch
                  (this is itself a finding — surfaced by the caller).
                - 403: token lacks the ``administration:read`` scope
                  for this repo. Genuine permission gap; we can't
                  tell the operator's posture, so don't surface.
                - network / rate-limit: same disposition as 403.
              The caller layer treats None as "no answer available"
              and emits no finding — better silent than wrong.

        The branch-protection API requires Authenticated requests
        with the ``administration:read`` scope (or
        ``repo`` scope for legacy tokens). Anonymous requests
        always return 404. The caller is expected to configure the
        underlying ``HttpClient`` with a token; without one this
        detector silently no-ops.
        """
        if "/" not in owner_repo or not branch:
            return None
        cache_key = f"ghactions-branch-prot:{owner_repo}:{branch}"
        if self._cache is not None:
            cached = self._cache.try_get(cache_key, ttl_seconds=self._ttl)
            if cached is not MISSING:
                return cached if isinstance(cached, dict) else None
        if self._offline:
            return None
        try:
            data = self._http.get_json(
                f"https://api.github.com/repos/{owner_repo}"
                f"/branches/{branch}/protection",
            )
        except Exception as e:                      # noqa: BLE001
            # Surface 404 as a distinct sentinel so the caller can
            # tell "no protection rule" from "couldn't ask." We
            # encode it in the cache as the literal dict
            # ``{"_sentinel": "not_found"}``.
            err_str = str(e)
            is_404 = "404" in err_str or "Not Found" in err_str
            sentinel = {"_sentinel": "not_found"} if is_404 else None
            logger.debug(
                "sca.registries.github_actions: branch-protection "
                "failed for %s/%s: %s", owner_repo, branch, e,
            )
            if self._cache is not None:
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
