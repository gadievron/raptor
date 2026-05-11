"""Tests for ``core.upstream_latest.github_releases``."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from core.http import HttpError
from core.upstream_latest.github_releases import (
    NoStableVersionsFound,
    UpstreamLookupError,
    latest_release,
    latest_tag,
)


# ---------------------------------------------------------------------------
# Stub HttpClient — records every URL hit + headers, replies with
# operator-supplied payloads.
# ---------------------------------------------------------------------------

class _StubHttp:
    def __init__(self, urls: Dict[str, Any], *,
                 raise_on: Optional[str] = None,
                 raise_with: Optional[Exception] = None):
        self._urls = urls
        self._raise_on = raise_on
        self._raise_with = raise_with or HttpError("stub error")
        self.calls: List[Dict[str, Any]] = []

    def get_json(self, url: str, **kwargs):
        self.calls.append({"url": url, "headers": kwargs.get("headers", {})})
        if self._raise_on and self._raise_on in url:
            raise self._raise_with
        if url not in self._urls:
            raise HttpError(f"stub: no payload for {url}")
        return self._urls[url]


class _StubCache:
    def __init__(self):
        self.store: Dict[str, Any] = {}
        self.gets: List[str] = []
        self.puts: List[str] = []

    def get(self, key: str, *, ttl_seconds: int):
        self.gets.append(key)
        return self.store.get(key)

    def put(self, key: str, value: Any, *, ttl_seconds: int):
        self.puts.append(key)
        self.store[key] = value


# ---------------------------------------------------------------------------
# latest_release
# ---------------------------------------------------------------------------

def test_latest_release_returns_tag_name() -> None:
    """GitHub's ``releases/latest`` already filters drafts and
    pre-releases, so trust its choice and return ``tag_name``
    verbatim."""
    http = _StubHttp({
        "https://api.github.com/repos/semgrep/semgrep/releases/latest":
            {"tag_name": "v1.119.0", "name": "1.119.0"},
    })
    assert latest_release("semgrep/semgrep", http=http) == "v1.119.0"


def test_latest_release_passes_github_api_headers() -> None:
    """GitHub's API wants the ``vnd.github+json`` Accept header
    and the X-GitHub-Api-Version pin for predictable response
    shapes. Pre-fix some quieter projects would 200-with-empty
    bodies when the header was wrong."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http)
    headers = http.calls[0]["headers"]
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"


def test_latest_release_includes_bearer_token_when_supplied() -> None:
    """``github_token`` plumbs into the Authorization header for
    higher rate limits + access to private repos."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http, github_token="secret")
    assert http.calls[0]["headers"]["Authorization"] == "Bearer secret"


def test_latest_release_no_token_no_auth_header() -> None:
    """No token → no Authorization header (unauth at 60/hr is
    fine for individual operator runs)."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http)
    assert "Authorization" not in http.calls[0]["headers"]


def test_latest_release_http_error_wraps_to_upstream_lookup_error() -> None:
    """HTTP-layer failures (404 / 403 / 5xx) wrap into
    ``UpstreamLookupError`` so callers don't need to import
    ``HttpError`` for the fail-soft fallthrough path."""
    http = _StubHttp({}, raise_on="releases/latest",
                      raise_with=HttpError("404"))
    with pytest.raises(UpstreamLookupError) as exc_info:
        latest_release("owner/repo", http=http)
    assert "404" in str(exc_info.value)


def test_latest_release_missing_tag_name_raises() -> None:
    """If the response is JSON but missing ``tag_name``, that's
    a server-shape regression — surface as
    ``UpstreamLookupError`` rather than returning empty."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"name": "no tag_name field"},
    })
    with pytest.raises(UpstreamLookupError):
        latest_release("owner/repo", http=http)


# ---------------------------------------------------------------------------
# latest_tag
# ---------------------------------------------------------------------------

def test_latest_tag_picks_highest_stable_semver() -> None:
    """Among the tags, pick the highest stable-semver version.
    The classic case: a repo with ``v1.0.0`` / ``v1.5.0`` /
    ``v2.0.0`` should return ``v2.0.0``."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/tags?per_page=100": [
            {"name": "v1.0.0"},
            {"name": "v2.0.0"},
            {"name": "v1.5.0"},
        ],
    })
    assert latest_tag("owner/repo", http=http) == "v2.0.0"


def test_latest_tag_filters_pre_releases() -> None:
    """Reject ``-rc``, ``-beta``, ``.dev0``, ``-alpha`` shapes —
    an auto-bumper must never land a pre-release in a pin. The
    only operator-acceptable bump is to a stable tag."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/tags?per_page=100": [
            {"name": "v2.0.0-rc.1"},     # pre-release — skip
            {"name": "v2.0.0-beta.2"},    # pre-release — skip
            {"name": "v2.0.0.dev0"},      # PEP440 dev — skip
            {"name": "v2.0.0-alpha"},     # pre-release — skip
            {"name": "v1.5.0"},           # stable — winner
        ],
    })
    assert latest_tag("owner/repo", http=http) == "v1.5.0"


def test_latest_tag_no_stable_raises() -> None:
    """If EVERY tag is pre-release / non-semver-shape, raise
    ``NoStableVersionsFound`` so the bumper can fall back or
    skip the surface."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/tags?per_page=100": [
            {"name": "v1.0.0-rc.1"},
            {"name": "v0.9.0-beta"},
            {"name": "main"},
        ],
    })
    with pytest.raises(NoStableVersionsFound):
        latest_tag("owner/repo", http=http)


def test_latest_tag_handles_four_part_versions() -> None:
    """NuGet-style ``1.2.3.4`` four-part versions. The regex
    accepts 1-4 parts so a project that ships ``1.0.0.1`` →
    ``1.0.0.2`` bumps works."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/tags?per_page=100": [
            {"name": "1.0.0.1"},
            {"name": "1.0.0.5"},
            {"name": "1.0.0.3"},
        ],
    })
    assert latest_tag("owner/repo", http=http) == "1.0.0.5"


def test_latest_tag_skips_non_semver_branches() -> None:
    """Branches / non-version refs that happen to be tagged
    (``main``, ``release-foo``, ``hash-deadbeef``) are silently
    skipped."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/tags?per_page=100": [
            {"name": "main"},
            {"name": "release-2026-01"},
            {"name": "v1.2.3"},
        ],
    })
    assert latest_tag("owner/repo", http=http) == "v1.2.3"


# ---------------------------------------------------------------------------
# Cache integration
# ---------------------------------------------------------------------------

def test_cache_miss_fetches_and_stores() -> None:
    """First call cache-misses → live HTTP → put into cache."""
    cache = _StubCache()
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http, cache=cache)
    assert len(http.calls) == 1
    assert len(cache.puts) == 1


def test_cache_hit_skips_http() -> None:
    """Second call within TTL cache-hits → no HTTP call."""
    cache = _StubCache()
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http, cache=cache)
    latest_release("owner/repo", http=http, cache=cache)
    # Two cache lookups, but only one HTTP call.
    assert len(cache.gets) == 2
    assert len(http.calls) == 1


def test_cache_disabled_via_ttl_zero() -> None:
    """``ttl_seconds=0`` forces a refresh (operator override
    for "I just want the latest")."""
    cache = _StubCache()
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    latest_release("owner/repo", http=http, cache=cache, ttl_seconds=0)
    latest_release("owner/repo", http=http, cache=cache, ttl_seconds=0)
    assert len(http.calls) == 2


def test_cache_optional() -> None:
    """No cache passed → still works, just no caching layer."""
    http = _StubHttp({
        "https://api.github.com/repos/owner/repo/releases/latest":
            {"tag_name": "v1.0"},
    })
    assert latest_release("owner/repo", http=http) == "v1.0"


# ---------------------------------------------------------------------------
# resolve_tag_to_sha (Phase 3.b.2)
# ---------------------------------------------------------------------------

from core.upstream_latest.github_releases import resolve_tag_to_sha


def test_resolve_tag_lightweight_returns_commit_sha() -> None:
    """Lightweight tag (object.type == 'commit') — the
    ``object.sha`` IS the commit SHA. One API call, no
    annotated-tag chase needed."""
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/git/refs/tags/v4":
            {"object": {
                "type": "commit",
                "sha": "abcdef0123456789abcdef0123456789abcdef01",
            }},
    })
    sha = resolve_tag_to_sha("actions/checkout", "v4", http=http)
    assert sha == "abcdef0123456789abcdef0123456789abcdef01"


def test_resolve_tag_annotated_chases_to_commit_sha() -> None:
    """Annotated tag (object.type == 'tag') — the first
    response's ``object.sha`` is a TAG OBJECT, not a commit.
    Chase one more API call to get the underlying commit SHA."""
    tag_obj_sha = "1111111111111111111111111111111111111111"
    commit_sha = "2222222222222222222222222222222222222222"
    http = _StubHttp({
        "https://api.github.com/repos/actions/checkout/git/refs/tags/v4":
            {"object": {"type": "tag", "sha": tag_obj_sha}},
        f"https://api.github.com/repos/actions/checkout/git/tags/{tag_obj_sha}":
            {"object": {"type": "commit", "sha": commit_sha}},
    })
    sha = resolve_tag_to_sha("actions/checkout", "v4", http=http)
    # Resolved to the underlying commit SHA, not the tag-object SHA.
    assert sha == commit_sha


def test_resolve_tag_missing_returns_upstream_error() -> None:
    """Non-existent tag → 404 → ``UpstreamLookupError``."""
    http = _StubHttp({}, raise_on="refs/tags/", raise_with=HttpError("404"))
    with pytest.raises(UpstreamLookupError):
        resolve_tag_to_sha("actions/checkout", "v99", http=http)


def test_resolve_tag_malformed_object_raises() -> None:
    """200 with malformed ``object`` shape → UpstreamLookupError
    (rather than silently returning an invalid SHA)."""
    http = _StubHttp({
        "https://api.github.com/repos/x/y/git/refs/tags/v1":
            {"object": {"type": "commit", "sha": "too-short"}},
    })
    with pytest.raises(UpstreamLookupError):
        resolve_tag_to_sha("x/y", "v1", http=http)
