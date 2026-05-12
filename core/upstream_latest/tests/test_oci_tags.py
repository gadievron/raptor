"""Tests for ``core.upstream_latest.oci_tags``.

Auth handling is exercised end-to-end by
``core/oci/tests/test_client_list_tags.py``; this file focuses
on the upstream-latest semantics (stable-semver filtering,
cache integration, fallback behaviour)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import pytest

from core.oci.client import OciRegistryClient
from core.upstream_latest.github_releases import (
    NoStableVersionsFound,
    UpstreamLookupError,
)
from core.upstream_latest.oci_tags import latest_tag, list_all_tags


class _Resp:
    def __init__(self, status: int, body: bytes,
                 headers: Optional[Dict[str, str]] = None):
        self.status_code = status
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def close(self):
        pass


class _StubHttp:
    def __init__(self, responses: Dict[str, _Resp]):
        self._responses = responses
        self.calls: List[Dict] = []

    def request(self, method, url, **kw):
        self.calls.append({"method": method, "url": url})
        if url in self._responses:
            return self._responses[url]
        return _Resp(404, b'{"errors":[]}')


def _tags_response(tags: List[str]) -> _Resp:
    return _Resp(
        200,
        json.dumps({"name": "ignored", "tags": tags}).encode(),
    )


class _StubCache:
    def __init__(self):
        self.store: Dict[str, Any] = {}
        self.put_count = 0

    def get(self, key: str, *, ttl_seconds: int):
        return self.store.get(key)

    def put(self, key: str, value: Any, *, ttl_seconds: int):
        self.put_count += 1
        self.store[key] = value


# ---------------------------------------------------------------------------
# latest_tag
# ---------------------------------------------------------------------------

def test_latest_tag_picks_highest_stable_oci_tag() -> None:
    """Among a Python image's tags, pick the highest stable
    numeric tag. Tags like ``3.12-bookworm`` (variant) and
    ``latest`` (alias) are correctly rejected by the
    stable-semver filter."""
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response([
                "3.11", "3.12", "3.12.1", "3.13.0",
                "3.12-bookworm", "3.12-slim",        # variants — skip
                "latest", "main",                      # aliases — skip
            ]),
    })
    assert latest_tag("docker.io/library/python", http=http) == "3.13.0"


def test_latest_tag_no_stable_raises() -> None:
    """An image whose entire tag list is variant / alias / date
    shapes raises ``NoStableVersionsFound``."""
    http = _StubHttp({
        "https://ghcr.io/v2/foo/bar/tags/list?n=100":
            _tags_response([
                "main", "latest", "stable",
                "2024-01-15", "deadbeef",
                "3.12-alpine",
            ]),
    })
    with pytest.raises(NoStableVersionsFound):
        latest_tag("ghcr.io/foo/bar", http=http)


def test_latest_tag_registry_error_wraps_to_upstream_lookup_error() -> None:
    """Registry-layer failures (404 / 5xx / auth issues) wrap into
    ``UpstreamLookupError`` so the bumper's fail-soft fallthrough
    doesn't need to import ``RegistryError`` from core.oci."""
    http = _StubHttp({})        # everything → 404
    with pytest.raises(UpstreamLookupError):
        latest_tag("docker.io/library/no-such-image", http=http)


def test_latest_tag_short_form_image_resolves() -> None:
    """Short-form ``python`` expands to ``docker.io/library/python``
    via ``parse_image_ref``. Verifies we don't crash on a bare
    name."""
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response(["3.13.0"]),
    })
    assert latest_tag("python", http=http) == "3.13.0"


def test_latest_tag_ghcr_short_form() -> None:
    """ghcr.io repos use ``ghcr.io/<owner>/<repo>`` form."""
    http = _StubHttp({
        "https://ghcr.io/v2/anthropic/claude-code/tags/list?n=100":
            _tags_response(["2.1.138", "2.2.0", "v3.0.0"]),
    })
    assert latest_tag(
        "ghcr.io/anthropic/claude-code", http=http,
    ) == "v3.0.0"


# ---------------------------------------------------------------------------
# list_all_tags
# ---------------------------------------------------------------------------

def test_list_all_tags_returns_unfiltered() -> None:
    """``list_all_tags`` returns the full tag list including
    variants / aliases. Used for diagnostic / future-detector
    work, not for auto-bump."""
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response(["3.12", "3.12-bookworm", "latest"]),
    })
    tags = list_all_tags("docker.io/library/python", http=http)
    assert tags == ["3.12", "3.12-bookworm", "latest"]


# ---------------------------------------------------------------------------
# Cache integration
# ---------------------------------------------------------------------------

def test_cache_hit_skips_http() -> None:
    """Second call within TTL → no HTTP."""
    cache = _StubCache()
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response(["3.13.0"]),
    })
    latest_tag("docker.io/library/python", http=http, cache=cache)
    latest_tag("docker.io/library/python", http=http, cache=cache)
    # One HTTP call, two cache lookups.
    assert len(http.calls) == 1


def test_cache_key_includes_repo_and_per_page() -> None:
    """Different per_page should not collide in cache (different
    response shapes possible if the registry caps differently)."""
    cache = _StubCache()
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response(["3.13.0"]),
        "https://registry-1.docker.io/v2/library/python/tags/list?n=500":
            _tags_response(["3.13.0", "3.14.0"]),
    })
    latest_tag("docker.io/library/python", http=http, cache=cache,
                per_page=100)
    latest_tag("docker.io/library/python", http=http, cache=cache,
                per_page=500)
    # Both must hit the registry — separate cache entries.
    assert len(http.calls) == 2


def test_cache_ttl_zero_forces_refresh() -> None:
    """``ttl_seconds=0`` skips both read AND write — operator
    override for "I want the absolute latest right now"."""
    cache = _StubCache()
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _tags_response(["3.13.0"]),
    })
    latest_tag("docker.io/library/python", http=http, cache=cache,
                ttl_seconds=0)
    latest_tag("docker.io/library/python", http=http, cache=cache,
                ttl_seconds=0)
    assert len(http.calls) == 2
    assert cache.put_count == 0
