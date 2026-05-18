"""Tests for ``OciRegistryClient.list_tags``.

Covers the OCI Distribution Spec ``/v2/<repo>/tags/list`` endpoint
wrapper. Auth handling (the 401-challenge-then-bearer-token
exchange) is exercised end-to-end by ``test_manifest.py``-shaped
tests; this file focuses on the tags-list-specific JSON shape,
URL construction, and error paths."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

import pytest

from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref


# ---------------------------------------------------------------------------
# Minimal HTTP / Response stubs — track URLs hit, reply with
# operator-supplied payloads.
# ---------------------------------------------------------------------------

class _StubResponse:
    def __init__(self, status_code: int, body: bytes,
                 headers: Optional[Dict[str, str]] = None):
        self.status_code = status_code
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def close(self):
        pass


class _StubHttp:
    def __init__(self, responses: Dict[str, _StubResponse]):
        self._responses = responses
        self.calls: List[Dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url,
                           "headers": kwargs.get("headers") or {}})
        if url not in self._responses:
            return _StubResponse(404, b'{"errors": []}')
        return self._responses[url]


def _ok(body: dict) -> _StubResponse:
    return _StubResponse(200, json.dumps(body).encode())


# ---------------------------------------------------------------------------
# list_tags
# ---------------------------------------------------------------------------

def test_list_tags_returns_tags_from_200_response() -> None:
    """Happy path: registry returns the tags list, we return it."""
    ref = parse_image_ref("docker.io/library/python:3.12")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _ok({"name": "library/python",
                 "tags": ["3.11", "3.12", "3.12.0", "3.12.1"]}),
    })
    client = OciRegistryClient(http)
    tags = client.list_tags(ref)
    assert tags == ["3.11", "3.12", "3.12.0", "3.12.1"]


def test_list_tags_passes_per_page() -> None:
    """``per_page`` plumbs into the ``n=`` query param so callers
    can scale up to "all the tags this registry has indexed"
    without re-fetching paginated."""
    ref = parse_image_ref("ghcr.io/anthropic/claude-code:latest")
    http = _StubHttp({
        "https://ghcr.io/v2/anthropic/claude-code/tags/list?n=500":
            _ok({"name": "anthropic/claude-code", "tags": []}),
    })
    client = OciRegistryClient(http)
    client.list_tags(ref, per_page=500)
    assert "n=500" in http.calls[0]["url"]


def test_list_tags_filters_non_string_entries() -> None:
    """Registries occasionally include ``null`` for in-progress
    pushes. Filter them out — they're not addressable tags."""
    ref = parse_image_ref("docker.io/library/python:3.12")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _ok({"name": "library/python",
                 "tags": ["3.12", None, "", "3.13"]}),
    })
    client = OciRegistryClient(http)
    tags = client.list_tags(ref)
    assert tags == ["3.12", "3.13"]


def test_list_tags_non_200_raises_registry_error() -> None:
    """5xx / 404 / etc. → ``RegistryError``. Caller decides
    whether to fall back to a different surface or skip."""
    ref = parse_image_ref("docker.io/library/no-such-image:1")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/no-such-image/tags/list?n=100":
            _StubResponse(404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}'),
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError) as exc_info:
        client.list_tags(ref)
    assert exc_info.value.status == 404


def test_list_tags_malformed_json_raises() -> None:
    """200 with non-JSON / shape regression → ``RegistryError``."""
    ref = parse_image_ref("docker.io/library/python:3.12")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _StubResponse(200, b'not json'),
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError):
        client.list_tags(ref)


def test_list_tags_missing_tags_field_raises() -> None:
    """``{"name": "x"}`` without a ``tags`` array is a server
    regression — surface as ``RegistryError`` instead of
    returning ``[]`` silently (silent-skip would mask bugs)."""
    ref = parse_image_ref("docker.io/library/python:3.12")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _ok({"name": "library/python"}),
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError):
        client.list_tags(ref)


# ---------------------------------------------------------------------------
# Link-header pagination — the ollama bug fix
# ---------------------------------------------------------------------------

def test_list_tags_follows_link_next_header() -> None:
    """The bug this fixes: Docker Hub returns ``ollama/ollama``
    tags in repository-internal index order (alphabetic-ish).
    The first page is the ``0.1.x`` line; ``0.21.x`` lives on a
    later page. Without Link-header pagination, ``latest_tag``
    recommended a downgrade (0.21.0 → 0.1.45).
    """
    ref = parse_image_ref("docker.io/ollama/ollama:0.21.0")
    page1 = _StubResponse(200, _ok_body({
        "name": "ollama/ollama",
        "tags": ["0.1.42", "0.1.43", "0.1.44", "0.1.45"],
    }), headers={
        "Link": '</v2/ollama/ollama/tags/list?n=100&last=0.1.45>; rel="next"',
    })
    page2 = _StubResponse(200, _ok_body({
        "name": "ollama/ollama",
        "tags": ["0.20.0", "0.21.0", "0.22.0"],
    }))
    http = _StubHttp({
        "https://registry-1.docker.io/v2/ollama/ollama/tags/list?n=100": page1,
        "https://registry-1.docker.io/v2/ollama/ollama/tags/list?n=100&last=0.1.45":
            page2,
    })
    client = OciRegistryClient(http)
    tags = client.list_tags(ref)
    assert "0.21.0" in tags
    assert "0.1.45" in tags
    assert len(tags) == 7


def test_list_tags_no_link_header_returns_single_page() -> None:
    """No ``Link: rel=next`` → just one page. (Existing
    behaviour preserved; this isn't a breaking change.)"""
    ref = parse_image_ref("docker.io/library/python:3.12")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/library/python/tags/list?n=100":
            _ok({"name": "library/python",
                 "tags": ["3.11", "3.12"]}),
    })
    client = OciRegistryClient(http)
    assert client.list_tags(ref) == ["3.11", "3.12"]


def test_list_tags_pagination_bounded_by_max_pages() -> None:
    """A pathological infinite ``Link`` chain would never
    terminate. ``max_pages`` (default 50) caps the walk so
    misconfigured registries don't hang the bumper."""
    # Build a Link header that points BACK to the same URL — a
    # registry bug we should be defensive against.
    bad_resp = _StubResponse(200, _ok_body({
        "name": "ouroboros/loop",
        "tags": ["a"],
    }), headers={
        "Link": '</v2/ouroboros/loop/tags/list?n=100>; rel="next"',
    })
    ref = parse_image_ref("docker.io/ouroboros/loop:a")
    http = _StubHttp({
        "https://registry-1.docker.io/v2/ouroboros/loop/tags/list?n=100":
            bad_resp,
    })
    client = OciRegistryClient(http)
    tags = client.list_tags(ref, max_pages=3)
    # 3 pages × 1 tag each = 3 entries; doesn't loop forever.
    assert len(tags) == 3


# Helper for byte-encoding test bodies inline.
def _ok_body(payload: dict) -> bytes:
    import json as _json
    return _json.dumps(payload).encode()
