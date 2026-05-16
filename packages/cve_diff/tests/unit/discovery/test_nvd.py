"""
Tests for the NVD Patch-tag discoverer. NVD's `references[].tags=["Patch"]`
is structured data most CVEs carry but we weren't consulting. Every
HTTP round-trip is mocked at the ``_client()`` boundary.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any

import pytest

from core.http import HttpError, Response
from packages.nvd import client as nvd_client_mod
from cve_diff.discovery.nvd import NvdDiscoverer


# ---------------------------------------------------------------------------
# Stub client — replays canned responses for NVD's single endpoint
# ---------------------------------------------------------------------------


@dataclass
class _Call:
    method: str
    url: str
    headers: dict
    timeout: int | None = None


class _NvdStubClient:
    """FIFO response queue mocking ``UrllibClient.request()``.

    - status 200 → returns ``Response``
    - status >= 400 → raises ``HttpError`` (matching UrllibClient behaviour)
    """

    def __init__(self) -> None:
        self.calls: list[_Call] = []
        self._queue: list[dict[str, Any]] = []

    def add(self, *, json: Any = None, status: int = 200) -> None:
        self._queue.append({"json": json, "status": status})

    def request(
        self, method: str, url: str, *, headers: dict | None = None,
        timeout: int | None = None, retries: int = 0, **kw: Any,
    ) -> Response:
        self.calls.append(_Call(
            method=method, url=url,
            headers=dict(headers or {}), timeout=timeout,
        ))
        if not self._queue:
            raise HttpError("no mock response queued")
        spec = self._queue.pop(0) if len(self._queue) > 1 else self._queue[0]
        if spec["status"] >= 400:
            raise HttpError(
                f"HTTP {spec['status']}", status=spec["status"],
                retry_after=0 if spec["status"] == 429 else None,
            )
        body = _json.dumps(spec["json"]).encode() if spec["json"] is not None else b""
        return Response(status=spec["status"], headers={}, body=body, url=url)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Keep each test hermetic — no ambient network, no shared disk cache."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        nvd_client_mod, "DEFAULT_CACHE_DIR",
        tmp_path / "nvd_cache",
    )


@pytest.fixture
def nvd_stub(monkeypatch) -> _NvdStubClient:
    """Patches the shared NvdClient's HTTP transport."""
    stub = _NvdStubClient()
    monkeypatch.setattr(nvd_client_mod, "_default_http", lambda: stub)
    return stub


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nvd_payload(refs: list[dict]) -> dict:
    """Minimal NVD 2.0-shaped response wrapping ``refs``."""
    return {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-1234", "references": refs}}
        ]
    }


def _nvd_payload_with_cpe(cpe_entries: list[str]) -> dict:
    """Minimal NVD 2.0-shaped response with CPE configuration only."""
    return {
        "vulnerabilities": [
            {"cve": {
                "id": "CVE-2024-1234",
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{"criteria": c} for c in cpe_entries],
                    }],
                }],
                "references": [],
            }}
        ]
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDefaultTimeout:
    def test_default_timeout_is_at_least_thirty_seconds(self) -> None:
        from cve_diff.discovery.nvd import DEFAULT_TIMEOUT_S
        assert DEFAULT_TIMEOUT_S >= 30


class TestExtractsPatchTaggedGithubCommits:
    def test_single_patch_tagged_commit_becomes_tuple(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {
                "url": "https://github.com/curl/curl/commit/172e54cda18412da73fd8eb4e444e8a5b371ca59",
                "tags": ["Patch"],
            }
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert result.source == "nvd"
        assert len(result.tuples) == 1
        tup = result.tuples[0]
        assert tup.repository_url == "https://github.com/curl/curl"
        assert tup.fix_commit == "172e54cda18412da73fd8eb4e444e8a5b371ca59"
        assert tup.introduced is None

    def test_multiple_patch_refs_deduplicated(self, nvd_stub) -> None:
        url = "https://github.com/x/y/commit/abcdef1234567890abcdef1234567890abcdef12"
        nvd_stub.add(json=_nvd_payload([
            {"url": url, "tags": ["Patch"]},
            {"url": url, "tags": ["Patch", "Third Party Advisory"]},
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert len(result.tuples) == 1


class TestFiltersNonPatchTagged:
    def test_ref_without_patch_tag_is_ignored(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {
                "url": "https://github.com/x/y/commit/abc1234567890abc",
                "tags": ["Third Party Advisory"],
            }
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_patch_tagged_non_commit_url_is_ignored(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {"url": "https://github.com/x/y/pull/42", "tags": ["Patch"]},
            {"url": "https://bugzilla.redhat.com/show_bug.cgi?id=123", "tags": ["Patch"]},
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestExtractsEmbeddedUrls:
    def test_url_with_leading_prose_is_extracted(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {
                "url": (
                    "Fixed by commit "
                    "https://github.com/curl/curl/commit/"
                    "172e54cda18412da73fd8eb4e444e8a5b371ca59"
                ),
                "tags": ["Patch"],
            }
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert len(result.tuples) == 1
        assert result.tuples[0].repository_url == "https://github.com/curl/curl"


class TestRejectsShortShas:
    def test_sha_below_seven_chars_rejected(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {"url": "https://github.com/x/y/commit/abc123", "tags": ["Patch"]},
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestEmptyAndMissing:
    def test_no_refs_returns_none(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_cve_not_in_nvd_returns_none(self, nvd_stub) -> None:
        nvd_stub.add(json={"vulnerabilities": []})
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_404_returns_none(self, nvd_stub) -> None:
        nvd_stub.add(status=404)
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_rate_limited_returns_none(self, nvd_stub) -> None:
        nvd_stub.add(status=403)
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestRawIsPreservedForContext:
    def test_raw_is_full_cve_record(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload([
            {
                "url": "https://github.com/x/y/commit/abcdef1234567890abcdef1234567890abcdef12",
                "tags": ["Patch"],
            }
        ]))
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert result.raw is not None
        assert result.raw.get("id") == "CVE-2024-1234"


class TestRateLimitRetry:
    def test_retries_once_on_429(self, nvd_stub, monkeypatch) -> None:
        monkeypatch.setattr(nvd_client_mod, "_RETRY_BASE_S", 0)
        nvd_stub.add(status=429)
        nvd_stub.add(json=_nvd_payload_with_cpe(
            ["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"],
        ))
        payload = NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is not None
        assert payload["vulnerabilities"]

    def test_gives_up_after_max_retries(self, nvd_stub, monkeypatch) -> None:
        monkeypatch.setattr(nvd_client_mod, "_RETRY_BASE_S", 0)
        for _ in range(5):
            nvd_stub.add(status=429)
        payload = NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is None


class TestProcessLocalCache:
    def test_second_call_is_served_from_cache(self, nvd_stub) -> None:
        nvd_stub.add(json=_nvd_payload_with_cpe(
            ["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"],
        ))
        disc = NvdDiscoverer(disk_cache_dir=None)
        first = disc.get_payload("CVE-2099-9999")
        assert first is not None
        second = disc.get_payload("CVE-2099-9999")
        assert second is not None
        assert len(nvd_stub.calls) == 1


class TestApiKeyHeader:
    def test_api_key_env_sends_header(self, nvd_stub, monkeypatch) -> None:
        # Bug-hunt-6 batch 550 added UUID-format validation to the
        # NVD client (rejects placeholders like "test-key-123" /
        # "YOUR_KEY_HERE" before sending — they would otherwise
        # trigger 401/403 retry storms). Use a real-format UUID
        # so this happy-path test exercises the header-sending
        # behaviour rather than the validation-rejection branch.
        monkeypatch.setenv(
            "NVD_API_KEY", "12345678-1234-1234-1234-1234567890ab",
        )
        nvd_stub.add(json=_nvd_payload_with_cpe(
            ["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"],
        ))
        NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-9999")
        assert len(nvd_stub.calls) == 1
        assert (
            nvd_stub.calls[0].headers.get("apiKey")
            == "12345678-1234-1234-1234-1234567890ab"
        )

    def test_no_api_key_sends_no_header(self, nvd_stub, monkeypatch) -> None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        nvd_stub.add(json=_nvd_payload_with_cpe(
            ["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"],
        ))
        NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-9998")
        assert "apiKey" not in nvd_stub.calls[0].headers
