"""
Tests for the NVD Patch-tag discoverer. NVD's `references[].tags=["Patch"]`
is structured data most CVEs carry but we weren't consulting. Every
HTTP round-trip is mocked.
"""

from __future__ import annotations

import pytest

from cve_diff.discovery.nvd import NvdDiscoverer

from .._http_mock import GET


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Keep each test hermetic — no ambient network, no shared disk cache.

    The disk cache at `~/.cache/cve-diff/nvd/` is shared across processes
    for the real bench, but unit tests must not write to (or read from) it.
    Point `DEFAULT_CACHE_DIR` at a per-test tmp_path so the constructor
    default doesn't leak between tests or contaminate the user's cache.
    """
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(
        "cve_diff.discovery.nvd.DEFAULT_CACHE_DIR",
        tmp_path / "nvd_cache",
    )


def _nvd_payload(refs: list[dict]) -> dict:
    """Minimal NVD 2.0-shaped response wrapping ``refs``."""
    return {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-1234", "references": refs}}
        ]
    }


class TestDefaultTimeout:
    def test_default_timeout_is_at_least_thirty_seconds(self, http) -> None:
        """NVD's endpoint is slow under real load — the 2026-04-20 re-bench
        had NvdDiscoverer time out on ~all 80 CVEs with a 10s default."""
        from cve_diff.discovery.nvd import DEFAULT_TIMEOUT_S
        assert DEFAULT_TIMEOUT_S >= 30


class TestExtractsPatchTaggedGithubCommits:
    def test_single_patch_tagged_commit_becomes_tuple(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {
                    "url": "https://github.com/curl/curl/commit/172e54cda18412da73fd8eb4e444e8a5b371ca59",
                    "tags": ["Patch"],
                }
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert result.source == "nvd"
        assert len(result.tuples) == 1
        tup = result.tuples[0]
        assert tup.repository_url == "https://github.com/curl/curl"
        assert tup.fix_commit == "172e54cda18412da73fd8eb4e444e8a5b371ca59"
        assert tup.introduced is None

    def test_multiple_patch_refs_deduplicated(self, http) -> None:
        url = "https://github.com/x/y/commit/abcdef1234567890abcdef1234567890abcdef12"
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {"url": url, "tags": ["Patch"]},
                {"url": url, "tags": ["Patch", "Third Party Advisory"]},
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert len(result.tuples) == 1


class TestFiltersNonPatchTagged:
    def test_ref_without_patch_tag_is_ignored(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {
                    "url": "https://github.com/x/y/commit/abc1234567890abc",
                    "tags": ["Third Party Advisory"],
                }
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_patch_tagged_non_commit_url_is_ignored(self, http) -> None:
        """A Patch-tagged link that isn't github.com/.../commit/<sha> (e.g.
        points at a PR or an issue tracker) carries no usable SHA."""
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {"url": "https://github.com/x/y/pull/42", "tags": ["Patch"]},
                {"url": "https://bugzilla.redhat.com/show_bug.cgi?id=123", "tags": ["Patch"]},
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestExtractsEmbeddedUrls:
    """Pre-2026-05-02 the NVD URL regex used ``.match()``, which only
    matched at position 0. NVD references are routinely wrapped in
    advisory text (``"Patch: <URL>"``, ``"See <URL> for details"``);
    those references were silently dropped. ``.search()`` recovers them.
    """

    def test_url_with_leading_prose_is_extracted(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {
                    "url": (
                        "Fixed by commit "
                        "https://github.com/curl/curl/commit/"
                        "172e54cda18412da73fd8eb4e444e8a5b371ca59"
                    ),
                    "tags": ["Patch"],
                }
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert len(result.tuples) == 1
        assert result.tuples[0].repository_url == "https://github.com/curl/curl"


class TestRejectsShortShas:
    def test_sha_below_seven_chars_rejected(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {"url": "https://github.com/x/y/commit/abc123", "tags": ["Patch"]},
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestEmptyAndMissing:
    def test_no_refs_returns_none(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_cve_not_in_nvd_returns_none(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json={"vulnerabilities": []},
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_404_returns_none(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            status=404,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None

    def test_rate_limited_returns_none(self, http) -> None:
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            status=403,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is None


class TestRawIsPreservedForContext:
    def test_raw_is_full_cve_record(self, http) -> None:
        """The cve dict is preserved in `raw` so downstream can build an
        AdvisoryContext from the CPE configurations later."""
        http.add(GET,
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            json=_nvd_payload([
                {
                    "url": "https://github.com/x/y/commit/abcdef1234567890abcdef1234567890abcdef12",
                    "tags": ["Patch"],
                }
            ]),
            status=200,
        )
        result = NvdDiscoverer().fetch("CVE-2024-1234")
        assert result is not None
        assert result.raw is not None
        assert result.raw.get("id") == "CVE-2024-1234"


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


class TestRateLimitRetry:
    """429 under ProcessPoolExecutor workers is the most common NVD failure
    (public quota is 5 req/30s; 4 workers × 2 calls/CVE blows past it).
    The old behaviour was silent None return → lost CPE context → scorer
    false-passes like `CpanelInc/tech-CSI` winning CVE-2022-32250 because
    without CPE products, mismatch penalty doesn't fire on writeup repos.
    """

    def test_retries_once_on_429(self, http, monkeypatch) -> None:
        monkeypatch.setattr(
            "cve_diff.discovery.nvd._RETRY_BASE_S", 0
        )  # no real sleep in unit tests
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        http.add(GET, url, status=429)
        http.add(GET,
            url,
            json=_nvd_payload_with_cpe(["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"]),
            status=200,
        )
        payload = NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is not None
        assert payload["vulnerabilities"]

    def test_gives_up_after_max_retries(self, http, monkeypatch) -> None:
        monkeypatch.setattr("cve_diff.discovery.nvd._RETRY_BASE_S", 0)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        for _ in range(5):
            http.add(GET, url, status=429)
        payload = NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-1234")
        assert payload is None


class TestProcessLocalCache:
    """Repeated get_payload calls on the same CVE serve from the process-local
    memory cache; one network call total."""

    def test_second_call_is_served_from_cache(self, http) -> None:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        http.add(GET,
            url,
            json=_nvd_payload_with_cpe(["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"]),
            status=200,
        )
        disc = NvdDiscoverer(disk_cache_dir=None)  # disable disk so memory cache is the test
        first = disc.get_payload("CVE-2099-9999")
        assert first is not None
        second = disc.get_payload("CVE-2099-9999")
        assert second is not None
        assert len(http.calls) == 1


class TestApiKeyHeader:
    """NVD_API_KEY raises the quota from 5/30s to 50/30s. Required under
    any serious bench parallelism."""

    def test_api_key_env_sends_header(self, http, monkeypatch) -> None:
        monkeypatch.setenv("NVD_API_KEY", "test-key-123")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        http.add(GET,
            url,
            json=_nvd_payload_with_cpe(["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"]),
            status=200,
        )
        NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-9999")
        assert len(http.calls) == 1
        assert http.calls[0].headers.get("apiKey") == "test-key-123"

    def test_no_api_key_sends_no_header(self, http, monkeypatch) -> None:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        http.add(GET,
            url,
            json=_nvd_payload_with_cpe(["cpe:2.3:a:curl:curl:*:*:*:*:*:*:*:*"]),
            status=200,
        )
        NvdDiscoverer(cache_enabled=False).get_payload("CVE-2024-9998")
        assert "apiKey" not in http.calls[0].headers
