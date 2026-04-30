"""Unit tests for NVD oracle — mocked HTTP, no network."""
from __future__ import annotations

import pytest
import responses

from cve_diff.discovery.nvd import NvdDiscoverer
from tools.oracle import nvd_oracle
from tools.oracle.types import Verdict


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@pytest.fixture(autouse=True)
def _fresh_cache(monkeypatch, tmp_path):
    """Isolate each test from the on-disk NVD cache."""
    nvd_oracle._nvd = NvdDiscoverer(cache_enabled=False)


def _nvd_payload(refs: list[dict]) -> dict:
    return {
        "vulnerabilities": [
            {"cve": {"id": "CVE-TEST", "references": refs}}
        ]
    }


@responses.activate
def test_match_exact_on_patch_tagged_commit() -> None:
    responses.add(responses.GET, _NVD_URL, json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = nvd_oracle.verify("CVE-TEST", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    assert v.verdict == Verdict.MATCH_EXACT
    assert v.source == "nvd"


@responses.activate
def test_orphan_when_no_patch_tagged_refs() -> None:
    responses.add(responses.GET, _NVD_URL, json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Third Party Advisory"]},
    ]))
    v = nvd_oracle.verify("CVE-TEST", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "nvd"


@responses.activate
def test_hallucination_when_nvd_patch_ref_disagrees() -> None:
    responses.add(responses.GET, _NVD_URL, json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = nvd_oracle.verify("CVE-TEST", "other/repo", "deadbeefcafebabe1234567890abcdef12345678")
    assert v.verdict == Verdict.LIKELY_HALLUCINATION


@responses.activate
def test_dispute_when_bench_refused_but_nvd_has_patch() -> None:
    responses.add(responses.GET, _NVD_URL, json=_nvd_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    v = nvd_oracle.verify("CVE-TEST", "", "")
    assert v.verdict == Verdict.DISPUTE


@responses.activate
def test_orphan_on_nvd_fetch_error() -> None:
    responses.add(responses.GET, _NVD_URL, status=500)
    responses.add(responses.GET, _NVD_URL, status=500)
    responses.add(responses.GET, _NVD_URL, status=500)
    responses.add(responses.GET, _NVD_URL, status=500)
    responses.add(responses.GET, _NVD_URL, status=500)
    v = nvd_oracle.verify("CVE-TEST", "curl/curl", "abc1234")
    assert v.verdict == Verdict.ORPHAN
