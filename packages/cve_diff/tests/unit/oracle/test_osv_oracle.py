"""Unit tests for OSV oracle — mocked HTTP, no network."""
from __future__ import annotations

import json

import pytest

from tools.oracle import osv_oracle
from tools.oracle.types import Verdict

from .._http_mock import GET, POST


_OSV_URL = "https://api.osv.dev/v1/vulns/CVE-2023-38545"


def _payload(references: list[dict] | None = None, affected: list[dict] | None = None) -> dict:
    return {
        "id": "CVE-2023-38545",
        "references": references or [],
        "affected": affected or [],
    }


def test_match_exact_on_references(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "FIX", "url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    assert v.verdict == Verdict.MATCH_EXACT
    assert v.source == "osv"


def test_match_range_on_affected_events(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        affected=[{"ranges": [{"type": "GIT", "repo": "https://github.com/curl/curl",
                               "events": [{"fixed": "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}]}]}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    assert v.verdict == Verdict.MATCH_RANGE


def test_mirror_different_slug(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        affected=[{"ranges": [{"type": "GIT", "repo": "https://github.com/sourceware/glibc",
                               "events": [{"fixed": "d5dd6189d506968ed10339b4bd5412e95f1ad2bf"}]}]}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "bminor/glibc", "d5dd6189d506968ed10339b4bd5412e95f1ad2bf")
    assert v.verdict == Verdict.MIRROR_DIFFERENT_SLUG
    assert v.verdict.is_pass


def test_likely_hallucination(http) -> None:
    # OSV has a real answer; agent picked a different SHA on a different slug.
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "FIX", "url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "somerando/curl", "deadbeefcafebabe1234567890abcdef12345678")
    assert v.verdict == Verdict.LIKELY_HALLUCINATION


def test_dispute_same_slug_different_sha(http) -> None:
    # OSV has a real SHA on curl/curl; we claim a different SHA on curl/curl.
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "FIX", "url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "deadbeefcafebabe1234567890abcdef12345678")
    assert v.verdict == Verdict.DISPUTE


def test_orphan_on_404(http) -> None:
    http.add(GET, _OSV_URL, status=404)
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "abc123")
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "none"


def test_orphan_no_commit_data(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "ADVISORY", "url": "https://example.com/advisory"}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "abc123")
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "osv"


def test_dispute_when_bench_refused_but_osv_has_data(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "FIX", "url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}]
    ))
    # Empty pick simulates bench's UnsupportedSource or DiscoveryError.
    v = osv_oracle.verify("CVE-2023-38545", "", "")
    assert v.verdict == Verdict.DISPUTE
    assert "bench refused" in v.notes


def test_kernel_shortlink_maps_to_torvalds_linux(http) -> None:
    http.add(GET, _OSV_URL, json=_payload(
        references=[{"type": "FIX", "url": "https://git.kernel.org/linus/c/e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c"}]
    ))
    v = osv_oracle.verify("CVE-2023-38545", "torvalds/linux", "e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c")
    assert v.verdict == Verdict.MATCH_EXACT


def test_alias_following_recovers_ghsa_ref(http) -> None:
    """CVE record has no commit refs, but GHSA alias does.

    Primary OSV record for CVE-X returns aliases=[GHSA-xyz] and no
    references/ranges with commits. Following the alias to the GHSA
    record yields a github commit URL; oracle returns MATCH_EXACT.
    """
    # Primary CVE record: only aliases, no commits.
    http.add(GET, _OSV_URL, json={
        "id": "CVE-2023-38545",
        "aliases": ["GHSA-abcd-1234-wxyz"],
        "references": [{"type": "ADVISORY", "url": "https://example.com/a"}],
    })
    # Alias GHSA record: carries the github commit.
    http.add(GET,
                  "https://api.osv.dev/v1/vulns/GHSA-abcd-1234-wxyz",
                  json={
                      "id": "GHSA-abcd-1234-wxyz",
                      "references": [{"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"}],
                  })
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    assert v.verdict == Verdict.MATCH_EXACT
    assert "GHSA-" in v.source  # source label records the alias chain


def test_alias_following_skips_non_ghsa_aliases(http) -> None:
    """DSA/USN aliases are advisory pages, not worth fetching — should be ignored."""
    http.add(GET, _OSV_URL, json={
        "id": "CVE-2023-38545",
        "aliases": ["DSA-5000-1", "USN-1234-1"],  # neither is GHSA
        "references": [{"type": "ADVISORY", "url": "https://example.com/a"}],
    })
    v = osv_oracle.verify("CVE-2023-38545", "curl/curl", "fb4415d8")
    # No alias follow-up attempted → verdict is ORPHAN on primary only
    assert v.verdict == Verdict.ORPHAN
    assert v.source == "osv"


def test_verdict_is_pass(http) -> None:
    assert Verdict.MATCH_EXACT.is_pass
    assert Verdict.MATCH_RANGE.is_pass
    assert Verdict.MIRROR_DIFFERENT_SLUG.is_pass
    assert not Verdict.DISPUTE.is_pass
    assert not Verdict.ORPHAN.is_pass
    assert not Verdict.LIKELY_HALLUCINATION.is_pass
