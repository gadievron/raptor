"""Tests for cve_diff/report/consensus.py — aggregation logic (2 methods)."""
from __future__ import annotations

import pytest

from cve_diff.report.consensus import (
    ConsensusReport,
    MethodResult,
    _extract_pair_from_url,
    _nvd_patch_tagged,
    _osv_references,
    render_markdown,
    run_consensus,
)


def test_extract_pair_from_github_url() -> None:
    pair = _extract_pair_from_url(
        "https://github.com/torvalds/linux/commit/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    )
    assert pair == ("torvalds/linux", "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619")


def test_extract_pair_from_kernel_shortlink() -> None:
    pair = _extract_pair_from_url(
        "https://git.kernel.org/linus/19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    )
    assert pair == ("torvalds/linux", "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619")


def test_extract_pair_returns_none_for_advisory_url() -> None:
    assert _extract_pair_from_url("https://nvd.nist.gov/vuln/detail/CVE-X") is None
    assert _extract_pair_from_url("") is None


def test_consensus_both_methods_agree() -> None:
    """Both methods agree on the same (slug, sha) → strong consensus."""
    methods = (
        MethodResult("OSV references", True, "acme/widget", "deadbeef1234567"),
        MethodResult("NVD Patch-tagged", True, "acme/widget", "deadbeef1234567"),
    )
    r = ConsensusReport(
        cve_id="CVE-X", methods=methods,
        consensus_slug="acme/widget", consensus_sha="deadbeef1234567",
        agreement_count=2,
    )
    md = render_markdown(r)
    assert "Both methods agree" in md
    assert r.agreement_count == 2
    assert r.attempted_count == 2


def test_consensus_disagreement() -> None:
    """Methods found different (slug, sha) — surfaces as 'No consensus'."""
    methods = (
        MethodResult("OSV references", True, "torvalds/linux", "abc1234567890def"),
        MethodResult("NVD Patch-tagged", True, "noise/repo", "ffffffffffffffff"),
    )
    r = ConsensusReport(
        cve_id="CVE-X", methods=methods,
        consensus_slug="", consensus_sha="",
        agreement_count=1,
    )
    md = render_markdown(r)
    assert "No consensus" in md
    assert r.attempted_count == 2


def test_consensus_only_one_method_found() -> None:
    """Only OSV found a pointer; NVD did not — agreement < 2, no consensus."""
    methods = (
        MethodResult("OSV references", True, "torvalds/linux", "abc1234567890def"),
        MethodResult("NVD Patch-tagged", False, detail="no Patch-tagged refs"),
    )
    r = ConsensusReport(
        cve_id="CVE-X", methods=methods,
        consensus_slug="", consensus_sha="",
        agreement_count=1,
    )
    md = render_markdown(r)
    assert "No consensus" in md
    assert "1 of 2" in md
    assert r.attempted_count == 1


def test_consensus_no_method_found() -> None:
    """Neither method found a pointer — no public source available."""
    methods = (
        MethodResult("OSV references", False, detail="OSV 404"),
        MethodResult("NVD Patch-tagged", False, detail="no Patch-tagged refs"),
    )
    r = ConsensusReport(
        cve_id="CVE-X", methods=methods,
        consensus_slug="", consensus_sha="", agreement_count=0,
    )
    md = render_markdown(r)
    assert "No method found" in md
    assert r.attempted_count == 0


def test_matches_pipeline_pick_handles_case_and_prefix() -> None:
    """Pipeline pick may be longer SHA / different case — match by prefix."""
    methods = (
        MethodResult("OSV references", True, "Acme/Widget", "deadbeef1234567"),
        MethodResult("NVD Patch-tagged", True, "Acme/Widget", "deadbeef1234567"),
    )
    r = ConsensusReport(
        cve_id="CVE-X", methods=methods,
        consensus_slug="acme/widget", consensus_sha="deadbeef1234567",
        agreement_count=2,
    )
    assert r.matches_pipeline_pick("Acme/Widget", "DEADBEEF1234567ABCDEF") is True
    assert r.matches_pipeline_pick("acme/widget", "deadbeef1234")  is True
    assert r.matches_pipeline_pick("other/repo", "deadbeef1234567") is False


# --- data-extraction layer (_osv_references, _nvd_patch_tagged) ------------
# The aggregation tests above assume each method's MethodResult; these tests
# cover the methods themselves — fetch + parse. Stubbed network for speed +
# determinism. Pre-2026-05 the entire data-extraction layer was uncovered by
# unit tests (only `run_consensus` integration via the live-NVD path).

def test_osv_references_returns_not_found_when_payload_none(monkeypatch) -> None:
    """OSV 404 / network failure → MethodResult with found=False."""
    from tools.oracle import osv_oracle
    monkeypatch.setattr(osv_oracle, "_fetch_osv", lambda _cve: None)
    r = _osv_references("CVE-9999-9999")
    assert r.found is False
    assert "OSV" in r.detail or "network" in r.detail


def test_osv_references_extracts_pair_from_references_url(monkeypatch) -> None:
    """OSV.references[].url with a github commit URL → MethodResult.found."""
    from tools.oracle import osv_oracle
    monkeypatch.setattr(osv_oracle, "_fetch_osv", lambda _cve: {
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/whatever"},
            {"type": "FIX",
             "url": "https://github.com/socketio/engine.io/commit/c0e194d4493326a1a45f9eebd64bccf81d56fbf3"},
        ],
    })
    r = _osv_references("CVE-2022-21676")
    assert r.found is True
    assert r.slug == "socketio/engine.io"
    assert r.sha.startswith("c0e194d4")


def test_osv_references_falls_back_to_affected_ranges(monkeypatch) -> None:
    """When references[] has no commit URLs, the function falls back to
    affected[].ranges[].events[].fixed for a (repo, fixed_sha) tuple."""
    from tools.oracle import osv_oracle
    monkeypatch.setattr(osv_oracle, "_fetch_osv", lambda _cve: {
        "references": [{"type": "WEB", "url": "https://example.com/blog"}],
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "repo": "https://github.com/torvalds/linux",
                "events": [
                    {"introduced": "0"},
                    {"fixed": "abc1234567890abc1234567890abc1234567890a"},
                ],
            }],
        }],
    })
    r = _osv_references("CVE-X")
    assert r.found is True
    assert r.slug == "torvalds/linux"
    assert r.sha.startswith("abc12345")


def test_osv_references_returns_not_found_when_no_commit_url(monkeypatch) -> None:
    """All references are advisory URLs (no /commit/) → not found.
    The tracker-redirect-to-writeup case from the corpus."""
    from tools.oracle import osv_oracle
    monkeypatch.setattr(osv_oracle, "_fetch_osv", lambda _cve: {
        "references": [
            {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-X"},
            {"type": "WEB", "url": "https://www.example.com/blog/cve-x"},
        ],
    })
    r = _osv_references("CVE-X")
    assert r.found is False
    assert "no commit URLs" in r.detail


def test_nvd_patch_tagged_returns_not_found_when_payload_none(monkeypatch) -> None:
    """NVD 404 / network failure → MethodResult with found=False."""
    from cve_diff.report import consensus as mod

    class _FakeNvd:
        def get_payload(self, _cve_id):
            return None
    monkeypatch.setattr("cve_diff.discovery.nvd.NvdDiscoverer", _FakeNvd)
    r = _nvd_patch_tagged("CVE-9999-9999")
    assert r.found is False
    assert "NVD" in r.detail or "network" in r.detail


def test_nvd_patch_tagged_extracts_only_patch_tagged_refs(monkeypatch) -> None:
    """A reference with tags=['Patch'] and a github commit URL is the
    canonical signal. Other refs (Vendor Advisory, Press, etc.) are
    skipped even if their URL is a commit."""
    class _FakeNvd:
        def get_payload(self, _cve_id):
            return {
                "vulnerabilities": [{
                    "cve": {
                        "references": [
                            {"url": "https://example.com/blog",
                             "tags": ["Vendor Advisory"]},
                            # Untagged commit URL — must be ignored
                            {"url": "https://github.com/wrong/repo/commit/" + "f" * 40,
                             "tags": ["Press"]},
                            # The legit one
                            {"url": "https://github.com/socketio/engine.io/commit/"
                                    "c0e194d4493326a1a45f9eebd64bccf81d56fbf3",
                             "tags": ["Patch"]},
                        ],
                    },
                }],
            }
    monkeypatch.setattr("cve_diff.discovery.nvd.NvdDiscoverer", _FakeNvd)
    r = _nvd_patch_tagged("CVE-2022-21676")
    assert r.found is True
    assert r.slug == "socketio/engine.io"
    assert r.sha.startswith("c0e194d4")


def test_nvd_patch_tagged_returns_not_found_when_no_patch_tag(monkeypatch) -> None:
    """All references are present but none are tagged 'Patch' → not found."""
    class _FakeNvd:
        def get_payload(self, _cve_id):
            return {
                "vulnerabilities": [{
                    "cve": {
                        "references": [
                            {"url": "https://example.com/advisory",
                             "tags": ["Vendor Advisory"]},
                            {"url": "https://example.com/exploit",
                             "tags": ["Exploit"]},
                        ],
                    },
                }],
            }
    monkeypatch.setattr("cve_diff.discovery.nvd.NvdDiscoverer", _FakeNvd)
    r = _nvd_patch_tagged("CVE-X")
    assert r.found is False
    assert "no Patch-tagged" in r.detail


def test_run_consensus_combines_both_methods(monkeypatch) -> None:
    """Top-level orchestrator: when both methods return MethodResults,
    ``ConsensusReport`` aggregates by (slug, sha[:12]). Two methods
    pointing at the same canonical key → agreement_count=2."""
    from cve_diff.report import consensus as mod

    monkeypatch.setattr(mod, "_osv_references", lambda _c: MethodResult(
        "OSV references", True, slug="acme/widget", sha="deadbeef" * 5,
        detail="ref",
    ))
    monkeypatch.setattr(mod, "_nvd_patch_tagged", lambda _c: MethodResult(
        "NVD Patch-tagged", True, slug="acme/widget", sha="deadbeef" * 5,
        detail="patch",
    ))
    r = run_consensus("CVE-X")
    assert r.agreement_count == 2
    assert r.attempted_count == 2
    assert r.consensus_slug == "acme/widget"
    assert r.consensus_sha.startswith("deadbeef")
