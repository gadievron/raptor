"""Tests for packages.nvd.parser — Patch-tagged reference extraction."""
from __future__ import annotations

from packages.nvd.parser import extract_patch_refs


def _payload(refs: list[dict]) -> dict:
    return {"vulnerabilities": [{"cve": {"id": "CVE-TEST", "references": refs}}]}


def test_single_patch_tagged_github_commit() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb", "tags": ["Patch"]},
    ]))
    assert pairs == [("curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")]


def test_non_patch_tagged_ignored() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://github.com/x/y/commit/abc1234567890abc", "tags": ["Third Party Advisory"]},
    ]))
    assert pairs == []


def test_deduplicates() -> None:
    url = "https://github.com/x/y/commit/abcdef1234567890abcdef1234567890abcdef12"
    pairs = extract_patch_refs(_payload([
        {"url": url, "tags": ["Patch"]},
        {"url": url, "tags": ["Patch", "Third Party Advisory"]},
    ]))
    assert len(pairs) == 1


def test_embedded_url_extracted() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "Fixed by https://github.com/curl/curl/commit/172e54cda18412da73fd8eb4e444e8a5b371ca59", "tags": ["Patch"]},
    ]))
    assert len(pairs) == 1
    assert pairs[0] == ("curl/curl", "172e54cda18412da73fd8eb4e444e8a5b371ca59")


def test_short_sha_rejected() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://github.com/x/y/commit/abc123", "tags": ["Patch"]},
    ]))
    assert pairs == []


def test_kernel_shortlink_extracted() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://git.kernel.org/linus/e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c", "tags": ["Patch"]},
    ]))
    assert pairs == [("torvalds/linux", "e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c")]


def test_kernel_dance_shortlink() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://kernel.dance/abc1234567", "tags": ["Patch"]},
    ]))
    assert pairs == [("torvalds/linux", "abc1234567")]


def test_non_commit_url_ignored() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://github.com/x/y/pull/42", "tags": ["Patch"]},
        {"url": "https://bugzilla.redhat.com/show_bug.cgi?id=123", "tags": ["Patch"]},
    ]))
    assert pairs == []


def test_empty_vulnerabilities() -> None:
    assert extract_patch_refs({"vulnerabilities": []}) == []


def test_missing_vulnerabilities_key() -> None:
    assert extract_patch_refs({}) == []


def test_dot_git_suffix_stripped() -> None:
    pairs = extract_patch_refs(_payload([
        {"url": "https://github.com/Curl/Curl.git/commit/abc1234567890abc", "tags": ["Patch"]},
    ]))
    assert len(pairs) == 1
    assert pairs[0][0] == "curl/curl"
