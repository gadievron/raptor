"""Tests for core.url_patterns — commit URL extraction."""
from __future__ import annotations

from core.url_patterns import (
    GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE,
    extract_github_slug,
    is_github_url,
    is_gitlab_url,
    is_kernel_org_url,
    normalize_slug,
)


def test_github_commit_url_extraction() -> None:
    m = GITHUB_COMMIT_URL_RE.search(
        "https://github.com/curl/curl/commit/fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"
    )
    assert m
    assert m.group(1) == "curl/curl"
    assert m.group(2) == "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"


def test_github_commit_url_embedded_in_prose() -> None:
    m = GITHUB_COMMIT_URL_RE.search(
        "See https://github.com/owner/repo/commit/abc1234 for the fix"
    )
    assert m
    assert m.group(1) == "owner/repo"


def test_kernel_shortlink() -> None:
    m = KERNEL_SHA_URL_RE.search(
        "https://git.kernel.org/linus/e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c"
    )
    assert m
    assert m.group(1) == "e9be9d5e76e34872f0c37d72e25bc27fe9e2c54c"


def test_kernel_dance_shortlink() -> None:
    m = KERNEL_SHA_URL_RE.search("https://kernel.dance/abc1234567")
    assert m
    assert m.group(1) == "abc1234567"


def test_normalize_slug() -> None:
    assert normalize_slug("Curl/Curl.git") == "curl/curl"
    assert normalize_slug("  owner/repo  ") == "owner/repo"


def test_extract_github_slug() -> None:
    assert extract_github_slug("https://github.com/curl/curl") == "curl/curl"
    assert extract_github_slug("https://github.com/socketio/engine.io/commit/abc") == "socketio/engine.io"
    assert extract_github_slug("not a url") is None
    assert extract_github_slug("") is None


def test_is_github_url_hostname_anchored() -> None:
    assert is_github_url("https://github.com/owner/repo")
    assert not is_github_url("https://github.com.evil.com/owner/repo")
    assert not is_github_url("https://notgithub.com/owner/repo")


def test_is_gitlab_url_hostname_anchored() -> None:
    assert is_gitlab_url("https://gitlab.com/owner/repo")
    assert not is_gitlab_url("https://gitlab.com.evil.com/owner/repo")


def test_is_kernel_org_url() -> None:
    assert is_kernel_org_url("https://git.kernel.org/linus/abc123")
    assert is_kernel_org_url("https://kernel.org/")
    assert not is_kernel_org_url("https://kernel.org.evil.com/")
