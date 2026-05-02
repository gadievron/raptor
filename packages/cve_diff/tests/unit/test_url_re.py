"""Tests for cve_diff/core/url_re.py — slug + commit URL parsing."""
from __future__ import annotations

import pytest

from cve_diff.core.url_re import (
    GITHUB_COMMIT_URL_RE,
    extract_github_slug,
    normalize_slug,
)


# ---- extract_github_slug — dotted repo names regression -----------

def test_extract_slug_keeps_dotted_repo_name() -> None:
    """Repo names with dots (``engine.io``, ``socket.io``, ``express.js``,
    ``vscode.dev``) must not be truncated. Bug caught 2026-04-26 on
    CVE-2022-21676 — old regex excluded ``.`` from the second segment to
    strip ``.git`` and silently truncated legitimate dotted names,
    producing ``sha_not_found_in_repo`` post-submit.
    """
    cases = {
        "https://github.com/socketio/engine.io": "socketio/engine.io",
        "https://github.com/socketio/socket.io": "socketio/socket.io",
        "https://github.com/expressjs/express.js": "expressjs/express.js",
        "https://github.com/microsoft/vscode.dev": "microsoft/vscode.dev",
        "https://github.com/facebook/react.js": "facebook/react.js",
    }
    for url, expected in cases.items():
        assert extract_github_slug(url) == expected, url


def test_extract_slug_strips_git_suffix() -> None:
    """``.git`` suffix stripping is handled by ``normalize_slug``;
    confirm the round-trip drops it without harming the rest of the slug."""
    assert extract_github_slug("https://github.com/aws/aws-sdk-go.git") == "aws/aws-sdk-go"
    # And the dotted-name+suffix combo:
    assert extract_github_slug("https://github.com/socketio/engine.io.git") == "socketio/engine.io"


def test_extract_slug_simple_cases() -> None:
    assert extract_github_slug("https://github.com/torvalds/linux") == "torvalds/linux"
    assert extract_github_slug("https://github.com/curl/curl") == "curl/curl"
    assert extract_github_slug("https://github.com/python/cpython") == "python/cpython"
    assert extract_github_slug("https://gitlab.com/foo/bar") is None


def test_extract_slug_lowercases() -> None:
    assert extract_github_slug("https://github.com/Curl/Curl") == "curl/curl"


def test_extract_slug_finds_embedded_url() -> None:
    """``.search()``-not-``.match()``: the slug extractor must find a
    GitHub URL even when there's leading prose. Pre-2026-05-02 used
    ``.match()`` and silently dropped any URL not at position 0 —
    OSV/NVD reference text routinely wraps the URL ("see fix at
    https://github.com/...", "Mitigated by https://github.com/..."),
    so the bug suppressed valid references from advisory pages.
    """
    cases = {
        "see fix at https://github.com/torvalds/linux": "torvalds/linux",
        "Mitigated by https://github.com/curl/curl/pull/1234": "curl/curl",
        "Reference: https://github.com/python/cpython for details":
            "python/cpython",
    }
    for url, expected in cases.items():
        assert extract_github_slug(url) == expected, url


def test_extract_slug_returns_none_for_no_match() -> None:
    assert extract_github_slug("") is None
    assert extract_github_slug("not a url") is None
    assert extract_github_slug("https://example.com/foo/bar") is None


# ---- GITHUB_COMMIT_URL_RE — already correct, just regression-cover

def test_commit_url_re_keeps_dotted_repo_name() -> None:
    """The commit-URL regex already permits ``.`` (different from
    ``GITHUB_REPO_URL_RE``); regression-test it alongside the slug fix."""
    m = GITHUB_COMMIT_URL_RE.search(
        "https://github.com/socketio/engine.io/commit/c0e194d44933bd83bf9a4b126fca68ba7bf5098c"
    )
    assert m is not None
    assert m.group(1) == "socketio/engine.io"
    assert m.group(2) == "c0e194d44933bd83bf9a4b126fca68ba7bf5098c"
