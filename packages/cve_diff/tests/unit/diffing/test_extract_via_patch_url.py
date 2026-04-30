"""Tests for cve_diff/diffing/extract_via_patch_url.py — third diff source.

The forge's raw ``<sha>.patch`` URL is a non-git, non-API-JSON
extractor. It complements the clone (git CLI) and forge API (HTTP/JSON)
paths so we can triangulate three ways. Crucially this is the FIRST
second-source coverage for cgit (kernel.org), which has no JSON API.
"""
from __future__ import annotations

import pytest

from cve_diff.core.models import RepoRef


def _ref(repo: str = "https://github.com/socketio/engine.io",
         sha: str = "c0e194d4493326a1a45f9eebd64bccf81d56fbf3") -> RepoRef:
    return RepoRef(
        repository_url=repo,
        fix_commit=sha,
        introduced=None,
        canonical_score=100,
    )


# ---- URL builder dispatch -------------------------------------------------

def test_patch_url_for_github() -> None:
    """GitHub repos yield ``github.com/<slug>/commit/<sha>.patch``."""
    from cve_diff.diffing.extract_via_patch_url import _patch_url_for
    sha = "c0e194d4493326a1a45f9eebd64bccf81d56fbf3"
    url = _patch_url_for(_ref(repo="https://github.com/socketio/engine.io",
                              sha=sha))
    assert url == f"https://github.com/socketio/engine.io/commit/{sha}.patch"


def test_patch_url_for_gitlab() -> None:
    """GitLab repos yield ``gitlab.com/<slug>/-/commit/<sha>.patch``."""
    from cve_diff.diffing.extract_via_patch_url import _patch_url_for
    sha = "deadbeef" * 5  # 40-char SHA
    url = _patch_url_for(_ref(repo="https://gitlab.com/foo/bar", sha=sha))
    assert url == f"https://gitlab.com/foo/bar/-/commit/{sha}.patch"


def test_patch_url_for_cgit_kernel_org() -> None:
    """cgit (kernel.org) yields ``?id=<sha>&format=patch``. This is the
    first non-clone source for kernel CVEs."""
    from cve_diff.diffing.extract_via_patch_url import _patch_url_for
    sha = "abc1234567890abc1234567890abc1234567890a"
    ref = _ref(repo="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
               sha=sha)
    url = _patch_url_for(ref)
    assert url is not None
    assert "format=patch" in url
    assert sha in url


def test_patch_url_for_unsupported_forge_returns_none() -> None:
    """File-system / unrecognized forges yield None — no second source
    available, caller should mark single_source."""
    from cve_diff.diffing.extract_via_patch_url import _patch_url_for
    assert _patch_url_for(_ref(repo="file:///tmp/some/repo")) is None
    assert _patch_url_for(_ref(repo="https://bitbucket.org/foo/bar")) is None
    # An unrecognized https forge with no commit-ref structure also
    # yields None (caller treats as third-source unavailable).
    assert _patch_url_for(_ref(repo="https://example.com/some/repo")) is None


# ---- Extractor end-to-end (with mocked HTTP) ------------------------------

# Sample 2-file unified-diff body, as `<sha>.patch` would return.
SAMPLE_PATCH = """\
From c0e194d4493326a1a45f9eebd64bccf81d56fbf3 Mon Sep 17 00:00:00 2001
From: Author <a@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
Subject: [PATCH] fix the bug

---
 lib/server.js | 4 ++--
 lib/socket.js | 2 +-
 2 files changed, 3 insertions(+), 3 deletions(-)

diff --git a/lib/server.js b/lib/server.js
index 1234567..89abcde 100644
--- a/lib/server.js
+++ b/lib/server.js
@@ -1,3 +1,3 @@
-old line one
+new line one
 unchanged
@@ -10,2 +10,2 @@
-another old
+another new
diff --git a/lib/socket.js b/lib/socket.js
index 2222222..3333333 100644
--- a/lib/socket.js
+++ b/lib/socket.js
@@ -5,1 +5,1 @@
-bad
+good
--
2.30.0
"""


def test_extract_via_patch_url_parses_unified_diff(monkeypatch) -> None:
    """Happy path: HTTP returns a unified-diff body; we get a DiffBundle
    with the right file count, byte count, and per-file hunk counts."""
    from cve_diff.diffing import extract_via_patch_url as evpu

    def fake_get(url, timeout=None, headers=None):
        class R:
            status_code = 200
            text = SAMPLE_PATCH
        return R()
    monkeypatch.setattr(evpu, "requests", type("M", (), {
        "get": staticmethod(fake_get),
        "RequestException": Exception,
    }))

    bundle = evpu.extract_via_patch_url("CVE-2022-21676", _ref())
    assert bundle is not None
    assert bundle.files_changed == 2
    paths = sorted(f.path for f in bundle.files)
    assert paths == ["lib/server.js", "lib/socket.js"]
    # Hunk counts: lib/server.js has 2 `@@` hunks, lib/socket.js has 1
    by_path = {f.path: f.hunks_count for f in bundle.files}
    assert by_path["lib/server.js"] == 2
    assert by_path["lib/socket.js"] == 1
    # Diff text retained as-is (the user can save it for audit)
    assert bundle.bytes_size == len(SAMPLE_PATCH.encode("utf-8"))


def test_extract_via_patch_url_returns_none_on_404(monkeypatch) -> None:
    """A 404 (commit not visible / repo gone) is NOT a pipeline error —
    it's a missing source. Caller treats absence as "third-source
    unavailable", verdict adapts."""
    from cve_diff.diffing import extract_via_patch_url as evpu

    def fake_get(url, timeout=None, headers=None):
        class R:
            status_code = 404
            text = "Not Found"
        return R()
    monkeypatch.setattr(evpu, "requests", type("M", (), {
        "get": staticmethod(fake_get),
        "RequestException": Exception,
    }))

    bundle = evpu.extract_via_patch_url("CVE-2022-21676", _ref())
    assert bundle is None


def test_extract_via_patch_url_returns_none_on_unsupported_forge() -> None:
    """A repo URL we can't map to a `.patch` URL returns None upfront —
    no HTTP call. Caller sees "third-source unavailable"."""
    from cve_diff.diffing.extract_via_patch_url import extract_via_patch_url
    bundle = extract_via_patch_url("CVE-X",
                                   _ref(repo="https://bitbucket.org/foo/bar"))
    assert bundle is None


def test_extract_via_patch_url_returns_none_on_empty_body(monkeypatch) -> None:
    """An empty / whitespace body is treated as "no diff" — bundle is
    None. (200 with empty body happens occasionally for moved repos.)"""
    from cve_diff.diffing import extract_via_patch_url as evpu

    def fake_get(url, timeout=None, headers=None):
        class R:
            status_code = 200
            text = "   \n   \n"
        return R()
    monkeypatch.setattr(evpu, "requests", type("M", (), {
        "get": staticmethod(fake_get),
        "RequestException": Exception,
    }))

    bundle = evpu.extract_via_patch_url("CVE-X", _ref())
    assert bundle is None


def test_extract_via_patch_url_swallows_network_errors(monkeypatch) -> None:
    """A connection failure is NOT a pipeline error — we just lose the
    third source. The agreement check adapts."""
    from cve_diff.diffing import extract_via_patch_url as evpu

    class _RE(Exception):
        pass

    def fake_get(url, timeout=None, headers=None):
        raise _RE("connection refused")

    monkeypatch.setattr(evpu, "requests", type("M", (), {
        "get": staticmethod(fake_get),
        "RequestException": _RE,
    }))

    bundle = evpu.extract_via_patch_url("CVE-X", _ref())
    assert bundle is None
