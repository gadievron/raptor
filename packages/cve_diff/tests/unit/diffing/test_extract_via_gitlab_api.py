"""Tests for cve_diff/diffing/extract_via_gitlab_api.py.

Closes the diff-capability gap: today's extraction-agreement check only
runs for GitHub-hosted CVEs (about 90% of PASSes). For GitLab-hosted
repos (libtiff on gitlab.com, all freedesktop.org projects), the clone
path runs alone and the report shows ``extraction_agree=single_source``.

This module adds an analogous API-side extractor for GitLab — same
shape as ``extract_via_api`` for GitHub: returns a ``DiffBundle``
suitable for ``compute_extraction_agreement`` to compare against the
clone bundle.
"""
from __future__ import annotations

import json

import pytest

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import CommitSha, RepoRef


# --- _slug_of_gitlab — recognise gitlab hosts ---

def test_slug_of_gitlab_recognises_gitlab_com() -> None:
    from cve_diff.diffing.extract_via_gitlab_api import _gitlab_host_and_slug
    host, slug = _gitlab_host_and_slug("https://gitlab.com/libtiff/libtiff")
    assert host == "https://gitlab.com"
    assert slug == "libtiff/libtiff"


def test_slug_of_gitlab_recognises_self_hosted_freedesktop() -> None:
    from cve_diff.diffing.extract_via_gitlab_api import _gitlab_host_and_slug
    host, slug = _gitlab_host_and_slug("https://gitlab.freedesktop.org/xorg/xserver")
    assert host == "https://gitlab.freedesktop.org"
    assert slug == "xorg/xserver"


def test_slug_of_gitlab_returns_none_for_github() -> None:
    from cve_diff.diffing.extract_via_gitlab_api import _gitlab_host_and_slug
    assert _gitlab_host_and_slug("https://github.com/curl/curl") == (None, None)


def test_slug_of_gitlab_handles_nested_subgroups() -> None:
    """GitLab supports group/subgroup/project paths — preserve them."""
    from cve_diff.diffing.extract_via_gitlab_api import _gitlab_host_and_slug
    host, slug = _gitlab_host_and_slug(
        "https://gitlab.freedesktop.org/glvnd/libglvnd"
    )
    assert host == "https://gitlab.freedesktop.org"
    assert slug == "glvnd/libglvnd"


# --- extract_via_gitlab_api ---

def test_extract_via_gitlab_api_returns_bundle_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Successful API call yields a DiffBundle with parent SHA + per-file
    diffs, matching the shape `extract_via_api` produces for GitHub."""
    import cve_diff.diffing.extract_via_gitlab_api as mod

    captured_urls: list[str] = []

    def fake_get(url, **_kw):
        captured_urls.append(url)
        # First call: fetch the commit (for parent_ids)
        if "/commits/" in url and "/diff" not in url:
            return _FakeResp(200, {
                "id": "deadbeef0001",
                "parent_ids": ["cafebabe9999"],
                "title": "fix something",
            })
        # Second call: fetch the diff
        if url.endswith("/diff"):
            return _FakeResp(200, [
                {"old_path": "src/foo.c", "new_path": "src/foo.c",
                 "diff": "@@ -1,1 +1,1 @@\n-old\n+new\n",
                 "new_file": False, "deleted_file": False},
                {"old_path": "tests/test_foo.c", "new_path": "tests/test_foo.c",
                 "diff": "@@ -1,1 +1,2 @@\n test\n+new test\n",
                 "new_file": False, "deleted_file": False},
            ])
        return _FakeResp(404, {})

    monkeypatch.setattr(mod.requests, "get", fake_get)
    bundle = mod.extract_via_gitlab_api(
        "CVE-9999-9999",
        RepoRef(
            repository_url="https://gitlab.com/libtiff/libtiff",
            fix_commit=CommitSha("deadbeef0001"),
            introduced=None, canonical_score=100,
        ),
    )
    assert bundle.cve_id == "CVE-9999-9999"
    assert bundle.commit_after == "deadbeef0001"
    assert bundle.commit_before == "cafebabe9999"
    assert bundle.files_changed == 2
    paths = [f.path for f in bundle.files]
    assert "src/foo.c" in paths
    assert "tests/test_foo.c" in paths
    # The two API calls were made (commit metadata + diff)
    assert any("/commits/deadbeef0001/diff" in u for u in captured_urls)
    assert any("/commits/deadbeef0001" in u and "/diff" not in u for u in captured_urls)
    # URL-encoded slug
    assert "libtiff%2Flibtiff" in captured_urls[0]


def test_extract_via_gitlab_api_refuses_non_gitlab_url() -> None:
    """Non-GitLab URLs raise AnalysisError, mirroring GitHub's
    AnalysisError for non-github URLs."""
    from cve_diff.diffing.extract_via_gitlab_api import extract_via_gitlab_api
    with pytest.raises(AnalysisError):
        extract_via_gitlab_api(
            "CVE-9999-9999",
            RepoRef(
                repository_url="https://github.com/curl/curl",
                fix_commit=CommitSha("deadbeef0001"),
                introduced=None, canonical_score=100,
            ),
        )


def test_extract_via_gitlab_api_raises_on_404(monkeypatch: pytest.MonkeyPatch) -> None:
    import cve_diff.diffing.extract_via_gitlab_api as mod
    monkeypatch.setattr(mod.requests, "get",
                        lambda *_a, **_k: _FakeResp(404, {}))
    with pytest.raises(AnalysisError):
        mod.extract_via_gitlab_api(
            "CVE-9999-9999",
            RepoRef(
                repository_url="https://gitlab.com/foo/bar",
                fix_commit=CommitSha("deadbeef0001"),
                introduced=None, canonical_score=100,
            ),
        )


def test_extract_via_gitlab_api_raises_on_no_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A root commit (parent_ids: []) propagates as a clear error,
    same shape as GitHub's API path for root commits."""
    import cve_diff.diffing.extract_via_gitlab_api as mod
    monkeypatch.setattr(mod.requests, "get", lambda u, **_kw: (
        _FakeResp(200, {"id": "deadbeef0001", "parent_ids": []})
        if "/diff" not in u else _FakeResp(200, [])
    ))
    with pytest.raises(AnalysisError):
        mod.extract_via_gitlab_api(
            "CVE-9999-9999",
            RepoRef(
                repository_url="https://gitlab.com/foo/bar",
                fix_commit=CommitSha("deadbeef0001"),
                introduced=None, canonical_score=100,
            ),
        )


# --- dispatch helper ---

def test_extract_for_agreement_picks_github_for_github_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`extract_for_agreement` routes to the GitHub extractor for github URLs.

    After 2026-04-30 it now ALSO tries the patch-URL extractor for every
    forge — but for this test we only verify which JSON-API extractor
    fired. The patch-URL path is monkey-patched off so the test stays
    network-isolated.
    """
    from cve_diff.diffing import extract_via_gitlab_api as mod
    from cve_diff.diffing import extract_via_patch_url as evpu

    called = {"github": 0, "gitlab": 0}

    def fake_github(c, r):
        called["github"] += 1
        return _stub_bundle("CVE-X")

    def fake_gitlab(c, r):
        called["gitlab"] += 1
        return _stub_bundle("CVE-X")

    monkeypatch.setattr(mod, "_extract_via_api_github", fake_github)
    monkeypatch.setattr(mod, "extract_via_gitlab_api", fake_gitlab)
    monkeypatch.setattr(evpu, "extract_via_patch_url", lambda *_a, **_kw: None)
    out = mod.extract_for_agreement(
        "CVE-X", RepoRef(repository_url="https://github.com/a/b",
                         fix_commit=CommitSha("dead"), introduced=None, canonical_score=100),
    )
    assert called["github"] == 1
    assert called["gitlab"] == 0
    # New return shape: list of (method, bundle).
    assert any(m == "github_api" for m, _b in out)


def test_extract_for_agreement_picks_gitlab_for_gitlab_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`extract_for_agreement` routes to the GitLab extractor for gitlab.* URLs."""
    from cve_diff.diffing import extract_via_gitlab_api as mod
    from cve_diff.diffing import extract_via_patch_url as evpu

    called = {"github": 0, "gitlab": 0}

    def fake_github(c, r):
        called["github"] += 1
        return _stub_bundle("CVE-X")

    def fake_gitlab(c, r):
        called["gitlab"] += 1
        return _stub_bundle("CVE-X")

    monkeypatch.setattr(mod, "_extract_via_api_github", fake_github)
    monkeypatch.setattr(mod, "extract_via_gitlab_api", fake_gitlab)
    monkeypatch.setattr(evpu, "extract_via_patch_url", lambda *_a, **_kw: None)
    out = mod.extract_for_agreement(
        "CVE-X", RepoRef(repository_url="https://gitlab.com/a/b",
                         fix_commit=CommitSha("dead"), introduced=None, canonical_score=100),
    )
    assert called["github"] == 0
    assert called["gitlab"] == 1
    assert any(m == "gitlab_api" for m, _b in out)


def test_extract_for_agreement_empty_for_unsupported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For forges we don't recognize (bitbucket, plain HTTPS), neither
    JSON-API nor patch-URL extractor maps. Dispatcher returns an empty
    list — caller treats as `single_source`."""
    from cve_diff.diffing import extract_via_gitlab_api as mod
    from cve_diff.diffing import extract_via_patch_url as evpu

    # Force the patch-URL path off too — the savannah cgit case used to
    # be "unsupported" but is now reachable via patch_url; for a truly
    # unsupported forge use bitbucket.
    monkeypatch.setattr(evpu, "extract_via_patch_url", lambda *_a, **_kw: None)
    out = mod.extract_for_agreement(
        "CVE-X", RepoRef(repository_url="https://bitbucket.org/foo/bar",
                         fix_commit=CommitSha("dead"), introduced=None, canonical_score=100),
    )
    assert out == []


# --- helpers for the tests above ---

class _FakeResp:
    def __init__(self, status_code: int, body) -> None:
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


def _stub_bundle(cve_id: str):
    """Minimal DiffBundle for routing tests."""
    from cve_diff.core.models import DiffBundle
    return DiffBundle(
        cve_id=cve_id,
        repo_ref=RepoRef(repository_url="https://x", fix_commit=CommitSha("dead"),
                         introduced=None, canonical_score=100),
        commit_before=CommitSha("c0ffee"),
        commit_after=CommitSha("dead"),
        diff_text="",
        files_changed=0,
        bytes_size=0,
        shape="source",
        files=(),
    )
