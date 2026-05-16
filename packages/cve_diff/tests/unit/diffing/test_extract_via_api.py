"""Tests for cve_diff/diffing/extract_via_api.py — GitHub Commits API extractor."""
from __future__ import annotations

import pytest

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import RepoRef
from cve_diff.diffing import extract_via_api as eva_mod
from cve_diff.diffing.extract_via_api import extract_via_api


def _ref(repo: str = "https://github.com/torvalds/linux",
         sha: str = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619") -> RepoRef:
    return RepoRef(
        repository_url=repo,
        fix_commit=sha,
        introduced=None,
        canonical_score=100,
    )


# ---- Bug #12 defenses -------------------------------------------------------

def test_extract_via_api_rejects_head_literal() -> None:
    """`fix_commit='HEAD'` is not allowed — Bug #12."""
    # RepoRef itself rejects bad fix_commit, so call extract_via_api with a
    # ref whose .fix_commit was already constructed but bypassed (we mutate
    # the frozen field via dataclasses.replace path is blocked; build via
    # __new__-equivalent: use object.__setattr__ on a constructed instance).
    ref = _ref()
    object.__setattr__(ref, "fix_commit", "HEAD")
    with pytest.raises(AnalysisError, match="Bug #12 defense"):
        extract_via_api("CVE-2016-5195", ref)


def test_extract_via_api_rejects_branch_name() -> None:
    ref = _ref()
    object.__setattr__(ref, "fix_commit", "main")
    with pytest.raises(AnalysisError, match="Bug #12 defense"):
        extract_via_api("CVE-2016-5195", ref)


def test_extract_via_api_rejects_empty_sha() -> None:
    ref = _ref()
    object.__setattr__(ref, "fix_commit", "")
    with pytest.raises(AnalysisError, match="Bug #12 defense"):
        extract_via_api("CVE-2016-5195", ref)


def test_extract_via_api_rejects_non_hex_sha() -> None:
    ref = _ref()
    object.__setattr__(ref, "fix_commit", "v1.2.3")
    with pytest.raises(AnalysisError, match="Bug #12 defense"):
        extract_via_api("CVE-2016-5195", ref)


def test_extract_via_api_rejects_non_github_url() -> None:
    ref = _ref(repo="https://gitlab.com/foo/bar")
    with pytest.raises(AnalysisError, match="github.com URLs only"):
        extract_via_api("CVE-2016-5195", ref)


def test_extract_via_api_accepts_dotted_repo_names(monkeypatch) -> None:
    """Repos with dots in the name (``socketio/engine.io``,
    ``expressjs/express.js``, ``microsoft/vscode.dev``) must NOT be
    silently truncated to ``socketio/engine`` etc.

    Regression for the 2026-04-30 demo bug: ``_slug_of`` had its own
    inline regex that excluded ``.`` from the repo segment, so the
    extraction-agreement comparison silently fell back to
    ``single_source`` for any dotted repo. The same regex was already
    fixed in ``core.url_re.GITHUB_REPO_URL_RE`` for the OSS-bench-caught
    CVE-2022-21676 (``engine.io``) but ``_slug_of`` was a copy that
    wasn't migrated.
    """
    sha = "c0e194d4493326a1a45f9eebd64bccf81d56fbf3"
    parent_sha = "b04967b52eb1234567890abcdef1234567890abc"
    captured: dict = {}

    def fake_get_commit(slug: str, _sha: str):
        captured["slug"] = slug
        return {
            "sha": sha,
            "parents": [{"sha": parent_sha}],
            "files": [{"filename": "lib/server.js",
                       "patch": "@@ -1 +1 @@\n-old\n+new\n"}],
        }

    monkeypatch.setattr(
        "cve_diff.diffing.extract_via_api.github_client.get_commit",
        fake_get_commit,
    )
    ref = _ref(repo="https://github.com/socketio/engine.io", sha=sha)
    # Should NOT raise — the dotted repo name must round-trip through
    # the slug extractor and reach the API client unchanged.
    bundle = extract_via_api("CVE-2022-21676", ref)
    assert captured["slug"] == "socketio/engine.io"
    assert bundle.files_changed == 1


# ---- Successful extraction --------------------------------------------------

def test_extract_via_api_builds_diff_from_files(monkeypatch) -> None:
    """Happy path: API returns one file with a patch → DiffBundle has it."""
    sha = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    parent_sha = "feedfacefeedfacefeedfacefeedfacefeedface"
    payload = {
        "sha": sha,
        "parents": [{"sha": parent_sha}],
        "files": [
            {
                "filename": "src/foo.c",
                "patch": "@@ -1,3 +1,3 @@\n-bad\n+good\n",
                "additions": 1,
                "deletions": 1,
                "status": "modified",
            },
        ],
    }

    captured: dict = {}

    def fake_get_commit(slug: str, s: str):
        captured["slug"] = slug
        captured["sha"] = s
        return payload

    def fake_get_languages(slug: str):
        return {"C": 1000}

    monkeypatch.setattr(eva_mod.github_client, "get_commit", fake_get_commit)
    monkeypatch.setattr(eva_mod.github_client, "get_languages", fake_get_languages)

    bundle = extract_via_api("CVE-2016-5195", _ref(sha=sha))

    assert captured == {"slug": "torvalds/linux", "sha": sha}
    assert bundle.commit_after == sha
    assert bundle.commit_before == parent_sha
    assert bundle.files_changed == 1
    assert "diff --git a/src/foo.c b/src/foo.c" in bundle.diff_text
    assert "+good" in bundle.diff_text
    assert bundle.shape == "source"
    assert len(bundle.files) == 1
    assert bundle.files[0].path == "src/foo.c"
    assert bundle.files[0].is_test is False
    # API path doesn't return full source blobs.
    assert bundle.files[0].before_source is None
    assert bundle.files[0].after_source is None


def test_extract_via_api_marks_test_files(monkeypatch) -> None:
    sha = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    payload = {
        "sha": sha,
        "parents": [{"sha": "feed" * 10}],
        "files": [
            {"filename": "tests/test_foo.py",
             "patch": "@@ -1 +1 @@\n-old\n+new\n"},
        ],
    }
    monkeypatch.setattr(eva_mod.github_client, "get_commit",
                        lambda slug, s: payload)
    monkeypatch.setattr(eva_mod.github_client, "get_languages",
                        lambda slug: {"Python": 100})

    bundle = extract_via_api("CVE-X", _ref(sha=sha))
    assert bundle.files[0].is_test is True


# ---- Error paths ------------------------------------------------------------

def test_extract_via_api_404(monkeypatch) -> None:
    """API returns None (404 or rate-limit) → AnalysisError."""
    monkeypatch.setattr(eva_mod.github_client, "get_commit",
                        lambda slug, s: None)
    with pytest.raises(AnalysisError, match="returned no data"):
        extract_via_api("CVE-X", _ref())


def test_extract_via_api_root_commit_no_parents(monkeypatch) -> None:
    """Commit with no parents (initial commit) → AnalysisError."""
    sha = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    monkeypatch.setattr(
        eva_mod.github_client, "get_commit",
        lambda slug, s: {"sha": sha, "parents": [], "files": []},
    )
    with pytest.raises(AnalysisError, match="no parent"):
        extract_via_api("CVE-X", _ref(sha=sha))


def test_extract_via_api_empty_files(monkeypatch) -> None:
    """API returns parent but no files → AnalysisError."""
    sha = "19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619"
    monkeypatch.setattr(
        eva_mod.github_client, "get_commit",
        lambda slug, s: {
            "sha": sha,
            "parents": [{"sha": "feed" * 10}],
            "files": [],
        },
    )
    with pytest.raises(AnalysisError, match="no file changes"):
        extract_via_api("CVE-X", _ref(sha=sha))
