"""Stage 4 (empty-diff) and Stage 5 (OSV shape) assertion tests."""
from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import CommitSha, DiffBundle, RepoRef
from cve_diff.diffing.extractor import extract_diff
from cve_diff.report.osv_schema import _assert_osv_shape, render


# ---------- Stage 4: empty-diff detection ----------

def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    )
    return r.stdout.strip()


def test_extract_diff_raises_analysis_error_on_empty_diff(tmp_path: Path, monkeypatch):
    """Identical trees at before/after: git diff returns empty; extractor raises."""
    repo = tmp_path / "origin"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    _git(repo, "config", "user.email", "t@e.com")
    _git(repo, "config", "user.name", "T")
    (repo / "f.txt").write_text("a\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-q", "-m", "one")
    sha = _git(repo, "rev-parse", "HEAD")

    ref = RepoRef(
        repository_url=f"file://{repo}",
        fix_commit=CommitSha(sha),
        introduced=None,
        canonical_score=100,
    )

    # Monkeypatch shape classifier to avoid a real GitHub fetch.
    from cve_diff.diffing import shape_dynamic
    monkeypatch.setattr(shape_dynamic, "classify", lambda *a, **kw: "source")

    with pytest.raises(AnalysisError, match="empty diff"):
        extract_diff(
            repo_path=repo, cve_id="CVE-EMPTY",
            ref=ref, commit_before=CommitSha(sha), commit_after=CommitSha(sha),
        )


# ---------- Stage 5: OSV shape assertions ----------

def _bundle(**overrides) -> DiffBundle:
    defaults = dict(
        cve_id="CVE-2023-TEST",
        repo_ref=RepoRef(
            repository_url="https://github.com/curl/curl",
            fix_commit=CommitSha("fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"),
            introduced=None,
            canonical_score=100,
        ),
        commit_before=CommitSha("parent00000000000000000000000000000000000"),
        commit_after=CommitSha("fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"),
        diff_text="some diff",
        files_changed=3,
        bytes_size=4096,
        shape="source",
    )
    defaults.update(overrides)
    return DiffBundle(**defaults)


def test_osv_shape_happy_path() -> None:
    osv = render(_bundle(), modified=datetime(2026, 4, 24, tzinfo=UTC))
    # If _assert_osv_shape didn't raise, render succeeded.
    assert osv["id"] == "CVE-2023-TEST"
    assert osv["references"][0]["type"] == "FIX"
    assert osv["affected"][0]["ranges"][0]["repo"] == "https://github.com/curl/curl"


def test_osv_shape_rejects_missing_top_level_id() -> None:
    with pytest.raises(ValueError, match="missing required field"):
        _assert_osv_shape({
            "schema_version": "1.6.0",
            "modified": "2026-04-24T00:00:00Z",
            "references": [{"url": "https://x"}],
            "affected": [{"ranges": [{"repo": "r", "events": [{"fixed": "a"}]}]}],
        })


def test_osv_shape_rejects_empty_references() -> None:
    with pytest.raises(ValueError, match="empty references"):
        _assert_osv_shape({
            "schema_version": "1.6.0", "id": "CVE-X", "modified": "now",
            "references": [],
            "affected": [{"ranges": [{"repo": "r", "events": [{"fixed": "a"}]}]}],
        })


def test_osv_shape_rejects_empty_repo() -> None:
    with pytest.raises(ValueError, match="empty repo"):
        _assert_osv_shape({
            "schema_version": "1.6.0", "id": "CVE-X", "modified": "now",
            "references": [{"url": "https://x"}],
            "affected": [{"ranges": [{"repo": "", "events": [{"fixed": "a"}]}]}],
        })


def test_osv_shape_rejects_missing_fixed_event() -> None:
    with pytest.raises(ValueError, match="no non-empty fixed event"):
        _assert_osv_shape({
            "schema_version": "1.6.0", "id": "CVE-X", "modified": "now",
            "references": [{"url": "https://x"}],
            "affected": [{"ranges": [{"repo": "r", "events": [{"introduced": "z"}]}]}],
        })


def test_osv_shape_rejects_reference_without_url() -> None:
    with pytest.raises(ValueError, match="empty url"):
        _assert_osv_shape({
            "schema_version": "1.6.0", "id": "CVE-X", "modified": "now",
            "references": [{"type": "FIX"}],  # no url
            "affected": [{"ranges": [{"repo": "r", "events": [{"fixed": "a"}]}]}],
        })
