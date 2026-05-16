"""Tier-1 extractor additions: hunk counting, per-file blobs.

Test-path heuristic tests live in ``tests/unit/test_path_classifier.py``
(the helper itself moved to ``cve_diff/core/path_classifier.py``)."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cve_diff.core.models import CommitSha, FileChange, RepoRef
from cve_diff.diffing.extractor import (
    MAX_FILE_BYTES,
    _count_hunks_per_file,
    _show_blob,
    extract_diff,
)


# ---------- hunk counting ----------

def test_count_hunks_single_file() -> None:
    diff = (
        "diff --git a/foo.c b/foo.c\n"
        "--- a/foo.c\n"
        "+++ b/foo.c\n"
        "@@ -1,3 +1,4 @@\n"
        " old\n+new1\n"
        "@@ -10,2 +11,3 @@\n"
        " old\n+new2\n"
    )
    assert _count_hunks_per_file(diff) == {"foo.c": 2}


def test_count_hunks_multi_file() -> None:
    diff = (
        "diff --git a/a.c b/a.c\n"
        "@@ -1 +1 @@\n-old\n+new\n"
        "diff --git a/b.c b/b.c\n"
        "@@ -1 +1 @@\n-old\n+new\n"
        "@@ -5 +5 @@\n-x\n+y\n"
    )
    assert _count_hunks_per_file(diff) == {"a.c": 1, "b.c": 2}


def test_count_hunks_empty_diff() -> None:
    assert _count_hunks_per_file("") == {}


# ---------- _show_blob ----------

def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True, check=True, timeout=15)
    return r.stdout.strip()


@pytest.fixture
def tiny_repo(tmp_path: Path) -> tuple[Path, str, str]:
    """Two commits: add f.c (with content A), then change to content B."""
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=15)
    _git(repo, "config", "user.email", "t@e.com")
    _git(repo, "config", "user.name", "T")
    (repo / "f.c").write_text("aaaa\n")
    _git(repo, "add", "f.c")
    _git(repo, "commit", "-q", "-m", "initial")
    sha1 = _git(repo, "rev-parse", "HEAD")
    (repo / "f.c").write_text("bbbb\n")
    _git(repo, "add", "f.c")
    _git(repo, "commit", "-q", "-m", "fix")
    sha2 = _git(repo, "rev-parse", "HEAD")
    return repo, sha1, sha2


def test_show_blob_returns_content_for_existing_file(tiny_repo) -> None:
    repo, sha1, sha2 = tiny_repo
    assert _show_blob(repo, CommitSha(sha1), "f.c", 10) == "aaaa\n"
    assert _show_blob(repo, CommitSha(sha2), "f.c", 10) == "bbbb\n"


def test_show_blob_returns_none_for_missing_path(tiny_repo) -> None:
    repo, sha1, _ = tiny_repo
    # f.c wasn't added yet at the empty-tree; a nonexistent path returns None.
    assert _show_blob(repo, CommitSha(sha1), "nonexistent.txt", 10) is None


def test_show_blob_truncates_large_file(tmp_path: Path) -> None:
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, timeout=15)
    _git(repo, "config", "user.email", "t@e.com")
    _git(repo, "config", "user.name", "T")
    big = "x" * (MAX_FILE_BYTES * 2)
    (repo / "big.txt").write_text(big)
    _git(repo, "add", "big.txt")
    _git(repo, "commit", "-q", "-m", "b")
    sha = _git(repo, "rev-parse", "HEAD")
    out = _show_blob(repo, CommitSha(sha), "big.txt", 10)
    assert out is not None
    assert "[truncated]" in out
    assert len(out.encode("utf-8")) <= MAX_FILE_BYTES + 100  # some slack for suffix


# ---------- extract_diff end-to-end produces files[] ----------

def test_extract_diff_populates_files(tiny_repo, monkeypatch) -> None:
    repo, sha1, sha2 = tiny_repo
    ref = RepoRef(
        repository_url=f"file://{repo}",
        fix_commit=CommitSha(sha2),
        introduced=None,
        canonical_score=100,
    )
    from cve_diff.diffing import shape_dynamic
    monkeypatch.setattr(shape_dynamic, "classify", lambda *a, **kw: "source")
    bundle = extract_diff(
        repo_path=repo, cve_id="CVE-TEST",
        ref=ref, commit_before=CommitSha(sha1), commit_after=CommitSha(sha2),
    )
    assert bundle.files_changed == 1
    assert len(bundle.files) == 1
    fc = bundle.files[0]
    assert isinstance(fc, FileChange)
    assert fc.path == "f.c"
    assert fc.is_test is False
    assert fc.hunks_count == 1
    assert fc.before_source == "aaaa\n"
    assert fc.after_source == "bbbb\n"
