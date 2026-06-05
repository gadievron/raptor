"""Tests for ``packages/describe/git_provenance.py``."""

from __future__ import annotations

import subprocess
from pathlib import Path

from packages.describe.git_provenance import (
    GitProvenance,
    detect_git_provenance,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-b", "main")
    (repo / "f.txt").write_text("hello\n")
    _git(repo, "add", "f.txt")
    _git(repo, "commit", "-m", "first")


class TestDetectGitProvenance:
    def test_non_git_tree_returns_all_none(self, tmp_path):
        result = detect_git_provenance(tmp_path)
        assert result == GitProvenance(None, None, None, None)

    def test_clean_repo_populates_fields(self, tmp_path):
        _init_repo(tmp_path)
        result = detect_git_provenance(tmp_path)
        assert result.branch == "main"
        assert result.commit_short is not None
        assert 7 <= len(result.commit_short) <= 12
        assert result.dirty is False
        assert result.last_commit_date is not None
        # ISO 8601: "2026-05-30T14:22:11+00:00" — accept any timezone.
        assert "T" in result.last_commit_date

    def test_dirty_tree_flips_dirty(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "f.txt").write_text("changed\n")
        result = detect_git_provenance(tmp_path)
        assert result.dirty is True

    def test_untracked_file_counts_as_dirty(self, tmp_path):
        _init_repo(tmp_path)
        (tmp_path / "new.txt").write_text("untracked\n")
        result = detect_git_provenance(tmp_path)
        assert result.dirty is True

    def test_detached_head_branch_is_none(self, tmp_path):
        _init_repo(tmp_path)
        # Add a second commit so we have something to detach to
        (tmp_path / "f.txt").write_text("v2\n")
        _git(tmp_path, "add", "f.txt")
        _git(tmp_path, "commit", "-m", "second")
        sha = subprocess.run(
            ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        _git(tmp_path, "checkout", sha)
        result = detect_git_provenance(tmp_path)
        # Detached: symbolic-ref returns None → branch=None
        assert result.branch is None
        # But commit + dirty still readable
        assert result.commit_short is not None
        assert result.dirty is False
