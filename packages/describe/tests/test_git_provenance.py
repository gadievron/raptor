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

    def test_dirty_probe_never_executes_repo_configured_filters(
            self, tmp_path):
        """The described target can arrive with its own hostile .git:
        a committed `* filter=evil` .gitattributes plus
        `filter.evil.clean=<cmd>` in .git/config turns any
        worktree-re-hashing probe (`git status`, index refresh) into
        command execution at the operator's uid. The dirty flag must
        come from plumbing that never re-hashes content."""
        repo = tmp_path / "target"
        _init_repo(repo)
        marker = tmp_path / "filter-executed"
        (repo / ".gitattributes").write_text("* filter=evil\n")
        _git(repo, "add", ".gitattributes")
        _git(repo, "commit", "-m", "attrs")
        _git(repo, "config", "filter.evil.clean", f"touch {marker} && cat")
        (repo / "f.txt").write_text("edited after commit\n")

        result = detect_git_provenance(repo)

        assert result.dirty is True
        assert not marker.exists(), (
            "the repo-configured clean filter EXECUTED during the "
            "dirty probe — attacker-shipped .git config ran a command "
            "outside any sandbox"
        )

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
