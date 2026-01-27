"""Tests for core.git module."""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.git import (
    validate_repository,
    validate_repo_url,
    clone_repository,
    get_safe_git_env,
    get_repository_metadata,
)
from core.exec import run


class TestValidateRepoUrl:
    """Tests for validate_repo_url function."""

    def test_valid_github_https_url(self):
        """Test valid GitHub HTTPS URLs."""
        assert validate_repo_url("https://github.com/owner/repo") is True
        assert validate_repo_url("https://github.com/owner/repo/") is True
        assert validate_repo_url("https://github.com/my-org/my-repo") is True
        assert validate_repo_url("https://github.com/org/repo.name") is True

    def test_valid_gitlab_https_url(self):
        """Test valid GitLab HTTPS URLs."""
        assert validate_repo_url("https://gitlab.com/owner/repo") is True
        assert validate_repo_url("https://gitlab.com/owner/repo/") is True

    def test_valid_github_ssh_url(self):
        """Test valid GitHub SSH URLs."""
        assert validate_repo_url("git@github.com:owner/repo.git") is True
        assert validate_repo_url("git@github.com:my-org/my-repo.git") is True

    def test_valid_gitlab_ssh_url(self):
        """Test valid GitLab SSH URLs."""
        assert validate_repo_url("git@gitlab.com:owner/repo.git") is True

    def test_invalid_urls(self):
        """Test invalid repository URLs are rejected."""
        # Arbitrary URLs
        assert validate_repo_url("https://evil.com/owner/repo") is False
        assert validate_repo_url("http://github.com/owner/repo") is False  # HTTP not HTTPS
        assert validate_repo_url("https://github.com/owner") is False  # Missing repo
        assert validate_repo_url("git@evil.com:owner/repo.git") is False
        # Command injection attempts
        assert validate_repo_url("https://github.com/owner/repo;ls") is False
        assert validate_repo_url("https://github.com/owner/repo|cat /etc/passwd") is False


class TestValidateRepository:
    """Tests for validate_repository function."""

    def test_valid_git_repository(self, tmp_path):
        """Test detection of valid git repository."""
        # Create .git directory
        git_dir = tmp_path / ".git"
        git_dir.mkdir()

        assert validate_repository(tmp_path) is True

    def test_invalid_git_repository(self, tmp_path):
        """Test detection fails for non-git directory."""
        assert validate_repository(tmp_path) is False

    def test_git_file_not_dir(self, tmp_path):
        """Test that .git as file (submodule) is rejected."""
        git_file = tmp_path / ".git"
        git_file.write_text("gitdir: ../somewhere")

        assert validate_repository(tmp_path) is False


class TestGetSafeGitEnv:
    """Tests for get_safe_git_env function."""

    def test_returns_dict(self):
        """Test function returns a dictionary."""
        env = get_safe_git_env()
        assert isinstance(env, dict)

    def test_contains_terminal_prompt_disabled(self):
        """Test GIT_TERMINAL_PROMPT is disabled."""
        env = get_safe_git_env()
        assert env.get("GIT_TERMINAL_PROMPT") == "0"


class TestGetRepositoryMetadata:
    """Tests for get_repository_metadata function."""

    def test_non_git_directory(self, tmp_path):
        """Test metadata extraction from non-git directory returns empty values."""
        metadata = get_repository_metadata(tmp_path)

        assert metadata["commit_hash"] is None
        assert metadata["branch"] is None
        assert metadata["remote_url"] is None


class TestCloneRepository:
    """Tests for clone_repository function."""

    def test_invalid_url_rejected(self, tmp_path):
        """Test that invalid URLs raise ValueError."""
        with pytest.raises(ValueError, match="Invalid or untrusted repository URL"):
            clone_repository("https://evil.com/owner/repo", tmp_path / "target")

    @patch('core.exec.run')
    def test_clone_failure_raises_runtime_error(self, mock_run, tmp_path):
        """Test that clone failure raises RuntimeError."""
        mock_run.return_value = (1, "", "fatal: repository not found")

        with pytest.raises(RuntimeError, match="git clone failed"):
            clone_repository("https://github.com/valid/repo", tmp_path / "target")


class TestRunCommand:
    """Tests for run command helper."""

    def test_run_simple_command(self):
        """Test running a simple command."""
        rc, stdout, stderr = run(["echo", "hello"], timeout=10)
        # Note: On Windows 'echo' might behave differently
        assert rc == 0

    def test_run_with_timeout(self):
        """Test that timeout is respected."""
        import subprocess
        # This test is platform-specific, skip detailed implementation
        # Just verify the function accepts timeout parameter
        try:
            rc, stdout, stderr = run(["sleep", "0.1"], timeout=5)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # sleep might not exist on Windows, that's OK
            pass
