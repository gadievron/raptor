#!/usr/bin/env python3
"""
Unit tests for _clients.py module.

Tests the extracted client classes. These are mostly structural tests
since the actual API calls require network access (covered in integration tests).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.clients.gharchive import GHArchiveClient
from src.clients.git import GitClient
from src.clients.github import GitHubClient
from src.clients.wayback import WaybackClient
from src.schema.common import EvidenceSource


# =============================================================================
# GITHUB CLIENT TESTS
# =============================================================================


class TestGitHubClient:
    """Test GitHubClient structure and properties."""

    def test_source_is_github(self):
        """Source property returns GITHUB."""
        client = GitHubClient()
        assert client.source == EvidenceSource.GITHUB

    def test_base_url(self):
        """BASE_URL is GitHub API."""
        assert GitHubClient.BASE_URL == "https://api.github.com"

    def test_lazy_session_creation(self):
        """Session is created lazily."""
        client = GitHubClient()
        assert client._session is None
        # We don't call _get_session() here to avoid network call

    def test_has_required_methods(self):
        """Client has all required methods."""
        client = GitHubClient()
        assert hasattr(client, "get_commit")
        assert hasattr(client, "get_issue")
        assert hasattr(client, "get_pull_request")
        assert hasattr(client, "get_file")
        assert hasattr(client, "get_branch")
        assert hasattr(client, "get_tag")
        assert hasattr(client, "get_release")
        assert hasattr(client, "get_forks")
        assert hasattr(client, "get_repo")


# =============================================================================
# WAYBACK CLIENT TESTS
# =============================================================================


class TestWaybackClient:
    """Test WaybackClient structure and properties."""

    def test_source_is_wayback(self):
        """Source property returns WAYBACK."""
        client = WaybackClient()
        assert client.source == EvidenceSource.WAYBACK

    def test_cdx_url(self):
        """CDX_URL is correct."""
        assert "web.archive.org/cdx" in WaybackClient.CDX_URL

    def test_has_required_methods(self):
        """Client has required methods."""
        client = WaybackClient()
        assert hasattr(client, "search_cdx")
        assert hasattr(client, "get_snapshot")


# =============================================================================
# GHARCHIVE CLIENT TESTS
# =============================================================================


class TestGHArchiveClient:
    """Test GHArchiveClient structure and properties."""

    def test_source_is_gharchive(self):
        """Source property returns GHARCHIVE."""
        client = GHArchiveClient()
        assert client.source == EvidenceSource.GHARCHIVE

    def test_accepts_project_id(self):
        """Can initialize with project ID."""
        client = GHArchiveClient(project_id="my-project")
        assert client.project_id == "my-project"

    def test_lazy_client_creation(self):
        """BigQuery client is created lazily."""
        client = GHArchiveClient()
        assert client._client is None

    def test_has_query_events_method(self):
        """Client has query_events method."""
        client = GHArchiveClient()
        assert hasattr(client, "query_events")


# =============================================================================
# GIT CLIENT TESTS
# =============================================================================


class TestGitClient:
    """Test GitClient structure and properties."""

    def test_source_is_git(self):
        """Source property returns GIT."""
        client = GitClient()
        assert client.source == EvidenceSource.GIT

    def test_accepts_repo_path(self):
        """Can initialize with repo path."""
        client = GitClient(repo_path="/path/to/repo")
        assert client.repo_path == "/path/to/repo"

    def test_default_repo_path(self):
        """Default repo path is current directory."""
        client = GitClient()
        assert client.repo_path == "."

    def test_has_required_methods(self):
        """Client has required methods."""
        client = GitClient()
        assert hasattr(client, "get_commit")
        assert hasattr(client, "get_commit_files")
        assert hasattr(client, "get_log")


# =============================================================================
# CLIENT ISOLATION TESTS
# =============================================================================


class TestClientIsolation:
    """Test that clients are properly isolated."""

    def test_multiple_github_clients_independent(self):
        """Multiple GitHubClient instances are independent."""
        client1 = GitHubClient()
        client2 = GitHubClient()
        assert client1 is not client2
        assert client1._session is None
        assert client2._session is None

    def test_multiple_gharchive_clients_independent(self):
        """Multiple GHArchiveClient instances are independent."""
        client1 = GHArchiveClient(project_id="project1")
        client2 = GHArchiveClient(project_id="project2")
        assert client1 is not client2
        assert client1.project_id == "project1"
        assert client2.project_id == "project2"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
