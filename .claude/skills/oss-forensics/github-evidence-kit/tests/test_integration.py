#!/usr/bin/env python3
"""
Integration tests: Verify Collectors work with real APIs.

These tests hit actual external services:
- GitHub REST API (60 req/hr unauthenticated)
- (Optional) GH Archive BigQuery

Run with: pytest tests/test_integration.py -v -m integration

To skip these in CI: pytest -m "not integration"

GH Archive BigQuery Credentials (two options):

Option 1: JSON file path
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

Option 2: JSON content directly (useful for .env files or CI secrets)
    export GOOGLE_APPLICATION_CREDENTIALS='{"type":"service_account",...}'

    Note: The JSON can be wrapped in single quotes. The client will
    auto-detect JSON content vs file path.

For .env file usage:
    # .env
    GOOGLE_APPLICATION_CREDENTIALS='{"type":"service_account","project_id":"...",...}'

    Then use python-dotenv or similar to load it before running tests.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.collectors.api import GitHubAPICollector
from src.collectors.archive import GHArchiveCollector
from src.collectors.local import LocalGitCollector
from src.schema.common import EvidenceSource, IOCType


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration


# =============================================================================
# GITHUB API INTEGRATION TESTS
#
# These hit the real GitHub API to verify the full pipeline works.
# Uses public repos that are unlikely to disappear.
# =============================================================================


class TestGitHubAPIIntegration:
    """Integration tests against real GitHub API."""

    @pytest.fixture
    def collector(self):
        """Create a collector."""
        return GitHubAPICollector()

    def test_fetch_real_commit(self, collector):
        """
        Fetch a real commit from a stable public repo.

        Uses: torvalds/linux - unlikely to disappear, immutable history.
        Commit: 1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 (initial Linux commit)
        """
        obs = collector.collect_commit(
            owner="torvalds",
            repo="linux",
            sha="1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
        )

        # Verify evidence was created
        assert obs is not None
        assert obs.sha == "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"

        # Verify this is the famous "Linux-2.6.12-rc2" initial commit
        assert "Linux-2.6.12-rc2" in obs.message

        # Verify author
        assert obs.author.name == "Linus Torvalds"

        # Verify verification info is set
        assert obs.verification.source == EvidenceSource.GITHUB
        assert obs.verification.url is not None
        assert "github.com" in str(obs.verification.url)

    def test_fetch_real_pull_request(self, collector):
        """
        Fetch a real merged PR from a stable public repo.

        Uses: python/cpython PR #1 - historic, won't change.
        """
        obs = collector.collect_pull_request(
            owner="python",
            repo="cpython",
            number=1
        )

        assert obs is not None
        assert obs.issue_number == 1
        assert obs.is_pull_request == True
        assert obs.verification.source == EvidenceSource.GITHUB

    def test_fetch_real_issue(self, collector):
        """
        Fetch a real issue from a stable public repo.

        Uses: python/cpython issue #1 (same as PR #1 on GitHub).
        """
        obs = collector.collect_issue(
            owner="python",
            repo="cpython",
            number=1
        )

        assert obs is not None
        assert obs.issue_number == 1
        assert obs.verification.source == EvidenceSource.GITHUB

    def test_fetch_nonexistent_commit_raises(self, collector):
        """Fetching a nonexistent commit raises an appropriate error."""
        with pytest.raises(Exception):  # Could be HTTPError, ValueError, etc.
            collector.collect_commit(
                owner="torvalds",
                repo="linux",
                sha="0000000000000000000000000000000000000000"
            )

    def test_fetch_nonexistent_repo_raises(self, collector):
        """Fetching from a nonexistent repo raises an appropriate error."""
        with pytest.raises(Exception):
            collector.collect_commit(
                owner="this-owner-does-not-exist-12345",
                repo="this-repo-does-not-exist-12345",
                sha="1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"
            )


# =============================================================================
# AMAZON Q TIMELINE INTEGRATION TESTS
#
# These verify we can still fetch the real Amazon Q attack data.
# The commits/PRs may be deleted - tests should handle gracefully.
# =============================================================================


class TestAmazonQTimelineIntegration:
    """Integration tests against real Amazon Q attack artifacts."""

    @pytest.fixture
    def collector(self):
        return GitHubAPICollector()

    def test_fetch_malicious_commit_678851b(self, collector):
        """
        Attempt to fetch the malicious commit 678851b.

        This commit contained the downloader code.
        It may have been removed from GitHub.
        """
        try:
            obs = collector.collect_commit(
                owner="aws",
                repo="aws-toolkit-vscode",
                sha="678851bbe9776228f55e0460e66a6167ac2a1685"
            )
            # If we get here, the commit still exists
            assert obs.sha == "678851bbe9776228f55e0460e66a6167ac2a1685"
            assert obs.author.name == "lkmanka58"
        except Exception as e:
            # Commit was likely deleted - fail with info
            pytest.fail(f"Malicious commit not accessible: {e}")

    def test_fetch_revert_pr_7710(self, collector):
        """
        Fetch PR #7710 - the revert PR for the malicious code.

        This should still exist as it's the fix, not the attack.
        """
        try:
            obs = collector.collect_pull_request(
                owner="aws",
                repo="aws-toolkit-vscode",
                number=7710
            )
            assert obs.issue_number == 7710
            # The PR author should be yueny2020, not the attacker
            assert obs.original_who.login == "yueny2020"
            assert "revert" in obs.title.lower()
        except Exception as e:
            pytest.skip(f"PR #7710 not accessible: {e}")


# =============================================================================
# GH ARCHIVE INTEGRATION TESTS
#
# These require BigQuery credentials. Skip if not available.
# Set GOOGLE_APPLICATION_CREDENTIALS env var to credentials JSON path.
# =============================================================================


class TestGHArchiveIntegration:
    """Integration tests against real GH Archive BigQuery data."""

    @pytest.fixture
    def collector(self):
        """Create collector - will fail lazily if no credentials."""
        return GHArchiveCollector()

    def test_fetch_amazon_q_issue_event(self, collector):
        """
        Fetch the malicious issue #7651 from GH Archive.

        This is a historic event that should always be queryable.
        Timestamp: 2025-07-13 07:52 UTC
        """
        try:
            events = collector.collect_events(
                timestamp="202507130752",  # Minute when issue #7651 was created
                repo="aws/aws-toolkit-vscode",
                event_type="IssuesEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # Find issue #7651
        issue_7651 = None
        for event in events:
            if hasattr(event, "issue_number") and event.issue_number == 7651:
                issue_7651 = event
                break

        assert issue_7651 is not None, "Issue #7651 not found in GH Archive"
        assert issue_7651.who.login == "lkmanka58"
        assert "aws amazon donkey" in issue_7651.issue_title.lower()
        assert issue_7651.verification.source == EvidenceSource.GHARCHIVE

    def test_fetch_amazon_q_push_event(self, collector):
        """
        Fetch push events from the attack timeframe.

        Timestamp: 2025-07-13 20:37 UTC - when commits were pushed.
        """
        try:
            events = collector.collect_events(
                timestamp="202507132037",  # Minute when push occurred
                repo="aws/aws-toolkit-vscode",
                event_type="PushEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # Should have push events
        assert len(events) > 0, "No push events found"

        # All should be verified from GH Archive
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert event.verification.bigquery_table is not None

    def test_fetch_amazon_q_pull_request_event(self, collector):
        """Fetch PR events from GH Archive for the attack timeframe."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="PullRequestEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have PRs in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "pr_number")

    def test_fetch_amazon_q_issue_comment_event(self, collector):
        """Fetch issue comment events from GH Archive."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="IssueCommentEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have comments in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "comment_body")

    def test_fetch_create_event(self, collector):
        """Fetch CreateEvent (branch/tag creation) from GH Archive."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="CreateEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have create events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "ref_type")
            assert hasattr(event, "ref_name")

    def test_fetch_watch_event(self, collector):
        """Fetch WatchEvent (stars) from GH Archive."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="WatchEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have watch events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_fetch_fork_event(self, collector):
        """Fetch ForkEvent from GH Archive."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="aws/aws-toolkit-vscode",
                event_type="ForkEvent",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        # May or may not have fork events in this minute
        for event in events:
            assert event.verification.source == EvidenceSource.GHARCHIVE
            assert hasattr(event, "fork_full_name")

    def test_gharchive_query_returns_empty_for_nonexistent_repo(self, collector):
        """Query for nonexistent repo returns empty list, not error."""
        try:
            events = collector.collect_events(
                timestamp="202507130752",
                repo="this-owner-does-not-exist-12345/this-repo-does-not-exist-12345",
            )
        except (ModuleNotFoundError, Exception) as e:
            if isinstance(e, ModuleNotFoundError) or "credentials" in str(e).lower() or "bigquery" in str(e).lower():
                pytest.skip(f"BigQuery not available: {e}")
            raise

        assert events == []

    def test_gharchive_requires_repo_or_actor(self, collector):
        """Query without repo or actor raises ValueError to prevent expensive scans."""
        with pytest.raises(ValueError, match="Must specify.*repo.*actor"):
            collector.collect_events(
                timestamp="202507130752",
                event_type="PushEvent",
            )

    def test_gharchive_requires_valid_timestamp_format(self, collector):
        """Query with invalid timestamp format raises ValueError."""
        with pytest.raises(ValueError, match="YYYYMMDDHHMM"):
            collector.collect_events(
                timestamp="2025071307",  # Missing minute
                repo="aws/aws-toolkit-vscode",
            )


# =============================================================================
# LOCAL GIT INTEGRATION TESTS
# =============================================================================


class TestLocalGitIntegration:
    """Integration tests for local git operations."""

    @pytest.fixture
    def temp_repo(self):
        """Clone a real GitHub repo into a temp directory for testing."""
        import subprocess
        import tempfile
        import shutil
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        repo_path = Path(temp_dir) / "raptor"
        
        try:
            # Clone the repository
            subprocess.run(
                ["git", "clone", "--depth=10", "https://github.com/gadievron/raptor.git", str(repo_path)],
                check=True,
                capture_output=True,
                timeout=30
            )
            yield str(repo_path)
        finally:
            # Cleanup: remove the temp directory
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir)

    def test_git_client_get_commit_on_real_repo(self, temp_repo):
        """Test GitClient can read commits from a real cloned repository."""
        from src.clients.git import GitClient

        client = GitClient(repo_path=temp_repo)

        try:
            commit = client.get_commit("HEAD")
            assert commit["sha"] is not None
            assert len(commit["sha"]) == 40
            assert commit["author_name"] is not None
            assert commit["message"] is not None
        except Exception as e:
            pytest.fail(f"Git operations failed: {e}")

    def test_git_client_get_log_on_real_repo(self, temp_repo):
        """Test GitClient can get commit log from a real repository."""
        from src.clients.git import GitClient

        client = GitClient(repo_path=temp_repo)

        try:
            log = client.get_log(limit=5)
            assert len(log) <= 5
            assert len(log) > 0
            assert log[0]["sha"] is not None
            assert log[0]["author_name"] is not None
        except Exception as e:
            pytest.fail(f"Git log failed: {e}")

    def test_git_client_get_commit_files(self, temp_repo):
        """Test GitClient can get files changed in a commit."""
        from src.clients.git import GitClient

        client = GitClient(repo_path=temp_repo)

        try:
            log = client.get_log(limit=5)
            if log:
                files = client.get_commit_files(log[0]["sha"])
                assert isinstance(files, list)
        except Exception as e:
            pytest.fail(f"Get commit files failed: {e}")

    def test_collector_local_commit(self, temp_repo):
        """Test LocalGitCollector.collect_commit() creates CommitObservation."""
        try:
            collector = LocalGitCollector(repo_path=temp_repo)
            obs = collector.collect_commit("HEAD")

            assert obs is not None
            assert obs.observation_type == "commit"
            assert obs.verification.source == EvidenceSource.GIT
            assert len(obs.sha) == 40
            assert obs.author.name is not None
            assert obs.message is not None
        except Exception as e:
            pytest.fail(f"Collector failed: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
