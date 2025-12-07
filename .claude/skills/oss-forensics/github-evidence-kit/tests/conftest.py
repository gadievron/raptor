"""
Shared pytest fixtures for github-forensics-schema tests.

Provides:
- Fixture data loaders
- Sample evidence data
- EvidenceStore instances
"""

import json
import sys
from pathlib import Path

import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src import EvidenceStore, load_evidence_from_json


# =============================================================================
# FIXTURE DATA PATHS
# =============================================================================

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict | list:
    """Load a fixture file by name."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


# =============================================================================
# GH ARCHIVE FIXTURES
# =============================================================================


@pytest.fixture
def gharchive_events() -> list[dict]:
    """All GH Archive fixture data from July 13, 2025."""
    return load_fixture("gharchive_july13_2025.json")


@pytest.fixture
def gharchive_push_events(gharchive_events) -> list[dict]:
    """Only PushEvent from GH Archive fixtures."""
    return [e for e in gharchive_events if e["type"] == "PushEvent"]


@pytest.fixture
def gharchive_issue_events(gharchive_events) -> list[dict]:
    """Only IssuesEvent from GH Archive fixtures."""
    return [e for e in gharchive_events if e["type"] == "IssuesEvent"]


@pytest.fixture
def gharchive_create_events(gharchive_events) -> list[dict]:
    """Only CreateEvent from GH Archive fixtures."""
    return [e for e in gharchive_events if e["type"] == "CreateEvent"]


# =============================================================================
# SAMPLE EVIDENCE DATA
# =============================================================================


@pytest.fixture
def sample_push_event_data() -> dict:
    """Sample push event data for testing."""
    return {
        "event_type": "push",
        "evidence_id": "push-test-001",
        "when": "2025-07-13T20:37:04Z",
        "who": {"login": "testuser", "id": 12345},
        "what": "Pushed 1 commit(s) to refs/heads/master",
        "repository": {
            "owner": "aws",
            "name": "aws-toolkit-vscode",
            "full_name": "aws/aws-toolkit-vscode",
        },
        "verification": {
            "source": "gharchive",
            "bigquery_table": "githubarchive.day.20250713",
        },
        "ref": "refs/heads/master",
        "before_sha": "d1959b996841883b3c14eadc5bc195fe8f65a63b",
        "after_sha": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "size": 1,
        "commits": [],
        "is_force_push": False,
    }


@pytest.fixture
def sample_commit_observation_data() -> dict:
    """Sample commit observation data for testing."""
    return {
        "observation_type": "commit",
        "evidence_id": "commit-test-001",
        "original_when": "2025-07-13T20:30:24Z",
        "original_who": {"login": "lkmanka58"},
        "original_what": "Malicious commit",
        "observed_when": "2025-11-28T21:00:00Z",
        "observed_by": "github",
        "observed_what": "Commit observed via GitHub API",
        "repository": {
            "owner": "aws",
            "name": "aws-toolkit-vscode",
            "full_name": "aws/aws-toolkit-vscode",
        },
        "verification": {
            "source": "github",
            "url": "https://github.com/aws/aws-toolkit-vscode/commit/678851b",
        },
        "sha": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "message": "fix(amazonq): test commit",
        "author": {
            "name": "lkmanka58",
            "email": "lkmanka58@users.noreply.github.com",
            "date": "2025-07-13T20:30:24Z",
        },
        "committer": {
            "name": "lkmanka58",
            "email": "lkmanka58@users.noreply.github.com",
            "date": "2025-07-13T20:30:24Z",
        },
        "parents": [],
        "files": [],
    }


@pytest.fixture
def sample_ioc_data() -> dict:
    """Sample IOC data for testing."""
    return {
        "observation_type": "ioc",
        "evidence_id": "ioc-test-001",
        "observed_when": "2025-07-24T12:00:00Z",
        "observed_by": "security_vendor",
        "observed_what": "IOC commit_sha identified",
        "verification": {
            "source": "security_vendor",
            "url": "https://example.com/report",
        },
        "ioc_type": "commit_sha",
        "value": "678851bbe9776228f55e0460e66a6167ac2a1685",
        "first_seen": "2025-07-13T20:30:24Z",
        "last_seen": "2025-07-18T23:21:03Z",
    }


@pytest.fixture
def sample_issue_event_data() -> dict:
    """Sample issue event data for testing."""
    return {
        "event_type": "issue",
        "evidence_id": "issue-test-001",
        "when": "2025-07-13T07:52:37Z",
        "who": {"login": "lkmanka58", "id": 79083038},
        "what": "Issue #7651 opened",
        "repository": {
            "owner": "aws",
            "name": "aws-toolkit-vscode",
            "full_name": "aws/aws-toolkit-vscode",
        },
        "verification": {
            "source": "gharchive",
            "bigquery_table": "githubarchive.day.20250713",
        },
        "action": "opened",
        "issue_number": 7651,
        "issue_title": "Test issue title",
        "issue_body": "Test issue body",
    }


# =============================================================================
# LOADED EVIDENCE FIXTURES
# =============================================================================


@pytest.fixture
def sample_push_event(sample_push_event_data):
    """Sample push event loaded into evidence object."""
    return load_evidence_from_json(sample_push_event_data)


@pytest.fixture
def sample_commit_observation(sample_commit_observation_data):
    """Sample commit observation loaded into evidence object."""
    return load_evidence_from_json(sample_commit_observation_data)


@pytest.fixture
def sample_ioc(sample_ioc_data):
    """Sample IOC loaded into evidence object."""
    return load_evidence_from_json(sample_ioc_data)


@pytest.fixture
def sample_issue_event(sample_issue_event_data):
    """Sample issue event loaded into evidence object."""
    return load_evidence_from_json(sample_issue_event_data)


# =============================================================================
# STORE FIXTURES
# =============================================================================


@pytest.fixture
def empty_store() -> EvidenceStore:
    """Create an empty EvidenceStore."""
    return EvidenceStore()


@pytest.fixture
def populated_store(sample_push_event, sample_commit_observation, sample_ioc) -> EvidenceStore:
    """Create an EvidenceStore with sample data."""
    store = EvidenceStore()
    store.add(sample_push_event)
    store.add(sample_commit_observation)
    store.add(sample_ioc)
    return store


# =============================================================================
# GITHUB API FIXTURES (for integration tests)
# =============================================================================


@pytest.fixture
def github_api_commits() -> dict:
    """GitHub API commit fixture data."""
    return load_fixture("github_api_commits.json")


@pytest.fixture
def github_api_pr() -> dict:
    """GitHub API PR #7710 fixture data."""
    return load_fixture("github_api_pr7710.json")


# =============================================================================
# TIMELINE FIXTURE
# =============================================================================


@pytest.fixture
def amazon_q_timeline() -> list[dict]:
    """Amazon Q attack timeline evidence fixture."""
    return load_fixture("gharchive_amazon_q_timeline_evidence.json")
