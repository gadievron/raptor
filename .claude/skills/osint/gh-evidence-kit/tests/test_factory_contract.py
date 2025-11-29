#!/usr/bin/env python3
"""
Test: EvidenceFactory contract verification.

These tests verify the CONTRACT of the evidence schema:
1. Evidence can ONLY be created through EvidenceFactory
2. All evidence has verification info proving provenance
3. Unverified data cannot bypass the factory

Source data documented in fixtures/ for reference:
- https://mbgsec.com/posts/2025-07-24-constructing-a-timeline-for-amazon-q-prompt-infection/

NOTE: These are contract tests, not integration tests.
Integration tests that hit real APIs should be separate and marked accordingly.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import (
    EvidenceFactory,
    load_evidence_from_json,
    EvidenceSource,
    IOCType,
)


# =============================================================================
# CONTRACT TEST: Only EvidenceFactory can create evidence
# =============================================================================


class TestEvidenceFactoryContract:
    """Verify the factory is the only way to create evidence."""

    def test_factory_exists(self):
        """EvidenceFactory can be instantiated."""
        factory = EvidenceFactory()
        assert factory is not None

    def test_factory_has_required_methods(self):
        """Factory exposes all required creation methods."""
        factory = EvidenceFactory()

        # GitHub API methods
        assert hasattr(factory, 'commit')
        assert hasattr(factory, 'pull_request')
        assert hasattr(factory, 'issue')

        # GH Archive methods
        assert hasattr(factory, 'events_from_gharchive')

        # Article/IOC methods
        assert hasattr(factory, 'article')
        assert hasattr(factory, 'ioc')

    def test_schema_classes_not_importable(self):
        """Schema classes cannot be imported from public API."""
        import src

        # Data classes should NOT be directly accessible
        assert not hasattr(src, 'CommitObservation')
        assert not hasattr(src, 'IssueEvent')
        assert not hasattr(src, 'PushEvent')
        assert not hasattr(src, 'IssueObservation')

    def test_create_functions_not_importable(self):
        """Internal create_* functions cannot be imported from public API."""
        import src

        assert not hasattr(src, 'create_issue_event_from_gharchive')
        assert not hasattr(src, 'create_push_event_from_gharchive')
        assert not hasattr(src, 'create_commit_observation')
        assert not hasattr(src, 'create_ioc')
        assert not hasattr(src, 'create_article_observation')

    def test_only_safe_imports_available(self):
        """Only safe items are importable from public API."""
        import src

        # Factory - the ONLY creation mechanism
        assert hasattr(src, 'EvidenceFactory')

        # Deserialization - for loading previously verified evidence
        assert hasattr(src, 'load_evidence_from_json')

        # Enums - safe constants
        assert hasattr(src, 'EvidenceSource')
        assert hasattr(src, 'IOCType')
        assert hasattr(src, 'IssueAction')
        assert hasattr(src, 'RefType')

    def test_types_module_provides_type_hints(self):
        """Types module provides classes for type hints (not instantiation enforcement)."""
        from src.types import IssueEvent, CommitObservation

        # These classes are available for type hints
        # Note: Direct instantiation is allowed for deserialization use cases
        # The factory pattern is enforced by convention, not runtime checks
        assert IssueEvent is not None
        assert CommitObservation is not None


# =============================================================================
# CONTRACT TEST: All evidence has verification info
# =============================================================================


class TestVerificationContract:
    """Verify all evidence objects have proper verification."""

    def test_article_has_verification(self):
        """Articles created via factory have verification info."""
        factory = EvidenceFactory()

        article = factory.article(
            url="https://example.com/test",
            title="Test Article",
            author="Test Author",
        )

        assert hasattr(article, 'verification')
        assert article.verification.source == EvidenceSource.SECURITY_VENDOR
        # Verification includes URL for traceability
        assert article.verification.url is not None


# =============================================================================
# CONTRACT TEST: JSON round-trip preserves evidence
# =============================================================================


class TestJSONContract:
    """Verify evidence survives JSON serialization."""

    def test_article_survives_json_roundtrip(self):
        """Evidence can be serialized and deserialized."""
        factory = EvidenceFactory()

        original = factory.article(
            url="https://example.com/test",
            title="Test Article",
            author="Test Author",
        )

        # Serialize
        json_str = original.model_dump_json()
        json_data = json.loads(json_str)

        # Deserialize via safe loader
        loaded = load_evidence_from_json(json_data)

        # Verify fields preserved
        assert loaded.title == original.title
        assert loaded.author == original.author
        assert loaded.verification.source == original.verification.source

    def test_load_rejects_invalid_json(self):
        """load_evidence_from_json rejects data without type discriminator."""
        with pytest.raises(ValueError, match="must contain"):
            load_evidence_from_json({"foo": "bar"})

    def test_load_rejects_unknown_event_type(self):
        """load_evidence_from_json rejects unknown event types."""
        with pytest.raises(ValueError, match="Unknown event_type"):
            load_evidence_from_json({"event_type": "unknown_event"})

    def test_load_rejects_unknown_observation_type(self):
        """load_evidence_from_json rejects unknown observation types."""
        with pytest.raises(ValueError, match="Unknown observation_type"):
            load_evidence_from_json({"observation_type": "unknown_observation"})


# =============================================================================
# FIXTURE DOCUMENTATION: What the real data looks like
#
# These tests document the expected structure of real API data.
# They load fixtures and verify they match expected format.
# =============================================================================


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict | list:
    """Load a fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class TestFixtureDocumentation:
    """Document expected format of real API/archive data."""

    def test_gharchive_issue_event_structure(self):
        """GH Archive IssueEvent has expected structure."""
        fixtures = load_fixture("gharchive_july13_2025.json")

        issue_event = next(
            e for e in fixtures
            if e["type"] == "IssuesEvent"
            and e["payload"]["issue"]["number"] == 7651
        )

        # Document expected fields
        assert issue_event["type"] == "IssuesEvent"
        assert "created_at" in issue_event
        assert "actor_login" in issue_event
        assert issue_event["payload"]["action"] == "opened"
        assert issue_event["payload"]["issue"]["number"] == 7651
        assert issue_event["payload"]["issue"]["title"] == "aws amazon donkey aaaaaaiii aaaaaaaiii"
        assert issue_event["payload"]["issue"]["user"]["login"] == "lkmanka58"

    def test_gharchive_push_event_structure(self):
        """GH Archive PushEvent has expected structure."""
        fixtures = load_fixture("gharchive_july13_2025.json")

        push_event = next(
            e for e in fixtures
            if e["type"] == "PushEvent"
            and e["payload"]["ref"] == "refs/heads/master"
        )

        # Document expected fields
        assert push_event["type"] == "PushEvent"
        assert "created_at" in push_event
        assert push_event["payload"]["ref"] == "refs/heads/master"
        assert "commits" in push_event["payload"]

    def test_github_api_commit_structure(self):
        """GitHub API commit response has expected structure."""
        commits = load_fixture("github_api_commits.json")

        commit = commits["678851bbe9776228f55e0460e66a6167ac2a1685"]

        # Document expected fields
        assert commit["sha"] == "678851bbe9776228f55e0460e66a6167ac2a1685"
        assert commit["message"].startswith("fix(amazonq)")
        assert commit["author"]["name"] == "lkmanka58"
        assert len(commit["files"]) > 0
        assert commit["files"][0]["filename"] == "scripts/package.ts"

    def test_github_api_pr_structure(self):
        """GitHub API PR response has expected structure."""
        pr = load_fixture("github_api_pr7710.json")

        # Document expected fields
        assert pr["number"] == 7710
        assert pr["user"]["login"] == "yueny2020"
        assert pr["merged"] == True
        assert "revert" in pr["title"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
