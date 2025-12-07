#!/usr/bin/env python3
"""
Unit tests for _helpers.py module.

Tests the shared helper functions used across parsers and creation modules.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.helpers import (
    generate_evidence_id,
    make_actor,
    make_repo,
    make_repo_from_full_name,
    parse_datetime_lenient,
    parse_datetime_strict,
)


# =============================================================================
# EVIDENCE ID GENERATION TESTS
# =============================================================================


class TestGenerateEvidenceId:
    """Test evidence ID generation."""

    def test_deterministic(self):
        """Same inputs always produce same ID."""
        id1 = generate_evidence_id("test", "a", "b", "c")
        id2 = generate_evidence_id("test", "a", "b", "c")
        assert id1 == id2

    def test_different_inputs_different_ids(self):
        """Different inputs produce different IDs."""
        id1 = generate_evidence_id("test", "a", "b")
        id2 = generate_evidence_id("test", "a", "c")
        assert id1 != id2

    def test_prefix_applied(self):
        """Prefix is included in the ID."""
        evidence_id = generate_evidence_id("push", "repo", "sha")
        assert evidence_id.startswith("push-")

    def test_hash_length(self):
        """ID hash part is 12 characters."""
        evidence_id = generate_evidence_id("test", "input")
        prefix, hash_part = evidence_id.split("-", 1)
        assert len(hash_part) == 12

    def test_different_prefixes_same_parts(self):
        """Different prefixes with same parts produce different IDs."""
        id1 = generate_evidence_id("push", "repo", "sha")
        id2 = generate_evidence_id("commit", "repo", "sha")
        assert id1 != id2

    def test_empty_parts(self):
        """Handles empty parts list."""
        evidence_id = generate_evidence_id("test")
        assert evidence_id.startswith("test-")
        assert len(evidence_id) == 5 + 12  # "test-" + 12-char hash


# =============================================================================
# DATETIME PARSING TESTS - LENIENT
# =============================================================================


class TestParseDatetimeLenient:
    """Test lenient datetime parsing (for GH Archive data)."""

    def test_none_returns_now(self):
        """None input returns current time."""
        result = parse_datetime_lenient(None)
        assert isinstance(result, datetime)
        assert result.tzinfo is not None
        # Should be within last few seconds
        now = datetime.now(timezone.utc)
        assert abs((now - result).total_seconds()) < 5

    def test_datetime_passthrough(self):
        """datetime objects pass through unchanged."""
        dt = datetime(2025, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
        result = parse_datetime_lenient(dt)
        assert result == dt

    def test_iso_format_with_z(self):
        """Parses ISO format with Z suffix."""
        result = parse_datetime_lenient("2025-07-13T20:37:04Z")
        assert result.year == 2025
        assert result.month == 7
        assert result.day == 13
        assert result.hour == 20
        assert result.minute == 37
        assert result.second == 4

    def test_iso_format_with_timezone(self):
        """Parses ISO format with timezone offset."""
        result = parse_datetime_lenient("2025-07-13T07:52:37+00:00")
        assert result.year == 2025
        assert result.hour == 7

    def test_invalid_string_returns_now(self):
        """Invalid string returns current time (graceful degradation)."""
        result = parse_datetime_lenient("not a date")
        assert isinstance(result, datetime)
        # Should be recent
        now = datetime.now(timezone.utc)
        assert abs((now - result).total_seconds()) < 5


# =============================================================================
# DATETIME PARSING TESTS - STRICT
# =============================================================================


class TestParseDatetimeStrict:
    """Test strict datetime parsing (for verified data)."""

    def test_none_returns_none(self):
        """None input returns None."""
        result = parse_datetime_strict(None)
        assert result is None

    def test_datetime_passthrough(self):
        """datetime objects pass through unchanged."""
        dt = datetime(2025, 7, 13, 12, 0, 0, tzinfo=timezone.utc)
        result = parse_datetime_strict(dt)
        assert result == dt

    def test_iso_format_with_z(self):
        """Parses ISO format with Z suffix."""
        result = parse_datetime_strict("2025-07-13T20:37:04Z")
        assert result is not None
        assert result.year == 2025
        assert result.month == 7

    def test_invalid_string_raises(self):
        """Invalid string raises ValueError."""
        with pytest.raises(ValueError, match="Unable to parse"):
            parse_datetime_strict("not a date")


# =============================================================================
# ACTOR CREATION TESTS
# =============================================================================


class TestMakeActor:
    """Test GitHubActor creation."""

    def test_creates_actor_with_id(self):
        """Creates actor with login and id."""
        actor = make_actor("testuser", 12345)
        assert actor.login == "testuser"
        assert actor.id == 12345

    def test_creates_actor_without_id(self):
        """Creates actor without id (optional)."""
        actor = make_actor("testuser")
        assert actor.login == "testuser"
        assert actor.id is None

    def test_accepts_none_id(self):
        """Accepts explicit None for id."""
        actor = make_actor("testuser", None)
        assert actor.login == "testuser"
        assert actor.id is None


# =============================================================================
# REPOSITORY CREATION TESTS
# =============================================================================


class TestMakeRepo:
    """Test GitHubRepository creation from owner/name."""

    def test_creates_repo(self):
        """Creates repository from owner and name."""
        repo = make_repo("aws", "aws-toolkit-vscode")
        assert repo.owner == "aws"
        assert repo.name == "aws-toolkit-vscode"
        assert repo.full_name == "aws/aws-toolkit-vscode"


class TestMakeRepoFromFullName:
    """Test GitHubRepository creation from full name."""

    def test_creates_from_full_name(self):
        """Creates repository from owner/name format."""
        repo = make_repo_from_full_name("aws/aws-toolkit-vscode")
        assert repo.owner == "aws"
        assert repo.name == "aws-toolkit-vscode"
        assert repo.full_name == "aws/aws-toolkit-vscode"

    def test_handles_no_slash(self):
        """Raises error for repo name without slash."""
        with pytest.raises(ValueError, match="must be 'owner/repo' format"):
            make_repo_from_full_name("single-name")

    def test_handles_multiple_slashes(self):
        """Handles repo name with multiple slashes (takes first as owner)."""
        repo = make_repo_from_full_name("owner/repo/with/slashes")
        assert repo.owner == "owner"
        assert repo.name == "repo/with/slashes"
        assert repo.full_name == "owner/repo/with/slashes"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
