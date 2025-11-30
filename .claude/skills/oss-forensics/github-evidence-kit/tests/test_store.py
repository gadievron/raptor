#!/usr/bin/env python3
"""
Unit tests for EvidenceStore.

Tests save/load/query functionality for evidence collections.
Fixtures are defined in conftest.py.
"""

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src import EvidenceStore, EvidenceSource, load_evidence_from_json


# =============================================================================
# STORE BASIC OPERATIONS
# =============================================================================


class TestEvidenceStoreBasics:
    """Test basic store operations."""

    def test_create_empty_store(self):
        """Create an empty store."""
        store = EvidenceStore()
        assert len(store) == 0

    def test_add_and_get_evidence(self, sample_push_event_data):
        """Add evidence and retrieve by ID."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event_data)

        store.add(event)

        assert len(store) == 1
        assert store.get("push-test-001") is not None
        assert store.get("push-test-001").evidence_id == "push-test-001"

    def test_add_replaces_existing(self, sample_push_event_data):
        """Adding evidence with same ID replaces existing."""
        store = EvidenceStore()
        event1 = load_evidence_from_json(sample_push_event_data)

        # Modify and add again
        sample_push_event_data["what"] = "Modified description"
        event2 = load_evidence_from_json(sample_push_event_data)

        store.add(event1)
        store.add(event2)

        assert len(store) == 1
        assert store.get("push-test-001").what == "Modified description"

    def test_remove_evidence(self, sample_push_event_data):
        """Remove evidence by ID."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event_data)
        store.add(event)

        assert store.remove("push-test-001") is True
        assert len(store) == 0
        assert store.remove("push-test-001") is False

    def test_clear_store(self, sample_push_event_data, sample_commit_observation_data):
        """Clear all evidence from store."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        assert len(store) == 2
        store.clear()
        assert len(store) == 0

    def test_contains_check(self, sample_push_event_data):
        """Check if evidence ID exists in store."""
        store = EvidenceStore()
        event = load_evidence_from_json(sample_push_event_data)
        store.add(event)

        assert "push-test-001" in store
        assert "nonexistent" not in store

    def test_iterate_over_store(self, sample_push_event_data, sample_commit_observation_data):
        """Iterate over all evidence in store."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        evidence_ids = [e.evidence_id for e in store]
        assert len(evidence_ids) == 2
        assert "push-test-001" in evidence_ids
        assert "commit-test-001" in evidence_ids


# =============================================================================
# STORE FILTERING
# =============================================================================


class TestEvidenceStoreFiltering:
    """Test store filtering capabilities."""

    def test_filter_by_event_type(self, sample_push_event_data, sample_commit_observation_data):
        """Filter by event type."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        push_events = store.filter(event_type="push")
        assert len(push_events) == 1
        assert push_events[0].evidence_id == "push-test-001"

    def test_filter_by_observation_type(self, sample_push_event_data, sample_commit_observation_data, sample_ioc_data):
        """Filter by observation type."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))
        store.add(load_evidence_from_json(sample_ioc_data))

        commits = store.filter(observation_type="commit")
        assert len(commits) == 1
        assert commits[0].evidence_id == "commit-test-001"

        iocs = store.filter(observation_type="ioc")
        assert len(iocs) == 1

    def test_filter_by_source(self, sample_push_event_data, sample_commit_observation_data):
        """Filter by verification source."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        github_evidence = store.filter(source=EvidenceSource.GITHUB)
        assert len(github_evidence) == 1

        gharchive_evidence = store.filter(source="gharchive")
        assert len(gharchive_evidence) == 1

    def test_filter_by_repository(self, sample_push_event_data, sample_commit_observation_data):
        """Filter by repository."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        aws_evidence = store.filter(repo="aws/aws-toolkit-vscode")
        assert len(aws_evidence) == 2

        other_evidence = store.filter(repo="other/repo")
        assert len(other_evidence) == 0

    def test_filter_by_date_range(self, sample_push_event_data, sample_commit_observation_data):
        """Filter by date range."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        # Filter after July 1st
        after_july = store.filter(after=datetime(2025, 7, 1, tzinfo=timezone.utc))
        assert len(after_july) == 2

        # Filter before July 14th
        before_july14 = store.filter(before=datetime(2025, 7, 14, tzinfo=timezone.utc))
        assert len(before_july14) == 2

        # Filter outside range
        future = store.filter(after=datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert len(future) == 0

    def test_filter_with_predicate(self, sample_push_event_data, sample_commit_observation_data):
        """Filter with custom predicate."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        # Custom predicate
        has_sha = store.filter(predicate=lambda e: hasattr(e, "sha"))
        assert len(has_sha) == 1

    def test_events_property(self, sample_push_event_data, sample_commit_observation_data):
        """Get all events via property."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        events = store.events
        assert len(events) == 1
        assert events[0].evidence_id == "push-test-001"

    def test_observations_property(self, sample_push_event_data, sample_commit_observation_data, sample_ioc_data):
        """Get all observations via property."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))
        store.add(load_evidence_from_json(sample_ioc_data))

        observations = store.observations
        assert len(observations) == 2


# =============================================================================
# STORE SERIALIZATION
# =============================================================================


class TestEvidenceStoreSerialization:
    """Test store save/load functionality."""

    def test_to_json(self, sample_push_event_data, sample_commit_observation_data):
        """Serialize store to JSON string."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))

        json_str = store.to_json()
        data = json.loads(json_str)

        assert isinstance(data, list)
        assert len(data) == 2

    def test_from_json(self, sample_push_event_data, sample_commit_observation_data):
        """Create store from JSON string."""
        # Create and serialize
        store1 = EvidenceStore()
        store1.add(load_evidence_from_json(sample_push_event_data))
        store1.add(load_evidence_from_json(sample_commit_observation_data))
        json_str = store1.to_json()

        # Deserialize
        store2 = EvidenceStore.from_json(json_str)

        assert len(store2) == 2
        assert store2.get("push-test-001") is not None
        assert store2.get("commit-test-001") is not None

    def test_save_and_load(self, sample_push_event_data, sample_commit_observation_data):
        """Save to file and load back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "evidence.json"

            # Save
            store1 = EvidenceStore()
            store1.add(load_evidence_from_json(sample_push_event_data))
            store1.add(load_evidence_from_json(sample_commit_observation_data))
            store1.save(filepath)

            # Load
            store2 = EvidenceStore.load(filepath)

            assert len(store2) == 2
            assert store2.get("push-test-001") is not None

    def test_save_creates_directories(self, sample_push_event_data):
        """Save creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "nested" / "path" / "evidence.json"

            store = EvidenceStore()
            store.add(load_evidence_from_json(sample_push_event_data))
            store.save(filepath)

            assert filepath.exists()


# =============================================================================
# STORE MERGE AND SUMMARY
# =============================================================================


class TestEvidenceStoreMerge:
    """Test store merge and summary."""

    def test_merge_stores(self, sample_push_event_data, sample_commit_observation_data, sample_ioc_data):
        """Merge two stores."""
        store1 = EvidenceStore()
        store1.add(load_evidence_from_json(sample_push_event_data))

        store2 = EvidenceStore()
        store2.add(load_evidence_from_json(sample_commit_observation_data))
        store2.add(load_evidence_from_json(sample_ioc_data))

        store1.merge(store2)

        assert len(store1) == 3
        assert "push-test-001" in store1
        assert "commit-test-001" in store1
        assert "ioc-test-001" in store1

    def test_summary(self, sample_push_event_data, sample_commit_observation_data, sample_ioc_data):
        """Get store summary."""
        store = EvidenceStore()
        store.add(load_evidence_from_json(sample_push_event_data))
        store.add(load_evidence_from_json(sample_commit_observation_data))
        store.add(load_evidence_from_json(sample_ioc_data))

        summary = store.summary()

        assert summary["total"] == 3
        assert summary["events"]["push"] == 1
        assert summary["observations"]["commit"] == 1
        assert summary["observations"]["ioc"] == 1
        assert "gharchive" in summary["by_source"]
        assert "github" in summary["by_source"]
        assert "security_vendor" in summary["by_source"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
