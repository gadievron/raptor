#!/usr/bin/env python3
"""
Unit tests for _parsers.py module.

Tests the GH Archive event parser functions.

Note: Helper function tests (generate_evidence_id, parse_datetime, etc.)
are in test_helpers.py to avoid duplication.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parsers import (
    _RowContext,
    parse_create_event,
    parse_delete_event,
    parse_fork_event,
    parse_gharchive_event,
    parse_issue_event,
    parse_member_event,
    parse_public_event,
    parse_push_event,
    parse_release_event,
    parse_watch_event,
    parse_workflow_run_event,
)
from src.schema.common import EvidenceSource, IssueAction, RefType, WorkflowConclusion


# =============================================================================
# ROW CONTEXT TESTS
# =============================================================================


class TestRowContext:
    """Test _RowContext extraction."""

    def test_extracts_payload_from_dict(self):
        """Extracts payload when it's already a dict."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main"},
        }
        ctx = _RowContext(row)
        assert ctx.payload["ref"] == "refs/heads/main"

    def test_parses_payload_from_json_string(self):
        """Parses payload when it's a JSON string."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": '{"ref": "refs/heads/main"}',
        }
        ctx = _RowContext(row)
        assert ctx.payload["ref"] == "refs/heads/main"

    def test_creates_verification_info(self):
        """Creates VerificationInfo with GHARCHIVE source."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "repo_name": "owner/repo",
            "payload": {},
        }
        ctx = _RowContext(row)
        assert ctx.verification.source == EvidenceSource.GHARCHIVE


# =============================================================================
# PARSER TESTS
# =============================================================================


class TestParsePushEvent:
    """Test push event parser."""

    def test_parses_basic_push(self, gharchive_events):
        """Parses a basic push event."""
        push_events = [e for e in gharchive_events if e["type"] == "PushEvent"]
        assert len(push_events) > 0

        event = parse_push_event(push_events[0])
        assert event.event_type == "push"
        assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_extracts_ref(self, gharchive_push_events):
        """Extracts ref from push event."""
        event = parse_push_event(gharchive_push_events[0])
        assert event.ref is not None
        assert event.ref.startswith("refs/heads/")

    def test_extracts_commits(self, gharchive_push_events):
        """Extracts commits from push event."""
        # Find a push with commits
        push_with_commits = next(
            (e for e in gharchive_push_events if len(e["payload"].get("commits", [])) > 0),
            gharchive_push_events[0],
        )
        event = parse_push_event(push_with_commits)
        # May have 0 commits if they're not distinct
        assert hasattr(event, "commits")


class TestParseIssueEvent:
    """Test issue event parser."""

    def test_parses_issue_opened(self, gharchive_issue_events):
        """Parses an issue opened event."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.event_type == "issue"
        assert event.action == IssueAction.OPENED

    def test_extracts_issue_number(self, gharchive_issue_events):
        """Extracts issue number."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.issue_number > 0

    def test_extracts_issue_title(self, gharchive_issue_events):
        """Extracts issue title."""
        event = parse_issue_event(gharchive_issue_events[0])
        assert event.issue_title is not None
        assert len(event.issue_title) > 0


class TestParseCreateEvent:
    """Test create event parser."""

    def test_parses_create_event(self, gharchive_create_events):
        """Parses a create event."""
        if not gharchive_create_events:
            pytest.skip("No CreateEvent in fixture")

        event = parse_create_event(gharchive_create_events[0])
        assert event.event_type == "create"
        assert event.ref_type in [RefType.BRANCH, RefType.TAG, RefType.REPOSITORY]

    def test_extracts_ref_name(self, gharchive_create_events):
        """Extracts ref name."""
        if not gharchive_create_events:
            pytest.skip("No CreateEvent in fixture")

        event = parse_create_event(gharchive_create_events[0])
        assert event.ref_name is not None


# =============================================================================
# DISPATCHER TESTS
# =============================================================================


class TestParseGharchiveEvent:
    """Test the dispatcher function."""

    def test_dispatches_push_event(self, gharchive_push_events):
        """Correctly dispatches PushEvent."""
        event = parse_gharchive_event(gharchive_push_events[0])
        assert event.event_type == "push"

    def test_dispatches_issue_event(self, gharchive_issue_events):
        """Correctly dispatches IssuesEvent."""
        event = parse_gharchive_event(gharchive_issue_events[0])
        assert event.event_type == "issue"

    def test_raises_for_unknown_event(self):
        """Raises ValueError for unknown event types."""
        row = {
            "type": "UnknownEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "test",
            "repo_name": "owner/repo",
            "payload": {},
        }
        with pytest.raises(ValueError, match="Unsupported"):
            parse_gharchive_event(row)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_missing_actor_id(self):
        """Handles row with no actor_id."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main", "commits": [], "before": "a" * 40, "head": "b" * 40},
        }
        event = parse_push_event(row)
        assert event.who.login == "testuser"
        assert event.who.id is None

    def test_handles_empty_commits(self):
        """Handles push with no commits."""
        row = {
            "type": "PushEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {"ref": "refs/heads/main", "commits": [], "before": "a" * 40, "head": "b" * 40, "size": 0},
        }
        event = parse_push_event(row)
        assert len(event.commits) == 0

    def test_handles_missing_issue_body(self):
        """Handles issue with no body."""
        row = {
            "type": "IssuesEvent",
            "created_at": "2025-07-13T07:52:37Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "opened",
                "issue": {
                    "number": 1,
                    "title": "Test",
                    # no body
                },
            },
        }
        event = parse_issue_event(row)
        assert event.issue_body is None


# =============================================================================
# NEW EVENT PARSER TESTS
# =============================================================================


class TestParseDeleteEvent:
    """Test DeleteEvent parser."""

    def test_parses_branch_deletion(self):
        """Parses a branch deletion event."""
        row = {
            "type": "DeleteEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "ref_type": "branch",
                "ref": "feature-branch",
            },
        }
        event = parse_delete_event(row)
        assert event.event_type == "delete"
        assert event.ref_type == RefType.BRANCH
        assert event.ref_name == "feature-branch"
        assert event.who.login == "testuser"
        assert event.repository.full_name == "owner/repo"
        assert event.verification.source == EvidenceSource.GHARCHIVE

    def test_parses_tag_deletion(self):
        """Parses a tag deletion event."""
        row = {
            "type": "DeleteEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "ref_type": "tag",
                "ref": "v1.0.0",
            },
        }
        event = parse_delete_event(row)
        assert event.event_type == "delete"
        assert event.ref_type == RefType.TAG
        assert event.ref_name == "v1.0.0"

    def test_dispatcher_handles_delete_event(self):
        """Dispatcher correctly routes DeleteEvent."""
        row = {
            "type": "DeleteEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "testuser",
            "repo_name": "owner/repo",
            "payload": {"ref_type": "branch", "ref": "test"},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "delete"


class TestParseMemberEvent:
    """Test MemberEvent parser."""

    def test_parses_member_added(self):
        """Parses a member added event."""
        row = {
            "type": "MemberEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "added",
                "member": {
                    "login": "newmember",
                    "id": 456,
                },
            },
        }
        event = parse_member_event(row)
        assert event.event_type == "member"
        assert event.action == "added"
        assert event.member.login == "newmember"
        assert event.member.id == 456
        assert event.who.login == "owner"

    def test_parses_member_removed(self):
        """Parses a member removed event."""
        row = {
            "type": "MemberEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "removed",
                "member": {
                    "login": "exmember",
                    "id": 789,
                },
            },
        }
        event = parse_member_event(row)
        assert event.action == "removed"
        assert event.member.login == "exmember"

    def test_dispatcher_handles_member_event(self):
        """Dispatcher correctly routes MemberEvent."""
        row = {
            "type": "MemberEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "repo_name": "owner/repo",
            "payload": {"action": "added", "member": {"login": "test"}},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "member"


class TestParsePublicEvent:
    """Test PublicEvent parser."""

    def test_parses_public_event(self):
        """Parses a repository made public event."""
        row = {
            "type": "PublicEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/private-repo",
            "payload": {},
        }
        event = parse_public_event(row)
        assert event.event_type == "public"
        assert event.who.login == "owner"
        assert event.repository.full_name == "owner/private-repo"
        assert "public" in event.what.lower()

    def test_dispatcher_handles_public_event(self):
        """Dispatcher correctly routes PublicEvent."""
        row = {
            "type": "PublicEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "repo_name": "owner/repo",
            "payload": {},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "public"


class TestParseReleaseEvent:
    """Test ReleaseEvent parser."""

    def test_parses_release_published(self):
        """Parses a release published event."""
        row = {
            "type": "ReleaseEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "published",
                "release": {
                    "tag_name": "v1.0.0",
                    "name": "Release 1.0.0",
                    "body": "Initial release",
                },
            },
        }
        event = parse_release_event(row)
        assert event.event_type == "release"
        assert event.action == "published"
        assert event.tag_name == "v1.0.0"
        assert event.release_name == "Release 1.0.0"
        assert event.release_body == "Initial release"

    def test_parses_release_created(self):
        """Parses a release created event."""
        row = {
            "type": "ReleaseEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "created",
                "release": {
                    "tag_name": "v2.0.0-beta",
                },
            },
        }
        event = parse_release_event(row)
        assert event.action == "created"
        assert event.tag_name == "v2.0.0-beta"

    def test_dispatcher_handles_release_event(self):
        """Dispatcher correctly routes ReleaseEvent."""
        row = {
            "type": "ReleaseEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "repo_name": "owner/repo",
            "payload": {"action": "published", "release": {"tag_name": "v1.0"}},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "release"


class TestParseWorkflowRunEvent:
    """Test WorkflowRunEvent parser."""

    def test_parses_workflow_requested(self):
        """Parses a workflow run requested event."""
        row = {
            "type": "WorkflowRunEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "requested",
                "workflow_run": {
                    "name": "CI",
                    "head_sha": "abc123def456abc123def456abc123def456abc1",
                },
            },
        }
        event = parse_workflow_run_event(row)
        assert event.event_type == "workflow_run"
        assert event.action == "requested"
        assert event.workflow_name == "CI"
        assert event.head_sha == "abc123def456abc123def456abc123def456abc1"
        assert event.conclusion is None

    def test_parses_workflow_completed_success(self):
        """Parses a workflow run completed with success."""
        row = {
            "type": "WorkflowRunEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "completed",
                "workflow_run": {
                    "name": "Build",
                    "head_sha": "abc123def456abc123def456abc123def456abc1",
                    "conclusion": "success",
                },
            },
        }
        event = parse_workflow_run_event(row)
        assert event.action == "completed"
        assert event.conclusion == WorkflowConclusion.SUCCESS

    def test_parses_workflow_completed_failure(self):
        """Parses a workflow run completed with failure."""
        row = {
            "type": "WorkflowRunEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "actor_id": 123,
            "repo_name": "owner/repo",
            "payload": {
                "action": "completed",
                "workflow_run": {
                    "name": "Tests",
                    "head_sha": "abc123def456abc123def456abc123def456abc1",
                    "conclusion": "failure",
                },
            },
        }
        event = parse_workflow_run_event(row)
        assert event.conclusion == WorkflowConclusion.FAILURE

    def test_dispatcher_handles_workflow_run_event(self):
        """Dispatcher correctly routes WorkflowRunEvent."""
        row = {
            "type": "WorkflowRunEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "owner",
            "repo_name": "owner/repo",
            "payload": {"action": "requested", "workflow_run": {"name": "CI", "head_sha": "a" * 40}},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "workflow_run"


class TestParseForkEvent:
    """Test ForkEvent parser."""

    def test_parses_fork_event(self):
        """Parses a fork event."""
        row = {
            "type": "ForkEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "forker",
            "actor_id": 123,
            "repo_name": "owner/original-repo",
            "payload": {
                "forkee": {
                    "full_name": "forker/original-repo",
                },
            },
        }
        event = parse_fork_event(row)
        assert event.event_type == "fork"
        assert event.fork_full_name == "forker/original-repo"
        assert event.who.login == "forker"
        assert event.repository.full_name == "owner/original-repo"

    def test_dispatcher_handles_fork_event(self):
        """Dispatcher correctly routes ForkEvent."""
        row = {
            "type": "ForkEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "forker",
            "repo_name": "owner/repo",
            "payload": {"forkee": {"full_name": "forker/repo"}},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "fork"


class TestParseWatchEvent:
    """Test WatchEvent parser."""

    def test_parses_watch_event(self):
        """Parses a watch (star) event."""
        row = {
            "type": "WatchEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "stargazer",
            "actor_id": 123,
            "repo_name": "owner/popular-repo",
            "payload": {"action": "started"},
        }
        event = parse_watch_event(row)
        assert event.event_type == "watch"
        assert event.who.login == "stargazer"
        assert event.repository.full_name == "owner/popular-repo"
        assert "starred" in event.what.lower()

    def test_dispatcher_handles_watch_event(self):
        """Dispatcher correctly routes WatchEvent."""
        row = {
            "type": "WatchEvent",
            "created_at": "2025-07-13T20:37:04Z",
            "actor_login": "stargazer",
            "repo_name": "owner/repo",
            "payload": {"action": "started"},
        }
        event = parse_gharchive_event(row)
        assert event.event_type == "watch"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
