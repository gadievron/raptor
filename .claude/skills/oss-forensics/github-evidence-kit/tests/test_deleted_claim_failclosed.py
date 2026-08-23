#!/usr/bin/env python3
"""
Regression tests: deleted-claim verification fails CLOSED.

``ConsistencyVerifier._verify_github_observation`` used to auto-pass
any observation marked ``is_deleted=True`` when the source fetch
raised. ``is_deleted`` is a freely settable schema field, so a
fabricated "deleted issue" whose repo 404s self-verified and flowed to
the hypothesis/checker/report agents as verified forensic evidence.
Fetch failure on a deleted-marked observation must now return
``is_valid=False`` with an ``unverifiable`` error pointing at the GH
Archive recovery path (the sanctioned way to verify deletion claims).

No network: the GitHub client is a raising stub.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

# .claude/skills/oss-forensics/github-evidence-kit/tests/... ->
# .claude/skills/oss-forensics/github-evidence-kit
sys.path.insert(0, str(Path(__file__).parents[1]))

from src.helpers import make_repo
from src.schema.common import EvidenceSource, VerificationInfo
from src.schema.observations import IssueObservation
from src.verifiers.consistency import ConsistencyVerifier


class _RaisingGitHubClient:
    """Stub whose every fetch raises — the 404/network-failure shape."""

    def __getattr__(self, name):
        def _raise(*args, **kwargs):
            raise RuntimeError("404 Not Found (stub)")
        return _raise


class _StubGHArchiveClient:
    def _get_client(self):
        raise RuntimeError("no credentials (stub)")


def _issue_observation(is_deleted: bool) -> IssueObservation:
    now = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)
    return IssueObservation(
        evidence_id="issue-fabricated-1",
        original_when=now,
        original_who=None,
        original_what="Issue #42 created",
        observed_when=now,
        observed_by=EvidenceSource.GITHUB,
        observed_what="Fabricated deleted issue",
        repository=make_repo("owner", "repo"),
        verification=VerificationInfo(source=EvidenceSource.GITHUB),
        issue_number=42,
        is_pull_request=False,
        title="attacker-chosen title",
        body="attacker-chosen body",
        state="open",
        is_deleted=is_deleted,
    )


def _verifier() -> ConsistencyVerifier:
    return ConsistencyVerifier(
        github_client=_RaisingGitHubClient(),
        gharchive_client=_StubGHArchiveClient(),
    )


class TestDeletedClaimFailsClosed:
    def test_deleted_marked_observation_fails_closed_on_fetch_failure(self):
        result = _verifier().verify(_issue_observation(is_deleted=True))
        assert result.is_valid is False
        assert any("unverifiable" in e for e in result.errors)
        # The error points the operator at the sanctioned path.
        assert any("GH Archive" in e for e in result.errors)

    def test_non_deleted_observation_still_fails_closed(self):
        result = _verifier().verify(_issue_observation(is_deleted=False))
        assert result.is_valid is False

    def test_verify_all_aggregates_the_unverifiable_error(self):
        obs = _issue_observation(is_deleted=True)
        result = _verifier().verify_all([obs])
        assert result.is_valid is False
        assert any("unverifiable" in e for e in result.errors)
