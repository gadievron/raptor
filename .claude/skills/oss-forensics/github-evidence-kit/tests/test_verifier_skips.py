"""Skipped verification must never read as silently fully-verified.

``verify_all`` is the forensic pipeline's anti-fabrication chokepoint.
GH Archive checks without BigQuery credentials and local-git sources
are SKIPPED, not performed — the aggregate result must carry that as a
warning so reports can distinguish "verified" from "not checked".
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from src.clients.gharchive import GHArchiveClient
from src.schema.common import (
    EvidenceSource,
    GitHubActor,
    GitHubRepository,
    VerificationInfo,
)
from src.schema.events import Event
from src.verifiers.consistency import ConsistencyVerifier


class _NoCredentialsClient(GHArchiveClient):
    def _get_client(self):  # noqa: D102 - credential-less host shape
        raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS not set")


def _event(evidence_id: str, source: EvidenceSource, table: str | None = None) -> Event:
    return Event(
        evidence_id=evidence_id,
        when=datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        who=GitHubActor(login="someone"),
        what="collaborator added",
        repository=GitHubRepository(owner="o", name="r", full_name="o/r"),
        verification=VerificationInfo(source=source, bigquery_table=table),
    )


def test_git_source_event_is_warning_not_silent_pass():
    verifier = ConsistencyVerifier(gharchive_client=_NoCredentialsClient())
    result = verifier.verify(_event("EVD-001", EvidenceSource.GIT))
    assert result.is_valid
    assert result.warnings, "skipped git verification must surface a warning"
    assert not result.errors


def test_credentialless_gharchive_event_is_warning_not_silent_pass():
    verifier = ConsistencyVerifier(gharchive_client=_NoCredentialsClient())
    result = verifier.verify(
        _event("EVD-002", EvidenceSource.GHARCHIVE, table="githubarchive.day.20240115")
    )
    assert result.is_valid
    assert result.warnings, "credential-less GH Archive skip must surface a warning"
    assert not result.errors


def test_verify_all_aggregates_skip_warnings_with_evidence_ids():
    verifier = ConsistencyVerifier(gharchive_client=_NoCredentialsClient())
    result = verifier.verify_all(
        [
            _event("EVD-001", EvidenceSource.GIT),
            _event("EVD-002", EvidenceSource.GHARCHIVE, table="githubarchive.day.20240115"),
        ]
    )
    assert result.is_valid
    assert not result.errors
    assert len(result.warnings) == 2
    assert any(w.startswith("[EVD-001]") for w in result.warnings)
    assert any(w.startswith("[EVD-002]") for w in result.warnings)


def test_store_verify_all_carries_warnings(monkeypatch):
    from src.store import EvidenceStore
    from src.verifiers import consistency as consistency_mod

    monkeypatch.setattr(
        consistency_mod, "GHArchiveClient", _NoCredentialsClient
    )
    store = EvidenceStore()
    store.add(_event("EVD-003", EvidenceSource.GIT))
    is_valid, messages = store.verify_all()
    assert is_valid
    assert any(m.startswith("[warning]") for m in messages), (
        "store.verify_all() must not return (True, []) for a skipped check"
    )


# =============================================================================
# SINGLE-SOURCE CORROBORATION WARNING
# =============================================================================


def _commit(eid, sha, source):
    from src.schema.observations import CommitObservation, CommitAuthor
    now = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)
    author = CommitAuthor(name="T", email="t@t.com", date=now)
    return CommitObservation(
        evidence_id=eid,
        observed_when=now,
        observed_by=source,
        observed_what="commit",
        verification=VerificationInfo(source=source),
        sha=sha,
        message="m",
        author=author,
        committer=author,
    )


def test_verify_all_warns_on_single_sourced_commits():
    verifier = ConsistencyVerifier(gharchive_client=_NoCredentialsClient())
    result = verifier.verify_all([
        _commit("commit-aaa", "a" * 40, EvidenceSource.GIT),
    ])
    assert any("[corroboration]" in w for w in result.warnings)


def test_verify_all_no_corroboration_warning_when_dual_sourced():
    verifier = ConsistencyVerifier(gharchive_client=_NoCredentialsClient())
    result = verifier.verify_all([
        _commit("commit-aaa", "a" * 40, EvidenceSource.GIT),
        _commit("commit-api-aaa", "a" * 40, EvidenceSource.GITHUB),
    ])
    assert not any("[corroboration]" in w for w in result.warnings)
