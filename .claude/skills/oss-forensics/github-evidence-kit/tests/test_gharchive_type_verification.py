"""GH Archive event verification must be type- and payload-aware.

Repo + actor + minute alone is not evidence: on a busy repo, ANY
same-minute event (a WatchEvent) would "verify" a fabricated
"collaborator added" event. The verifier must filter the query on the
event's GH Archive type and compare a discriminating payload field.
"""

from __future__ import annotations

import json
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
from src.schema.events import MemberEvent, PushEvent, WatchEvent
from src.verifiers.consistency import ConsistencyVerifier

_WHEN = datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc)


class _CannedClient(GHArchiveClient):
    """Credentialed-looking client returning canned rows; captures the
    query kwargs so tests can assert the SQL-side filter."""

    def __init__(self, rows):
        super().__init__()
        self._rows = rows
        self.captured: dict = {}

    def _get_client(self):
        return object()

    def query_events(self, **kwargs):
        self.captured = kwargs
        return list(self._rows)


def _common(evidence_id: str) -> dict:
    return {
        "evidence_id": evidence_id,
        "when": _WHEN,
        "who": GitHubActor(login="attacker"),
        "repository": GitHubRepository(owner="o", name="r", full_name="o/r"),
        "verification": VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.20240115",
        ),
    }


def _member_event() -> MemberEvent:
    return MemberEvent(
        **_common("evt-member"),
        what="Collaborator mallory added",
        action="added",
        member=GitHubActor(login="mallory"),
    )


def _push_event(sha: str = "a" * 40) -> PushEvent:
    return PushEvent(
        **_common("evt-push"),
        what="Pushed 1 commit(s) to refs/heads/main",
        ref="refs/heads/main",
        before_sha="b" * 40,
        after_sha=sha,
        size=1,
    )


def _row(row_type: str, payload: dict) -> dict:
    return {
        "type": row_type,
        "created_at": "2024-01-15T10:30:12Z",
        "actor_login": "attacker",
        "repo_name": "o/r",
        "payload": json.dumps(payload),
    }


def test_query_filters_on_gharchive_event_type():
    client = _CannedClient(
        [_row("MemberEvent", {"member": {"login": "mallory"}, "action": "added"})],
    )
    result = ConsistencyVerifier(gharchive_client=client).verify(_member_event())
    assert result.is_valid
    assert client.captured.get("event_type") == "MemberEvent"


def test_same_minute_unrelated_row_does_not_verify():
    # A fabricated member event with only a same-minute WatchEvent-shaped
    # row available: no member payload -> must NOT verify.
    client = _CannedClient([_row("WatchEvent", {"action": "started"})])
    result = ConsistencyVerifier(gharchive_client=client).verify(_member_event())
    assert not result.is_valid


def test_discriminating_payload_mismatch_does_not_verify():
    # Right type, wrong payload: a member event for a DIFFERENT login
    # in the same minute must not verify the fabricated one.
    client = _CannedClient(
        [_row("MemberEvent", {"member": {"login": "someone-else"}, "action": "added"})],
    )
    result = ConsistencyVerifier(gharchive_client=client).verify(_member_event())
    assert not result.is_valid


def test_push_event_verified_by_head_sha():
    sha = "c" * 40
    client = _CannedClient([
        _row("PushEvent", {"ref": "refs/heads/main", "head": "d" * 40}),
        _row("PushEvent", {"ref": "refs/heads/main", "head": sha}),
    ])
    result = ConsistencyVerifier(gharchive_client=client).verify(_push_event(sha))
    assert result.is_valid
    assert client.captured.get("event_type") == "PushEvent"


def test_push_event_wrong_sha_not_verified():
    client = _CannedClient(
        [_row("PushEvent", {"ref": "refs/heads/main", "head": "d" * 40})],
    )
    result = ConsistencyVerifier(gharchive_client=client).verify(_push_event("c" * 40))
    assert not result.is_valid


def test_watch_event_needs_no_discriminator():
    event = WatchEvent(**_common("evt-watch"), what="User attacker starred repository")
    client = _CannedClient([_row("WatchEvent", {"action": "started"})])
    result = ConsistencyVerifier(gharchive_client=client).verify(event)
    assert result.is_valid
    assert client.captured.get("event_type") == "WatchEvent"


def test_malformed_payload_never_verifies_discriminated_type():
    client = _CannedClient([
        {
            "type": "MemberEvent",
            "created_at": "2024-01-15T10:30:12Z",
            "actor_login": "attacker",
            "repo_name": "o/r",
            "payload": "{not json",
        },
    ])
    result = ConsistencyVerifier(gharchive_client=client).verify(_member_event())
    assert not result.is_valid
