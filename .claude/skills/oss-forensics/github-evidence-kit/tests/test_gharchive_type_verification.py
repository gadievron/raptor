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


# =============================================================================
# Observation side — the deletion-claim lane. _verify_github_observation
# fail-closes deletion claims onto _verify_gharchive_observation, so a
# repo/minute existence check alone would launder a fabricated
# "recovered deleted issue/PR/commit" (agent-authored, attacker-chosen
# title/body) through verify_all().
# =============================================================================

from src.schema.observations import (  # noqa: E402
    CommitAuthor,
    CommitObservation,
    FileObservation,
    IssueObservation,
)


def _issue_obs(number: int = 77, title: str | None = "Backdoor report",
               body: str | None = "details") -> IssueObservation:
    return IssueObservation(
        evidence_id="obs-issue",
        observed_when=_WHEN,
        observed_by=EvidenceSource.GHARCHIVE,
        observed_what=f"Issue #{number} recovered from GH Archive",
        original_who=GitHubActor(login="creator"),
        repository=GitHubRepository(owner="o", name="r", full_name="o/r"),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.20240115",
        ),
        issue_number=number,
        title=title,
        body=body,
        is_deleted=True,
    )


def _commit_obs(sha: str, message: str = "msg",
                author_name: str = "A Uthor",
                author_email: str = "a@example.invalid") -> CommitObservation:
    author = CommitAuthor(name=author_name, email=author_email,
                          date=_WHEN)
    return CommitObservation(
        evidence_id="obs-commit",
        observed_when=_WHEN,
        observed_by=EvidenceSource.GHARCHIVE,
        observed_what=f"Commit {sha[:8]} recovered from GH Archive",
        # Recovery stamps the commit AUTHOR NAME here — not a login.
        original_who=GitHubActor(login="A Uthor"),
        repository=GitHubRepository(owner="o", name="r", full_name="o/r"),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.20240115",
        ),
        sha=sha,
        message=message,
        author=author,
        committer=author,
        is_deleted=True,
    )


def _issue_row(number: int, title: str = "Backdoor report",
               body: str = "details") -> dict:
    return _row("IssuesEvent", {
        "action": "opened",
        "issue": {"number": number, "title": title, "body": body},
    })


def test_recovered_issue_verifies_on_type_number_and_text():
    client = _CannedClient([_issue_row(77)])
    result = ConsistencyVerifier(gharchive_client=client).verify(_issue_obs())
    assert result.is_valid
    assert client.captured.get("event_type") == "IssuesEvent"
    # No actor filter: recovery can stamp non-login identities and
    # non-creator row actors; the payload discriminators carry the
    # evidence.
    assert client.captured.get("actor") is None


def test_fabricated_issue_same_minute_rows_do_not_verify():
    # Rows exist for the repo/minute, none carries the claimed number.
    client = _CannedClient([_issue_row(12), _issue_row(13)])
    result = ConsistencyVerifier(gharchive_client=client).verify(_issue_obs(77))
    assert not result.is_valid


def test_fabricated_issue_free_text_does_not_verify():
    # Right number, forged title/body — the free text is exactly what
    # a fabricated deletion claim carries; it must match the archive
    # row verbatim (recovery copies it verbatim).
    client = _CannedClient([_issue_row(77, title="harmless docs tweak")])
    result = ConsistencyVerifier(gharchive_client=client).verify(_issue_obs(77))
    assert not result.is_valid


def test_recovered_issue_without_text_still_verifies_on_number():
    # Recovery can yield title=None (payload lacked it) — the number
    # remains the primary discriminator.
    client = _CannedClient([_issue_row(77)])
    obs = _issue_obs(77, title=None, body=None)
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert result.is_valid


def test_recovered_pr_maps_to_pull_request_event():
    obs = _issue_obs(9, title=None, body=None)
    obs = obs.model_copy(update={"is_pull_request": True})
    client = _CannedClient([_row("PullRequestEvent", {
        "action": "opened", "pull_request": {"number": 9},
    })])
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert result.is_valid
    assert client.captured.get("event_type") == "PullRequestEvent"


def test_recovered_commit_verifies_on_sha_in_push_payload():
    sha = "e" * 40
    client = _CannedClient([_row("PushEvent", {
        "commits": [{"sha": "f" * 40}, {"sha": sha}],
    })])
    result = ConsistencyVerifier(gharchive_client=client).verify(_commit_obs(sha))
    assert result.is_valid
    assert client.captured.get("event_type") == "PushEvent"
    assert client.captured.get("actor") is None


def test_recovered_force_push_verifies_on_before_sha():
    sha = "0" * 39 + "1"
    client = _CannedClient([_row("PushEvent", {
        "size": 0, "before": sha, "head": "a" * 40,
    })])
    result = ConsistencyVerifier(gharchive_client=client).verify(_commit_obs(sha))
    assert result.is_valid


def test_fabricated_commit_sha_does_not_verify():
    client = _CannedClient([_row("PushEvent", {
        "commits": [{"sha": "f" * 40}],
    })])
    result = ConsistencyVerifier(gharchive_client=client).verify(
        _commit_obs("e" * 40))
    assert not result.is_valid


def _push_row(sha: str, message: str = "fix build on musl",
              name: str = "A Uthor",
              email: str = "a@example.invalid", **extra) -> dict:
    return _row("PushEvent", {
        "commits": [{"sha": sha, "message": message,
                     "author": {"name": name, "email": email}}],
        **extra,
    })


def test_fabricated_commit_message_does_not_verify():
    # The laundering lane on the highest-stakes record type: a REAL
    # archived sha carrying attacker-chosen free text. message is
    # copied verbatim from the archive row at recovery, so it must
    # match the row verbatim — same rule as the issue leg's title/body.
    sha = "e" * 40
    client = _CannedClient([_push_row(sha)])
    obs = _commit_obs(sha, message="maintainer intentionally added backdoor")
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert not result.is_valid


def test_fabricated_commit_author_does_not_verify():
    sha = "e" * 40
    client = _CannedClient([_push_row(sha)])
    verifier = ConsistencyVerifier(gharchive_client=client)
    forged_name = _commit_obs(sha, message="fix build on musl",
                              author_name="Trusted Maintainer")
    assert not verifier.verify(forged_name).is_valid
    forged_email = _commit_obs(sha, message="fix build on musl",
                               author_email="attacker@example.invalid")
    assert not verifier.verify(forged_email).is_valid


def test_recovered_commit_free_text_verifies_verbatim():
    sha = "e" * 40
    client = _CannedClient([_push_row(sha)])
    obs = _commit_obs(sha, message="fix build on musl")
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert result.is_valid


def test_recovered_commit_with_empty_text_verifies_on_sha():
    # Recovery stamps "" when the payload lacked message/author — the
    # sha remains the discriminator (mirrors title=None on the issue
    # leg); an empty observation field carries no forged text.
    sha = "e" * 40
    client = _CannedClient([_push_row(sha)])
    obs = _commit_obs(sha, message="", author_name="", author_email="")
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert result.is_valid


def test_commit_row_without_free_text_verifies_on_sha():
    # Old archive rows can omit message/author on commits[] entries;
    # there is nothing to compare, so the sha carries the evidence.
    sha = "e" * 40
    client = _CannedClient([_row("PushEvent", {"commits": [{"sha": sha}]})])
    result = ConsistencyVerifier(gharchive_client=client).verify(
        _commit_obs(sha, message="anything"))
    assert result.is_valid


def test_forged_text_cannot_ride_head_sha_of_commit_bearing_row():
    # A row that DOES carry commits[] must never fall through to the
    # force-push sha-only arm: the pushed head sha is usually also a
    # commits[] entry, and the fall-through would let forged free text
    # ride a sha whose own row entry refused it verbatim.
    sha = "e" * 40
    client = _CannedClient([_push_row(sha, head=sha)])
    obs = _commit_obs(sha, message="maintainer intentionally added backdoor")
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert not result.is_valid


def test_undiscriminable_observation_type_fails_closed():
    obs = FileObservation(
        evidence_id="obs-file",
        observed_when=_WHEN,
        observed_by=EvidenceSource.GHARCHIVE,
        observed_what="file",
        repository=GitHubRepository(owner="o", name="r", full_name="o/r"),
        verification=VerificationInfo(
            source=EvidenceSource.GHARCHIVE,
            bigquery_table="githubarchive.day.20240115",
        ),
        file_path="x/y.py",
    )
    client = _CannedClient([_issue_row(1)])
    result = ConsistencyVerifier(gharchive_client=client).verify(obs)
    assert not result.is_valid


# =============================================================================
# Enumeration closure — the verifier keeps three parallel hand-written
# registries (type map, parser dispatcher, discriminator arms) plus the
# observation-side dispatch. Drift silently weakens verification back
# toward existence-checking, so the closures are pinned mechanically.
# =============================================================================


def test_type_map_closes_over_the_parser_registry():
    from src.parsers import _PARSERS
    from src.verifiers.consistency import _GHARCHIVE_TYPE_BY_EVENT_TYPE

    assert set(_GHARCHIVE_TYPE_BY_EVENT_TYPE.values()) == set(_PARSERS), (
        "kit event-type map and parser dispatcher drifted — a type "
        "wired in one but not the other verifies (or parses) blind"
    )


def test_every_mapped_type_has_a_discriminator_or_is_allowlisted():
    from types import SimpleNamespace

    from src.verifiers.consistency import (
        _GHARCHIVE_TYPE_BY_EVENT_TYPE,
        _discriminator_pair,
    )

    # The ONLY types GH Archive carries no per-event payload for.
    undiscriminable = {"watch", "public"}
    for event_type in _GHARCHIVE_TYPE_BY_EVENT_TYPE:
        stub = SimpleNamespace(event_type=event_type, member=None)
        pair = _discriminator_pair(stub, {})
        if event_type in undiscriminable:
            assert pair is None
        else:
            assert pair is not None, (
                f"event type {event_type!r} has no discriminator arm — "
                "it silently downgrades to existence-checking"
            )


def test_observation_verifier_covers_every_archive_recovery_type():
    # Every observation type the GH Archive collector can mint
    # (the recover_* return annotations) must be discriminable by
    # _verify_gharchive_observation — an uncovered type fails closed,
    # which for a REAL recovery lane means legit evidence can never
    # verify.
    import inspect
    import typing

    from src.collectors.archive import GHArchiveCollector

    minted_types = set()
    for name, method in inspect.getmembers(
            GHArchiveCollector, predicate=inspect.isfunction):
        if not name.startswith("recover_"):
            continue
        hints = typing.get_type_hints(method)
        ret = hints.get("return")
        if ret is not None and hasattr(ret, "model_fields"):
            field = ret.model_fields.get("observation_type")
            if field is not None and field.default is not None:
                minted_types.add(field.default)
    assert minted_types, "no recover_* producers found — extractor broke"
    supported = {"issue", "commit"}  # the verifier's dispatch arms
    assert minted_types <= supported, (
        f"archive recovery mints observation types {minted_types - supported} "
        "that the GH Archive observation verifier fail-closes on"
    )
