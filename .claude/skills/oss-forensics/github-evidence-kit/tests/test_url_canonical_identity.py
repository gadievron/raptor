"""GitHub verification legs must verify against the CANONICAL source
identity.

verify_all is the anti-fabrication chokepoint. The GitHub client
previously string-joined observation fields into URL paths, so a
fabricated record claiming ``victim/repo`` could carry a traversal
``file_path`` (``../../../attacker/arepo/contents/f.txt``) that
re-addressed the verification fetch to the attacker's own repository —
requests resolves dot-segments CLIENT-SIDE — and the record earned
VERIFIED. Three layers close it, each pinned here:

1. schema: identity fields reject hostile shapes (traversal, ``?#``,
   non-hex shas, ``full_name`` != owner/name);
2. client: URLs are assembled from percent-encoded typed segments on
   an allowlisted host, and off-host redirects fail closed;
3. verifier: per-leg echo checks (response path/name/ref must match
   the observation), mirroring the commit/release legs.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from pydantic import ValidationError

from src.clients.github import GitHubClient
from src.schema.common import (
    EvidenceSource,
    GitHubRepository,
    VerificationInfo,
)
from src.schema.observations import (
    BranchObservation,
    CommitObservation,
    FileObservation,
    TagObservation,
)
from src.verifiers.consistency import ConsistencyVerifier

_WHEN = datetime(2025, 7, 13, 20, 30, tzinfo=timezone.utc)


def _obs_common(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "evidence_id": "EVD-1",
        "observed_when": _WHEN,
        "observed_by": EvidenceSource.GITHUB,
        "observed_what": "observation",
        "repository": GitHubRepository(
            owner="victim", name="repo", full_name="victim/repo"),
        "verification": VerificationInfo(
            source=EvidenceSource.GITHUB,
            url="https://github.com/victim/repo"),
    }
    data.update(overrides)
    return data


class _FakeResponse:
    def __init__(self, url: str, payload: dict[str, Any]) -> None:
        self.url = url
        self._payload = payload

    def raise_for_status(self) -> None:
        pass

    def json(self) -> dict[str, Any]:
        return self._payload


class _RecordingSession:
    """Stands in for requests.Session: records the URL and echoes the
    payload it was armed with (optionally from a different final URL,
    simulating a redirect)."""

    def __init__(self, payload: dict[str, Any] | None = None,
                 final_url: str | None = None) -> None:
        self.payload = payload or {}
        self.final_url = final_url
        self.requested: list[str] = []

    def get(self, url: str, params: dict[str, Any] | None = None,
            timeout: int | None = None) -> _FakeResponse:
        self.requested.append(url)
        return _FakeResponse(self.final_url or url, self.payload)


def _client(session: _RecordingSession) -> GitHubClient:
    client = GitHubClient()
    client._session = session
    return client


# =============================================================================
# Layer 1: schema rejects forged identity shapes
# =============================================================================


def test_schema_rejects_traversal_file_path():
    with pytest.raises(ValidationError):
        FileObservation(
            observation_type="file",
            file_path="../../../attacker/arepo/contents/f.txt",
            **_obs_common(),
        )


def test_schema_rejects_traversal_branch_name():
    with pytest.raises(ValidationError):
        BranchObservation(
            observation_type="branch",
            branch_name="x/../../../repos/attacker/arepo/branches/main",
            **_obs_common(),
        )


def test_schema_rejects_query_and_fragment_in_tag_name():
    with pytest.raises(ValidationError):
        TagObservation(
            observation_type="tag",
            tag_name="x?ref=EVIL#frag",
            **_obs_common(),
        )


def test_schema_rejects_non_hex_sha():
    with pytest.raises(ValidationError):
        CommitObservation(
            observation_type="commit",
            sha="Z" * 40,
            message="m",
            author={"name": "a", "email": "a@example.org",
                    "date": "2025-07-13T20:30:24Z"},
            committer={"name": "a", "email": "a@example.org",
                       "date": "2025-07-13T20:30:24Z"},
            **_obs_common(),
        )


def test_schema_rejects_full_name_mismatch():
    with pytest.raises(ValidationError):
        GitHubRepository(owner="attacker", name="arepo",
                         full_name="victim/repo")


def test_schema_accepts_legitimate_shapes():
    FileObservation(
        observation_type="file",
        file_path="src/lib/util.py",
        branch="release/v1.0",
        **_obs_common(),
    )
    TagObservation(observation_type="tag", tag_name="v1.2.3",
                   **_obs_common())
    GitHubRepository(owner="aws", name="aws-toolkit-vscode",
                     full_name="aws/aws-toolkit-vscode")


# =============================================================================
# Layer 2: client canonicalises the URL (typed segments, host allowlist)
# =============================================================================


def test_client_rejects_dot_segment_components():
    client = _client(_RecordingSession())
    with pytest.raises(ValueError):
        client.get_file("victim", "repo",
                        "../../../attacker/arepo/contents/f.txt")
    with pytest.raises(ValueError):
        client.get_branch("victim", "repo", "x/../../../branches/main")


def test_client_percent_encodes_metacharacters():
    session = _RecordingSession(payload={"ref": "refs/tags/x"})
    client = _client(session)
    client.get_tag("victim", "repo", "x?y")
    url = session.requested[0]
    split = urlsplit(url)
    assert split.hostname == "api.github.com"
    assert split.query == "" and split.fragment == ""
    assert "%3F" in split.path  # '?' arrived as data, not URL structure


def test_client_encodes_userinfo_trick_and_unicode():
    session = _RecordingSession()
    client = _client(session)
    client.get_repo("evil.example@api.github.com", "répo")
    url = session.requested[0]
    split = urlsplit(url)
    assert split.hostname == "api.github.com"
    assert "@" not in split.netloc
    assert "%40" in split.path
    assert "%C3%A9" in split.path


def test_client_rejects_offsite_redirect():
    session = _RecordingSession(
        payload={"path": "f.txt"},
        final_url="https://attacker.example/repos/victim/repo/contents/f.txt",
    )
    client = _client(session)
    with pytest.raises(ValueError, match="canonical host"):
        client.get_file("victim", "repo", "f.txt")


def test_client_prepared_url_is_canonical_under_requests():
    """The adjudicator's PoC-2, inverted: with canonical segments the
    URL requests would actually send stays on the victim's repo even
    for hostile-shaped inputs that survive as data."""
    requests = pytest.importorskip("requests")
    session = _RecordingSession()
    client = _client(session)
    client.get_file("victim", "repo", "docs/read me.txt")
    prepared = requests.PreparedRequest()
    prepared.prepare_url(session.requested[0], None)
    assert prepared.url.startswith(
        "https://api.github.com/repos/victim/repo/contents/docs/read%20me.txt")


# =============================================================================
# Layer 3: verifier echo checks + the full fabricated-record PoC
# =============================================================================


def test_verify_file_echo_check_rejects_other_object():
    session = _RecordingSession(
        payload={"path": "totally/other.txt", "content": ""})
    verifier = ConsistencyVerifier(github_client=_client(session))
    obs = FileObservation(
        observation_type="file",
        file_path="src/lib/util.py",
        **_obs_common(),
    )
    result = verifier._verify_file(obs)
    assert not result.is_valid
    assert any("mismatch" in e.lower() for e in result.errors)


def test_verify_branch_echo_check_rejects_other_branch():
    session = _RecordingSession(payload={"name": "other",
                                         "commit": {"sha": "0" * 40}})
    verifier = ConsistencyVerifier(github_client=_client(session))
    obs = BranchObservation(
        observation_type="branch",
        branch_name="main",
        **_obs_common(),
    )
    result = verifier._verify_branch(obs)
    assert not result.is_valid


def test_verify_tag_echo_check_rejects_other_ref():
    session = _RecordingSession(
        payload={"ref": "refs/tags/other", "object": {"sha": "0" * 40}})
    verifier = ConsistencyVerifier(github_client=_client(session))
    obs = TagObservation(
        observation_type="tag",
        tag_name="v1.0.0",
        **_obs_common(),
    )
    result = verifier._verify_tag(obs)
    assert not result.is_valid


def test_fabricated_victim_record_cannot_reach_attacker_repo():
    """End-to-end PoC-3 shape: a record claiming victim/repo must never
    produce a fetch outside victim/repo. The traversal path is stopped
    at the schema; a hand-built equivalent is stopped at the client."""
    with pytest.raises(ValidationError):
        FileObservation(
            observation_type="file",
            file_path="../../../attacker/arepo/contents/f.txt",
            **_obs_common(),
        )
    client = _client(_RecordingSession(payload={"path": "f.txt"}))
    with pytest.raises(ValueError):
        client.get_file("victim", "repo",
                        "../../../attacker/arepo/contents/f.txt")
