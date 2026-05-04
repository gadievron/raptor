"""Tests for agent/invariants.py — the four-check validator."""
from __future__ import annotations

import pytest

from cve_diff.agent.invariants import check_diff_shape, discover_validator
from cve_diff.agent.types import AgentContext, AgentOutput, AgentSurrender
from cve_diff.core.models import PatchTuple

_CTX = AgentContext(cve_id="CVE-2023-38545")


@pytest.fixture(autouse=True)
def _stub_commit_exists(monkeypatch):
    """Default: every SHA exists. Tests that exercise check 3 override this."""
    from cve_diff.infra import github_client
    monkeypatch.setattr(github_client, "commit_exists", lambda slug, sha: True)


def _rescued(**kw):
    base = {
        "outcome": "rescued",
        "repository_url": "https://github.com/curl/curl",
        "fix_commit": "fb4415d8",
        "rationale": "message references CVE-2023-38545",
    }
    base.update(kw)
    return base


def test_rescued_happy_path() -> None:
    out = discover_validator(_rescued(), _CTX)
    assert isinstance(out, AgentOutput)
    assert isinstance(out.value, PatchTuple)
    assert out.value.repository_url == "https://github.com/curl/curl"


def test_rescued_rejects_hallucinated_sha(monkeypatch) -> None:
    # commit_exists returns False → reject
    from cve_diff.infra import github_client
    monkeypatch.setattr(github_client, "commit_exists", lambda slug, sha: False)
    out = discover_validator(_rescued(fix_commit="fb4415d8aee6c14a9ec300ca28dfe318fe85e1cc"), _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "sha_not_found_in_repo"


def test_rescued_accepts_when_commit_exists_unknown(monkeypatch) -> None:
    # commit_exists returns None (rate-limited / auth) → still accept
    from cve_diff.infra import github_client
    monkeypatch.setattr(github_client, "commit_exists", lambda slug, sha: None)
    out = discover_validator(_rescued(), _CTX)
    assert isinstance(out, AgentOutput)


def test_non_github_url_skips_existence_check(monkeypatch) -> None:
    # cgit / freedesktop / gitlab — can't enforce existence via github API
    called = {"hit": False}

    def _spy(slug, sha):
        called["hit"] = True
        return False
    from cve_diff.infra import github_client
    monkeypatch.setattr(github_client, "commit_exists", _spy)
    out = discover_validator(
        _rescued(repository_url="https://gitlab.freedesktop.org/cairo/cairo", fix_commit="abc1234"),
        _CTX,
    )
    assert isinstance(out, AgentOutput)
    assert called["hit"] is False  # we never asked github


def test_rescued_rejects_short_sha_literal() -> None:
    out = discover_validator(_rescued(fix_commit="0"), _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "invalid_sha_format"


def test_rescued_rejects_version_string_as_sha() -> None:
    out = discover_validator(_rescued(fix_commit="1.2.3"), _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "invalid_sha_format"


def test_rescued_rejects_none_literal() -> None:
    out = discover_validator(_rescued(fix_commit="none"), _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "invalid_sha_format"


def test_rescued_rejects_malformed_repository_url() -> None:
    # No http(s) scheme — reject as malformed. No slug-content list lookup.
    out = discover_validator(
        _rescued(repository_url="cveproject/cvelistv5"),
        _CTX,
    )
    assert isinstance(out, AgentSurrender)
    assert out.reason == "malformed_repository_url"


def test_rescued_rejects_empty_repo() -> None:
    out = discover_validator(_rescued(repository_url=""), _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "malformed_repository_url"


def test_unsupported() -> None:
    out = discover_validator({"outcome": "unsupported", "rationale": "router firmware"}, _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "unsupported_source"


def test_no_evidence() -> None:
    out = discover_validator({"outcome": "no_evidence", "rationale": "tried 5 searches"}, _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "no_evidence"


def test_invalid_outcome() -> None:
    out = discover_validator({"outcome": "???", "rationale": "."}, _CTX)
    assert isinstance(out, AgentSurrender)
    assert out.reason == "invalid_outcome"


def test_shape_sanity_notes_only_rejected() -> None:
    assert check_diff_shape("notes_only") == "notes_only_diff"


def test_shape_sanity_source_ok() -> None:
    assert check_diff_shape("source") is None


def test_shape_sanity_packaging_only_ok() -> None:
    # packaging_only intentionally passes — some real patches are pure bumps.
    assert check_diff_shape("packaging_only") is None
