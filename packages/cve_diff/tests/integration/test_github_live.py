"""
Live GitHub API integration test. Hits api.github.com for a stable public
repo (torvalds/linux) and asserts the thin client returns the fields the
metadata scorer reads.

Skipped by default (addopts `-m 'not integration'`). Run explicitly with
`.venv/bin/pytest tests/integration -m integration -q`.
"""

from __future__ import annotations

import os

import pytest

from cve_diff.infra import github_client


@pytest.mark.integration
def test_github_live_get_repo_returns_metadata_fields() -> None:
    """Reads torvalds/linux. Chosen because it's public, stable, high-star,
    not a fork — the exact profile the scorer must NOT penalise. Verifies
    the live client plumbs through fields `metadata_score` reads.
    """
    github_client.reset_for_tests()
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN unset — unauth hits 60 req/h; skip to keep CI green")

    payload = github_client.get_repo("torvalds/linux")
    assert payload is not None, "GET /repos returned None — rate-limit or network?"
    assert payload.get("fork") is False
    assert isinstance(payload.get("stargazers_count"), int)
    assert payload["stargazers_count"] > 100_000
    assert isinstance(payload.get("size"), int)
    assert payload.get("created_at", "").startswith("20")
    assert payload.get("language") is not None


@pytest.mark.integration
def test_github_live_get_languages_returns_dict() -> None:
    """/languages is used by shape_dynamic. A known Python repo should
    return a dict with 'Python' as a non-trivial key.
    """
    github_client.reset_for_tests()
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN unset")

    payload = github_client.get_languages("python/cpython")
    assert payload is not None
    assert isinstance(payload, dict)
    assert "Python" in payload or "C" in payload
