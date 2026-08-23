"""URL-target behavior of the run-dir target checks."""

from __future__ import annotations

import pytest

from core.run.output import TargetMismatchError, _check_target_mismatch, volatile_target_reason


def test_volatile_reason_names_urls_instead_of_misdiagnosing():
    reason = volatile_target_reason("https://example.test")

    assert reason is not None
    assert "URL" in reason
    assert "does not exist" not in reason


def test_url_run_against_matching_url_project_passes():
    _check_target_mismatch(
        "https://example.test/", "webapp", "https://example.test",
    )


def test_url_run_against_different_url_project_raises():
    with pytest.raises(TargetMismatchError):
        _check_target_mismatch(
            "https://other.test", "webapp", "https://example.test",
        )


def test_url_run_against_filesystem_project_still_skips(tmp_path):
    # Mixed projects (a repo project whose deployment gets /web scans)
    # keep the historical skip: only URL-vs-URL is comparable.
    _check_target_mismatch(
        "https://example.test", "repo", str(tmp_path),
    )
