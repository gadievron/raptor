"""Contract tests for core.container.failures — the stderr taxonomy.

One representative pattern per class plus the load-bearing precedence
pins (the ordering rationale documented on ``_CLASSIFIER_TABLE``)."""

from __future__ import annotations

import pytest

from core.container.failures import classify_docker_stderr, is_retry_eligible


@pytest.mark.parametrize(("stderr", "expected"), [
    ("no space left on device", "disk_full"),
    ("manifest unknown", "manifest_unknown"),
    ("received unexpected HTTP status: 503", "transport"),
    ("pull access denied for x, repository does not exist", "manifest_unknown"),
    ("unauthorized: authentication required", "auth"),
    ("temporary failure in name resolution", "network"),
    ("corrupted containerd storage: persistent input/output error",
     "daemon_corruption"),
    ("At least one invalid signature was encountered", "gpg_signature"),
    ("bind source path does not exist", "fatal_compose_config"),
    ("You have reached your unauthenticated pull rate limit", "rate_limited"),
    ("something entirely new", "unknown"),
])
def test_representative_patterns(stderr: str, expected: str) -> None:
    assert classify_docker_stderr(stderr) == expected


def test_empty_and_none_are_unknown() -> None:
    assert classify_docker_stderr("") == "unknown"
    assert classify_docker_stderr(None) == "unknown"


def test_bytes_stderr_decoded() -> None:
    assert classify_docker_stderr(b"no space left on device") == "disk_full"


def test_daemon_corruption_beats_disk_full() -> None:
    """The corruption signature co-occurs with 'input/output error' —
    a disk_full verdict would trigger a futile prune+retry on a daemon
    that needs a restart."""
    combined = ("corrupted containerd storage: persistent "
                "input/output error")
    assert classify_docker_stderr(combined) == "daemon_corruption"


def test_rate_limited_beats_auth() -> None:
    """Docker Hub rate-limit messages use auth-flavoured words; the
    rate_limited class must win or the caller mislabels a cooldown
    situation as a permanent credential failure."""
    combined = "unauthenticated pull rate limit exceeded; unauthorized"
    assert classify_docker_stderr(combined) == "rate_limited"


def test_retry_eligibility_partition() -> None:
    retry = {"disk_full", "transport", "network", "unknown", "rate_limited"}
    permanent = {"manifest_unknown", "auth", "daemon_corruption",
                 "gpg_signature", "fatal_compose_config", "ok"}
    for klass in retry:
        assert is_retry_eligible(klass), klass
    for klass in permanent:
        assert not is_retry_eligible(klass), klass
