"""Unit tests for the shared docker-stderr failure classifier (Phase 9.1)."""

from __future__ import annotations

import pytest

from cve_env.tools._failure_class import classify_docker_stderr, is_retry_eligible


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        # disk_full
        ("write /var/lib/docker/overlay2/x: no space left on device", "disk_full"),
        ("failed to register layer: no space left on device", "disk_full"),
        ("disk full", "disk_full"),
        ("input/output error", "disk_full"),
        # manifest_unknown
        (
            "manifest for nonexistent:latest not found: manifest unknown",
            "manifest_unknown",
        ),
        ("repository foo/bar not found", "manifest_unknown"),
        (
            "pull access denied for X, repository does not exist or may require 'docker login'",
            "manifest_unknown",
        ),
        ("Error: image not found", "manifest_unknown"),
        # transport
        ("received unexpected HTTP status: 503 Service Unavailable", "transport"),
        ("toomanyrequests: You have reached your pull rate limit", "transport"),
        ("connection reset by peer", "transport"),
        ("read tcp 1.2.3.4: i/o timeout", "transport"),
        (
            "Error response from daemon: timeout while waiting for connection",
            "transport",
        ),
        # auth
        ("denied: requested access to the resource is denied", "auth"),
        ("Error response from daemon: 401 Unauthorized", "auth"),
        ("authentication required", "auth"),
        # network
        ("network is unreachable", "network"),
        (
            "dial tcp: lookup registry-1.docker.io: temporary failure in name resolution",
            "network",
        ),
        ("Could not resolve host: registry-1.docker.io", "network"),
        # unknown / fallback
        ("some bizarre error nobody has ever seen", "unknown"),
        # empty stderr → no evidence to classify
        ("", "unknown"),
        (None, "unknown"),
    ],
)
def test_classify_docker_stderr_known_patterns(
    stderr: str | None, expected: str
) -> None:
    assert classify_docker_stderr(stderr) == expected


def test_classify_docker_stderr_disk_full_takes_precedence_over_auth() -> None:
    """A disk-full message that mentions 'denied' should still classify as disk_full."""
    stderr = "no space left on device; pull access denied"
    assert classify_docker_stderr(stderr) == "disk_full"


def test_classify_docker_stderr_handles_bytes_input() -> None:
    """Some docker subprocess wrappers return stderr as bytes."""
    stderr = b"no space left on device"
    assert classify_docker_stderr(stderr) == "disk_full"


def test_is_retry_eligible_classes() -> None:
    """Retry: disk_full/transport/network/unknown YES; manifest_unknown/auth/ok NO."""
    assert is_retry_eligible("disk_full") is True
    assert is_retry_eligible("transport") is True
    assert is_retry_eligible("network") is True
    assert is_retry_eligible("unknown") is True
    assert is_retry_eligible("manifest_unknown") is False
    assert is_retry_eligible("auth") is False
    assert is_retry_eligible("ok") is False


# B12 (2026-05-02): fatal_compose_config classification ------------------


@pytest.mark.parametrize(
    "stderr",
    [
        # Verbatim from CVE-2019-11043 in bench50-20260502-180209: agent
        # cycled compose retries because OCI mount errors looked transient.
        "Error response from daemon: failed to create task for container: "
        "failed to create shim: OCI runtime create failed: cannot create "
        'subdirectories in "/var/lib/docker/.../mounts": no such file or directory',
        "OCI runtime exec failed: exec failed: container_linux.go: starting "
        "container process caused: process_linux.go: ...: cannot create "
        "subdirectories",
        "Bind source path does not exist: /host/missing/dir",
        'invalid mount config for type "bind": bind source path does not exist',
    ],
)
def test_b12_fatal_compose_config_class(stderr: str) -> None:
    """B12: OCI mount / bind-source-missing errors are CONFIG bugs, not transient.
    Classifying them as fatal_compose_config lets is_retry_eligible() return
    False, breaking the agent's retry-loop that consumed CVE-2019-11043's
    full 600s wall budget without ever reaching verify."""
    assert classify_docker_stderr(stderr) == "fatal_compose_config"


def test_b12_fatal_compose_config_not_retry_eligible() -> None:
    """fatal_compose_config is permanent: agent must pivot, not retry the
    same compose call. Mirrors manifest_unknown/auth semantics."""
    assert is_retry_eligible("fatal_compose_config") is False


def test_b12_fatal_compose_config_has_prompt_recovery_rule() -> None:
    """B12 followup (2026-05-02 persona review): the engine's retry-skip
    is necessary but not sufficient. Without an explicit recovery rule in
    the agent's SYSTEM_PROMPT, the agent sees an unfamiliar reason_class
    and may still spend turns rewriting the compose yaml before giving up.
    Mirrors the gpg_signature pattern at prompts.py:473.

    The rule must (a) name the class so the agent recognizes it, (b) tell
    the agent to NOT retry the same yaml, and (c) offer concrete recovery
    paths (single-service docker_run / rewrite without bind mount)."""
    from cve_env.agent.prompts import SYSTEM_PROMPT

    assert "fatal_compose_config" in SYSTEM_PROMPT, (
        "B12 prompt rule missing: agent gets unfamiliar reason_class with no playbook"
    )
    assert "Do NOT retry" in SYSTEM_PROMPT or "do NOT retry" in SYSTEM_PROMPT, (
        "B12 rule must explicitly forbid retrying the same compose yaml"
    )


# Phase 37.4: GPG-signature classification tests --------------------------


@pytest.mark.parametrize(
    "stderr",
    [
        "W: GPG error: http://deb.debian.org/debian bullseye InRelease: "
        "At least one invalid signature was encountered.",
        "E: The repository 'http://deb.debian.org/debian bullseye InRelease' "
        "is not signed.",
        "W: GPG error: At least one invalid signature was encountered",
        "NO_PUBKEY 0E98404D386FA1D9",
    ],
)
def test_phase37_4_gpg_signature_class(stderr: str) -> None:
    """Phase 37.4: GPG/apt signature errors get a dedicated class."""
    assert classify_docker_stderr(stderr) == "gpg_signature"


def test_phase37_4_disk_full_still_wins_over_gpg() -> None:
    """If both disk-full AND gpg-signature errors are in stderr (rare but
    plausible mid-build), disk_full takes precedence — fixing disk
    unblocks gpg, but not vice-versa.
    """
    stderr = "no space left on device\nGPG error: invalid signature"
    assert classify_docker_stderr(stderr) == "disk_full"


# A1: Docker Hub anonymous rate-limit classification (CVE-2019-3396 forensic)


@pytest.mark.parametrize(
    "stderr",
    [
        # Verbatim phrasing from CVE-2019-3396 docker_compose_up failure
        "error from registry: You have reached your unauthenticated pull rate limit. "
        "https://www.docker.com/increase-rate-limit",
        # Variant phrasings
        "You have reached your unauthenticated pull rate limit",
        "unauthenticated pull rate limit exceeded",
    ],
)
def test_classify_docker_stderr_rate_limited(stderr: str) -> None:
    """Docker Hub anonymous rate limit gets its own class so agents can pivot
    to mirror.gcr.io/library/ rather than treating the error as transport.
    CVE-2019-3396: postgres:10.7-alpine rate-limited; agent gave up as
    'proprietary' because reason_class was 'unknown'.
    """
    assert classify_docker_stderr(stderr) == "rate_limited"


def test_rate_limited_is_retry_eligible() -> None:
    """rate_limited is retriable via mirror.gcr.io substitution."""
    assert is_retry_eligible("rate_limited") is True


@pytest.mark.parametrize(
    "stderr",
    [
        # Verbatim from CVE-2024-35746 (bench50-20260602-070917): disk pressure
        # corrupted the colima containerd storage mid-run.
        "Host docker daemon has corrupted containerd storage: persistent input/output error",
        "failed to retrieve image list: rpc error: code = Unknown desc = ...",
        "Error response from daemon: failed to retrieve image list",
        "rpc error: code = Unknown desc = readlink /var/lib/containerd: input/output error",
    ],
)
def test_classify_docker_stderr_daemon_corruption(stderr: str) -> None:
    """2026-06-02: disk-pressure corrupted colima containerd → builds fail with
    'corrupted containerd storage' / 'failed to retrieve image list'. This is HOST
    INFRA corruption, NOT disk_full (prune+retry is futile — the daemon stays
    corrupted) and NOT the agent's build error. Must classify distinctly so the
    agent gives up cleanly (infra) and the bench can heal (daemon restart) rather
    than cascade one corruption into many futile-retry failures."""
    assert classify_docker_stderr(stderr) == "daemon_corruption"


def test_daemon_corruption_not_in_run_retry_eligible() -> None:
    """In-run auto-retry is FUTILE on a corrupted daemon (it stays corrupted) —
    the heal is a daemon restart at the bench layer, not a docker_build retry."""
    assert is_retry_eligible("daemon_corruption") is False


def test_plain_disk_full_still_disk_full_not_corruption() -> None:
    """Guard: a genuine no-space error must STILL classify as disk_full (the
    daemon_corruption patterns must not over-capture plain disk exhaustion)."""
    assert (
        classify_docker_stderr("write /var/lib/docker/x: no space left on device")
        == "disk_full"
    )
