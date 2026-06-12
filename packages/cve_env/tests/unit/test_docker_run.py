"""Unit tests for :mod:`cve_env.tools.docker_run`.

Scope: pure-function + failure-path coverage without calling real docker.
Live-docker integration is exercised by the Week-1 e2e test on
CVE-2018-7600.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cve_env.tools.docker_run import RunError, _normalize_ports


def test_normalize_ports_accepts_bind_dict() -> None:
    assert _normalize_ports({8080: {"bind": "127.0.0.1"}}) == (8080, "127.0.0.1")


def test_normalize_ports_accepts_plain_bind_string() -> None:
    assert _normalize_ports({80: "127.0.0.1"}) == (80, "127.0.0.1")


def test_normalize_ports_rejects_non_localhost_bind() -> None:
    with pytest.raises(RunError) as excinfo:
        _normalize_ports({80: {"bind": "0.0.0.0"}})
    assert excinfo.value.reason == "disallowed_bind"


def test_normalize_ports_rejects_empty() -> None:
    with pytest.raises(RunError) as excinfo:
        _normalize_ports({})
    assert excinfo.value.reason == "no_ports"


def test_normalize_ports_picks_first_numeric_key() -> None:
    # Non-numeric keys are skipped.
    result = _normalize_ports({"not-a-port": {"bind": "127.0.0.1"}, 443: {"bind": "127.0.0.1"}})
    assert result == (443, "127.0.0.1")


def test_run_error_carries_reason_and_image_ref() -> None:
    err = RunError("boom", reason="no_image", image_ref="foo@sha256:abc")
    assert err.reason == "no_image"
    assert err.image_ref == "foo@sha256:abc"
    assert str(err) == "boom"


# -- S23.2 (2026-05-03): --pull always for external images -------------------
# Cache-bypass cascade-leak fix. External images (registry-pulled) MUST get
# --pull always so docker run never silently uses a stale cached layer.
# Locally-built images (source_build output, bare names) skip the flag.

def _find_docker_run_cmd(mock_run: Any) -> list[str]:
    """Helper: among all subprocess.run calls, find the `docker run -d ...`
    invocation. docker_run() also shells out for logs/inspect; we want the
    main run command specifically."""
    for call in mock_run.call_args_list:
        cmd = call[0][0]
        if isinstance(cmd, list) and len(cmd) >= 3 and cmd[0] == "docker" and cmd[1] == "run":
            return cmd
    raise AssertionError(
        f"no `docker run ...` call found in mock_run; "
        f"calls: {mock_run.call_args_list}"
    )


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_appends_pull_always_for_external_image(mock_run: Any) -> None:
    """External image (vulhub/openssl) → --pull always in argv."""
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_run.return_value = MagicMock(returncode=0, stdout="abc123def456\n", stderr="")
    docker_run(image="vulhub/openssl:1.0.1g", container_port=80)
    cmd = _find_docker_run_cmd(mock_run)
    assert "--pull" in cmd, f"missing --pull in argv: {cmd}"
    pull_idx = cmd.index("--pull")
    assert cmd[pull_idx + 1] == "always", f"--pull value not 'always': {cmd}"
    image_idx = cmd.index("vulhub/openssl:1.0.1g")
    assert pull_idx < image_idx, f"--pull must come before image: {cmd}"


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_skips_pull_always_for_local_image(mock_run: Any) -> None:
    """Locally-built image (cve-X:build) → no --pull flag (no upstream)."""
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_run.return_value = MagicMock(returncode=0, stdout="abc123def456\n", stderr="")
    docker_run(image="cve-2015-10010-openresolve:build", container_port=80)
    cmd = _find_docker_run_cmd(mock_run)
    assert "--pull" not in cmd, f"--pull should not appear for local image: {cmd}"


# -- sticky-retry guard ---------------------------------------------------


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_blocks_duplicate_failing_attempt(mock_run: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    # First call fails (e.g., arch mismatch).
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="platform mismatch")
    r1 = docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")
    assert r1.ok is False
    assert r1.reason == "docker_run_failed"

    # Second call with the SAME (image, platform) must be blocked without shelling out.
    mock_run.reset_mock()
    r2 = docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")
    assert r2.ok is False
    assert r2.reason == "duplicate_failing_attempt"
    mock_run.assert_not_called()


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_allows_different_platform_after_failure(mock_run: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    # Use stderr that classifies as manifest_unknown (Phase 9.1) so the
    # auto-retry-on-transient logic doesn't fire and the test can assert a
    # single subprocess call on a permanent failure.
    permanent_stderr = "Error response from daemon: manifest unknown"
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=permanent_stderr)
    docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")

    # Different platform arg -> not blocked. Still fails but via real docker, not the guard.
    mock_run.reset_mock()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=permanent_stderr)
    r = docker_run(image="foo@sha256:a", container_port=80, platform="linux/amd64")
    assert r.reason == "docker_run_failed"
    mock_run.assert_called_once()


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_allows_different_image_after_failure(mock_run: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    permanent_stderr = "manifest for foo not found: manifest unknown"
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=permanent_stderr)
    docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")

    mock_run.reset_mock()
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr=permanent_stderr)
    r = docker_run(image="bar@sha256:b", container_port=80, platform="linux/arm64")
    assert r.reason == "docker_run_failed"
    mock_run.assert_called_once()


def test_reset_failed_attempts_clears_guard() -> None:
    from cve_env.tools.docker_run import _FAILED_ATTEMPTS, reset_failed_attempts

    _FAILED_ATTEMPTS.add(("foo", "linux/arm64"))
    reset_failed_attempts()
    assert set() == _FAILED_ATTEMPTS


# Phase 9.5: docker_run next_step_hint --------------------------------


def test_docker_run_next_step_hint_for_duplicate_attempt() -> None:
    from cve_env.tools.docker_run import _docker_run_next_step_hint

    h = _docker_run_next_step_hint("duplicate_failing_attempt", "ok", "")
    assert "image" in h or "platform" in h


def test_docker_run_next_step_hint_for_manifest_unknown() -> None:
    from cve_env.tools.docker_run import _docker_run_next_step_hint

    h = _docker_run_next_step_hint("docker_run_failed", "manifest_unknown", "")
    assert "image_resolve" in h or "source_build" in h


def test_docker_run_next_step_hint_for_disk_full() -> None:
    from cve_env.tools.docker_run import _docker_run_next_step_hint

    h = _docker_run_next_step_hint("docker_run_failed", "disk_full", "")
    assert "disk" in h.lower()


def test_docker_run_next_step_hint_for_arch_mismatch_via_stderr() -> None:
    from cve_env.tools.docker_run import _docker_run_next_step_hint

    h = _docker_run_next_step_hint(
        "docker_run_failed",
        "unknown",
        "no matching manifest for linux/arm64 in the manifest list",
    )
    assert "arch" in h.lower() or "platform" in h.lower()


@patch("cve_env.utils.run.subprocess.run")
def test_docker_run_failure_payload_includes_next_step_hint(
    mock_run: Any,
) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="manifest unknown"
    )
    r = docker_run(
        image="nope@sha256:" + "a" * 64,
        container_port=80,
        platform="linux/arm64",
    )
    assert r.ok is False
    assert r.next_step_hint != ""


# -- Phase B (docker-pull hang): bound `docker run --pull always` ------------
# The main `docker run --pull always` now goes through run_with_timeout (in
# cve_env.utils.run); a stalled registry pull surfaces as RunOutcome
# (timed_out=True, returncode=None) instead of hanging until the 1440s
# wall-guard. docker_run must turn that into a fast, pivot-able failure.


@patch("cve_env.tools.docker_run.run_with_timeout")
@patch("cve_env.tools.docker_run.time.sleep")  # don't burn the retry backoff
def test_docker_run_pull_timeout_surfaces_pivot(
    mock_sleep: Any, mock_rwt: Any
) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts
    from cve_env.utils.run import RunOutcome

    reset_failed_attempts()
    # Simulate a slow/stalled registry pull on every attempt.
    mock_rwt.return_value = RunOutcome(
        returncode=None, stdout="", stderr="", timed_out=True
    )
    r = docker_run(image="vulhub/confluence:7.13.6", container_port=8090)

    assert r.ok is False
    assert r.reason == "pull_timeout"
    assert r.reason_class == "transport"
    # Hint must steer the agent to pivot rather than re-pull.
    hint = r.next_step_hint.lower()
    assert "source_build" in hint
    assert "pivot" in hint or "do not retry" in hint
    # MED-1 (judge): a stalled pull must FAIL FAST — exactly ONE attempt, no
    # internal retry. A 2nd full timeout window (600s) would push the docker_run
    # budget to ~1205s, risking the 1440s wall-guard the timeout exists to beat.
    assert mock_rwt.call_count == 1
