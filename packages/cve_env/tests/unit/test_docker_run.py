"""Unit tests for :mod:`cve_env.tools.docker_run`.

Scope: pure-function + failure-path coverage without calling real docker.
Live-docker integration is exercised by the Week-1 e2e test on
CVE-2018-7600.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from cve_env.tools.docker_run import RunError, _normalize_ports

from core.container.proc import RunOutcome
from core.testing.module_bindings import patch_module_attribute
from core.testing.poll_clock import install_poll_clock


@pytest.fixture(autouse=True)
def _isolate_clock_patch_targets(monkeypatch):
    """Keep clock patch decorators and contexts on this consumer's view."""
    import core.container.containers as clock_consumer

    patch_module_attribute(
        monkeypatch, clock_consumer, "time", "sleep", clock_consumer.time.sleep,
    )


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
    result = _normalize_ports(
        {"not-a-port": {"bind": "127.0.0.1"}, 443: {"bind": "127.0.0.1"}}
    )
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


def _find_docker_run_cmd(mock_cli: Any) -> list[str]:
    """Helper: among all CLI calls, find the `docker run -d ...`
    invocation. docker_run() also shells out for logs/inspect; we want the
    main run command specifically."""
    for call in mock_cli.call_args_list:
        cmd = call[0][0]
        if (
            isinstance(cmd, list)
            and len(cmd) >= 3
            and cmd[0] == "docker"
            and cmd[1] == "run"
        ):
            return cmd
    raise AssertionError(
        f"no `docker run ...` call found in mock_cli; calls: {mock_cli.call_args_list}"
    )


def _successful_launch_cli(cmd, **kwargs):
    stdout = ('{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"49000"}]}'
              if cmd[:2] == ["docker", "inspect"] else "abc123def456\n")
    return RunOutcome(returncode=0, stdout=stdout, stderr="", timed_out=False)


@pytest.fixture(autouse=True)
def _owned_launch_state(monkeypatch):
    """Reset tests must not clear a caller's failure/session registries."""
    import cve_env.tools.docker_run as consumer

    for name in consumer._RESET_GLOBALS:
        monkeypatch.setattr(consumer, name, set())


@pytest.fixture(autouse=True)
def _virtual_launch_waits(monkeypatch):
    """Exercise real retry/poll budgets without real sleeps or shorter caps."""
    import core.container.containers as consumer

    return install_poll_clock(monkeypatch, consumer)


@patch("core.container.containers.run_cli")
def test_docker_run_appends_pull_always_for_external_image(mock_cli: Any) -> None:
    """External image (vulhub/openssl) → --pull always in argv."""
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_cli.side_effect = _successful_launch_cli
    result = docker_run(image="vulhub/openssl:1.0.1g", container_port=80)
    assert result.ok
    cmd = _find_docker_run_cmd(mock_cli)
    assert "--pull" in cmd, f"missing --pull in argv: {cmd}"
    pull_idx = cmd.index("--pull")
    assert cmd[pull_idx + 1] == "always", f"--pull value not 'always': {cmd}"
    image_idx = cmd.index("vulhub/openssl:1.0.1g")
    assert pull_idx < image_idx, f"--pull must come before image: {cmd}"


@patch("core.container.containers.run_cli")
def test_docker_run_skips_pull_always_for_local_image(mock_cli: Any) -> None:
    """Locally-built image (cve-X:build) → no --pull flag (no upstream)."""
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_cli.side_effect = _successful_launch_cli
    result = docker_run(image="cve-2015-10010-openresolve:build", container_port=80)
    assert result.ok
    cmd = _find_docker_run_cmd(mock_cli)
    assert "--pull" not in cmd, f"--pull should not appear for local image: {cmd}"


@patch("core.container.containers.run_cli")
def test_missing_port_reports_failure_after_full_poll_budget(mock_cli, _virtual_launch_waits):
    from cve_env.tools import docker_run as consumer

    mock_cli.return_value = RunOutcome(
        returncode=0, stdout="abc123def456\n", stderr="", timed_out=False,
    )
    result = consumer.docker_run(image="nginx:1.25", container_port=80)
    assert not result.ok
    assert result.reason == "no_host_port"
    assert _virtual_launch_waits.seconds >= 10.0
    inspections = [call for call in mock_cli.call_args_list
                   if call.args[0][:2] == ["docker", "inspect"]]
    assert len(inspections) > 1
    assert not consumer.session_container_ids()


# -- sticky-retry guard ---------------------------------------------------


@patch("core.container.containers.run_cli")
def test_docker_run_blocks_duplicate_failing_attempt(mock_cli: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    # First call fails (e.g., arch mismatch).
    mock_cli.return_value = RunOutcome(timed_out=False,
        returncode=1, stdout="", stderr="platform mismatch"
    )
    r1 = docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")
    assert r1.ok is False
    assert r1.reason == "docker_run_failed"

    # Second call with the SAME (image, platform) must be blocked without shelling out.
    mock_cli.reset_mock()
    r2 = docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")
    assert r2.ok is False
    assert r2.reason == "duplicate_failing_attempt"
    mock_cli.assert_not_called()


@patch("core.container.containers.run_cli")
def test_docker_run_allows_different_platform_after_failure(mock_cli: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    # Use stderr that classifies as manifest_unknown (Phase 9.1) so the
    # auto-retry-on-transient logic doesn't fire and the test can assert a
    # single subprocess call on a permanent failure.
    permanent_stderr = "Error response from daemon: manifest unknown"
    mock_cli.return_value = RunOutcome(timed_out=False, returncode=1, stdout="", stderr=permanent_stderr)
    docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")

    # Different platform arg -> not blocked. Still fails but via real docker, not the guard.
    mock_cli.reset_mock()
    mock_cli.return_value = RunOutcome(timed_out=False, returncode=1, stdout="", stderr=permanent_stderr)
    r = docker_run(image="foo@sha256:a", container_port=80, platform="linux/amd64")
    assert r.reason == "docker_run_failed"
    mock_cli.assert_called_once()


@patch("core.container.containers.run_cli")
def test_docker_run_allows_different_image_after_failure(mock_cli: Any) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    permanent_stderr = "manifest for foo not found: manifest unknown"
    mock_cli.return_value = RunOutcome(timed_out=False, returncode=1, stdout="", stderr=permanent_stderr)
    docker_run(image="foo@sha256:a", container_port=80, platform="linux/arm64")

    mock_cli.reset_mock()
    mock_cli.return_value = RunOutcome(timed_out=False, returncode=1, stdout="", stderr=permanent_stderr)
    r = docker_run(image="bar@sha256:b", container_port=80, platform="linux/arm64")
    assert r.reason == "docker_run_failed"
    mock_cli.assert_called_once()


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


@patch("core.container.containers.run_cli")
def test_docker_run_failure_payload_includes_next_step_hint(
    mock_cli: Any,
) -> None:
    from cve_env.tools.docker_run import docker_run, reset_failed_attempts

    reset_failed_attempts()
    mock_cli.return_value = RunOutcome(timed_out=False,
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


@patch("core.container.containers.run_cli")
@patch("core.container.containers.time.sleep")  # don't burn the retry backoff
def test_docker_run_pull_timeout_surfaces_pivot(mock_sleep: Any, mock_rwt: Any) -> None:
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


# -- session container registry (verify tcp-probe allowlist scope) -----------


def test_successful_launch_records_session_container(monkeypatch) -> None:
    """docker_run registers the launched container id in the per-run
    session registry that scopes the verify tool's tcp-probe port
    allowlist; reset clears it (per-CVE state contract)."""
    from core.container.containers import LaunchResult
    from cve_env.tools import docker_run as dr

    dr.reset_failed_attempts()
    cid = "e" * 64
    monkeypatch.setattr(
        dr, "launch_container",
        lambda **kw: LaunchResult(ok=True, container_id=cid,
                                  host_port=49001, container_port=80))
    result = dr.docker_run(image="nginx:1.25", container_port=80)
    assert result.ok
    assert cid in dr.session_container_ids()
    dr.reset_failed_attempts()
    assert dr.session_container_ids() == frozenset()


def test_failed_launch_not_recorded(monkeypatch) -> None:
    from core.container.containers import LaunchResult
    from cve_env.tools import docker_run as dr

    dr.reset_failed_attempts()
    monkeypatch.setattr(
        dr, "launch_container",
        lambda **kw: LaunchResult(ok=False, container_id="d" * 64,
                                  reason="no_host_port",
                                  reason_class="unknown", stderr="x"))
    result = dr.docker_run(image="nginx:1.25", container_port=80)
    assert not result.ok
    assert dr.session_container_ids() == frozenset()
    dr.reset_failed_attempts()
