"""Resilience tests for sites migrated to ``run_with_timeout``.

Cleanup-Item-3 Stage 2 follow-up (2026-05-07c): the work-audit found that
several migrated sites (``docker_stop``, ``_container_logs_tail``,
``_compose_invocation``, ``_resolve_github_token_for_probe``,
``_inspect_state``, ``check_logs``, ``_manifest_inspect``) had NO direct
tests for the timeout / missing-binary / OSError branches. These tests
fill that gap by mocking ``cve_env.utils.run.subprocess.run`` to raise
each transport exception and asserting the migrated function returns its
documented safe-fallback value (rather than propagating the exception).

Each test is small and atomic — one site × one exception class — to make
regressions trivially traceable.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch


# ============================================================================
# verify._inspect_state — returns {"_error": str} on any failure
# ============================================================================


def test_inspect_state_returns_error_on_timeout() -> None:
    """Pre-migration this raised TimeoutExpired out of the verify chain;
    post-migration it returns a structured error dict so verify continues."""
    from cve_env.tools.verify import _inspect_state

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30),
    ):
        result = _inspect_state("c123")
    assert "_error" in result
    assert "timed out" in result["_error"].lower()


def test_inspect_state_returns_error_on_missing_binary() -> None:
    from cve_env.tools.verify import _inspect_state

    with patch(
        "cve_env.utils.run.subprocess.run", side_effect=FileNotFoundError("docker")
    ):
        result = _inspect_state("c123")
    assert "_error" in result


def test_inspect_state_returns_error_on_oserror() -> None:
    from cve_env.tools.verify import _inspect_state

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=OSError(24, "Too many open files"),
    ):
        result = _inspect_state("c123")
    assert "_error" in result


# ============================================================================
# verify._container_logs_tail — returns "" on any failure
# ============================================================================


def test_container_logs_tail_returns_empty_on_timeout() -> None:
    from cve_env.tools.verify import _container_logs_tail

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=10),
    ):
        result = _container_logs_tail("c123")
    assert result == ""


def test_container_logs_tail_returns_empty_on_missing_binary() -> None:
    from cve_env.tools.verify import _container_logs_tail

    with patch(
        "cve_env.utils.run.subprocess.run", side_effect=FileNotFoundError("docker")
    ):
        result = _container_logs_tail("c123")
    assert result == ""


# ============================================================================
# verify.check_logs — log_check that returns structured failure on timeout
# ============================================================================


def test_check_logs_returns_failed_on_timeout() -> None:
    """Pre-migration this raised TimeoutExpired out of the verify-plan
    executor; post-migration it returns a structured log_check entry with
    passed=False so the verify plan continues to other checks."""
    from cve_env.tools.verify import check_logs

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30),
    ):
        result = check_logs(
            container_id="c123",
            expected_patterns=["Server started"],
            tail=100,
        )
    assert result["type"] == "log_check"
    assert result["passed"] is False
    assert "error" in result["details"]
    assert "timed out" in result["details"]["error"].lower()


# ============================================================================
# arch._manifest_inspect — returns None on any failure
# ============================================================================


def test_manifest_inspect_returns_none_on_timeout() -> None:
    """Per docstring: ``None`` means the manifest could not be fetched
    (private registry, nonexistent image, docker-cli unavailable)."""
    from cve_env.tools.arch import _manifest_inspect

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30),
    ):
        result = _manifest_inspect("alpine:3.19")
    assert result is None


def test_manifest_inspect_returns_none_on_missing_binary() -> None:
    from cve_env.tools.arch import _manifest_inspect

    with patch(
        "cve_env.utils.run.subprocess.run", side_effect=FileNotFoundError("docker")
    ):
        result = _manifest_inspect("alpine:3.19")
    assert result is None


# ============================================================================
# docker_run.docker_stop — errors swallowed (best effort) per docstring
# ============================================================================


def test_docker_stop_swallows_timeout() -> None:
    """docker_stop's docstring promises 'errors are swallowed (best effort)'.
    Pre-migration this was untrue: a timeout would propagate. Post-migration
    the helper catches it so the contract holds."""
    from cve_env.tools.docker_run import docker_stop

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30),
    ):
        # Must NOT raise.
        docker_stop("c123")


def test_docker_stop_swallows_missing_binary() -> None:
    from cve_env.tools.docker_run import docker_stop

    with patch(
        "cve_env.utils.run.subprocess.run", side_effect=FileNotFoundError("docker")
    ):
        # Must NOT raise.
        docker_stop("c123")


def test_docker_stop_swallows_oserror() -> None:
    from cve_env.tools.docker_run import docker_stop

    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=OSError(24, "Too many open files"),
    ):
        # Must NOT raise.
        docker_stop("c123")


# ============================================================================
# infra/service_health._resolve_github_token_for_probe — returns "" on any failure
# ============================================================================


def test_service_health_token_returns_empty_on_timeout(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The probe's token-resolver: returns "" if `gh auth token` fails."""
    from cve_env.infra import service_health

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with patch(
        "cve_env.utils.run.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="gh", timeout=2),
    ):
        result = service_health._resolve_github_token_for_probe()
    assert result == ""


def test_service_health_token_returns_empty_on_missing_binary(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from cve_env.infra import service_health

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with patch("cve_env.utils.run.subprocess.run", side_effect=FileNotFoundError("gh")):
        result = service_health._resolve_github_token_for_probe()
    assert result == ""


# ============================================================================
# docker_compose_up._compose_invocation — falls through to docker-compose on
# probe failure (so caller gets the legacy invocation as fallback)
# ============================================================================


def test_compose_invocation_falls_back_when_probe_times_out() -> None:
    """Pre-migration the probe caught (TimeoutExpired, OSError) → proc=None.
    Post-migration helper does the same — function should still return the
    legacy ``docker-compose`` tuple if `docker compose version` fails AND
    legacy is on PATH; otherwise raise ComposeError. This test verifies the
    timeout path doesn't crash with TimeoutExpired.

    We patch shutil.which to return docker_bin AND docker-compose, then
    make the probe time out. Function should return the legacy tuple.
    """
    from cve_env.tools import docker_compose_up

    docker_compose_up._compose_invocation.cache_clear()

    with (
        patch(
            "cve_env.tools.docker_compose_up.shutil.which",
            side_effect=lambda b: f"/usr/bin/{b}",
        ),
        patch(
            "cve_env.utils.run.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=10),
        ),
    ):
        result = docker_compose_up._compose_invocation()
    docker_compose_up._compose_invocation.cache_clear()
    # Probe failed → falls back to legacy docker-compose
    assert result == ("/usr/bin/docker-compose",)
