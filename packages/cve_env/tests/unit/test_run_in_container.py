"""Fix C (run_in_container): thin docker-exec wrapper for in-container
verification of non-HTTP / local-exec CVEs.
"""

from __future__ import annotations

import subprocess
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from cve_env.tools.run_in_container import run_in_container


@pytest.fixture(autouse=True)
def _bypass_ownership_check() -> Generator[None, None, None]:
    """All tests in this file assume a cve-env-owned container."""
    with patch(
        "cve_env.tools.run_in_container._is_owned_container", return_value=True
    ):
        yield


def test_rejects_empty_container_id() -> None:
    r = run_in_container(container_id="", command="echo hi")
    assert r.ok is False
    assert "empty" in r.reason


def test_rejects_empty_command() -> None:
    r = run_in_container(container_id="abc", command="")
    assert r.ok is False
    assert "command is empty" in r.reason


def test_rejects_whitespace_only_command() -> None:
    r = run_in_container(container_id="abc", command="   ")
    assert r.ok is False
    assert "command is empty" in r.reason


@patch("cve_env.utils.run.subprocess.run")
def test_exec_success_returns_exit_code_zero(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="hello\n", stderr="")
    r = run_in_container(container_id="cid", command="echo hello")
    assert r.ok is True
    assert r.exit_code == 0
    assert r.stdout.strip() == "hello"
    assert r.reason == ""


@patch("cve_env.utils.run.subprocess.run")
def test_exec_nonzero_exit_is_not_ok(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=42, stdout="", stderr="boom")
    r = run_in_container(container_id="cid", command="false")
    assert r.ok is False
    assert r.exit_code == 42
    assert r.stderr.strip() == "boom"
    assert "exit_code=42" in r.reason


@patch("cve_env.utils.run.subprocess.run")
def test_exec_timeout_returns_structured_failure(mock_run: Any) -> None:
    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["docker", "exec"], timeout=1.0
    )
    r = run_in_container(container_id="cid", command="sleep 60", timeout_seconds=1.0)
    assert r.ok is False
    assert "timeout" in r.reason
    assert r.exit_code == -1


@patch("cve_env.utils.run.subprocess.run")
def test_docker_cli_not_found(mock_run: Any) -> None:
    mock_run.side_effect = FileNotFoundError()
    r = run_in_container(container_id="cid", command="echo hi")
    assert r.ok is False
    assert "docker CLI not found" in r.reason


@patch("cve_env.utils.run.subprocess.run")
def test_invocation_does_not_include_privileged(mock_run: Any) -> None:
    """P17 invariant: no privilege-escalation flags on docker exec."""
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    run_in_container(container_id="cid", command="id")
    argv = mock_run.call_args.args[0]
    assert "--privileged" not in argv
    assert "-u" not in argv
    assert "--user" not in argv
    assert "-t" not in argv  # no TTY
    # Must use sh -c for shell syntax support.
    assert "sh" in argv
    assert "-c" in argv


@patch("cve_env.utils.run.subprocess.run")
def test_workdir_is_threaded_through(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="/app\n", stderr="")
    run_in_container(container_id="cid", command="pwd", workdir="/app")
    argv = mock_run.call_args.args[0]
    assert "--workdir" in argv
    assert "/app" in argv


@patch("cve_env.utils.run.subprocess.run")
def test_stdout_is_capped(mock_run: Any) -> None:
    big = "x" * (16 * 1024)
    mock_run.return_value = MagicMock(returncode=0, stdout=big, stderr="")
    r = run_in_container(container_id="cid", command="spew")
    assert len(r.stdout) <= 8 * 1024


@patch("cve_env.utils.run.subprocess.run")
def test_timeout_is_clamped_upward_to_max(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    run_in_container(container_id="cid", command="echo", timeout_seconds=10_000.0)
    # subprocess.run was called with timeout kwarg; assert it was clamped.
    called_timeout = mock_run.call_args.kwargs.get("timeout")
    assert called_timeout is not None
    assert called_timeout <= 300.0


@patch("cve_env.utils.run.subprocess.run")
def test_timeout_is_clamped_upward_from_zero(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    run_in_container(container_id="cid", command="echo", timeout_seconds=0.0)
    called_timeout = mock_run.call_args.kwargs.get("timeout")
    assert called_timeout is not None
    assert called_timeout >= 1.0


# Phase 12.2: reason_class population --------------------------------


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_ok_on_zero_exit(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="hi", stderr="")
    r = run_in_container(container_id="cid", command="echo hi")
    assert r.ok is True
    assert r.reason_class == "ok"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_command_not_found_on_127(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=127, stdout="", stderr="sh: 1: foobar: not found"
    )
    r = run_in_container(container_id="cid", command="foobar")
    assert r.ok is False
    assert r.reason_class == "command_not_found"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_permission_denied_on_126(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=126, stdout="", stderr="sh: 1: ./script.sh: Permission denied"
    )
    r = run_in_container(container_id="cid", command="./script.sh")
    assert r.ok is False
    assert r.reason_class == "permission_denied"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_oom_killed_on_137(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=137, stdout="", stderr="Killed")
    r = run_in_container(container_id="cid", command="memhog")
    assert r.ok is False
    assert r.reason_class == "oom_killed"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_disk_full_via_stderr(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=1,
        stdout="",
        stderr="cp: cannot create '/foo': No space left on device",
    )
    r = run_in_container(container_id="cid", command="cp big /foo")
    assert r.ok is False
    assert r.reason_class == "disk_full"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_unknown_for_generic_failure(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=42, stdout="", stderr="weird app error"
    )
    r = run_in_container(container_id="cid", command="myapp")
    assert r.ok is False
    assert r.reason_class == "unknown"


@patch("cve_env.utils.run.subprocess.run")
def test_reason_class_transport_on_timeout(mock_run: Any) -> None:
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="docker exec", timeout=30)
    r = run_in_container(container_id="cid", command="long_running")
    assert r.ok is False
    assert r.reason_class == "transport"


# -- Ownership validation ------------------------------------------------


@patch(
    "cve_env.tools.run_in_container._is_owned_container",
    return_value=False,
)
def test_rejects_unowned_container(_mock_own: Any) -> None:
    r = run_in_container(container_id="foreign", command="echo hi")
    assert r.ok is False
    assert "not owned by cve-env" in r.reason
