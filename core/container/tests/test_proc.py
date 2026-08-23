"""Contract tests for core.container.proc — the bounded CLI runner.

The cve_env suite pins the same behaviour through its delegating shim
(``packages/cve_env/tests/unit/test_utils_run.py``); these pin the core
surface directly so the substrate stays covered if the shim ever goes.
"""

from __future__ import annotations

import os
from unittest.mock import patch

from core.container.proc import (
    DOCKER_CHILD_ENV_VARS,
    RunOutcome,
    docker_child_env,
    run_cli,
)


def test_fast_command_returns_outcome() -> None:
    outcome = run_cli(["sh", "-c", "echo hello && exit 0"], timeout=5.0)
    assert isinstance(outcome, RunOutcome)
    assert outcome.timed_out is False
    assert outcome.returncode == 0
    assert "hello" in outcome.stdout


def test_timeout_never_raises() -> None:
    outcome = run_cli(["sleep", "5"], timeout=0.1)
    assert outcome.timed_out is True
    assert outcome.returncode is None


def test_nonzero_exit_is_data_not_exception() -> None:
    outcome = run_cli(["sh", "-c", "echo err >&2; exit 7"], timeout=5.0)
    assert outcome.returncode == 7
    assert "err" in outcome.stderr
    assert outcome.timed_out is False


def test_missing_binary_folds_to_command_not_found() -> None:
    outcome = run_cli(["definitely-not-a-real-binary-xyz"], timeout=5.0)
    assert outcome.returncode is None
    assert outcome.timed_out is False
    assert outcome.stderr.startswith("command_not_found:")


def test_non_utf8_output_decoded_leniently() -> None:
    outcome = run_cli(["sh", "-c", r"printf 'a\251b'"], timeout=5.0)
    assert outcome.returncode == 0
    assert outcome.stdout.startswith("a")
    assert outcome.stdout.endswith("b")


def test_default_env_strips_dangerous_vars() -> None:
    with patch.dict(os.environ, {"LD_PRELOAD": "/tmp/evil.so",
                                 "HTTPS_PROXY": "http://x:1"}):
        env = docker_child_env()
    assert "LD_PRELOAD" not in env
    assert "HTTPS_PROXY" not in env


def test_docker_daemon_vars_kept() -> None:
    with patch.dict(os.environ, {"DOCKER_HOST": "unix:///x.sock"}):
        env = docker_child_env()
    assert env["DOCKER_HOST"] == "unix:///x.sock"
    assert set(DOCKER_CHILD_ENV_VARS) >= {"DOCKER_HOST", "DOCKER_CONFIG"}


def test_keep_opts_a_var_back_in() -> None:
    with patch.dict(os.environ, {"HTTPS_PROXY": "http://x:1"}):
        env = docker_child_env(keep=frozenset({"HTTPS_PROXY"}))
    assert env["HTTPS_PROXY"] == "http://x:1"


def test_caller_env_used_verbatim() -> None:
    outcome = run_cli(["sh", "-c", "echo $ONLY_VAR"], timeout=5.0,
                      env={"ONLY_VAR": "v", "PATH": os.environ["PATH"]})
    assert outcome.stdout.strip() == "v"
