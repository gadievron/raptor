"""Contract tests for core.container.proc — the bounded CLI runner.

The cve_env suite pins the same behaviour through its delegating shim
(``packages/cve_env/tests/unit/test_utils_run.py``); these pin the core
surface directly so the substrate stays covered if the shim ever goes.
"""

from __future__ import annotations

import os
import subprocess
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


def test_output_capped_at_read_boundary_keeps_tail() -> None:
    """Hostile output larger than the cap is truncated AS IT IS READ —
    the tail (where diagnostics land) is what survives."""
    outcome = run_cli(
        ["sh", "-c", "yes 0123456789 | head -c 500000; printf TAILMARK"],
        timeout=30.0,
        max_output_bytes=4096,
    )
    assert outcome.returncode == 0
    assert len(outcome.stdout) <= 4096
    assert outcome.stdout.endswith("TAILMARK")


def test_output_below_cap_is_intact() -> None:
    """The cap must not disturb outputs smaller than itself (the
    truncate-too-eagerly direction)."""
    outcome = run_cli(
        ["sh", "-c", "printf HEAD; printf %01000d 7; printf TAIL"],
        timeout=5.0,
        max_output_bytes=4096,
    )
    assert outcome.returncode == 0
    assert outcome.stdout.startswith("HEAD")
    assert outcome.stdout.endswith("TAIL")
    assert len(outcome.stdout) == 1008


def test_stderr_capped_independently() -> None:
    outcome = run_cli(
        ["sh", "-c", "yes err | head -c 100000 1>&2"],
        timeout=30.0,
        max_output_bytes=2048,
    )
    assert outcome.returncode == 0
    assert len(outcome.stderr) <= 2048
    assert outcome.stderr.endswith("err\n")
    assert outcome.truncated is True


def test_output_exactly_at_cap_not_flagged_truncated() -> None:
    """Boundary: output EQUAL to the cap is complete — it must come back
    intact and NOT carry the truncation flag (the flag exists so parsing
    consumers can refuse partial documents; flagging complete output
    would make them refuse good runs)."""
    outcome = run_cli(
        ["sh", "-c", "printf %04096d 7"],
        timeout=5.0,
        max_output_bytes=4096,
    )
    assert outcome.returncode == 0
    assert len(outcome.stdout) == 4096
    assert outcome.truncated is False


def test_output_over_cap_flagged_truncated() -> None:
    """Boundary: one byte over the cap loses its head AND says so —
    silent tail-keep is indistinguishable from complete output to a
    consumer that parses stdout."""
    outcome = run_cli(
        ["sh", "-c", "printf %04097d 7"],
        timeout=5.0,
        max_output_bytes=4096,
    )
    assert outcome.returncode == 0
    assert len(outcome.stdout) == 4096
    assert outcome.truncated is True


def test_below_cap_not_flagged_truncated() -> None:
    outcome = run_cli(
        ["sh", "-c", "printf small"],
        timeout=5.0,
        max_output_bytes=4096,
    )
    assert outcome.stdout == "small"
    assert outcome.truncated is False


def test_timeout_partial_output_carries_truncation_flag() -> None:
    """A stream that overflowed BEFORE the timeout fired reports both
    timed_out and truncated — the partial tail is doubly partial."""
    # ``exec`` keeps everything in the DIRECT child: the kill at timeout
    # reaps it immediately (no orphan grandchild holding the pipe open,
    # which would exercise the abandon path instead).
    outcome = run_cli(
        ["sh", "-c", "printf %02000d 7; exec sleep 5"],
        timeout=1.0,
        max_output_bytes=1024,
    )
    assert outcome.timed_out is True
    assert outcome.truncated is True
    assert len(outcome.stdout) <= 1024


def test_mocked_run_never_reads_as_truncated() -> None:
    """The repo-wide test seam (mocking subprocess.run) writes nothing to
    the drain pipes — a mock supplying stdout larger than the cap must
    come back verbatim with truncated=False, or every cve_env mock site
    would need cap-awareness."""
    big = "x" * 8192
    fake = subprocess.CompletedProcess(["docker", "ps"], 0,
                                       stdout=big, stderr="")
    with patch("core.container.proc.subprocess.run", return_value=fake):
        outcome = run_cli(["docker", "ps"], timeout=5.0,
                          max_output_bytes=4096)
    assert outcome.stdout == big
    assert outcome.truncated is False
