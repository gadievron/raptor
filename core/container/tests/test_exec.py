"""Contract tests for core.container.exec."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from core.container import exec as ce
from core.container.proc import RunOutcome


def _ok(stdout: str = "", stderr: str = "", rc: int = 0) -> RunOutcome:
    return RunOutcome(returncode=rc, stdout=stdout, stderr=stderr,
                      timed_out=False)


def test_exec_command_shape_minimal_posture() -> None:
    captured: list[list[str]] = []

    def run(cmd: list[str], **_kw: Any) -> RunOutcome:
        captured.append(list(cmd))
        return _ok(stdout="hi")

    with patch.object(ce, "run_cli", side_effect=run):
        r = ce.exec_in_container(container_id="cid", command="echo hi",
                                 workdir="/app")
    assert r.ok and r.stdout == "hi"
    (cmd,) = captured
    assert cmd == ["docker", "exec", "--workdir", "/app", "cid",
                   "sh", "-c", "echo hi"]
    # No -u/-t/--privileged ever.
    assert not ({"-u", "-t", "--privileged"} & set(cmd))


def test_required_label_gate_refuses_unowned() -> None:
    with patch.object(ce, "run_cli",
                      return_value=_ok(stdout="other\n")) as m:
        r = ce.exec_in_container(container_id="cid", command="id",
                                 required_label=("o", "mine"))
    assert not r.ok and "not owned" in r.reason
    assert m.call_count == 1  # inspect only; no exec issued


def test_empty_inputs_refused() -> None:
    assert not ce.exec_in_container(container_id="", command="x").ok
    with patch.object(ce, "run_cli") as m:
        r = ce.exec_in_container(container_id="cid", command="   ")
    assert not r.ok and "command is empty" in r.reason
    m.assert_not_called()


def test_timeout_clamped_and_classified_transport() -> None:
    seen: dict[str, float] = {}

    def run(cmd: list[str], *, timeout: float, **_kw: Any) -> RunOutcome:
        seen["timeout"] = timeout
        return RunOutcome(returncode=None, stdout="", stderr="",
                          timed_out=True)

    with patch.object(ce, "run_cli", side_effect=run):
        r = ce.exec_in_container(container_id="cid", command="sleep 999",
                                 timeout_seconds=9999.0)
    assert seen["timeout"] == ce.MAX_TIMEOUT_SECONDS
    assert not r.ok and r.exit_code == -1
    assert r.reason_class == "transport"


@pytest.mark.parametrize(("rc", "stderr", "expected"), [
    (0, "", "ok"),
    (127, "", "command_not_found"),
    (1, "sh: 1: xyz: command not found", "command_not_found"),
    (126, "", "permission_denied"),
    (137, "", "oom_killed"),
    (1, "tar: write error: no space left on device", "disk_full"),
    (1, "read: connection reset by peer", "transport"),
    (3, "some app error", "unknown"),
])
def test_exit_classification(rc: int, stderr: str, expected: str) -> None:
    assert ce.classify_exec_exit(rc, stderr) == expected


def test_output_caps_applied() -> None:
    big = "x" * (ce.STDOUT_CAP_BYTES + 100)
    with patch.object(ce, "run_cli", return_value=_ok(stdout=big)):
        r = ce.exec_in_container(container_id="cid", command="cat big")
    assert len(r.stdout) == ce.STDOUT_CAP_BYTES
