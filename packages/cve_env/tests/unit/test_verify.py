"""Unit tests for :mod:`cve_env.tools.verify`.

Scope: HTTP/log/plan aggregation via patching. Live-docker integration
is exercised by the e2e test.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from cve_env.tools.run_in_container import ExecResult
from cve_env.tools.verify import (
    check_container_status,
    check_exec,
    check_http,
    check_http_request,
    check_logs,
    check_tcp_probe,
    stability_wait,
    verify,
)


def _mk_resp(*, status: int, body: bytes) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    return r


@patch("cve_env.tools.verify.requests.request")
def test_http_check_passes_on_200_nonempty(mock_req: Any) -> None:
    mock_req.return_value = _mk_resp(status=200, body=b"hello")
    r = check_http(host_ip="127.0.0.1", host_port=8080)
    assert r["passed"] is True
    assert r["details"]["response_size_bytes"] == 5
    assert r["details"]["actual_status"] == 200


@patch("cve_env.tools.verify.requests.request")
def test_http_check_fails_on_zero_bytes_200(mock_req: Any) -> None:
    """P: zero-bytes-200 trap must be a hard failure, not lifecycle-only pass."""
    mock_req.return_value = _mk_resp(status=200, body=b"")
    r = check_http(host_ip="127.0.0.1", host_port=8080)
    assert r["passed"] is False
    assert r["details"]["failure_kind"] == "CONTENT_MISSING"


@patch("cve_env.tools.verify.requests.request")
def test_http_check_fails_on_unexpected_status(mock_req: Any) -> None:
    mock_req.return_value = _mk_resp(status=500, body=b"err")
    r = check_http(host_ip="127.0.0.1", host_port=8080, expected_status=[200, 403])
    assert r["passed"] is False
    assert "500" in r["reason"]


@patch("cve_env.tools.verify.requests.request")
def test_http_check_accepts_403_when_in_expected_list(mock_req: Any) -> None:
    mock_req.return_value = _mk_resp(status=403, body=b"forbidden")
    r = check_http(host_ip="127.0.0.1", host_port=8080, expected_status=[200, 403])
    assert r["passed"] is True


@patch("cve_env.tools.verify.requests.request")
def test_http_check_timeout_fails(mock_req: Any) -> None:
    mock_req.side_effect = requests.exceptions.Timeout("too slow")
    r = check_http(host_ip="127.0.0.1", host_port=8080, timeout_seconds=1.0)
    assert r["passed"] is False
    assert "timeout" in r["reason"].lower()


@patch("cve_env.tools.verify.requests.request")
def test_http_check_connection_error_fails(mock_req: Any) -> None:
    mock_req.side_effect = requests.exceptions.ConnectionError("refused")
    r = check_http(host_ip="127.0.0.1", host_port=8080)
    assert r["passed"] is False
    assert "connection error" in r["reason"].lower()


def test_http_check_rejects_bad_method() -> None:
    r = check_http(host_ip="127.0.0.1", host_port=8080, method="PATCH")
    assert r["passed"] is False
    assert "not allowed" in r["reason"]


@patch("cve_env.tools.verify.requests.request")
def test_http_check_content_check_missing(mock_req: Any) -> None:
    mock_req.return_value = _mk_resp(status=200, body=b"hello world")
    r = check_http(
        host_ip="127.0.0.1", host_port=8080, content_check=["hello", "admin"]
    )
    assert r["passed"] is False
    assert "admin" in r["details"]["missing_content"]


@patch("cve_env.utils.run.subprocess.run")
def test_check_logs_passes_when_all_patterns_match(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=0, stdout="Started\nlistening on 80\n", stderr=""
    )
    r = check_logs("cid", expected_patterns=[r"Started", r"listening on \d+"])
    assert r["passed"] is True


@patch("cve_env.utils.run.subprocess.run")
def test_check_logs_fails_on_missing_pattern(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="hello\n", stderr="")
    r = check_logs("cid", expected_patterns=["missing-pattern"])
    assert r["passed"] is False


@patch("cve_env.utils.run.subprocess.run")
def test_check_logs_fails_on_invalid_regex(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="some logs\n", stderr="")
    r = check_logs("cid", expected_patterns=["("])
    assert r["passed"] is False
    assert "invalid regex" in r["reason"]


def test_check_logs_empty_patterns_passes() -> None:
    r = check_logs("cid", expected_patterns=[])
    assert r["passed"] is True


@patch("cve_env.utils.run.subprocess.run")
def test_check_container_status_passes_on_running(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=0, stdout='{"Status":"running","Running":true}', stderr=""
    )
    r = check_container_status("cid")
    assert r["passed"] is True


@patch("cve_env.utils.run.subprocess.run")
def test_check_container_status_fails_on_exited(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout='{"Status":"exited","Running":false,"ExitCode":0}',
        stderr="",
    )
    r = check_container_status("cid")
    assert r["passed"] is False


@patch("cve_env.utils.run.subprocess.run")
def test_check_container_status_fails_on_inspect_error(mock_run: Any) -> None:
    mock_run.return_value = MagicMock(
        returncode=1, stdout="", stderr="no such container"
    )
    r = check_container_status("cid")
    assert r["passed"] is False


def test_stability_wait_rejects_out_of_range() -> None:
    r = stability_wait("cid", wait_seconds=9999)
    assert r["passed"] is False
    assert "out of range" in r["reason"]


@patch("cve_env.tools.verify.time.sleep", return_value=None)
@patch("cve_env.tools.verify.check_container_status")
def test_stability_wait_passes_when_still_running(
    mock_status: Any, mock_sleep: Any
) -> None:
    mock_status.return_value = {
        "passed": True,
        "details": {},
        "type": "container_status",
    }
    r = stability_wait("cid", wait_seconds=1)
    assert r["passed"] is True
    mock_sleep.assert_called_once_with(1)


@patch("cve_env.tools.verify.check_container_status")
def test_verify_stops_at_first_failure(mock_status: Any) -> None:
    # container_status fails -> plan aborts
    mock_status.return_value = {"passed": False, "details": {}, "reason": "exited"}
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            {"type": "http_check"},
        ],
    )
    assert out["passed"] is False
    assert len(out["results"]) == 1


@patch("cve_env.tools.verify.check_container_status")
@patch("cve_env.tools.verify.requests.request")
def test_verify_runs_whole_plan_when_all_pass(mock_req: Any, mock_status: Any) -> None:
    mock_status.return_value = {
        "passed": True,
        "details": {},
        "type": "container_status",
    }
    mock_req.return_value = _mk_resp(status=200, body=b"ok")
    # Phase 32 (2026-05-14): use ≥2 distinct http_check paths so the
    # smoke injector short-circuits (else it appends 2 more http_checks
    # for Phase 48 functional-smoke coverage and the count assertion would
    # need to be ==4 instead of ==3).
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            {"type": "http_check", "path": "/"},
            {"type": "http_check", "path": "/about"},
        ],
    )
    assert out["passed"] is True
    assert len(out["results"]) == 3


def _mk_exec_result(
    *,
    exit_code: int = 0,
    stdout: str = "",
    stderr: str = "",
    reason: str = "",
    duration_s: float = 0.1,
) -> ExecResult:
    return ExecResult(
        ok=exit_code == 0,
        container_id="cid",
        command="cmd",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration_s,
        reason=reason,
    )


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_passes_on_expected_exit(mock_run: Any) -> None:
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="PONG\n")
    r = check_exec("cid", command="redis-cli ping")
    assert r["passed"] is True
    assert r["details"]["exit_code"] == 0


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_fails_on_exit_mismatch(mock_run: Any) -> None:
    mock_run.return_value = _mk_exec_result(exit_code=1, stderr="err")
    r = check_exec("cid", command="false", expected_exit=0)
    assert r["passed"] is False
    assert "!=" in r["reason"]


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_custom_expected_exit(mock_run: Any) -> None:
    # Some probes expect a specific non-zero exit.
    mock_run.return_value = _mk_exec_result(exit_code=2)
    r = check_exec("cid", command="grep", expected_exit=2)
    assert r["passed"] is True


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_stdout_contains_pass(mock_run: Any) -> None:
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="uid=0(root)")
    r = check_exec("cid", command="id", expected_stdout_contains="uid=0")
    assert r["passed"] is True


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_stdout_contains_missing(mock_run: Any) -> None:
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="uid=1000")
    r = check_exec("cid", command="id", expected_stdout_contains="uid=0")
    assert r["passed"] is False
    assert "missing required substring" in r["reason"]


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_pass_branch_propagates_expected_stdout_contains_phase37(
    mock_run: Any,
) -> None:
    """Phase 37 RED — verify.py:1154-1158 PASS branch asymmetry.

    Failing branch at line 1145-1152 propagates `expected_stdout_contains` into
    `details` (for error message construction). PASS branch at 1154-1158 does
    NOT. This blinds the Phase 52.1 strict-marker gate (`_has_specific_version_marker`
    in `loop.py:259-287`) on any successful version-assertion exec_check: the
    gate inspects `details.expected_stdout_contains` and finds None on every
    passing check → demotes verified runs to verified_partial.

    Forensic: CVE-2024-0229 in bench50-20260516-053221 — agent's verify plan
    had `dpkg -l xserver-xorg-core | awk` + expected `21.1.3-2ubuntu2` (a valid
    version marker per the regex). Stdout matched `2:21.1.3-2ubuntu2`. Check
    PASSED. But details.expected_stdout_contains was missing → gate demoted.

    The fix: 1-line symmetry repair at verify.py:1157 — propagate the field
    on PASS exactly as the FAIL branch does.
    """
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="2:21.1.3-2ubuntu2\n")
    r = check_exec(
        "cid",
        command="dpkg -l xserver-xorg-core | awk '/^ii/ {print $3}'",
        expected_stdout_contains="21.1.3-2ubuntu2",
    )
    # Sanity: this should pass — substring is present in stdout.
    assert r["passed"] is True
    # The fix: details must carry expected_stdout_contains so the Phase 52.1
    # gate at loop.py:_has_specific_version_marker can see the version marker.
    assert r["details"].get("expected_stdout_contains") == "21.1.3-2ubuntu2", (
        "PASS branch must propagate expected_stdout_contains into details, "
        "mirroring the FAIL branch at verify.py:1152. Without this, the Phase "
        "52.1 strict-marker gate is blind to version markers on passing checks."
    )


@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_check_exec_accepts_and_propagates_workdir(mock_run: Any) -> None:
    """B8 fix (2026-05-02): check_exec must accept workdir kwarg and pass it
    through to run_in_container. Pre-existing impedance: run_in_container has
    workdir, prompt advertises workdir as a verify-time arg, but check_exec
    didn't accept it. CVE-2018-1273 + CVE-2017-12149 both crashed with
    "check_exec() got an unexpected keyword argument 'workdir'" in
    bench50-20260502-180209."""
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="ok")
    r = check_exec("cid", command="ls", workdir="/srv/app")
    assert r["passed"] is True
    # Verify workdir was forwarded to the underlying run_in_container call
    _, kwargs = mock_run.call_args
    assert kwargs.get("workdir") == "/srv/app"


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_verify_dispatches_exec_check(mock_run: Any, mock_subproc: Any) -> None:
    """Phase 1 canonicalization auto-prepends container_status; mock it as running."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_run.return_value = _mk_exec_result(exit_code=0, stdout="PONG")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "exec_check",
                "command": "redis-cli ping",
                "expected_exit": 0,
                "expected_stdout_contains": "PONG",
            }
        ],
    )
    assert out["passed"] is True
    # Phase 1: container_status runs first, then exec_check.
    assert out["results"][0]["type"] == "container_status"
    assert out["results"][1]["type"] == "exec_check"


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify._run_in_container.run_in_container")
def test_verify_exec_check_aliases_normalized(mock_run: Any, mock_subproc: Any) -> None:
    """LLM may use 'cmd' / 'exit_code' / 'stdout_contains' aliases."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_run.return_value = _mk_exec_result(exit_code=42)
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "exec_check",
                "cmd": "custom",  # alias for command
                "exit_code": 42,  # alias for expected_exit
            }
        ],
    )
    assert out["passed"] is True


# Phase 5: http_request_check (active payload injection) ---------------


def _mk_payload_resp(*, status: int, body: str) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.content = body.encode("utf-8")
    return r


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_passes_on_marker_present(mock_req: Any) -> None:
    """Status matches AND response body contains the expected response marker → pass."""
    mock_req.return_value = _mk_payload_resp(
        status=200, body="injected: uid=0(root) gid=0(root)"
    )
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        method="POST",
        path="/",
        request_body="${script:javascript:Runtime.getRuntime().exec('id')}",
        field_name="search",
        expected_response_contains="uid=0",
    )
    assert r["passed"] is True
    assert r["details"]["actual_status"] == 200


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_fails_on_missing_marker(mock_req: Any) -> None:
    """Status matches but body is just the lifecycle '200 OK' page → fail."""
    mock_req.return_value = _mk_payload_resp(
        status=200, body="<html><body>Welcome</body></html>"
    )
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="malicious",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "missing expected response marker" in r["reason"]


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_fails_on_status_mismatch(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=403, body="Forbidden")
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "status 403" in r["reason"]


# Phase 9.4: failure introspection hints --------------------------------


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_html_response_without_marker(
    mock_req: Any,
) -> None:
    mock_req.return_value = _mk_payload_resp(
        status=200, body="<html><body>Welcome to the app</body></html>"
    )
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="hello",
        expected_response_contains="EXPECTED_MARKER",
    )
    assert r["passed"] is False
    hint = r["details"].get("hint", "")
    # Functional pivot guidance (build-only reframe): the marker was absent, so
    # the hint points at a better marker / endpoint / field / encoding.
    assert "marker" in hint
    assert "endpoint" in hint or "field name" in hint or "encoding" in hint


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_empty_response(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=200, body="")
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "empty response" in r["details"]["hint"]


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_auth_status_mismatch(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=401, body="Unauthorized")
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "auth required" in r["details"]["hint"]


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_404(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=404, body="Not Found")
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "endpoint not found" in r["details"]["hint"]


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_json_response(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=200, body='{"status": "ok"}')
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "JSON" in r["details"]["hint"]


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_hint_for_500_server_error(mock_req: Any) -> None:
    mock_req.return_value = _mk_payload_resp(status=500, body="Internal Server Error")
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="uid=",
    )
    assert r["passed"] is False
    assert "server error" in r["details"]["hint"]


# Phase 13.1: container_status logs_tail + hint -----------------------


@patch("cve_env.utils.run.subprocess.run")
def test_container_status_failure_includes_logs_tail_and_hint(mock_run: Any) -> None:
    """When container_status reports exited, augment details with logs_tail
    + a classified hint instead of just the bare State dict.
    """
    from cve_env.tools.verify import check_container_status

    inspect_state = {
        "Running": False,
        "Status": "exited",
        "ExitCode": 1,
        "OOMKilled": False,
    }
    inspect_proc = MagicMock(returncode=0, stdout=json.dumps(inspect_state), stderr="")
    logs_proc = MagicMock(
        returncode=0,
        stdout=(
            "apache2: Address already in use: AH00072: make_sock: "
            "could not bind to address [::]:80"
        ),
        stderr="",
    )
    # First call: docker inspect; second call: docker logs.
    mock_run.side_effect = [inspect_proc, logs_proc]

    r = check_container_status(container_id="cid-port-conflict")
    assert r["passed"] is False
    assert "logs_tail" in r["details"]
    assert "Address already in use" in r["details"]["logs_tail"]
    assert "port conflict" in r["details"]["hint"]


@patch("cve_env.utils.run.subprocess.run")
def test_container_status_oom_hint(mock_run: Any) -> None:
    from cve_env.tools.verify import check_container_status

    inspect_state = {
        "Running": False,
        "Status": "exited",
        "ExitCode": 137,
        "OOMKilled": True,
    }
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=json.dumps(inspect_state), stderr=""),
        MagicMock(returncode=0, stdout="killed", stderr=""),
    ]
    r = check_container_status(container_id="cid-oom")
    assert r["passed"] is False
    assert "OOM" in r["details"]["hint"]


@patch("cve_env.utils.run.subprocess.run")
def test_container_status_silent_death_hint(mock_run: Any) -> None:
    """Empty logs + non-running container → ENTRYPOINT/CMD ran-to-completion hint."""
    from cve_env.tools.verify import check_container_status

    inspect_state = {
        "Running": False,
        "Status": "exited",
        "ExitCode": 0,
        "OOMKilled": False,
    }
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=json.dumps(inspect_state), stderr=""),
        MagicMock(returncode=0, stdout="", stderr=""),  # empty logs
    ]
    r = check_container_status(container_id="cid-silent")
    assert r["passed"] is False
    assert "ENTRYPOINT" in r["details"]["hint"] or "CMD" in r["details"]["hint"]


@patch("cve_env.utils.run.subprocess.run")
def test_container_status_missing_module_hint(mock_run: Any) -> None:
    from cve_env.tools.verify import check_container_status

    inspect_state = {
        "Running": False,
        "Status": "exited",
        "ExitCode": 1,
        "OOMKilled": False,
    }
    mock_run.side_effect = [
        MagicMock(returncode=0, stdout=json.dumps(inspect_state), stderr=""),
        MagicMock(
            returncode=0,
            stdout="ModuleNotFoundError: No module named 'flask'",
            stderr="",
        ),
    ]
    r = check_container_status(container_id="cid-missing-mod")
    assert r["passed"] is False
    assert "missing language deps" in r["details"]["hint"]


@patch("cve_env.utils.run.subprocess.run")
def test_container_status_running_does_not_fetch_logs(mock_run: Any) -> None:
    """Phase 13.1: don't waste a docker logs call when the container is fine."""
    from cve_env.tools.verify import check_container_status

    inspect_state = {
        "Running": True,
        "Status": "running",
    }
    mock_run.return_value = MagicMock(
        returncode=0, stdout=json.dumps(inspect_state), stderr=""
    )
    r = check_container_status(container_id="cid-healthy")
    assert r["passed"] is True
    # Only one subprocess call (docker inspect); no docker logs.
    assert mock_run.call_count == 1


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_rejects_missing_payload(mock_req: Any) -> None:
    """Empty payload is invalid — guard against agent passing nothing."""
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="",
        expected_response_contains="x",
    )
    assert r["passed"] is False
    assert "request_body is required" in r["reason"]
    mock_req.assert_not_called()


@patch("cve_env.tools.verify.requests.request")
def test_http_request_check_rejects_missing_marker(mock_req: Any) -> None:
    """Empty marker is invalid — without it we can't distinguish exploit from lifecycle."""
    r = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="x",
        expected_response_contains="",
    )
    assert r["passed"] is False
    assert "expected_response_contains is required" in r["reason"]
    mock_req.assert_not_called()


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_verify_dispatches_http_request_check_with_aliases(
    mock_req: Any, mock_subproc: Any
) -> None:
    """LLM may use 'data'/'marker'/'param' aliases; verify dispatches via verify()."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_req.return_value = _mk_payload_resp(status=200, body="output: uid=0 (proof)")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "http_request_check",
                "method": "POST",
                "path": "/",
                "data": "x",  # alias for payload
                "param": "search",  # alias for field_name
                "marker": "uid=0",  # alias for expected_response_contains
            }
        ],
    )
    assert out["passed"] is True
    assert out["results"][0]["type"] == "container_status"
    assert out["results"][1]["type"] == "http_request_check"


# Phase 1: verify-plan canonicalization ---------------------------------


def test_canonicalize_plan_prepends_container_status_when_missing() -> None:
    """Plan starting with stability_wait gets container_status prepended."""
    from cve_env.tools.verify import _canonicalize_plan

    plan = [{"type": "stability_wait", "wait_seconds": 60}, {"type": "http_check"}]
    out = _canonicalize_plan(plan)
    assert out[0] == {"type": "container_status"}
    assert out[1] == plan[0]
    assert out[2] == plan[1]


def test_canonicalize_plan_passes_through_when_already_first() -> None:
    """Plan already starting with container_status is unchanged."""
    from cve_env.tools.verify import _canonicalize_plan

    plan = [{"type": "container_status"}, {"type": "http_check"}]
    out = _canonicalize_plan(plan)
    assert out == plan


def test_canonicalize_plan_handles_empty_plan() -> None:
    """Empty plan gets a container_status step."""
    from cve_env.tools.verify import _canonicalize_plan

    out = _canonicalize_plan([])
    assert out == [{"type": "container_status"}]


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
def test_verify_canonicalizes_at_dispatch(mock_subproc: Any, mock_run: Any) -> None:
    """End-to-end: a stability_wait-first plan runs container_status BEFORE stability_wait."""
    # First call: docker inspect for container_status -> running.
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    # Pretend stability_wait succeeds (container still running).
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "stability_wait", "wait_seconds": 0},
            # http_check intentionally omitted to keep test focused on order.
        ],
    )
    # Result list MUST include a container_status check that ran FIRST.
    types_in_order = [r.get("type") for r in out["results"]]
    assert types_in_order[0] == "container_status"
    assert "stability_wait" in types_in_order


# Phase 2 (Java-class auto-stability_wait bump) tests removed in Phase 42.2
# revert. Code was DEAD per Phase 39.1 audit — never fired in any bench.


# Phase 28.1: tcp_probe_check tests ----------------------------------


class _FakeTCPSocket:
    """Mimics socket / SSLSocket interface for check_tcp_probe tests."""

    def __init__(
        self,
        *,
        response: bytes = b"",
        raise_on_recv: type[BaseException] | None = None,
    ) -> None:
        self._response = response
        self._raise = raise_on_recv
        self.sent: bytes = b""
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        if self._raise is not None:
            raise self._raise()
        return self._response[:n]

    def close(self) -> None:
        self.closed = True


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_passes_on_marker_present(mock_conn: Any) -> None:
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="*1\r\n$4\r\nPING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is True
    assert r["type"] == "tcp_probe_check"
    assert r["details"]["host_port"] == 6379
    assert r["details"]["response_size_bytes"] == len(b"+PONG\r\n")


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_fails_on_marker_absent(mock_conn: Any) -> None:
    mock_conn.return_value = _FakeTCPSocket(response=b"-ERR unknown command\r\n")
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="WHATEVER\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is False
    assert "missing expected response marker" in r["reason"]
    assert "hint" in r["details"]
    assert r["details"]["response_tail_ascii"].startswith("-ERR")


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_hex_payload_and_marker(mock_conn: Any) -> None:
    """Hex payload + hex marker — used for binary protocols (DNS, raw RTSP)."""
    mock_conn.return_value = _FakeTCPSocket(response=bytes.fromhex("deadbeef"))
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=53,
        send_hex="cafebabe",
        expected_response_hex="deadbeef",
    )
    assert r["passed"] is True


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_banner_grab_no_payload(mock_conn: Any) -> None:
    """SSH/MySQL/Postgres send first — no payload needed."""
    fake = _FakeTCPSocket(response=b"SSH-2.0-OpenSSH_8.2p1\r\n")
    mock_conn.return_value = fake
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=22,
        expected_response_contains="SSH-2.0-",
    )
    assert r["passed"] is True
    assert fake.sent == b""  # banner-grab sends nothing


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_connection_refused_hint(mock_conn: Any) -> None:
    mock_conn.side_effect = ConnectionRefusedError("Connection refused")
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is False
    assert r["reason"] == "connection refused"
    assert "ss -tlnp" in r["details"]["hint"]


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_timeout_hint(mock_conn: Any) -> None:
    mock_conn.return_value = _FakeTCPSocket(raise_on_recv=TimeoutError)
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is False
    assert "timeout" in r["reason"]
    assert "wrong protocol or wrong port" in r["details"]["hint"]


@patch("cve_env.tools.verify.socket.create_connection")
def test_tcp_probe_check_empty_response_hint(mock_conn: Any) -> None:
    """Service closed connection without responding."""
    mock_conn.return_value = _FakeTCPSocket(response=b"")
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is False
    assert "closed connection" in r["reason"]
    assert "protocol mismatch" in r["details"]["hint"]


def test_tcp_probe_check_rejects_dual_payload() -> None:
    """Setting both send_text AND send_hex is an error."""
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING",
        send_hex="50494e47",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is False
    assert "at most one" in r["reason"]


def test_tcp_probe_check_rejects_missing_marker() -> None:
    """One of expected_response_contains / expected_response_hex required."""
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING\r\n",
    )
    assert r["passed"] is False
    assert "expected_response" in r["reason"]


def test_tcp_probe_check_rejects_invalid_hex() -> None:
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=53,
        send_hex="not-hex-at-all",
        expected_response_contains="x",
    )
    assert r["passed"] is False
    assert "not valid hex" in r["reason"]


# Phase 61.4 — host_ip loopback/private-only whitelist for TCP + HTTP probes.
#
# Without this, the agent could send raw TLS payloads or HTTP requests to
# arbitrary public hosts via cve-env's process — combined with the SSRF
# guard in web_fetch, this is a second exfil path. verify probes are only
# meaningful against published container ports (loopback or Docker bridge).


@patch("cve_env.tools.verify.socket.create_connection")
def test_phase61_check_tcp_probe_rejects_public_ip(mock_conn: Any) -> None:
    """tcp_probe_check refuses to connect to a public IP (e.g., 8.8.8.8)."""
    r = check_tcp_probe(
        host_ip="8.8.8.8",
        host_port=443,
        send_text="hello",
        expected_response_contains="ok",
    )
    assert r["passed"] is False
    assert "host_ip" in r["reason"]
    # Must never even open the socket.
    assert mock_conn.call_count == 0


@patch("cve_env.tools.verify.socket.create_connection")
def test_phase61_check_tcp_probe_allows_loopback(mock_conn: Any) -> None:
    """Sanity: 127.0.0.1 still passes the gate (will then proceed to socket)."""
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    r = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=6379,
        send_text="PING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is True


@patch("cve_env.tools.verify.socket.create_connection")
def test_phase61_check_tcp_probe_allows_docker_bridge_ip(mock_conn: Any) -> None:
    """A Docker bridge IP (172.17.0.x is RFC 1918 private) is permitted."""
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    r = check_tcp_probe(
        host_ip="172.17.0.2",
        host_port=6379,
        send_text="PING\r\n",
        expected_response_contains="+PONG",
    )
    assert r["passed"] is True


@patch("cve_env.tools.verify.requests.request")
def test_phase61_check_http_rejects_public_ip(mock_req: Any) -> None:
    """check_http (uses requests.request which DNS-resolves) also gated."""
    r = check_http(host_ip="8.8.8.8", host_port=80)
    assert r["passed"] is False
    assert "host_ip" in r["reason"]
    assert mock_req.call_count == 0


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.socket.create_connection")
def test_verify_dispatches_tcp_probe_check_with_port_target_alias(
    mock_conn: Any, mock_subproc: Any
) -> None:
    """S29 Phase A (2026-05-04): `port_target` aliased to `host_port`. Surfaced
    by the S28 kwarg-frequency scan (CVE-2014-0160 prior bench, manual-1777*
    turn 27 — 1 historical use). Same B8-class alias pattern as `host`/`port`/
    `data`/`marker`. Was xfail-strict until the alias landed in
    _TCP_PROBE_KEY_ALIASES (verify.py); now a positive lock-test."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "tcp_probe_check",
                "port_target": 6379,  # alias for host_port (S29 Phase A)
                "data": "PING",
                "marker": "+PONG",
            }
        ],
    )
    assert out["passed"] is True, out
    args, _ = mock_conn.call_args
    assert args[0] == ("127.0.0.1", 6379)


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.socket.create_connection")
def test_verify_dispatches_tcp_probe_check_with_host_alias(
    mock_conn: Any, mock_subproc: Any
) -> None:
    """E1.1 (S28, 2026-05-04): `host` is a common LLM-synonym for `host_ip`.
    bench50-20260504-010418 CVE-2018-2628 turn 19 hit
    `check_tcp_probe() got an unexpected keyword argument 'host'`;
    agent recovered by retrying without `host` (turn 21 ✓), but the
    failure burned a turn. Add `host` to the alias dict to translate the
    synonym at dispatch time. Same precedent as B8 (check_exec workdir
    fix at test_verify.py:261-273)."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "tcp_probe_check",
                "host": "127.0.0.1",  # alias for host_ip (E1.1)
                "port": 6379,  # alias for host_port (existing)
                "data": "PING",  # alias for send_text (existing)
                "marker": "+PONG",  # alias for expected_response_contains (existing)
            }
        ],
    )
    assert out["passed"] is True, out
    assert out["results"][0]["type"] == "container_status"
    assert out["results"][1]["type"] == "tcp_probe_check"
    args, _ = mock_conn.call_args
    assert args[0] == ("127.0.0.1", 6379)


@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.socket.create_connection")
def test_verify_dispatches_tcp_probe_check_with_aliases(
    mock_conn: Any, mock_subproc: Any
) -> None:
    """LLM aliases: port→host_port, data→send_text, marker→expected_response_contains."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_conn.return_value = _FakeTCPSocket(response=b"+PONG\r\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "tcp_probe_check",
                "port": 6379,  # alias for host_port
                "data": "*1\r\n$4\r\nPING\r\n",  # alias for send_text
                "marker": "+PONG",  # alias for expected_response_contains
            }
        ],
    )
    assert out["passed"] is True
    assert out["results"][0]["type"] == "container_status"
    assert out["results"][1]["type"] == "tcp_probe_check"
    # mock_conn called with the tcp_payload's host_port, not the verify-level one
    args, _ = mock_conn.call_args
    assert args[0] == ("127.0.0.1", 6379)


# Phase 29: verify_quality_warning ------------------------------------------


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_verify_quality_warning_when_active_check_lacks_version_assertion(
    mock_req: Any, mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 29: verify response includes verify_quality_warning when active-
    vuln check passes but no exec_check command matches a version-assertion
    shape. Lets the agent self-heal in the same run before outcome locks in.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_req.return_value = _mk_payload_resp(status=200, body="output: uid=0 (proof)")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "http_request_check",
                "method": "POST",
                "path": "/",
                "payload": "x",
                "expected_response_contains": "uid=0",
            }
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    assert "version-assertion" in out["verify_quality_warning"]


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_verify_no_quality_warning_when_active_version_and_functional_smoke_all_present(
    mock_req: Any, mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 29 + Phase 49.3: when active payload + version-assertion exec_check
    + at least one additional functional-smoke check (third active or
    content-checking http_check) are ALL in the plan, no warning fires.
    Pre-Phase-49.3, just version + vuln was enough; Phase 49.3 raised the
    bar to require functional smoke too.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_req.return_value = _mk_payload_resp(status=200, body="uid=0")
    mock_exec.return_value = _mk_exec_result(exit_code=0, stdout="Apache/2.4.41\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            # Functional smoke: benign exec_check (third active check)
            {"type": "exec_check", "command": "echo hello"},
            # Version assertion
            {"type": "exec_check", "command": "apache2 -v"},
            # Active active payload check
            {
                "type": "http_request_check",
                "method": "POST",
                "path": "/",
                "payload": "x",
                "expected_response_contains": "uid=0",
            },
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" not in out


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_phase49_3_warning_when_only_version_and_vuln_no_functional_smoke(
    mock_req: Any, mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 49.3: plan passes Phase 29 minimum (active payload + version-
    assertion present) but lacks functional smoke — only 2 non-lifecycle
    checks (version + active payload check). Warning suggests adding 1-2 functional
    verbs on benign input. Forensic case: bench50-20260430-000207 successes
    ALL had this shape (1 version-exec + 1 vuln-exec, nothing in between).
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_req.return_value = _mk_payload_resp(status=200, body="uid=0")
    mock_exec.return_value = _mk_exec_result(exit_code=0, stdout="Apache/2.4.41\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            # Version assertion (1 active)
            {"type": "exec_check", "command": "apache2 -v"},
            # Active active payload check (2 active total)
            {
                "type": "http_request_check",
                "method": "POST",
                "path": "/",
                "payload": "x",
                "expected_response_contains": "uid=0",
            },
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    warning = out["verify_quality_warning"]
    assert "Phase 48" in warning, f"warning should reference Phase 48; got: {warning}"
    assert "FUNCTIONAL SMOKE" in warning or "functional" in warning


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_phase49_3_no_warning_when_http_check_with_content_check_provides_smoke(
    mock_req: Any, mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 49.3: an http_check with content_check (substring matching on
    response body) counts as functional smoke alongside the active checks.
    Plan: http_check with content_check + version exec + active payload check
    payload = 3 non-lifecycle, no warning.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    # Two distinct http calls: first is the content-check smoke, second is the vuln payload
    mock_req.side_effect = [
        _mk_payload_resp(status=200, body="Welcome to nginx"),
        _mk_payload_resp(status=200, body="uid=0"),
    ]
    mock_exec.return_value = _mk_exec_result(exit_code=0, stdout="Apache/2.4.41\n")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            # Functional smoke via http_check content_check (must be list[str])
            {"type": "http_check", "path": "/", "content_check": ["nginx"]},
            # Version assertion
            {"type": "exec_check", "command": "apache2 -v"},
            # Active active payload check
            {
                "type": "http_request_check",
                "method": "POST",
                "path": "/",
                "payload": "x",
                "expected_response_contains": "uid=0",
            },
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" not in out, (
        f"http_check content_check should count as functional smoke; "
        f"got warning: {out.get('verify_quality_warning')!r}"
    )


@patch("cve_env.utils.run.subprocess.run")
def test_verify_quality_warning_for_lifecycle_only_plans(mock_subproc: Any) -> None:
    """Phase 52: lifecycle-only plans get a quality warning. Reframed from
    "missing active payload check" to "missing version-assertion" — under the
    new gate, success requires version + smoke. A pure-lifecycle plan
    triggers the version-assertion warning first (the gate's first hurdle).
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[{"type": "container_status"}],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    warning = out["verify_quality_warning"]
    # The warning should reference the new gate's success criteria.
    assert "version-assertion" in warning
    assert "verified_partial" in warning


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
def test_phase49_3_warning_when_only_one_exec_check_is_both_active_and_version(
    mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 29 + Phase 49.3: a single exec_check whose command IS a version
    assertion counts as both active payload (via type) and version-assertion
    (via command regex). Pre-Phase-49.3 this passed Phase 29's gate cleanly
    with no warning. Post-Phase-49.3, having ONLY 1 active check (= no
    functional smoke + no separate active payload check) fires the Phase 48 warning.
    The agent should add at least one separate functional smoke check on
    benign input.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_exec.return_value = _mk_exec_result(exit_code=0, stdout="Apache/2.4.41")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {
                "type": "exec_check",
                "command": "apache2 -v",
                "expected_stdout_contains": "2.4.41",
            }
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    assert "Phase 48" in out["verify_quality_warning"]


# Phase 52 audit gap-fill tests ---------------------------------------------


@patch("cve_env.tools.verify._run_in_container.run_in_container")
@patch("cve_env.utils.run.subprocess.run")
@patch("cve_env.tools.verify.requests.request")
def test_phase52_no_warning_when_three_active_checks_satisfy_smoke_heuristic(
    mock_req: Any, mock_subproc: Any, mock_exec: Any
) -> None:
    """Phase 52 audit gap #1 (HIGH): the >=3-active-checks branch of the
    functional-smoke heuristic must satisfy the warning silencer in
    isolation — version-assertion + 2 more exec_checks (no http_check
    content_check, no multi-path http_checks). Tests the active_count >= 3
    arm of the OR.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    mock_exec.return_value = _mk_exec_result(exit_code=0, stdout="OK")
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            {"type": "exec_check", "command": "apache2 -v"},  # version
            {"type": "exec_check", "command": "echo hello"},  # functional
            {"type": "exec_check", "command": "/tmp/poc.sh"},  # active payload check
        ],
    )
    assert out["passed"] is True
    # 3 active checks total → has_smoke=True via active_count branch.
    # version present → no warning.
    assert "verify_quality_warning" not in out, (
        f"3 active checks should silence warning; got: "
        f"{out.get('verify_quality_warning')!r}"
    )


@patch("cve_env.tools.verify.requests.request")
@patch("cve_env.utils.run.subprocess.run")
def test_phase52_warning_when_smoke_present_but_no_version(
    mock_subproc: Any, mock_req: Any
) -> None:
    """Phase 52 audit gap #6 (MED): smoke present but missing version-assertion
    must trigger the version warning (NOT the smoke warning). Verifies the
    gate's missing-version branch fires even when smoke is present.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    # Mock both http_check calls as 200 OK (no body content_check, just status).
    resp = Mock()
    resp.status_code = 200
    resp.content = b"<html>ok</html>"
    resp.text = "<html>ok</html>"
    mock_req.return_value = resp
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            # 2 distinct-path http_checks → smoke heuristic satisfied
            {"type": "http_check", "path": "/"},
            {"type": "http_check", "path": "/health"},
        ],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    warning = out["verify_quality_warning"]
    # Should mention version-assertion, NOT functional smoke.
    assert "version-assertion" in warning
    assert "FUNCTIONAL SMOKE" not in warning


@patch("cve_env.utils.run.subprocess.run")
def test_phase52_http_check_with_content_check_sets_performed_flag(
    mock_subproc: Any,
) -> None:
    """Phase 49.3 / Phase 52: check_http must set
    details.content_check_performed=True when content_check arg is
    passed. The functional-smoke heuristic in
    _compute_verify_quality_warning relies on this field.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    # Mock the http call as a successful response with body containing the marker
    with patch("cve_env.tools.verify.requests.request") as mock_req:
        resp = Mock()
        resp.status_code = 200
        resp.content = b"Welcome to nginx"
        resp.text = "Welcome to nginx"
        mock_req.return_value = resp
        out = verify(
            container_id="cid",
            host_ip="127.0.0.1",
            host_port=8080,
            plan=[
                {"type": "container_status"},
                {
                    "type": "http_check",
                    "path": "/",
                    "content_check": ["nginx"],
                },
            ],
        )
    assert out["passed"] is True
    # Find the http_check result
    http_results = [r for r in out["results"] if r.get("type") == "http_check"]
    assert len(http_results) == 1
    details = http_results[0].get("details", {})
    assert details.get("content_check_performed") is True, (
        "check_http must mark content_check_performed=True when content_check "
        "is provided (Phase 49.3 / 52 — functional-smoke heuristic depends on it)"
    )


@patch("cve_env.utils.run.subprocess.run")
def test_phase52_quality_warning_when_both_version_and_smoke_missing(
    mock_subproc: Any,
) -> None:
    """Phase 52 audit gap #7 (MED): when BOTH version-assertion AND
    functional smoke are missing (pure-lifecycle plan), the warning fires
    on the version-assertion branch first (it's checked before smoke).
    Validates ordering of the two warning conditions.
    """
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[{"type": "container_status"}],
    )
    assert out["passed"] is True
    assert "verify_quality_warning" in out
    warning = out["verify_quality_warning"]
    # Version warning fires first (gate's first condition).
    assert "version-assertion" in warning
    # The smoke-only warning string ("FUNCTIONAL SMOKE on benign input was
    # found") is NOT present because we short-circuited on the missing-
    # version branch.
    assert "FUNCTIONAL SMOKE" not in warning


@patch("cve_env.utils.run.subprocess.run")
def test_verify_rejects_unknown_type(mock_subproc: Any) -> None:
    """Unknown check type fails. Phase 1: container_status runs first, then mystery_check."""
    mock_subproc.return_value.returncode = 0
    mock_subproc.return_value.stdout = '{"Status": "running", "Running": true}'
    mock_subproc.return_value.stderr = ""
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[{"type": "mystery_check"}],
    )
    assert out["passed"] is False
    # results[0] = container_status (passes); results[1] = mystery_check (unknown)
    assert out["results"][0]["type"] == "container_status"
    assert "unknown check type" in out["results"][1]["reason"]


def test_verify_rejects_string_encoded_plan() -> None:
    """E1.2 guard: plan passed as json.dumps(plan) string → clear error, no AttributeError.

    CVE-2018-16509 audit manual-1777848801 turn 69 is the confirmed corpus
    instance. Without this guard, _canonicalize_plan calls plan[0].get('type')
    on a single character, raising AttributeError.
    """
    result = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan='[{"type": "container_status"}]',  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "plan must be a list" in result["reason"]
    assert "str" in result["reason"]


# ─── BUG-004b: env-based proxy injection regression locks ────────────────
# /work-audit B-2 finding: BUG-004b had only 1 regression test (web_fetch).
# These 4 tests lock the fix in place at the 4 verify.py sites so a future
# refactor can't silently regress the security defense.
# Pattern: requests' proxies={} is a NO-OP (env vars merge); the explicit
# {"http":"","https":""} is required.
_EXPECTED_PROXIES = {"http": "", "https": ""}


@patch("cve_env.tools.verify.requests.request")
def test_BUG004b_check_http_passes_empty_proxies_kwarg(mock_req: Any) -> None:
    """BUG-004b lock: check_http (verify.py:_http_request → line 350)
    must pass proxies={"http":"","https":""} to requests.request to
    defeat env-based proxy injection (HTTP_PROXY / HTTPS_PROXY).
    """
    mock_req.return_value = _mk_resp(status=200, body=b"ok")
    check_http(host_ip="127.0.0.1", host_port=8080)
    assert mock_req.call_count >= 1
    _args, kwargs = mock_req.call_args
    assert kwargs.get("proxies") == _EXPECTED_PROXIES, (
        f"BUG-004b regression: check_http→requests.request did not pass "
        f"proxies={_EXPECTED_PROXIES!r}; got proxies={kwargs.get('proxies')!r}"
    )


@patch("cve_env.tools.verify.requests.get")
def test_BUG004b_check_http_request_GET_passes_empty_proxies_kwarg(
    mock_get: Any,
) -> None:
    """BUG-004b lock: check_http_request's GET branch (verify.py:603)
    must pass proxies={"http":"","https":""} to requests.get.
    """
    mock_get.return_value = _mk_resp(status=200, body=b"ok")
    check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        method="GET",
        path="/",
        request_body="probe",
        form_encoded=True,
        field_name="q",
        expected_response_contains="ok",
    )
    assert mock_get.call_count == 1
    _args, kwargs = mock_get.call_args
    assert kwargs.get("proxies") == _EXPECTED_PROXIES, (
        f"BUG-004b regression: check_http_request GET branch did not pass "
        f"proxies={_EXPECTED_PROXIES!r}; got proxies={kwargs.get('proxies')!r}"
    )


@patch("cve_env.tools.verify.requests.request")
def test_BUG004b_check_http_request_form_passes_empty_proxies_kwarg(
    mock_req: Any,
) -> None:
    """BUG-004b lock: check_http_request's form-payload branch
    (verify.py:612) must pass proxies={"http":"","https":""} to
    requests.request.
    """
    mock_req.return_value = _mk_resp(status=200, body=b"ok")
    check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        method="POST",
        path="/",
        request_body="probe",
        form_encoded=True,
        field_name="q",
        expected_response_contains="ok",
    )
    assert mock_req.call_count == 1
    _args, kwargs = mock_req.call_args
    assert kwargs.get("proxies") == _EXPECTED_PROXIES, (
        f"BUG-004b regression: check_http_request form branch did not pass "
        f"proxies={_EXPECTED_PROXIES!r}; got proxies={kwargs.get('proxies')!r}"
    )


@patch("cve_env.tools.verify.requests.request")
def test_BUG004b_check_http_request_raw_passes_empty_proxies_kwarg(
    mock_req: Any,
) -> None:
    """BUG-004b lock: check_http_request's raw-body branch
    (verify.py:623) must pass proxies={"http":"","https":""} to
    requests.request.
    """
    mock_req.return_value = _mk_resp(status=200, body=b"ok")
    check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        method="POST",
        path="/",
        request_body="probe",
        form_encoded=False,  # raw-body branch
        expected_response_contains="ok",
    )
    assert mock_req.call_count == 1
    _args, kwargs = mock_req.call_args
    assert kwargs.get("proxies") == _EXPECTED_PROXIES, (
        f"BUG-004b regression: check_http_request raw-body branch did not "
        f"pass proxies={_EXPECTED_PROXIES!r}; got proxies={kwargs.get('proxies')!r}"
    )


# ---- P8-C-01: injected functional-smoke checks must be NON-fatal ----
# Review finding (2026-06-02, HIGH): _inject_functional_smoke appends http_check
# probes (``<html`` on ``/``; 404 on a nonexistent path) whose PURPOSE is to
# UPGRADE a passing verify verified_partial->success. But the executor loop
# short-circuits ``if not out["passed"]: return {passed:False}`` on ANY failing
# check incl. injected ones — so a working JSON-API / redirect / subpath app, or
# one returning !=404 on unknown paths, gets graded verify_failed. The injector
# meant to upgrade can DOWNGRADE-to-fail. Fix: smoke-injected failures are
# recorded for grading but do NOT fail the verify (=> verified_partial, never
# verify_failed). Version-assertion injection stays fatal (wrong version = wrong
# build).


@patch("cve_env.tools.verify.check_http")
@patch("cve_env.tools.verify.check_container_status")
def test_injected_smoke_failure_does_not_fail_passing_verify(
    mock_status: Any, mock_http: Any
) -> None:
    """P8-C-01 regression: a FAILING Phase-32 smoke-injected check must NOT
    short-circuit verify to passed=False when the agent's own checks pass."""
    mock_status.return_value = {
        "passed": True,
        "details": {},
        "type": "container_status",
    }

    def fake_http(*, host_ip: str, host_port: int, path: Any = None, **kw: Any) -> dict:
        # agent's own /api check passes; injected smoke probes (/ and the 404
        # path) FAIL.
        ok = path == "/api"
        return {
            "type": "http_check",
            "passed": ok,
            "details": {"path": path},
            "reason": None if ok else f"smoke probe {path!r} failed",
        }

    mock_http.side_effect = fake_http
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            {"type": "http_check", "path": "/api", "expected_status": 200},
        ],
    )
    assert out["passed"] is True, (
        f"injected-smoke failure must NOT fail an otherwise-passing verify; "
        f"got {out.get('reason')!r}"
    )
    # the injected smoke checks are still RECORDED (so grading can see them) —
    # they just don't gate the overall pass.
    assert any(r.get("injected_source") == "phase32_smoke" for r in out["results"]), (
        "injected smoke results must be present in results for grading"
    )


@patch("cve_env.tools.verify.check_http")
@patch("cve_env.tools.verify.check_container_status")
def test_agent_http_failure_still_fails_verify(
    mock_status: Any, mock_http: Any
) -> None:
    """Scope guard for P8-C-01: a NON-injected (agent-authored) check failing
    still short-circuits to passed=False — the fix only spares smoke-injected
    indices."""
    mock_status.return_value = {
        "passed": True,
        "details": {},
        "type": "container_status",
    }
    mock_http.return_value = {
        "type": "http_check",
        "passed": False,
        "details": {},
        "reason": "agent check failed",
    }
    out = verify(
        container_id="cid",
        host_ip="127.0.0.1",
        host_port=8080,
        plan=[
            {"type": "container_status"},
            {"type": "http_check", "path": "/api"},
        ],
    )
    assert out["passed"] is False


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
