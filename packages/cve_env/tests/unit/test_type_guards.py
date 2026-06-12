"""E1.2-class type guard tests.

Each test covers a parameter that can receive a wrong type from the LLM
(json.dumps(list) instead of list, json.dumps(dict) instead of dict).
Without guards these either crash with confusing errors or silently produce
wrong results. The canonical incident: CVE-2018-16509 t69 where verify()
received json.dumps(plan) → _canonicalize_plan crashed on plan[0].get().

Pattern shared across: verify(), check_http(), check_http_request(),
check_logs(), check_exec(), dockerfile_gen().
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock, patch

from cve_env.tools.verify import (
    check_exec,
    check_http,
    check_http_request,
    check_logs,
    check_tcp_probe,
    verify,
)


def _mk_resp(*, status: int, body: bytes) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.content = body
    r.text = body.decode("utf-8", errors="replace")
    return r


# ── verify.py: check_http ────────────────────────────────────────────────


@patch("cve_env.tools.verify.requests.request")
def test_check_http_normalizes_single_str_content_check(mock_req: Any) -> None:
    """content_check as a single string → normalized to [str], works correctly.

    LLM shorthand: "nginx" instead of ["nginx"]. Should pass when body contains
    the string, not reject it.
    """
    mock_req.return_value = _mk_resp(status=200, body=b"Welcome to nginx")
    result = check_http(
        host_ip="127.0.0.1",
        host_port=8080,
        content_check="nginx",  # type: ignore[arg-type]
    )
    assert result["passed"] is True


@patch("cve_env.tools.verify.requests.request")
def test_check_http_json_string_no_false_positive(mock_req: Any) -> None:
    """content_check as JSON-encoded string → no false positive via char-search.

    Body contains all individual chars from '["hello"]' (including [, ", ]).
    Old char-search: finds all chars in body → false PASS (the bug).
    New normalization: treats full JSON string as a single pattern → correct FAIL
    because the literal string '["hello"]' is not in the body.
    """
    # Body contains '[', '"', 'h', 'e', 'l', 'o', ']' but not '["hello"]' literally
    mock_req.return_value = _mk_resp(status=200, body=b'[content] is "hello" world')
    result = check_http(
        host_ip="127.0.0.1",
        host_port=8080,
        content_check='["hello"]',  # type: ignore[arg-type]
    )
    assert result["passed"] is False


@patch("cve_env.tools.verify.requests.request")
def test_check_http_rejects_nonlist_nonstr_content_check(mock_req: Any) -> None:
    """content_check of a completely wrong type (int, dict) → type error."""
    mock_req.return_value = _mk_resp(status=200, body=b"hello world")
    result = check_http(
        host_ip="127.0.0.1",
        host_port=8080,
        content_check=42,  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "content_check" in result["reason"]
    assert "list" in result["reason"]


def test_check_http_rejects_string_expected_status() -> None:
    """expected_status as string → clear error, not ValueError from int().

    Without guard: int("200 OK") raises ValueError before the HTTP request.
    Guard fires before the request, no mock needed.
    """
    result = check_http(
        host_ip="127.0.0.1",
        host_port=8080,
        expected_status="200 OK",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_status" in result["reason"]
    assert "int" in result["reason"]


# ── verify.py: check_http_request ────────────────────────────────────────


@patch("cve_env.tools.verify.requests.request")
def test_check_http_rejects_list_method(mock_req: Any) -> None:
    """method as list → clear error, not AttributeError on .upper()."""
    mock_req.return_value = _mk_resp(status=200, body=b"ok")
    result = check_http(
        host_ip="127.0.0.1",
        host_port=8080,
        method=["GET"],  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "method" in result["reason"]
    assert "str" in result["reason"]


def test_check_http_request_rejects_list_method_path_field_name() -> None:
    """method/path/field_name as list → clear error before HTTP request."""
    for field, value in (("method", ["POST"]), ("path", ["/admin"]), ("field_name", ["q"])):
        kwargs: dict[str, Any] = {
            "host_ip": "127.0.0.1",
            "host_port": 8080,
            "request_body": "p",
            "expected_response_contains": "marker",
            field: value,
        }
        result = check_http_request(**kwargs)
        assert result["passed"] is False, f"{field} guard didn't fire"
        assert field in result["reason"], f"{field} not in reason: {result['reason']}"
        assert "str" in result["reason"]


def test_check_http_request_rejects_string_headers() -> None:
    """headers passed as JSON string → clear error, not TypeError from dict.update.

    Without guard: dict.update('{"Auth": "..."}') → TypeError (str not a mapping).
    The crash happens before the HTTP request, so no mock is needed.
    """
    result = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="payload",
        expected_response_contains="marker",
        headers='{"Authorization": "Bearer test"}',  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "headers" in result["reason"]
    assert "dict" in result["reason"]


def test_check_http_request_rejects_list_payload() -> None:
    """payload as list → clear error, not AttributeError on .encode().

    Without guard: list.encode('utf-8') raises AttributeError. Guard fires
    before the HTTP request, no mock needed.
    """
    result = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body=["cmd", "id"],  # type: ignore[arg-type]
        expected_response_contains="marker",
    )
    assert result["passed"] is False
    assert "request_body" in result["reason"]
    assert "str" in result["reason"]


def test_check_http_request_rejects_list_expected_response_contains() -> None:
    """expected_response_contains as list → clear error, not TypeError.

    Without guard: ["marker"] not in body_text raises TypeError: 'in <string>'
    requires string as left operand, not list.
    """
    result = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="payload",
        expected_response_contains=["marker"],  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_response_contains" in result["reason"]
    assert "str" in result["reason"]


def test_check_http_request_rejects_string_expected_status() -> None:
    """expected_status as string → clear error, not ValueError from int().

    Without guard: int("200 OK") raises ValueError before the HTTP request.
    Guard fires before the request, no mock needed.
    """
    result = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="payload",
        expected_response_contains="marker",
        expected_status="200 OK",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_status" in result["reason"]
    assert "int" in result["reason"]


# ── agent/tools.py: dockerfile_gen ───────────────────────────────────────


def _call_dockerfile_gen(args: dict[str, Any]) -> dict[str, Any]:
    from cve_env.agent.tools import dockerfile_gen

    return asyncio.run(dockerfile_gen.handler(args))


def _payload(result: dict[str, Any]) -> dict[str, Any]:
    return json.loads(result["content"][0]["text"])


def test_dockerfile_gen_rejects_string_install_steps() -> None:
    """install_steps as JSON string → clear error, not garbage Dockerfile.

    Without guard: list('["apt-get update"]') → ['[', '"', 'a', ...] (chars).
    render_dockerfile sees a valid list[str] (single chars pass isinstance
    checks) and emits RUN [ / RUN " / ... — a garbage Dockerfile with ok=True.
    """
    result = _call_dockerfile_gen(
        {"base_image": "ubuntu:20.04", "install_steps": '["apt-get update"]'}
    )
    p = _payload(result)
    assert p.get("ok") is False
    assert any("install_steps" in issue and "list" in issue for issue in p.get("issues", []))


def test_dockerfile_gen_rejects_string_cmd() -> None:
    """cmd as JSON string → clear error, not garbage CMD instruction.

    Without guard: list('["nginx","-g"]') → ['[', '"', 'n', ...].
    render_dockerfile emits CMD ["[", "\\"", "n", ...] — syntactically
    valid but semantically wrong; Docker would exec a literal '[' binary.
    """
    result = _call_dockerfile_gen(
        {"base_image": "nginx:alpine", "cmd": '["nginx", "-g", "daemon off;"]'}
    )
    p = _payload(result)
    assert p.get("ok") is False
    assert any("cmd" in issue and "list" in issue for issue in p.get("issues", []))


def test_dockerfile_gen_rejects_string_copy_ops() -> None:
    """copy_ops as JSON string → clear top-level error, not per-char dict errors.

    Without guard: _validate_copy_ops gets a list of chars; emits dozens of
    'copy_ops[N] must be a dict' messages — one per character. The agent
    can't tell what went wrong.
    """
    result = _call_dockerfile_gen(
        {
            "base_image": "ubuntu:20.04",
            "copy_ops": '[{"src": "plugin.jar", "dst": "/app/plugin.jar"}]',
        }
    )
    p = _payload(result)
    assert p.get("ok") is False
    assert any(
        "copy_ops" in issue and "list" in issue for issue in p.get("issues", [])
    )


# ── verify.py: check_logs ────────────────────────────────────────────────


def test_check_logs_rejects_string_expected_patterns() -> None:
    """expected_patterns as JSON string → clear error, not silent char-regex search.

    Without guard: for pattern in '["jndi|ldap"]' iterates over chars.
    re.search('[', logs) crashes with re.error; re.search('"', logs) may
    false-positive on any log line with a quote. The agent sees check pass
    even though the real pattern was never searched.
    """
    result = check_logs(
        "fake-container-id",
        expected_patterns='["jndi|ldap", "Error"]',  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_patterns" in result["reason"]
    assert "list" in result["reason"]


# ── verify.py: check_exec ────────────────────────────────────────────────


def test_check_exec_rejects_list_command() -> None:
    """command as list → clear error, not TypeError in subprocess.

    Without guard: run_in_container receives a list for command and crashes
    trying to construct argv. Guard fires before the container exec.
    """
    result = check_exec(
        "fake-id",
        command=["id"],  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "command" in result["reason"]
    assert "str" in result["reason"]


def test_check_exec_rejects_list_expected_stdout_contains() -> None:
    """expected_stdout_contains as list → clear error, not TypeError.

    Without guard: ["uid=0"] not in exec_result.stdout raises
    TypeError: 'in <string>' requires string as left operand, not list.
    The guard fires BEFORE the container exec, so no mock is needed.
    """
    result = check_exec(
        "fake-id",
        command="id",
        expected_stdout_contains=["uid=0"],  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_stdout_contains" in result["reason"]
    assert "str" in result["reason"]


# ── verify.py: verify dispatcher ─────────────────────────────────────────


def test_verify_rejects_non_dict_plan_step() -> None:
    """plan with a non-dict step → clear error, not AttributeError on step.get().

    Without guard: step.get("type") on a string raises AttributeError.
    Happens when LLM constructs plan as a mixed list or forgets step structure.
    We mock container_status to pass so the loop reaches the non-dict step.
    """
    from unittest.mock import patch

    passing = {"type": "container_status", "passed": True, "details": {}}
    with patch("cve_env.tools.verify.check_container_status", return_value=passing):
        result = verify(
            container_id="fake-id",
            host_ip="127.0.0.1",
            host_port=8080,
            plan=[{"type": "container_status"}, "http_check"],  # type: ignore[list-item]
        )
    assert result["passed"] is False
    assert "dict" in result["reason"]


# ── verify.py: check_tcp_probe ─────────────────────────────────────────


def test_check_tcp_probe_rejects_list_expected_response_contains() -> None:
    """expected_response_contains as list → clear error, not TypeError.

    Without guard: ["SSH"] in response_text raises TypeError: 'in <string>'
    requires string as left operand, not list.
    """
    result = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=22,
        expected_response_contains=["SSH"],  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_response_contains" in result["reason"]
    assert "str" in result["reason"]


# ── verify.py: verify dispatcher ─────────────────────────────────────────


def test_verify_rejects_string_plan() -> None:
    """plan as JSON string → clear error, not list-of-chars AttributeError.

    Without guard at tools.py boundary: list('..plan json..') → list of
    chars; _canonicalize_plan(chars)[0].get("type") raises AttributeError.
    verify.py already has the isinstance(plan, list) guard, but
    list(str) passes it — this tests the deeper non-dict-step guard.
    """
    result = verify(
        container_id="fake-id",
        host_ip="127.0.0.1",
        host_port=8080,
        plan='[{"type": "container_status"}]',  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "list" in result["reason"]


# ── Regression: None is allowed for optional parameters ──────────────────


@patch("cve_env.tools.verify.requests.request")
def test_check_http_none_content_check_allowed(mock_req: Any) -> None:
    """content_check=None passes through guard — normal 200 check still works.

    Guard is guarded: ``if content_check is not None:``. If a future change
    breaks this and rejects None, every call without a content check fails.
    """
    mock_req.return_value = _mk_resp(status=200, body=b"hello")
    result = check_http(host_ip="127.0.0.1", host_port=8080, content_check=None)
    assert result["passed"] is True
    assert result.get("reason") is None or "content_check" not in str(result.get("reason", ""))


@patch("cve_env.tools.verify.requests.request")
def test_check_http_request_none_headers_allowed(mock_req: Any) -> None:
    """headers=None passes through guard — request is made without extra headers.

    Guard is guarded: ``if headers is not None and not isinstance(...)``.
    If a future change breaks this and rejects None, every call without
    custom headers fails.
    """
    mock_req.return_value = _mk_resp(status=200, body=b"ok marker present")
    result = check_http_request(
        host_ip="127.0.0.1",
        host_port=8080,
        request_body="test",
        expected_response_contains="marker",
        headers=None,
    )
    assert result["passed"] is True
    assert result.get("reason") is None or "headers" not in str(result.get("reason", ""))


# ── agent/tools.py: dockerfile_gen — remaining 3 of 6 guarded fields ─────


def test_dockerfile_gen_rejects_string_ports() -> None:
    """ports as JSON string → clear error, not list-of-chars EXPOSE instruction."""
    result = _call_dockerfile_gen({"base_image": "nginx:alpine", "ports": "[80, 443]"})
    p = _payload(result)
    assert p.get("ok") is False
    assert any("ports" in issue and "list" in issue for issue in p.get("issues", []))


def test_dockerfile_gen_rejects_string_apt_packages() -> None:
    """apt_packages as JSON string → clear error, not char-by-char apt install."""
    result = _call_dockerfile_gen(
        {"base_image": "ubuntu:20.04", "apt_packages": '["nginx", "curl"]'}
    )
    p = _payload(result)
    assert p.get("ok") is False
    assert any("apt_packages" in issue and "list" in issue for issue in p.get("issues", []))


def test_dockerfile_gen_rejects_string_cve_named_packages() -> None:
    """cve_named_packages as JSON string → clear error, not char-by-char install."""
    result = _call_dockerfile_gen(
        {"base_image": "ubuntu:20.04", "cve_named_packages": '["vulnerable-pkg=1.0"]'}
    )
    p = _payload(result)
    assert p.get("ok") is False
    assert any("cve_named_packages" in issue and "list" in issue for issue in p.get("issues", []))


# ── verify.py: check_tcp_probe additional guards ────────────────────────


def test_check_tcp_probe_rejects_string_read_bytes() -> None:
    """read_bytes as string → clear error, not TypeError from 'str' <= 0.

    Without guard: '"4096" <= 0' raises TypeError: '<=' not supported between
    instances of 'str' and 'int' — the range-check itself crashes.
    """
    result = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=22,
        expected_response_contains="SSH",
        read_bytes="4096",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "read_bytes" in result["reason"]
    assert "int" in result["reason"]


def test_check_tcp_probe_rejects_string_tls() -> None:
    """tls as string 'false' → clear error, not silent TLS-always-on.

    Without guard: bool('false') == True → tls is silently forced on a
    non-TLS service, producing a TLS handshake error that masks the real issue.
    Checking 'true' would also silently behave wrong.
    """
    result = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=22,
        expected_response_contains="SSH",
        tls="false",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "tls" in result["reason"]
    assert "bool" in result["reason"]


# ── verify.py: check_exec additional guards ───────────────────────────────


def test_check_exec_rejects_string_expected_exit() -> None:
    """expected_exit as string → clear error, not silent wrong result.

    Without guard: 0 != "0" is always True in Python → exec_check that exits
    0 silently reports FAIL even when it should PASS. No exception raised.
    Guard fires before the container exec, so no mock is needed.
    """
    result = check_exec(
        "fake-id",
        command="id",
        expected_exit="0",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "expected_exit" in result["reason"]
    assert "int" in result["reason"]


# ── verify.py: stability_wait dispatch guard ─────────────────────────────


def test_check_tcp_probe_rejects_string_timeout_seconds() -> None:
    """timeout_seconds as string → clear error, not TypeError inside socket.

    Without guard: socket.create_connection(..., timeout='5') raises
    TypeError inside the C socket layer — not caught by OSError handlers.
    """
    result = check_tcp_probe(
        host_ip="127.0.0.1",
        host_port=22,
        expected_response_contains="SSH",
        timeout_seconds="5",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "timeout_seconds" in result["reason"]
    assert "float" in result["reason"] or "int" in result["reason"]


def test_check_exec_rejects_string_timeout_seconds() -> None:
    """timeout_seconds as string → clear error, not TypeError from float().

    Without guard: float(None) / float('fast') raises TypeError/ValueError
    inside check_exec before the container exec.
    """
    result = check_exec(
        "fake-id",
        command="id",
        timeout_seconds="fast",  # type: ignore[arg-type]
    )
    assert result["passed"] is False
    assert "timeout_seconds" in result["reason"]
    assert "float" in result["reason"] or "int" in result["reason"]


def test_tcp_probe_check_step_rejects_null_host_port() -> None:
    """tcp_probe_check step with host_port=null → clear error, not int(None) crash.

    Without guard: int(None) raises TypeError inside the verify dispatcher —
    the entire verify() call fails with an unhandled exception rather than
    a structured passed=False result.
    """
    from unittest.mock import patch

    passing = {"type": "container_status", "passed": True, "details": {}}
    with patch("cve_env.tools.verify.check_container_status", return_value=passing):
        result = verify(
            container_id="fake-id",
            host_ip="127.0.0.1",
            host_port=8080,
            plan=[
                {"type": "container_status"},
                {"type": "tcp_probe_check", "host_port": None, "expected_response_contains": "SSH"},
            ],
        )
    assert result["passed"] is False
    assert "host_port" in result["reason"]
    assert "int" in result["reason"]


def test_stability_wait_dispatch_rejects_null_wait_seconds() -> None:
    """wait_seconds=null in plan step → clear error, not int(None) TypeError.

    Without guard: int(None) raises TypeError inside the dispatch loop,
    propagating as an unhandled exception rather than passed=False.
    This tests the dispatch layer (verify() plan-step handling), not
    stability_wait() itself — the guard fires in the verify dispatcher.
    """
    from unittest.mock import patch

    passing = {"type": "container_status", "passed": True, "details": {}}
    with patch("cve_env.tools.verify.check_container_status", return_value=passing):
        result = verify(
            container_id="fake-id",
            host_ip="127.0.0.1",
            host_port=8080,
            plan=[
                {"type": "container_status"},
                {"type": "stability_wait", "wait_seconds": None},
            ],
        )
    assert result["passed"] is False
    assert "wait_seconds" in result["reason"]
    assert "int" in result["reason"]
