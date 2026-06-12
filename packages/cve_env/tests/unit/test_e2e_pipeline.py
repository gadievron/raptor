"""S28.1.h E2E mock pipeline test suite.

bench50-20260504-010418 + prior audits showed gaps between unit-test
coverage (per-tool isolation) and integration regressions surfaced by
real benches. Phases 2-5 add per-method happy/failure/cascade-on-off
tests using the foundation fixture defined here.

Scope evolution:
- Phase 1 (commit 61887e6): foundation `_e2e_io_mocked` fixture (4
  mock keys: subproc, req, sock, exec) + 1 lock test.
- Phase 2 (this commit): 5 per-method happy-path tests parametrized
  over (vulhub-image, vulhub-compose, custom-dockerfile, source-build,
  plugin-overlay). Uses `_fake_run_agent_factory` pattern from
  test_loop.py:88-124 to replay synthetic SDK message streams. Each
  test locks the loop's processing of a canonical method-specific
  tool sequence + Outcome classification.
- Phase 3-5: failure paths, audit shape, cascade-off forced-method.

Reused patterns:
- `tests/unit/test_prompt_schemas.py:289-356 _all_check_io_mocked` —
  the verify-stage portion of `_e2e_io_mocked` mirrors this; isolation
  between files intentional per FORBIDDEN-K.
- `tests/unit/test_loop.py:36-124` `_text_block / _tool_use /
  _tool_result / _assistant / _user / _result / _cve / _host /
  _fake_run_agent_factory` — Phase 2 message-flow helpers; duplicated
  here per FORBIDDEN-K (same isolation pattern as test_verify.py vs
  test_loop.py).
- `tests/unit/test_verify.py:709-736 _FakeTCPSocket` — partial-mock
  socket pattern; redefined locally.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from cve_env.agent.llm import AgentRunOutcome
from cve_env.agent.loop import build
from cve_env.models import CveRecord, HostInfo


class _FakeTCPSocket:
    """Minimal partial-mock socket (mirrors test_verify.py:709-736)."""

    def __init__(self, response: bytes = b"") -> None:
        self._response = response
        self.closed = False

    def settimeout(self, _t: float) -> None:
        pass

    def sendall(self, _data: bytes) -> None:
        pass

    def recv(self, n: int) -> bytes:
        return self._response[:n]

    def close(self) -> None:
        self.closed = True


# --- Phase 2 helpers: SDK message synthesis (mirror test_loop.py:36-124) ---


def _text_block(text: str) -> Any:
    from claude_agent_sdk import TextBlock

    return TextBlock(text=text)


def _tool_use(tool_use_id: str, name: str, args: dict[str, Any]) -> Any:
    from claude_agent_sdk import ToolUseBlock

    return ToolUseBlock(id=tool_use_id, name=name, input=args)


def _tool_result(tool_use_id: str, payload: dict[str, Any]) -> Any:
    from claude_agent_sdk import ToolResultBlock

    return ToolResultBlock(
        tool_use_id=tool_use_id,
        content=[{"type": "text", "text": json.dumps(payload)}],
    )


def _assistant(*blocks: Any) -> Any:
    from claude_agent_sdk import AssistantMessage

    return AssistantMessage(
        content=list(blocks), model="claude-opus-4-7", parent_tool_use_id=None
    )


def _user(*blocks: Any) -> Any:
    from claude_agent_sdk import UserMessage

    return UserMessage(content=list(blocks), parent_tool_use_id=None)


def _result(stop_reason: str, *, cost_usd: float = 0.50, turns: int = 8) -> Any:
    from claude_agent_sdk import ResultMessage

    return ResultMessage(
        subtype="success",
        duration_ms=1000,
        duration_api_ms=800,
        is_error=False,
        num_turns=turns,
        session_id="sess-e2e",
        stop_reason=stop_reason,
        total_cost_usd=cost_usd,
        usage=None,
        result=None,
        structured_output=None,
    )


def _cve() -> CveRecord:
    return CveRecord(
        cve_id="CVE-2018-7600",
        product="drupal",
        version="8.5.0",
        description="Drupalgeddon (test fixture)",
    )


def _host() -> HostInfo:
    return HostInfo(arch="arm64", os="darwin", rosetta_available=True)


def _fake_run_agent_factory(messages: list[Any], stop_reason: str = "end_turn") -> Any:
    """Mirror of test_loop.py:88-124 — replays synthetic messages
    through on_message; returns an AgentRunOutcome derived from the
    final ResultMessage."""

    async def fake_run_agent(
        *,
        system_prompt: str,
        user_prompt: str,
        tools: Any,
        model: str = "",
        max_turns: int = 12,
        max_cost_usd: float = 0.5,
        on_message: Any = None,
        mcp_server_name: str = "cve_env",
        resume: str | None = None,
        verify_passed_check: Any = None,
    ) -> AgentRunOutcome:
        result_msg = None
        for m in messages:
            if on_message is not None:
                on_message(m)
            if type(m).__name__ == "ResultMessage":
                result_msg = m
        if result_msg is None:
            result_msg = _result(stop_reason)
            if on_message is not None:
                on_message(result_msg)
        return AgentRunOutcome(
            stop_reason=result_msg.stop_reason or "",
            num_turns=result_msg.num_turns,
            total_cost_usd=result_msg.total_cost_usd or 0.0,
            is_error=result_msg.is_error,
            session_id=result_msg.session_id,
            final_text="",
            tool_uses=[],
        )

    return fake_run_agent


def _verify_passed_payload() -> dict[str, Any]:
    """Synthetic verify result with version-assertion + 3-active smoke
    (Phase 49.1 satisfied). Used by every Phase 2 happy-path test."""
    return {
        "passed": True,
        "results": [
            {"type": "container_status", "passed": True},
            # Version-assertion exec_check (Phase 53 + Phase 52.1).
            # `expected_stdout_contains` carries a `\d+\.\d+` marker so
            # `_has_specific_version_marker` (loop.py:162-190) returns
            # True; without it, build-method paths downgrade to
            # success_partial via the Phase 52.1 gate at loop.py:451.
            {
                "type": "exec_check",
                "passed": True,
                "details": {
                    "command": "apache2 -v",
                    "expected_stdout_contains": "2.4.49",
                },
            },
            # Trivial-use smoke exec_check (Phase 48)
            {
                "type": "exec_check",
                "passed": True,
                "details": {"command": "echo hello"},
            },
            # 3rd active check satisfies Phase 49.1 (≥3 active)
            {"type": "http_request_check", "passed": True},
        ],
        "reason": None,
    }


@pytest.fixture
def _e2e_io_mocked() -> Any:
    """Stack-patches every I/O surface the pipeline uses. Yields a dict
    of mocks so tests can assert per-step routing.

    Important: all `cve_env.tools.*` modules import the SAME `subprocess`
    module reference (verified: `docker_run.subprocess is verify.subprocess`
    is True). A separate `patch("cve_env.tools.X.subprocess.run", ...)` per
    module overrides the previous patch (last-wins, all targeting the same
    attribute). So we use ONE shared subprocess.run mock; tests assert
    per-tool routing by inspecting `subproc.call_args_list` filtered by
    argv pattern (e.g., `["docker","inspect",...]` vs `["docker","build",...]`).

    Mock keys:
      subproc — shared subprocess.run mock for ALL tools (verify dispatch
                + docker_run + docker_build + docker_compose_up + source_build).
                Default response: returncode=0, stdout=docker-inspect-running JSON.
                Tests can set `subproc.side_effect = lambda argv, **kw: ...`
                if argv-dependent behavior is needed.
      req     — verify.requests.request (http_check / http_request_check)
      sock    — verify.socket.create_connection (tcp_probe_check)
      exec    — verify._run_in_container.run_in_container (exec_check)
    """
    from cve_env.tools.run_in_container import ExecResult

    with ExitStack() as stack:
        # ONE shared subprocess.run mock — patched at verify's module-level
        # subprocess attribute; all pipeline tools see the same patch
        # because Python imports share the subprocess module ref.
        subproc = MagicMock()
        subproc.return_value.returncode = 0
        subproc.return_value.stdout = (
            '{"Status": "running", "Running": true, "ExitCode": 0}'
        )
        subproc.return_value.stderr = ""
        stack.enter_context(
            patch("cve_env.utils.run.subprocess.run", subproc)
        )
        # verify.py — requests.request (http_check, http_request_check)
        req_mock = MagicMock()
        req_mock.return_value.status_code = 200
        req_mock.return_value.content = b"hello"
        req_mock.return_value.text = "hello"
        stack.enter_context(
            patch("cve_env.tools.verify.requests.request", req_mock)
        )
        # verify.py — socket.create_connection (tcp_probe_check)
        sock_factory = MagicMock(return_value=_FakeTCPSocket(response=b"+PONG\r\n"))
        stack.enter_context(
            patch("cve_env.tools.verify.socket.create_connection", sock_factory)
        )
        # verify.py — _run_in_container.run_in_container (exec_check)
        exec_mock = MagicMock(
            return_value=ExecResult(
                ok=True,
                container_id="cid",
                command="id",
                exit_code=0,
                stdout="ok",
                stderr="",
                duration_s=0.001,
            )
        )
        stack.enter_context(
            patch(
                "cve_env.tools.verify._run_in_container.run_in_container",
                exec_mock,
            )
        )
        yield {
            "subproc": subproc,
            "req": req_mock,
            "sock": sock_factory,
            "exec": exec_mock,
        }


# --- Phase 1 foundation lock test -----------------------------------------


# --- Phase 2: per-method happy-path E2E tests --------------------------------


def _stream_vulhub_image(verify_payload: dict[str, Any]) -> list[Any]:
    """Synthetic SDK message stream for vulhub-image method.
    Cross-stage contract locked: image_resolve.matches → docker_run runs
    that image; tool_names_called records nvd_lookup + image_resolve +
    docker_run + verify in order."""
    return [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True, "product": "drupal"})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "drupal", "version": "8.5.0"})),
        _user(_tool_result("t2", {
            "ok": True,
            "matches": [{"image_ref": "vulhub/drupal:8.5.0", "category": "vulhub"}],
        })),
        _assistant(_tool_use("t3", "mcp__cve_env__docker_run",
                             {"image_ref": "vulhub/drupal:8.5.0"})),
        _user(_tool_result("t3", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t4", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t4", verify_payload)),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]


def _stream_vulhub_compose(verify_payload: dict[str, Any]) -> list[Any]:
    """Synthetic SDK message stream for vulhub-compose method.
    Cross-stage contract: image_resolve returns compose-dir, docker_
    compose_up consumes it, verify runs against the compose service."""
    return [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {
            "ok": True,
            "compose_dir": "/tmp/compose/cve-x",
        })),
        _assistant(_tool_use("t3", "mcp__cve_env__docker_compose_up",
                             {"compose_dir": "/tmp/compose/cve-x"})),
        _user(_tool_result("t3", {
            "ok": True, "container_id": "c1", "host_port": 8080,
        })),
        _assistant(_tool_use("t4", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t4", verify_payload)),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]


def _stream_custom_dockerfile(verify_payload: dict[str, Any]) -> list[Any]:
    """Synthetic SDK message stream for custom-dockerfile method.
    Cross-stage contract: image_resolve no_match → agent calls
    dockerfile_gen → docker_build → docker_run with the built image.
    Distinguishes from plugin-overlay by `copy_ops=[]` (empty)."""
    return [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),  # no_match
        _assistant(_tool_use("t3", "mcp__cve_env__dockerfile_gen",
                             {"product": "p", "version": "v", "copy_ops": []})),
        _user(_tool_result("t3", {
            "ok": True, "dockerfile_text": "FROM alpine\n",
            "context_dir": "/tmp/ctx-x",
        })),
        _assistant(_tool_use("t4", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/ctx-x", "image_tag": "cve-x:build"})),
        _user(_tool_result("t4", {"ok": True, "image_ref": "cve-x:build"})),
        _assistant(_tool_use("t5", "mcp__cve_env__docker_run",
                             {"image_ref": "cve-x:build"})),
        _user(_tool_result("t5", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t6", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t6", verify_payload)),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]


def _stream_source_build(verify_payload: dict[str, Any]) -> list[Any]:
    """Synthetic SDK message stream for source-build method.
    Cross-stage contract: image_resolve no_match → source_build clones
    + builds → docker_run uses the built image. Distinguishes from
    custom-dockerfile by source_build presence (no dockerfile_gen)."""
    return [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),
        _assistant(_tool_use("t3", "mcp__cve_env__source_build",
                             {"source_url": "https://github.com/x/x",
                              "product": "p", "version": "v"})),
        _user(_tool_result("t3", {
            "ok": True, "repo_dir": "/tmp/repo-x",
            "dockerfile_text": "FROM alpine\n",
        })),
        _assistant(_tool_use("t4", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/repo-x", "image_tag": "cve-x:src"})),
        _user(_tool_result("t4", {"ok": True, "image_ref": "cve-x:src"})),
        _assistant(_tool_use("t5", "mcp__cve_env__docker_run",
                             {"image_ref": "cve-x:src"})),
        _user(_tool_result("t5", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t6", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t6", verify_payload)),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]


def _stream_plugin_overlay(verify_payload: dict[str, Any]) -> list[Any]:
    """Synthetic SDK message stream for plugin-overlay method.
    Cross-stage contract: source_build → dockerfile_gen WITH
    copy_ops=non-empty (distinguishes from custom-dockerfile) → build →
    run. The `copy_ops` field is the marker that signals overlay."""
    return [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),
        _assistant(_tool_use("t3", "mcp__cve_env__source_build",
                             {"source_url": "https://github.com/x/x",
                              "product": "x-plugin", "version": "v"})),
        _user(_tool_result("t3", {"ok": True, "repo_dir": "/tmp/x-plugin"})),
        _assistant(_tool_use(
            "t4", "mcp__cve_env__dockerfile_gen",
            {"product": "wordpress", "version": "5.7",
             "copy_ops": [{"src": "/tmp/x-plugin", "dst": "/var/www/wp/plugin"}]},
        )),
        _user(_tool_result("t4", {
            "ok": True, "dockerfile_text": "FROM wordpress:5.7\n",
            "context_dir": "/tmp/ctx-overlay",
        })),
        _assistant(_tool_use("t5", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/ctx-overlay",
                              "image_tag": "cve-x:overlay"})),
        _user(_tool_result("t5", {"ok": True, "image_ref": "cve-x:overlay"})),
        _assistant(_tool_use("t6", "mcp__cve_env__docker_run",
                             {"image_ref": "cve-x:overlay"})),
        _user(_tool_result("t6", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t7", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t7", verify_payload)),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]


# Each method × its expected tool-name sequence (order = call order in stream)
_METHOD_FIXTURES: dict[str, dict[str, Any]] = {
    "vulhub-image": {
        "stream_fn": _stream_vulhub_image,
        "expected_tools": ["nvd_lookup", "image_resolve", "docker_run", "verify"],
    },
    "vulhub-compose": {
        "stream_fn": _stream_vulhub_compose,
        "expected_tools": [
            "nvd_lookup", "image_resolve", "docker_compose_up", "verify",
        ],
    },
    "custom-dockerfile": {
        "stream_fn": _stream_custom_dockerfile,
        "expected_tools": [
            "nvd_lookup", "image_resolve", "dockerfile_gen",
            "docker_build", "docker_run", "verify",
        ],
    },
    "source-build": {
        "stream_fn": _stream_source_build,
        "expected_tools": [
            "nvd_lookup", "image_resolve", "source_build",
            "docker_build", "docker_run", "verify",
        ],
    },
    "plugin-overlay": {
        "stream_fn": _stream_plugin_overlay,
        "expected_tools": [
            "nvd_lookup", "image_resolve", "source_build",
            "dockerfile_gen", "docker_build", "docker_run", "verify",
        ],
    },
}


@pytest.mark.parametrize(
    ("method_name", "fixture"),
    sorted(_METHOD_FIXTURES.items()),
    ids=sorted(_METHOD_FIXTURES),
)
def test_e2e_method_happy_path_yields_success(
    method_name: str, fixture: dict[str, Any], tmp_path: Path
) -> None:
    """Per-method E2E happy-path lock test (Phase 2 of S28.1.h).

    Cross-stage contract locked (per method):
    - vulhub-image: image_resolve.matches → docker_run.image_ref
    - vulhub-compose: image_resolve.compose_dir → docker_compose_up
    - custom-dockerfile: image_resolve no_match → dockerfile_gen
      (copy_ops=[]) → docker_build → docker_run
    - source-build: image_resolve no_match → source_build (clone+build)
      → docker_build → docker_run
    - plugin-overlay: source_build → dockerfile_gen (copy_ops=non-empty)
      → docker_build → docker_run

    Why unit-test alone insufficient: per-tool tests mock each tool in
    isolation; this lock covers the agent loop's processing of the
    canonical multi-tool sequence + Outcome classification when the
    method completes (status=success path).

    Historical bug class caught: Phase 57 (build_launched_unverified)
    pattern — existing test_loop.py:570 covers vulhub-image and
    test_loop.py:609 covers vulhub-compose, but only for the LAUNCHED
    UNVERIFIED edge case (docker_run.ok then end_turn before verify).
    No prior test parametrized over all 5 buildable methods for the
    full happy-path success-with-verify flow. This test fills that
    gap proactively (no specific past bug; future-proof for new
    method additions).
    """
    verify_payload = _verify_passed_payload()
    messages = fixture["stream_fn"](verify_payload)
    expected_tools = fixture["expected_tools"]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id=f"e2e-{method_name}", audit_root=tmp_path)
        )
    assert outcome.status == "success", (
        f"method={method_name}: expected success, got {outcome.status} "
        f"(verify_passed={outcome.verify_passed})"
    )
    assert outcome.verify_passed is True
    assert outcome.tool_names_called == expected_tools, (
        f"method={method_name}: tool sequence drift\n"
        f"  expected: {expected_tools}\n"
        f"  actual:   {outcome.tool_names_called}"
    )
    assert outcome.audit_path is not None
    assert outcome.audit_path.exists()


# --- Phase 3: per-method failure-path E2E tests ------------------------------


def test_e2e_verify_failed_yields_no_verify_pass(tmp_path: Path) -> None:
    """Phase 3 (S28.1.h): verify(passed=False) → outcome.status =
    'no_verify_pass'.

    Cross-stage contract locked: when the agent attempts verify and it
    returns passed=False, the loop's status mapping must produce
    no_verify_pass (NOT success / success_partial / unresolvable).

    Why unit-test alone insufficient: per-tool tests of verify check
    the per-check pass/fail logic; this lock covers the LOOP-level
    consequence (status mapping) of a verify-failure outcome.

    Historical bug class: forensic doc §3.1 documents 2/16 ✓BUILT
    CVEs (CVE-2019-11043, CVE-2020-15014) classified as no_verify_pass.
    Locks the status mapping that distinguishes these from success.
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {
            "ok": True,
            "matches": [{"image_ref": "test:1.0"}],
        })),
        _assistant(_tool_use("t3", "mcp__cve_env__docker_run",
                             {"image_ref": "test:1.0"})),
        _user(_tool_result("t3", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t4", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t4", {
            "passed": False,
            "results": [
                {"type": "container_status", "passed": True},
                {"type": "exec_check", "passed": False,
                 "details": {"command": "apache2 -v"}},
            ],
            "reason": "exec_check exit_code=1",
        })),
        _assistant(_text_block("Verify failed.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-verify-fail", audit_root=tmp_path)
        )
    assert outcome.status == "verify_failed", (
        f"expected no_verify_pass, got {outcome.status}"
    )
    assert outcome.verify_passed is False


def test_e2e_lifecycle_only_smoke_yields_success_partial(tmp_path: Path) -> None:
    """Phase 3 (S28.1.h): verify(passed=True) with only lifecycle checks
    (no Phase 49.1 active checks) → outcome.status = 'success_partial'.

    Cross-stage contract: smoke heuristic in _classify_verify_outcome
    requires ≥3 active checks (exec/http_payload/tcp_payload) OR
    multi-path http_check. A plan with only container_status +
    stability_wait + 1 http_check passes verify but lacks smoke;
    success_partial signals "build correctness unproven".

    Historical bug class: forensic doc §1 lists Phase 48/49.1 as the
    smoke-target metric; this lock catches regressions in the
    classification that determines success vs success_partial under
    lifecycle-only verify outcomes (the user's "all 38% lacked smoke"
    finding from bench50-20260504-010418).
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": [{"image_ref": "x:1"}]})),
        _assistant(_tool_use("t3", "mcp__cve_env__docker_run",
                             {"image_ref": "x:1"})),
        _user(_tool_result("t3", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t4", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t4", {
            "passed": True,
            "results": [
                {"type": "container_status", "passed": True},
                {"type": "stability_wait", "passed": True},
                # ONE active check, lacks smoke (smoke needs ≥3 active)
                {"type": "exec_check", "passed": True,
                 "details": {"command": "apache2 -v"}},
            ],
            "reason": None,
        })),
        _assistant(_text_block("Built but smoke is thin.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-partial", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial", (
        f"expected success_partial (lifecycle-only smoke), got {outcome.status}"
    )
    assert outcome.verify_passed is True


def test_e2e_give_up_yields_unresolvable(tmp_path: Path) -> None:
    """Phase 3 (S28.1.h): agent calls give_up tool → outcome.status =
    'unresolvable' with the give_up_reason recorded.

    Cross-stage contract: the give_up MCP tool is the agent's
    explicit "this CVE can't be built" signal. Loop must classify as
    unresolvable (NOT success_partial / no_verify_pass / incomplete)
    and propagate the reason.

    Historical bug class: forensic doc lists 4 ⊘ unresolvable in
    bench50-20260504-010418 (CVE-2017-0144 proprietary, CVE-2024-3400
    proprietary, CVE-2019-3396 proprietary, CVE-2018-19571
    arch_incompatible). Locks the unresolvable status mapping.
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__give_up",
                             {"reason": "proprietary",
                              "detail": "Vendor closed-source; no buildable artifact."})),
        # tool_result must include `reason` because loop reads it from the
        # tool_result payload, not the tool_input args.
        _user(_tool_result("t2", {
            "ok": True, "terminal": True,
            "reason": "proprietary",
            "detail": "Vendor closed-source; no buildable artifact.",
        })),
        _assistant(_text_block("Cannot build proprietary code.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-give-up", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable", (
        f"expected unresolvable, got {outcome.status}"
    )
    assert outcome.give_up_reason == "proprietary"


def test_e2e_no_tool_calls_yields_no_verify_pass(tmp_path: Path) -> None:
    """Phase 3 (S28.1.h): agent emits final TextBlock without ever
    calling verify (or any acquire/launch tool) → status =
    'no_verify_pass'.

    Cross-stage contract: build() requires verify-success to assign
    status=success. Without ANY verify call, the run is
    no_verify_pass (different from unresolvable which requires explicit
    give_up). Locks the "ended without verify" classification.

    Historical bug class: forensic-doc-aligned with test_loop.py:
    test_build_no_verify_pass_when_ended_without_verify exists for
    the basic case; this E2E lock covers it through the full message-
    flow factory pattern with research stage present.
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_text_block("Stopping early without verifying.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-noverify", audit_root=tmp_path)
        )
    assert outcome.status == "verify_failed", (
        f"expected no_verify_pass (ended without verify), got {outcome.status}"
    )
    assert outcome.verify_passed is False


def test_e2e_phase57_launched_unverified_when_docker_run_then_end_turn(
    tmp_path: Path,
) -> None:
    """Phase 3 (S28.1.h): agent runs docker_run.ok=true then end_turns
    BEFORE calling verify → status = 'launched_unverified' (Phase 57).

    Cross-stage contract: Phase 57 in loop.py distinguishes "container
    started successfully but agent never verified" from "no container
    ever started" (no_verify_pass). The launched_unverified status
    means a partial deliverable exists.

    Historical bug class: existing test_loop.py:570-607
    (test_phase57_build_launched_unverified_when_docker_run_ok_then_end_turn)
    locks this for vulhub-image specifically. This E2E variant covers
    it through the full method-flow pattern, locking the contract
    across the loop's tool-name detection chain.
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": [{"image_ref": "x:1"}]})),
        _assistant(_tool_use("t3", "mcp__cve_env__docker_run",
                             {"image_ref": "x:1"})),
        _user(_tool_result("t3", {"ok": True, "container_id": "c1", "host_port": 8080})),
        # Agent stops here without calling verify
        _assistant(_text_block("Container running. Stopping.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-phase57", audit_root=tmp_path)
        )
    assert outcome.status == "launched_no_verify", (
        f"expected launched_unverified (Phase 57), got {outcome.status}"
    )


# --- Phase 4: audit JSONL shape lock tests -----------------------------------


# Set of audit-event status literals from cve_env.agent.audit.AuditStatus
_KNOWN_AUDIT_STATUSES = {
    "tool_ok", "tool_rejected", "tool_error", "llm_turn",
    "budget_exhausted",
    "final_success", "final_give_up", "final_turn_cap",
}
_TERMINAL_STATUSES = {"final_success", "final_give_up", "final_turn_cap"}


def _run_happy_path_and_load_audit(tmp_path: Path) -> list[dict[str, Any]]:
    """Helper: run the vulhub-image happy-path stream and parse the
    emitted audit JSONL. Used by Phase 4 audit-shape tests."""
    messages = _stream_vulhub_image(_verify_passed_payload())
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="audit-shape-test", audit_root=tmp_path)
        )
    assert outcome.audit_path is not None
    assert outcome.audit_path.exists()
    return [
        json.loads(line)
        for line in outcome.audit_path.read_text().splitlines()
        if line.strip()
    ]


def test_audit_jsonl_every_event_has_turn_and_status(tmp_path: Path) -> None:
    """Phase 4 (S28.1.h): every audit JSONL event must have `turn:int`
    and `status:str` fields.

    Cross-stage contract locked: `triage_bench.sh` + `cve_evidence.py`
    + downstream tooling depend on these fields. A regression that
    drops either silently breaks per-CVE evidence rendering.

    Why unit-test alone insufficient: per-tool tests don't write audit
    JSONL; only the loop does. This is the canonical lock for the
    audit writer's per-event contract.

    Historical bug class: docs/_nav/04_REFACTOR_HAZARDS.md §4 lists
    audit JSONL shape as bench-harness load-bearing.
    """
    events = _run_happy_path_and_load_audit(tmp_path)
    assert len(events) > 0, "audit JSONL should have at least 1 event"
    for i, e in enumerate(events):
        assert "turn" in e, f"event {i} missing turn: {e}"
        assert isinstance(e["turn"], int), f"event {i} turn not int: {e['turn']!r}"
        assert "status" in e, f"event {i} missing status: {e}"
        assert isinstance(e["status"], str), f"event {i} status not str: {e['status']!r}"


def test_audit_jsonl_status_values_in_known_literal(tmp_path: Path) -> None:
    """Phase 4 (S28.1.h): every audit event's status must be in the
    documented AuditStatus literal set.

    Cross-stage contract: extending AuditStatus must be deliberate.
    A new status value silently appearing breaks downstream consumers
    that switch on the known set.
    """
    events = _run_happy_path_and_load_audit(tmp_path)
    for i, e in enumerate(events):
        assert e["status"] in _KNOWN_AUDIT_STATUSES, (
            f"event {i} has unknown status {e['status']!r}; "
            f"known: {sorted(_KNOWN_AUDIT_STATUSES)}"
        )


def test_audit_jsonl_turn_ordering_monotonic(tmp_path: Path) -> None:
    """Phase 4 (S28.1.h): turn numbers must be monotonic non-decreasing
    across the audit JSONL.

    Cross-stage contract: `triage_bench.sh` per-CVE tool-call sequence
    rendering relies on turn ordering. A regression that out-of-orders
    events would break attribution (e.g., wrong tool blamed for a
    final_status).
    """
    events = _run_happy_path_and_load_audit(tmp_path)
    turns = [e["turn"] for e in events]
    for i in range(1, len(turns)):
        assert turns[i] >= turns[i - 1], (
            f"turn went backwards at event {i}: {turns[i - 1]} → {turns[i]}; "
            f"full sequence: {turns}"
        )


def test_audit_jsonl_terminates_with_final_event(tmp_path: Path) -> None:
    """Phase 4 (S28.1.h): the LAST event in audit JSONL must be a
    terminal status (final_success / final_give_up / final_turn_cap).

    Cross-stage contract: every CVE run terminates with exactly one
    final_* event. Downstream consumers (triage, generate_report) rely
    on this for outcome attribution.
    """
    events = _run_happy_path_and_load_audit(tmp_path)
    assert len(events) > 0
    last = events[-1]
    assert last["status"] in _TERMINAL_STATUSES, (
        f"last event status {last['status']!r} not terminal; "
        f"expected one of {sorted(_TERMINAL_STATUSES)}"
    )


def test_audit_jsonl_tool_events_have_tool_name(tmp_path: Path) -> None:
    """Phase 4 (S28.1.h): tool_ok / tool_error / tool_rejected events
    must record `tool_name`.

    Cross-stage contract: per-tool error-rate analytics
    (aggregate_tool_errors.py + _tool_errors.tsv) require tool_name on
    every tool event. Missing tool_name silently zeros the per-tool
    columns.
    """
    events = _run_happy_path_and_load_audit(tmp_path)
    tool_events = [
        e for e in events
        if e["status"] in {"tool_ok", "tool_error", "tool_rejected"}
    ]
    assert tool_events, "vulhub-image happy-path must produce ≥1 tool_* event"
    for e in tool_events:
        assert "tool_name" in e, f"tool event missing tool_name: {e}"
        assert e["tool_name"], f"tool event has empty tool_name: {e}"


# --- Phase 5: multi-method-attempt scenarios ---------------------------------
#
# Phase 5 scope re-design: original plan said "cascade-off forced-method
# variants — for each method M, force-disable the other 4". In a pure-mock
# context this is REDUNDANT with Phase 2 (which already asserts EXACT tool
# sequences, excluding other methods' tools by construction). Per
# FORBIDDEN-N (no template-bloat), Phase 5 is re-scoped to lock distinct
# loop behaviors that Phase 2 doesn't:
# - method-pivot scenarios (agent tries vulhub, fails, pivots to source-
#   build, succeeds): outcome must be classified based on the FINAL verify
#   result, not the first failure
# - intra-method retry (docker_build fails, agent retries, succeeds):
#   outcome must classify on final result
# - synthetic-failure pivots (loop must record both methods' tools but
#   classify on the success path)


def test_e2e_pivot_vulhub_to_source_build_yields_success(tmp_path: Path) -> None:
    """Phase 5 (S28.1.h): agent tries vulhub-image first, image_resolve
    returns no_match, agent pivots to source_build → docker_build →
    docker_run → verify → success.

    Cross-stage contract locked: when MULTIPLE methods are attempted in
    one run, the loop classifies outcome based on the FINAL verify
    result, NOT the first method's failure. tool_names_called records
    BOTH methods' tools in order.

    Why distinct from Phase 2: Phase 2 asserts linear single-method
    sequences. This locks the LOOP'S processing of method-pivot
    sequences (specifically: failed image_resolve → recovery via
    source_build).

    Historical bug class: cascade-test/out/cascade-bug-report.md §P0
    documented "cascade-leak" — agent succeeds via a method that
    should have been disabled. This test locks the OPPOSITE
    (legitimate pivot is recorded correctly).
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        # First attempt: vulhub-image (image_resolve returns no_match)
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),
        # Pivot to source-build
        _assistant(_tool_use("t3", "mcp__cve_env__source_build",
                             {"source_url": "https://github.com/x/x",
                              "product": "p", "version": "v"})),
        _user(_tool_result("t3", {
            "ok": True, "repo_dir": "/tmp/repo-x",
            "dockerfile_text": "FROM alpine\n",
        })),
        _assistant(_tool_use("t4", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/repo-x", "image_tag": "x:src"})),
        _user(_tool_result("t4", {"ok": True, "image_ref": "x:src"})),
        _assistant(_tool_use("t5", "mcp__cve_env__docker_run",
                             {"image_ref": "x:src"})),
        _user(_tool_result("t5", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t6", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t6", _verify_passed_payload())),
        _assistant(_text_block("Built via source-build after vulhub no_match.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-pivot", audit_root=tmp_path)
        )
    assert outcome.status == "success"
    assert outcome.verify_passed is True
    # BOTH methods' tools recorded in order; image_resolve fired (vulhub
    # attempt) but didn't yield a method-completion (no docker_run after).
    assert "image_resolve" in outcome.tool_names_called
    assert "source_build" in outcome.tool_names_called
    # Order: research → vulhub-attempt → source-build pivot → verify
    expected_subsequence = [
        "nvd_lookup", "image_resolve", "source_build",
        "docker_build", "docker_run", "verify",
    ]
    assert outcome.tool_names_called == expected_subsequence, (
        f"pivot tool sequence: expected {expected_subsequence}, "
        f"got {outcome.tool_names_called}"
    )


def test_e2e_pivot_vulhub_to_custom_dockerfile_yields_success(tmp_path: Path) -> None:
    """Phase 5 (S28.1.h): agent tries vulhub-image, image_resolve fails,
    pivots to custom-dockerfile (dockerfile_gen → docker_build →
    docker_run) → verify → success.

    Cross-stage contract locked: pivot from vulhub-image to custom-
    dockerfile (DIFFERENT pivot path than source-build). The loop must
    record dockerfile_gen (without source_build) — distinguishing
    custom-dockerfile from plugin-overlay (which would have copy_ops
    non-empty).
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),
        _assistant(_tool_use("t3", "mcp__cve_env__dockerfile_gen",
                             {"product": "p", "version": "v", "copy_ops": []})),
        _user(_tool_result("t3", {
            "ok": True, "dockerfile_text": "FROM alpine\n",
            "context_dir": "/tmp/ctx-x",
        })),
        _assistant(_tool_use("t4", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/ctx-x", "image_tag": "x:custom"})),
        _user(_tool_result("t4", {"ok": True, "image_ref": "x:custom"})),
        _assistant(_tool_use("t5", "mcp__cve_env__docker_run",
                             {"image_ref": "x:custom"})),
        _user(_tool_result("t5", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t6", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t6", _verify_passed_payload())),
        _assistant(_text_block("Built via custom-dockerfile after vulhub no_match.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-pivot-custom", audit_root=tmp_path)
        )
    assert outcome.status == "success"
    # Pivot tool record: image_resolve (vulhub attempt) + dockerfile_gen
    # (NOT source_build — distinguishes from plugin-overlay).
    assert "dockerfile_gen" in outcome.tool_names_called
    assert "source_build" not in outcome.tool_names_called


def test_e2e_intra_method_retry_yields_success(tmp_path: Path) -> None:
    """Phase 5 (S28.1.h): agent calls docker_build twice (first fails,
    second succeeds with corrected dockerfile_gen), then docker_run +
    verify → success.

    Cross-stage contract locked: intra-method retry pattern (same
    method, multiple build attempts). The loop must:
    - Record both docker_build calls in order
    - Classify outcome based on the FINAL verify result (success)
    - Not double-count or skip the failed first attempt

    Historical bug class: phase-9.2 _FAILED_ATTEMPTS retry-loop
    behavior. This test locks the loop's consistent recording of
    intra-method retries.
    """
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("t1", {"hit": True})),
        _assistant(_tool_use("t2", "mcp__cve_env__image_resolve",
                             {"product": "p", "version": "v"})),
        _user(_tool_result("t2", {"ok": True, "matches": []})),
        _assistant(_tool_use("t3", "mcp__cve_env__dockerfile_gen",
                             {"product": "p", "version": "v", "copy_ops": []})),
        _user(_tool_result("t3", {
            "ok": True, "dockerfile_text": "FROM alpine:bad\n",
            "context_dir": "/tmp/ctx-1",
        })),
        # First docker_build attempt FAILS
        _assistant(_tool_use("t4", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/ctx-1", "image_tag": "x:try1"})),
        _user(_tool_result("t4", {"ok": False, "reason": "build error"})),
        # Agent regenerates dockerfile and retries
        _assistant(_tool_use("t5", "mcp__cve_env__dockerfile_gen",
                             {"product": "p", "version": "v", "copy_ops": []})),
        _user(_tool_result("t5", {
            "ok": True, "dockerfile_text": "FROM alpine:fixed\n",
            "context_dir": "/tmp/ctx-2",
        })),
        _assistant(_tool_use("t6", "mcp__cve_env__docker_build",
                             {"context_dir": "/tmp/ctx-2", "image_tag": "x:try2"})),
        _user(_tool_result("t6", {"ok": True, "image_ref": "x:try2"})),
        _assistant(_tool_use("t7", "mcp__cve_env__docker_run",
                             {"image_ref": "x:try2"})),
        _user(_tool_result("t7", {"ok": True, "container_id": "c1", "host_port": 8080})),
        _assistant(_tool_use("t8", "mcp__cve_env__verify", {"container_id": "c1"})),
        _user(_tool_result("t8", _verify_passed_payload())),
        _assistant(_text_block("Built after retry.")),
        _result("end_turn"),
    ]
    with patch(
        "cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="e2e-retry", audit_root=tmp_path)
        )
    assert outcome.status == "success"
    # Both docker_build calls recorded
    assert outcome.tool_names_called.count("docker_build") == 2, (
        f"expected 2 docker_build calls (retry pattern), got "
        f"{outcome.tool_names_called.count('docker_build')} in "
        f"{outcome.tool_names_called}"
    )
    # Both dockerfile_gen calls recorded
    assert outcome.tool_names_called.count("dockerfile_gen") == 2


def test_foundation_fixture_provides_all_pipeline_mock_handles(
    _e2e_io_mocked: dict[str, Any],  # noqa: PT019  (test asserts on the fixture's mock VALUES, can't use usefixtures decorator alone)
) -> None:
    """Phase 1 foundation lock: the `_e2e_io_mocked` fixture must yield
    a dict containing handles for every I/O surface the pipeline uses.

    Cross-stage contract locked: the fixture's mock-keys schema is the
    contract Phases 2-5 build on. If a future fixture refactor drops a
    key, every phase's tests fail loud rather than silently bypass the
    mock (= test would hit real docker / network).

    Why unit-test alone insufficient: per-tool tests mock their own
    subprocess.run individually; this fixture provides one shared
    foundation. Without this lock, fixture-extension drift goes
    silent.

    Historical bug class: future-proof — locks the foundation for
    Phases 2-5; no specific past bug.
    """
    expected_keys = {
        "subproc",
        "req",
        "sock",
        "exec",
    }
    assert set(_e2e_io_mocked.keys()) == expected_keys, (
        f"fixture mock-keys schema drifted: got {set(_e2e_io_mocked.keys())}, "
        f"expected {expected_keys}"
    )
    # Each value must be a MagicMock that can be asserted on.
    for key, mock in _e2e_io_mocked.items():
        assert hasattr(mock, "called"), (
            f"mock {key!r} not a MagicMock (lost the `called` attribute "
            f"reachable from tests)"
        )
    # Verify the verify-stage mocks fire when verify() is called with each
    # check type. This is the foundation contract Phases 2-5 depend on.
    from cve_env.tools.verify import verify

    plan = [
        {"type": "container_status"},
        {"type": "log_check", "expected_patterns": ["x"]},
        {"type": "exec_check", "command": "id"},
        {"type": "http_check", "path": "/"},
        {"type": "tcp_probe_check", "host_port": 8080,
         "send_text": "PING", "expected_response_contains": "+PONG"},
    ]
    verify(container_id="cid", host_ip="127.0.0.1", host_port=8080, plan=plan)
    assert _e2e_io_mocked["subproc"].called, (
        "verify-stage subprocess.run mock did NOT fire (container_status / "
        "log_check / stability_wait route through _inspect_state)"
    )
    assert _e2e_io_mocked["req"].called, (
        "verify-stage requests.request mock did NOT fire (http_check / "
        "http_request_check)"
    )
    assert _e2e_io_mocked["sock"].called, (
        "verify-stage socket.create_connection mock did NOT fire "
        "(tcp_probe_check)"
    )
    assert _e2e_io_mocked["exec"].called, (
        "verify-stage run_in_container mock did NOT fire (exec_check)"
    )
