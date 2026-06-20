"""Unit tests for the agent turn loop.

Strategy: fake ``run_agent`` with a stand-in that invokes ``on_message``
with canned SDK messages, then returns a fake outcome. Verifies that
success / give_up / turn_cap / budget / error all map to the right
``Outcome.status``, and that the audit JSONL gets a terminal entry.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cve_env.agent.llm import AgentRunOutcome
from cve_env.agent.loop import _mcp_suffix, _parse_tool_result_payload, build
from cve_env.models import CveRecord, HostInfo


def _text_block(text: str) -> Any:
    from claude_agent_sdk import TextBlock

    return TextBlock(text=text)


def _tool_use(tool_id: str, name: str, input_: dict[str, Any]) -> Any:
    from claude_agent_sdk import ToolUseBlock

    return ToolUseBlock(id=tool_id, name=name, input=input_)


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


def _result(stop_reason: str, *, cost_usd: float = 0.03, turns: int = 3) -> Any:
    from claude_agent_sdk import ResultMessage

    return ResultMessage(
        subtype="success",
        duration_ms=1000,
        duration_api_ms=800,
        is_error=False,
        num_turns=turns,
        session_id="sess-1",
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
        description="Drupalgeddon",
    )


def _host() -> HostInfo:
    return HostInfo(arch="arm64", os="darwin", rosetta_available=True)


def _fake_run_agent_factory(messages: list[Any], stop_reason: str = "end_turn"):
    """Return a coroutine function that drives on_message with canned messages.

    Mirrors real _run_query_once behaviour: catches GiveUpReceived and
    TurnCapReached from on_message and synthesizes outcome.
    """
    from cve_env.agent.llm import BudgetCapExceeded, GiveUpReceived, TurnCapReached

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
        early_stop_reason: str | None = None
        try:
            for m in messages:
                if on_message is not None:
                    on_message(m)
                # The real run_agent treats the ResultMessage specially; mimic it.
                if type(m).__name__ == "ResultMessage":
                    result_msg = m
        except GiveUpReceived:
            early_stop_reason = "end_turn"
        except TurnCapReached:
            early_stop_reason = "max_turns_reached"
        except BudgetCapExceeded:
            early_stop_reason = "budget_exceeded"

        if early_stop_reason is not None:
            return AgentRunOutcome(
                stop_reason=early_stop_reason,
                num_turns=result_msg.num_turns if result_msg else 0,
                total_cost_usd=(result_msg.total_cost_usd or 0.0)
                if result_msg
                else 0.0,
                is_error=False,
                session_id=result_msg.session_id if result_msg else "",
                final_text="",
                tool_uses=[],
            )
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


def test_parse_tool_result_payload_extracts_json() -> None:
    from claude_agent_sdk import ToolResultBlock

    block = ToolResultBlock(
        tool_use_id="tu_1",
        content=[{"type": "text", "text": json.dumps({"passed": True, "foo": 1})}],
    )
    assert _parse_tool_result_payload(block) == {"passed": True, "foo": 1}


def test_parse_tool_result_payload_returns_none_on_non_json() -> None:
    from claude_agent_sdk import ToolResultBlock

    block = ToolResultBlock(
        tool_use_id="tu_1", content=[{"type": "text", "text": "not-json"}]
    )
    assert _parse_tool_result_payload(block) is None


def test_mcp_suffix_strips_prefix() -> None:
    assert _mcp_suffix("mcp__cve_env__verify") == "verify"
    assert _mcp_suffix("ToolSearch") == "ToolSearch"
    assert _mcp_suffix("plain_name") == "plain_name"


def test_build_success_when_version_smoke_and_active_payload_check_present(
    tmp_path: Path,
) -> None:
    """Phase 52/53: ``success`` requires version-assertion + functional
    smoke (heuristic: >=3 active checks, OR http_check with content, OR
    multi-path http_checks). Active payload checks count toward the
    smoke heuristic but are not separately tracked.
    """
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__vulhub_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"hit": True})),
        _assistant(_tool_use("tu2", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu2",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Version assertion
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        # Trivial-use exec_check on benign input
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hello"},
                        },
                        # 3rd active check (gives smoke heuristic >=3 active).
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-1", audit_root=tmp_path)
        )
    assert outcome.status == "success"
    assert outcome.verify_passed is True
    assert outcome.tool_names_called == ["vulhub_lookup", "verify"]
    assert outcome.audit_path is not None
    assert outcome.audit_path.exists()


def test_build_calls_set_cve_id_context_for_per_cve_image_cleanup(
    tmp_path: Path,
) -> None:
    """GAP-1 (2026-05-24): build() MUST call set_cve_id_context(cve.cve_id) at
    setup so docker_build labels result images cve-env.cve-id=<id> and
    lifecycle.cleanup_result_images can rmi exactly THIS CVE's images (#6). The
    call was verified end-to-end on a real image but had NO unit test — a silent
    deletion fails nothing (the wrappers only READ the global; an empty id just
    skips the label, so cleanup quietly no-ops and images accumulate). Lock it."""
    messages = [_assistant(_text_block("noop")), _result("end_turn")]
    with (
        patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)),
        patch("cve_env.agent.loop.set_cve_id_context") as m_ctx,
    ):
        asyncio.run(build(_cve(), _host(), run_id="run-gap1", audit_root=tmp_path))
    m_ctx.assert_called_once_with("CVE-2018-7600")


def test_build_success_when_smoke_via_distinct_http_paths(tmp_path: Path) -> None:
    """Phase 52/53: a plan with version-assertion + multi-path
    http_checks (functional smoke via distinct paths) classifies as
    ``success`` — no active payload check needed.
    """
    messages = [
        _assistant(_tool_use("tu2", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu2",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Version assertion
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        # Functional smoke: 2 distinct paths
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/", "method": "GET"},
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/health", "method": "GET"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-no-payload", audit_root=tmp_path)
        )
    assert outcome.status == "success"


def test_build_success_partial_when_only_lifecycle_checks(tmp_path: Path) -> None:
    """Phase 52: verify passing with ONLY lifecycle checks (container_status
    / http_check / stability_wait, single path each) → status="verified_partial".
    Build reached verify but neither version assertion nor functional smoke
    is present, so we can't claim a full ``success``.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        {"type": "http_check", "passed": True},
                        {"type": "stability_wait", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-lc", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial"
    assert outcome.verify_passed is True
    # Reason should mention the missing pieces (both version + smoke missing here).
    assert "version-assertion" in outcome.reason
    assert "functional smoke" in outcome.reason


def test_build_success_when_three_active_exec_checks_provide_smoke_and_version(
    tmp_path: Path,
) -> None:
    """Phase 52/53: 3 exec_checks (one version-assertion, two trivial-use
    /benign-input) → has_version=True, has_smoke=True via the
    >=3-active-checks heuristic. Status = ``success``.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Trivial-use exec_check on benign input
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hello"},
                        },
                        # Vuln-trigger exec_check (sudo PoC)
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "/tmp/exploit.sh"},
                        },
                        # Version-assertion exec_check
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "dpkg -l sudo | grep ii"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-exec", audit_root=tmp_path)
        )
    assert outcome.status == "success"


# Phase 52: version-assertion gate (was Phase 29) ---------------------------


def test_build_payload_check_without_version_downgrades_to_partial(
    tmp_path: Path,
) -> None:
    """Phase 52/53: a passing http_request_check on its own (without a
    version-assertion exec_check) means the build correctness is unproven
    → outcome is ``success_partial``, NOT ``success``.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # http_request_check passes but no version-assertion.
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-no-version", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial"
    assert "version-assertion" in outcome.reason


def test_build_exec_check_non_version_command_yields_partial(tmp_path: Path) -> None:
    """Phase 52: a single exec_check whose command isn't a version-discovery
    shape doesn't satisfy version-assertion gate. Without smoke either,
    outcome is ``success_partial``.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Single exec_check, NOT a version-discovery command.
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi && curl localhost"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-non-version", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial"
    assert "version-assertion" in outcome.reason


def test_build_tcp_probe_check_with_version_and_smoke_is_success(
    tmp_path: Path,
) -> None:
    """Phase 52/53: tcp_probe_check + version-assertion + 1 more active
    check (3 total) → has_smoke=True via the heuristic, status="success".
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Functional smoke: trivial-use exec_check
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "redis-cli PING"},
                        },
                        # tcp_probe_check (active check)
                        {"type": "tcp_probe_check", "passed": True},
                        # Version-assertion exec_check
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "redis-server --version"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-tcp", audit_root=tmp_path)
        )
    assert outcome.status == "success"


def test_phase_52_1_loose_version_marker_downgrades_to_partial(tmp_path: Path) -> None:
    """Phase 52.1 runtime gate (2026-05-06): when the verify plan has a
    version-discovery exec_check (e.g. apache2 -v) BUT the
    expected_stdout_contains is missing or matches only a bare product
    name (no `\\d+\\.\\d+` pattern), the outcome MUST downgrade from
    `success` to `success_partial`. Otherwise the agent could submit
    `expected_stdout_contains: "Apache"` and pass against any deployed
    version, including post-patch.

    This is the runtime-side enforcement of Phase 52.1's prompt rule —
    the prompt asks the agent to pin the EXACT pre-patch version, the
    runtime verifies the marker is at least major.minor specific.

    NARROWED 2026-05-06 per user clarification: only fires for build
    paths (docker_build / dockerfile_gen / source_build). Image-pulled
    paths are exempt because the registry tag IS the version assertion.
    Test must therefore include a docker_build tool call to trigger the
    gate."""
    messages = [
        # Build-path: docker_build call activates state.has_built.
        _assistant(
            _tool_use(
                "tu0",
                "mcp__cve_env__docker_build",
                {"dockerfile": "FROM apache:2.4.49"},
            )
        ),
        _user(_tool_result("tu0", {"ok": True, "image_tag": "x:1"})),
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Version-DISCOVERY command but LOOSE marker — bare
                        # product name. Defeats Phase 52's purpose.
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {
                                "command": "apache2 -v",
                                "expected_stdout_contains": "Apache",
                            },
                        },
                        # Functional smoke (3 active checks).
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/", "method": "GET"},
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/health", "method": "GET"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-1-loose", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial", (
        f"Phase 52.1 not enforced: bare 'Apache' marker on BUILD path should "
        f"downgrade, got status={outcome.status!r} reason={outcome.reason!r}"
    )
    assert outcome.reason and "specific" in outcome.reason.lower(), (
        f"reason must explain the downgrade as marker-specificity issue; "
        f"got: {outcome.reason!r}"
    )


def test_phase_52_1_specific_version_marker_keeps_success(tmp_path: Path) -> None:
    """Phase 52.1 runtime gate: when expected_stdout_contains has a
    specific version (e.g. 'Apache/2.4.49' or '2.4.49'), the gate
    accepts the marker and outcome stays `success` (assuming smoke OK).

    Build-path test (docker_build present)."""
    messages = [
        _assistant(
            _tool_use(
                "tu0",
                "mcp__cve_env__docker_build",
                {"dockerfile": "FROM apache:2.4.49"},
            )
        ),
        _user(_tool_result("tu0", {"ok": True, "image_tag": "x:1"})),
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Version-discovery + SPECIFIC marker.
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {
                                "command": "apache2 -v",
                                "expected_stdout_contains": "Apache/2.4.49",
                            },
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/", "method": "GET"},
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/health", "method": "GET"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-1-specific", audit_root=tmp_path)
        )
    assert outcome.status == "success", (
        f"specific marker '2.4.49' should pass Phase 52.1; got "
        f"status={outcome.status!r} reason={outcome.reason!r}"
    )


def test_phase_52_1_specific_marker_credited_regardless_of_command_shape(
    tmp_path: Path,
) -> None:
    """Fix #3 (2026-05-24): the specific-version-marker credit must NOT depend on
    the version-discovery COMMAND SHAPE. Reproduces CVE-2022-44542: a whitelisted
    command (`dpkg -l`) set has_version but carried only a LOOSE marker, while the
    SPECIFIC marker ('version 2.05') rode on a non-whitelisted `head` command that
    `_is_version_assertion_exec_check` doesn't recognize — so the specific marker
    was orphaned and the BUILD-path outcome was downgraded success->verified_partial
    despite a correctly-pinned version. After the fix the marker is credited
    independent of command shape."""
    messages = [
        _assistant(
            _tool_use("tu0", "mcp__cve_env__docker_build", {"dockerfile": "FROM x"})
        ),
        _user(_tool_result("tu0", {"ok": True, "image_tag": "x:1"})),
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # Whitelisted shape -> sets has_version, but LOOSE marker.
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {
                                "command": "dpkg -l lesspipe",
                                "expected_stdout_contains": "lesspipe",
                            },
                        },
                        # NON-whitelisted shape (`head` of a script) but SPECIFIC marker.
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {
                                "command": "head -3 /usr/local/bin/lesspipe.sh",
                                "expected_stdout_contains": "version 2.05",
                            },
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/", "method": "GET"},
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/x", "method": "GET"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-1-shape", audit_root=tmp_path)
        )
    assert outcome.status == "success", (
        f"specific marker 'version 2.05' on a non-whitelisted command shape should "
        f"be credited (fix #3 decouples marker from command shape); got "
        f"status={outcome.status!r} reason={outcome.reason!r}"
    )


def test_phase_52_1_image_pulled_loose_marker_keeps_success(tmp_path: Path) -> None:
    """Phase 52.1 NARROWING: when the agent did NOT build (only used
    image_resolve + docker_run, the registry tag IS the version
    assertion), a loose marker is acceptable and outcome stays
    `success`. User clarification 2026-05-06: 'accept versions if come
    with a relevant image, but enforce it if we build.'

    This test verifies the gate's narrowing — without it, image-pulled
    paths would be over-enforced."""
    messages = [
        # Image-pulled path: image_resolve + docker_run, NO build.
        _assistant(
            _tool_use(
                "tu0",
                "mcp__cve_env__image_resolve",
                {"product": "apache", "version": "2.4.49"},
            )
        ),
        _user(_tool_result("tu0", {"ok": True, "image": "httpd:2.4.49"})),
        _assistant(
            _tool_use("tu_run", "mcp__cve_env__docker_run", {"image": "httpd:2.4.49"})
        ),
        _user(_tool_result("tu_run", {"ok": True, "container_id": "c"})),
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        # LOOSE marker — but image was pulled (not built).
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {
                                "command": "apache2 -v",
                                "expected_stdout_contains": "Apache",
                            },
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/", "method": "GET"},
                        },
                        {
                            "type": "http_check",
                            "passed": True,
                            "details": {"url": "http://h:p/health", "method": "GET"},
                        },
                    ],
                    "reason": None,
                },
            )
        ),
        _assistant(_text_block("Done.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-52-1-imgpull", audit_root=tmp_path)
        )
    assert outcome.status == "success", (
        f"image-pulled (no build) loose marker should NOT downgrade; got "
        f"status={outcome.status!r} reason={outcome.reason!r}. The registry "
        f"tag is the version assertion for this path."
    )


def test_is_version_assertion_exec_check_recognizes_known_commands() -> None:
    """Phase 29: regex matches the documented version-discovery shapes."""
    from cve_env.agent.loop import _is_version_assertion_exec_check

    matches = [
        "apache2 -v",
        "nginx -v 2>&1 | grep 1.18",
        "redis-server --version",
        "dpkg -l libtomcat9-java",
        "pip show Django",
        "pip3 freeze | grep nokogiri",
        "gem list nokogiri",
        "npm ls lodash --depth=0",
        "go version -m /app/binary",
        "find / -name 'log4j-core-*.jar'",
        "unzip -p /app/app.jar META-INF/MANIFEST.MF",
        "cat /app/pom.xml",
        "drush status drupal-version",
        "rpm -q openssl",
        "cat /etc/os-release",
    ]
    for cmd in matches:
        entry = {"type": "exec_check", "details": {"command": cmd}}
        assert _is_version_assertion_exec_check(entry), f"should match: {cmd}"


def test_is_version_assertion_exec_check_rejects_arbitrary_commands() -> None:
    """Phase 29: arbitrary commands and non-exec_check entries don't match."""
    from cve_env.agent.loop import _is_version_assertion_exec_check

    rejects = [
        ("exec_check", "echo hello"),
        ("exec_check", "curl http://localhost:8080"),
        ("exec_check", "/tmp/exploit.sh"),
        ("exec_check", "cat /etc/passwd"),  # LFI marker, not version
        ("http_request_check", "ignored"),  # wrong type
        ("container_status", ""),
    ]
    for ctype, cmd in rejects:
        entry: dict[str, Any] = {"type": ctype, "details": {"command": cmd}}
        assert not _is_version_assertion_exec_check(entry), (
            f"should NOT match: {ctype} / {cmd}"
        )


def test_is_version_assertion_handles_missing_or_malformed_details() -> None:
    """Phase 29: defensive — missing/non-dict details, missing command, etc."""
    from cve_env.agent.loop import _is_version_assertion_exec_check

    bad: list[dict[str, Any]] = [
        {"type": "exec_check"},  # no details
        {"type": "exec_check", "details": None},
        {"type": "exec_check", "details": "string-not-dict"},
        {"type": "exec_check", "details": {}},
        {"type": "exec_check", "details": {"command": None}},
        {"type": "exec_check", "details": {"command": 123}},
    ]
    for entry in bad:
        assert not _is_version_assertion_exec_check(entry)


def test_build_failed_verify_does_not_pollute_check_types(tmp_path: Path) -> None:
    """Phase 19.2: a FAILED verify call's check types must NOT count toward the
    active-check set. Only the PASSING verify's plan determines success type."""
    messages = [
        # First verify FAILS but has http_request_check in plan.
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": False,
                    "results": [
                        {"type": "http_request_check", "passed": False},
                    ],
                    "reason": "marker missing",
                },
            )
        ),
        # Second verify PASSES but only with lifecycle checks → lifecycle_only.
        _assistant(_tool_use("tu2", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu2",
                {
                    "passed": True,
                    "results": [{"type": "http_check", "passed": True}],
                    "reason": None,
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-mix", audit_root=tmp_path)
        )
    # Phase 52/53: failed http_request_check shouldn't pollute the
    # passing verify's check-types union. The PASSING verify is
    # lifecycle-only (no version, no smoke) → success_partial.
    assert outcome.status == "verified_partial"


def test_build_unresolvable_when_give_up(tmp_path: Path) -> None:
    # Uses reason='proprietary' to avoid the Phase 7.4 CF-4 classifier which
    # rewrites give_up(reason='no_image') WITHOUT a prior image_resolve call.
    # The generic give_up→unresolvable contract is the test's actual concern;
    # specific-reason tests live in test_cf4_* below.
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__vulhub_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"hit": False})),
        _assistant(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "proprietary", "detail": "no upstream"},
            )
        ),
        _user(
            _tool_result(
                "tu2",
                {"terminal": True, "reason": "proprietary", "detail": "no upstream"},
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-2", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert outcome.give_up_reason == "proprietary"
    assert outcome.give_up_detail == "no upstream"


def test_build_no_verify_pass_when_ended_without_verify(tmp_path: Path) -> None:
    messages = [
        _assistant(_text_block("I see no path forward but won't give up formally.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-3", audit_root=tmp_path)
        )
    assert outcome.status == "verify_failed"


def test_phase57_build_launched_unverified_when_docker_run_ok_then_end_turn(
    tmp_path: Path,
) -> None:
    """Phase 57: agent launched a container (docker_run.ok=true) then emitted
    end_turn without ever calling verify. Pre-Phase-57 this misclassified as
    'no_verify_pass' which is a superset (also covers verify-was-called-but-
    failed). Post-Phase-57 the runtime distinguishes the two: the launched-
    but-never-attempted-verify case gets its own status 'launched_unverified'
    so triage can surface it. Forensic case: CVE-2017-5638 in the /ship
    smoke (audit manual-1777590191), agent ran docker_run.ok=true at T15 then
    Bash 'docker logs' at T17, then end_turn at T19 with no verify.
    """
    messages = [
        _assistant(_tool_use("tu-run", "mcp__cve_env__docker_run", {"image_ref": "x"})),
        _user(
            _tool_result(
                "tu-run",
                {
                    "ok": True,
                    "container_id": "abc123",
                    "host_port": 32769,
                    "host_ip": "127.0.0.1",
                    "next_step_hint": "",
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(), _host(), run_id="run-launched-unverified", audit_root=tmp_path
            )
        )
    assert outcome.status == "launched_no_verify", (
        f"expected launched_unverified, got {outcome.status}: {outcome.reason}"
    )


def test_phase57_build_launched_unverified_for_docker_compose_up_too(
    tmp_path: Path,
) -> None:
    """Same pattern as above but the launch tool was docker_compose_up
    (vulhub-compose path). Generic guard must cover ALL launch tools."""
    messages = [
        _assistant(
            _tool_use(
                "tu-compose",
                "mcp__cve_env__docker_compose_up",
                {"compose_text": "version: '3'\nservices:\n  app:\n    image: x"},
            )
        ),
        _user(
            _tool_result(
                "tu-compose",
                {"ok": True, "project": "p", "services": [], "next_step_hint": ""},
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-compose-unverified", audit_root=tmp_path)
        )
    assert outcome.status == "launched_no_verify"


def test_phase57_build_no_verify_pass_when_verify_was_attempted_but_failed(
    tmp_path: Path,
) -> None:
    """Negative case: agent launched AND called verify but verify failed.
    Post-Phase-57 must STAY classified as 'no_verify_pass' (not
    'launched_unverified'), since verify WAS attempted."""
    messages = [
        _assistant(_tool_use("tu-run", "mcp__cve_env__docker_run", {"image_ref": "x"})),
        _user(
            _tool_result(
                "tu-run",
                {
                    "ok": True,
                    "container_id": "abc",
                    "host_port": 80,
                    "host_ip": "127.0.0.1",
                },
            )
        ),
        _assistant(
            _tool_use(
                "tu-verify",
                "mcp__cve_env__verify",
                {"plan": [{"type": "container_status"}]},
            )
        ),
        _user(
            _tool_result(
                "tu-verify",
                {
                    "passed": False,
                    "results": [{"type": "container_status", "passed": False}],
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-verify-failed", audit_root=tmp_path)
        )
    assert outcome.status == "verify_failed"


def test_build_maps_turn_cap(tmp_path: Path) -> None:
    messages = [_result("max_turns_reached")]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-4", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap"


def test_cf1_turn_cap_after_launch_unverified_enriched_reason(
    tmp_path: Path,
) -> None:
    """Phase 7.3 (CF-1 runtime classifier, 2026-05-11): when turn_cap fires
    AFTER the agent launched the environment (docker_run/compose_up.ok=true)
    but BEFORE calling verify, surface 'stuck_after_launch' in the reason
    field. Status remains 'turn_cap' (backwards-compat); only reason is
    enriched. Forensic case: CVE-2024-11664 in bench200_2024_2026 ran
    docker_run.ok=true 3 times then dockerfile_gen+Bash+docker_build loop
    until T96 — wasted 96 turns with no triage signal beyond 'turn_cap'.
    """
    messages = [
        _assistant(_tool_use("tu-run", "mcp__cve_env__docker_run", {"image_ref": "x"})),
        _user(
            _tool_result(
                "tu-run",
                {
                    "ok": True,
                    "container_id": "abc123",
                    "host_port": 32769,
                    "host_ip": "127.0.0.1",
                    "next_step_hint": "",
                },
            )
        ),
        _result("max_turns_reached"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf1", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap", (
        f"status must remain turn_cap (backwards-compat); got {outcome.status}"
    )
    assert "stuck_after_launch" in outcome.reason, (
        f"reason must include 'stuck_after_launch' marker; got: {outcome.reason!r}"
    )


def test_cf1_turn_cap_without_launch_keeps_generic_reason(
    tmp_path: Path,
) -> None:
    """Negative case for CF-1 classifier: turn_cap without launched_ok must
    NOT trigger 'stuck_after_launch' enrichment. Agent never reached launch —
    the failure mode is research-stage, not CF-1's launched-then-stuck."""
    messages = [_result("max_turns_reached")]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf1-neg", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap"
    assert "stuck_after_launch" not in outcome.reason, (
        f"reason must NOT include 'stuck_after_launch' when launched_ok=False; "
        f"got: {outcome.reason!r}"
    )


def test_cf4_give_up_no_image_without_image_resolve_enriched(
    tmp_path: Path,
) -> None:
    """Phase 7.4 (CF-4 runtime classifier, 2026-05-11): when the agent emits
    give_up(reason='no_image') WITHOUT ever calling image_resolve, the runtime
    rewrites the reason to 'no_image_without_resolve' — distinguishes
    'agent exhausted the registry cascade and found nothing' from 'agent
    bypassed the cascade'. Forensic: 9/63 CVEs in bench200_2024_2026 ended
    no_image; 2/3 sampled had 0 image_resolve calls.

    Per the 2026-05-11 retrospective §10.1 (revised F-UNIFIED-PROMPT design),
    this is the second high-leverage runtime guard replacing prompt-only
    strengthening.
    """
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__vulhub_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"hit": False})),
        _assistant(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "no_image", "detail": "no upstream"},
            )
        ),
        _user(
            _tool_result(
                "tu2",
                {"terminal": True, "reason": "no_image", "detail": "no upstream"},
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf4", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert outcome.give_up_reason == "skipped_image_lookup", (
        f"reason must be rewritten when no_image without image_resolve; "
        f"got: {outcome.give_up_reason!r}"
    )
    assert "without ever calling image_resolve" in outcome.give_up_detail, (
        f"detail must explain the cascade-skip; got: {outcome.give_up_detail!r}"
    )


def test_cf4_give_up_no_image_with_image_resolve_passes_through(
    tmp_path: Path,
) -> None:
    """Negative case for CF-4: when the agent DID attempt image_resolve and
    THEN gave up with 'no_image', the reason passes through unchanged.
    The classifier must not rewrite legitimate 'cascade exhausted' findings.
    """
    messages = [
        _assistant(
            _tool_use(
                "tu1",
                "mcp__cve_env__image_resolve",
                {"name_or_cpe": "drupal", "version": "8.5.0"},
            )
        ),
        _user(_tool_result("tu1", {"ok": False, "reason": "not_found"})),
        _assistant(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "no_image", "detail": "cascade exhausted"},
            )
        ),
        _user(
            _tool_result(
                "tu2",
                {"terminal": True, "reason": "no_image", "detail": "cascade exhausted"},
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf4-neg", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert outcome.give_up_reason == "no_image", (
        f"reason must pass through when image_resolve WAS called; "
        f"got: {outcome.give_up_reason!r}"
    )
    assert outcome.give_up_detail == "cascade exhausted"


def test_cf6_give_up_no_image_after_refusal_classifies_refusal_persistent(
    tmp_path: Path,
) -> None:
    """Phase 7.5 (CF-6 / F-REFUSAL-CLASSIFIER, 2026-05-11): when the agent
    emits give_up(reason='no_image') AFTER refusal event(s), refusals are
    the likely root cause, not registry exhaustion. Rewrite reason to
    'refusal_persistent'. Higher priority than CF-4's cascade-skip check.

    Forensic case: CVE-2024-13545 had 2 refusal events + API-level
    'Usage Policy' rejection, then ended incomplete with
    give_up_reason='no_image' — the no_image was the agent's fallback
    when blocked, not a genuine cascade-exhausted finding.
    """
    messages = [
        # Early refusal latches state.refusal_stop_reason_seen.
        _result(stop_reason="refusal", cost_usd=0.10, turns=5),
        # Agent later gives up with no_image (the misclassified failure).
        _assistant(
            _tool_use(
                "tu1",
                "mcp__cve_env__give_up",
                {"reason": "no_image", "detail": "blocked by content policy"},
            )
        ),
        _user(
            _tool_result(
                "tu1",
                {
                    "terminal": True,
                    "reason": "no_image",
                    "detail": "blocked by content policy",
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf6", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "refusal_no_recovery", (
        f"reason must be rewritten to refusal_persistent when refusals "
        f"preceded no_image give_up; got: {outcome.give_up_reason!r}"
    )
    assert "refusal event" in outcome.give_up_detail, (
        f"detail must explain the refusal root-cause; got: {outcome.give_up_detail!r}"
    )
    assert outcome.refusals >= 1, (
        f"refusal count must reflect the latched refusal; got: {outcome.refusals}"
    )


def test_phase_12_1_stage_costs_attributed_to_research_for_nvd_lookup(
    tmp_path: Path,
) -> None:
    """Phase 12.1: cost-delta from a ResultMessage following an nvd_lookup
    tool_use is attributed to the RESEARCH stage."""
    messages = [
        _assistant(_tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _result("end_turn", cost_usd=0.50),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-1-research", audit_root=tmp_path)
        )
    assert outcome.stage_costs is not None
    assert outcome.stage_costs.get("RESEARCH", 0.0) > 0.0, (
        f"RESEARCH should have cost; got: {outcome.stage_costs}"
    )
    assert outcome.stage_calls.get("RESEARCH", 0) >= 1


def test_phase_12_1_stage_costs_attributed_to_launch_for_docker_run(
    tmp_path: Path,
) -> None:
    """Phase 12.1: docker_run tool_use → LAUNCH stage attribution."""
    messages = [
        _assistant(_tool_use("tu-run", "mcp__cve_env__docker_run", {"image_ref": "x"})),
        _user(
            _tool_result(
                "tu-run",
                {
                    "ok": True,
                    "container_id": "c1",
                    "host_port": 32769,
                    "host_ip": "127.0.0.1",
                    "next_step_hint": "",
                },
            )
        ),
        _result("end_turn", cost_usd=0.30),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-1-launch", audit_root=tmp_path)
        )
    assert outcome.stage_costs.get("LAUNCH", 0.0) > 0.0
    assert outcome.stage_calls.get("LAUNCH", 0) >= 1


def test_phase_12_1_stage_costs_sum_to_total(
    tmp_path: Path,
) -> None:
    """Phase 12.1: per-stage costs sum to total_cost_usd (approximately —
    modulo the estimate-vs-reported max() reconciliation in B-19)."""
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.20),
        _assistant(
            _tool_use("tu-b", "mcp__cve_env__docker_build", {"context_dir": "/tmp/x"})
        ),
        _user(_tool_result("tu-b", {"ok": True})),
        _result("end_turn", cost_usd=0.40),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-1-sum", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # Sum of attributed cost should equal or be near total (B-19 may boost
    # total via token estimate but stage_costs only count reported deltas).
    assert summed >= 0.55, f"stage_costs sum {summed} expected ≥ ~0.60"
    assert summed <= outcome.total_cost_usd + 0.001


def test_phase_12_2_over_budget_stage_flagged(
    tmp_path: Path,
) -> None:
    """Phase 12.2: when a stage's cost exceeds its soft budget,
    `over_budget_stages_list` includes that stage. RESEARCH default
    budget is $0.50; emit $0.60 via nvd_lookup → should exceed."""
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.60),  # > $0.50 RESEARCH default
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-2-over", audit_root=tmp_path)
        )
    assert outcome.over_budget_stages_list is not None
    assert "RESEARCH" in outcome.over_budget_stages_list, (
        f"RESEARCH should be over-budget; got: {outcome.over_budget_stages_list} "
        f"with stage_costs={outcome.stage_costs}"
    )


def test_phase_12_2_under_budget_stage_not_flagged(
    tmp_path: Path,
) -> None:
    """Phase 12.2: stage UNDER soft budget is not in the list."""
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.10),  # well under $0.50
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-2-under", audit_root=tmp_path)
        )
    assert "RESEARCH" not in (outcome.over_budget_stages_list or [])


def test_phase_12_2_env_var_override_raises_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.2: CVE_ENV_BUDGET_RESEARCH=0.20 overrides the default
    $0.50 to a stricter $0.20. A $0.30 RESEARCH cost is now over budget."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.20")
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.30),  # > 0.20 (env), < 0.50 (default)
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-2-env", audit_root=tmp_path)
        )
    assert "RESEARCH" in (outcome.over_budget_stages_list or []), (
        f"env override should make RESEARCH over-budget at $0.30 > $0.20; "
        f"got over={outcome.over_budget_stages_list} costs={outcome.stage_costs}"
    )


def test_phase_12_3_hard_mode_terminates_on_over_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.3: when a stage mode = "hard" and cost > budget, the
    run terminates with give_up_reason = stage_budget_exhausted_<stage>."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.20")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "hard")
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.30),  # > $0.20 hard budget
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-3-hard", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "stage_budget_exhausted_RESEARCH", (
        f"hard mode should terminate; got give_up_reason={outcome.give_up_reason!r}"
    )
    assert outcome.status == "unresolvable"


def test_phase_12_3_soft_mode_does_not_terminate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.3: soft mode (the default) does NOT terminate, even
    if over budget. The stage appears in over_budget_stages_list but
    the run reaches its normal terminal state."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.20")
    # Default mode is "soft" — no env var override needed.
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.30),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-3-soft", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "", (
        f"soft mode must not terminate; got give_up_reason={outcome.give_up_reason!r}"
    )
    assert "RESEARCH" in (outcome.over_budget_stages_list or [])


def test_phase_12_3_off_mode_skips_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.3: off mode skips both telemetry and enforcement.
    Even with budget = $0.10 and cost = $0.50, no over-budget marker."""
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.10")
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH_MODE", "off")
    messages = [
        _assistant(_tool_use("tu-r", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu-r", {})),
        _result("end_turn", cost_usd=0.50),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-3-off", audit_root=tmp_path)
        )
    # off mode SHOULD still populate over_budget_stages_list (it's
    # telemetry), but hard-enforcement should NOT fire.
    # However per current design, off DOES skip telemetry too.
    assert outcome.give_up_reason == "", (
        f"off mode must not terminate; got give_up_reason={outcome.give_up_reason!r}"
    )


def test_phase_12_4_should_extend_cost_cap_granted_when_productive() -> None:
    """Phase 12.4: pure-function predicate. Granted when productive activity
    is recent + extensions remain + cost not too-far-over."""
    from cve_env.config import should_extend_cost_cap

    new_cap = should_extend_cost_cap(
        current_cost_usd=1.85,
        max_cost_usd=1.80,
        last_productive_turn=14,
        current_turn=15,
        cost_extension_count=0,
        max_cost_extensions=1,
        extension_pct=0.10,
        recency_window=5,
    )
    assert new_cap is not None
    assert abs(new_cap - 1.98) < 0.001, f"expected 1.98, got {new_cap}"


def test_phase_12_4_should_extend_cost_cap_denied_when_unproductive() -> None:
    """Phase 12.4: denied when productivity is too far in the past."""
    from cve_env.config import should_extend_cost_cap

    new_cap = should_extend_cost_cap(
        current_cost_usd=1.85,
        max_cost_usd=1.80,
        last_productive_turn=10,
        current_turn=20,  # 10 turns past last productive (window=5)
        cost_extension_count=0,
        max_cost_extensions=1,
        extension_pct=0.10,
        recency_window=5,
    )
    assert new_cap is None


def test_phase_12_4_should_extend_cost_cap_denied_when_too_far_over() -> None:
    """Phase 12.4: runaway protection — denied if cost > 1.5× cap."""
    from cve_env.config import should_extend_cost_cap

    new_cap = should_extend_cost_cap(
        current_cost_usd=3.00,
        max_cost_usd=1.80,  # 3.00 > 1.80 * 1.5 = 2.70
        last_productive_turn=14,
        current_turn=15,
        cost_extension_count=0,
        max_cost_extensions=1,
        extension_pct=0.10,
        recency_window=5,
    )
    assert new_cap is None


def test_phase_12_4_should_extend_cost_cap_disabled_when_max_zero() -> None:
    """Phase 12.4: max_cost_extensions=0 always returns None."""
    from cve_env.config import should_extend_cost_cap

    new_cap = should_extend_cost_cap(
        current_cost_usd=1.85,
        max_cost_usd=1.80,
        last_productive_turn=14,
        current_turn=15,
        cost_extension_count=0,
        max_cost_extensions=0,  # disabled
        extension_pct=0.10,
        recency_window=5,
    )
    assert new_cap is None


def test_phase_12_4_should_extend_cost_cap_no_history_denies() -> None:
    """Phase 12.4: last_productive_turn=0 means agent never made progress;
    deny extension."""
    from cve_env.config import should_extend_cost_cap

    new_cap = should_extend_cost_cap(
        current_cost_usd=1.85,
        max_cost_usd=1.80,
        last_productive_turn=0,
        current_turn=15,
        cost_extension_count=0,
        max_cost_extensions=1,
        extension_pct=0.10,
        recency_window=5,
    )
    assert new_cap is None


def test_phase_12_5_attempts_cap_fires_when_over(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.5: CVE_ENV_MAX_<TOOL>_ATTEMPTS=2 → 3rd call terminates."""
    monkeypatch.setenv("CVE_ENV_MAX_NVD_LOOKUP_ATTEMPTS", "2")
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu1", {})),
        _assistant(_tool_use("tu2", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu2", {})),
        _assistant(_tool_use("tu3", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu3", {})),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-5-fire", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "max_tool_attempts_nvd_lookup", (
        f"expected attempts cap give_up; got {outcome.give_up_reason!r}"
    )
    assert outcome.status == "unresolvable"


def test_3f_attempts_cap_extends_on_recent_productive_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """3F: the per-tool attempt cap is PROGRESS-AWARE (mirrors B-20). Exceeding
    the flat cap must NOT give_up when the agent made recent productive build
    progress — a productive image_resolve(ok=True) between the capped calls sets
    last_productive_turn, so the cap extends instead of firing. (Contrast the
    no-progress spiral in test_phase_12_5_attempts_cap_fires_when_over.)"""
    monkeypatch.setenv("CVE_ENV_MAX_NVD_LOOKUP_ATTEMPTS", "2")  # cap=2
    monkeypatch.setenv("CVE_ENV_MAX_TOOL_ATTEMPT_EXTENSIONS", "2")
    messages = [
        _assistant(_tool_use("t1", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("t1", {})),
        _assistant(_tool_use("t2", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("t2", {})),
        # productive build progress → sets last_productive_turn (recent)
        _assistant(
            _tool_use(
                "t3", "mcp__cve_env__image_resolve", {"product": "x", "version": "1"}
            )
        ),
        _user(_tool_result("t3", {"ok": True, "image_ref": "x:1"})),
        # 3rd nvd_lookup exceeds cap=2, but progress is recent → extend, no give_up
        _assistant(_tool_use("t4", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("t4", {})),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-3f-extend", audit_root=tmp_path)
        )
    assert outcome.give_up_reason != "max_tool_attempts_nvd_lookup", (
        "per-tool cap fired despite recent productive progress — 3F should "
        f"extend the cap, not give up. got give_up_reason={outcome.give_up_reason!r}"
    )


def test_3f_productive_extension_allowed_gate_boundaries() -> None:
    """3F unit: ``productive_extension_allowed`` is the single shared gate behind
    the turn-cap, cost-cap, AND per-tool-attempt-cap extensions. Pin its
    boundaries directly so a future caller-refactor can't silently drift them."""
    from cve_env.config import PRODUCTIVE_RECENCY_TURNS, productive_extension_allowed

    w = PRODUCTIVE_RECENCY_TURNS
    base = {"last_productive_turn": 10, "extension_count": 0, "max_extensions": 2}
    # disabled (max_extensions<=0) → never allowed (pre-3F flat-cap behavior)
    assert not productive_extension_allowed(
        current_turn=11, **{**base, "max_extensions": 0}
    )
    # budget exhausted (extension_count>=max_extensions)
    assert not productive_extension_allowed(
        current_turn=11, **{**base, "extension_count": 2}
    )
    # no productive progress recorded yet (last_productive_turn<=0)
    assert not productive_extension_allowed(
        current_turn=11, **{**base, "last_productive_turn": 0}
    )
    # within recency window (diff == window) → allowed (boundary)
    assert productive_extension_allowed(current_turn=10 + w, **base)
    # just past window (diff == window+1) → denied (boundary)
    assert not productive_extension_allowed(current_turn=10 + w + 1, **base)


def test_phase_12_5_attempts_cap_default_0_unbounded(
    tmp_path: Path,
) -> None:
    """Phase 12.5: with no env var set (default), no cap fires even after
    many calls. Preserves current behavior."""
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu1", {})),
        _assistant(_tool_use("tu2", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu2", {})),
        _assistant(_tool_use("tu3", "mcp__cve_env__nvd_lookup", {"cve_id": "x"})),
        _user(_tool_result("tu3", {})),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-5-default", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "", (
        f"default (cap=0) must not terminate; got {outcome.give_up_reason!r}"
    )


def test_phase_12_6_toml_loader_empty_when_file_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.6: TOML loader returns {} when no config file exists."""
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(tmp_path / "nonexistent.toml"))
    # Force a re-load by clearing module-level cache (or importing fresh).
    import importlib
    from cve_env import config as _config_mod

    importlib.reload(_config_mod)
    assert _config_mod._TOML_CONFIG == {}


def test_phase_12_6_toml_stage_budget_overrides_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.6: TOML [budget].research = 0.25 overrides default $0.50
    when no env var is set."""
    toml_path = tmp_path / "test.toml"
    toml_path.write_text("[budget]\nresearch = 0.25\n")
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(toml_path))
    monkeypatch.delenv("CVE_ENV_BUDGET_RESEARCH", raising=False)
    import importlib
    from cve_env import config as _config_mod

    importlib.reload(_config_mod)
    assert _config_mod.get_stage_budget("RESEARCH") == 0.25


def test_phase_12_6_env_var_overrides_toml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Phase 12.6: env var precedence — env wins over TOML."""
    toml_path = tmp_path / "test.toml"
    toml_path.write_text("[budget]\nresearch = 0.25\n")
    monkeypatch.setenv("CVE_ENV_CONFIG_FILE", str(toml_path))
    monkeypatch.setenv("CVE_ENV_BUDGET_RESEARCH", "0.15")
    import importlib
    from cve_env import config as _config_mod

    importlib.reload(_config_mod)
    assert _config_mod.get_stage_budget("RESEARCH") == 0.15


def test_phase_12_1_other_bucket_for_unknown_tool(
    tmp_path: Path,
) -> None:
    """Phase 12.1: a tool not in TOOL_TO_STAGE attributes cost to OTHER.

    Uses NotebookEdit (Claude Code builtin not used by cve-env, so it's
    not in our STAGE_MAP). Future-proof against unknown tools."""
    messages = [
        _assistant(_tool_use("tu-x", "NotebookEdit", {})),
        _user(_tool_result("tu-x", {})),
        _result("end_turn", cost_usd=0.10),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-12-1-other", audit_root=tmp_path)
        )
    assert outcome.stage_costs.get("OTHER", 0.0) > 0.0, (
        f"unknown tool should be in OTHER bucket; got: {outcome.stage_costs}"
    )


def test_cf6_give_up_proprietary_after_refusal_passes_through(
    tmp_path: Path,
) -> None:
    """Negative case for CF-6: when refusal is present BUT the agent gives
    up with a NON-no_image reason (e.g. 'proprietary'), reason passes
    through unchanged. CF-6 is narrowly scoped to the no_image-after-
    refusal misclassification — don't rewrite other reasons.
    """
    messages = [
        _result(stop_reason="refusal", cost_usd=0.10, turns=5),
        _assistant(
            _tool_use(
                "tu1",
                "mcp__cve_env__give_up",
                {"reason": "proprietary", "detail": "no upstream available"},
            )
        ),
        _user(
            _tool_result(
                "tu1",
                {
                    "terminal": True,
                    "reason": "proprietary",
                    "detail": "no upstream available",
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-cf6-neg", audit_root=tmp_path)
        )
    assert outcome.give_up_reason == "proprietary", (
        f"reason must pass through for non-no_image even with refusal; "
        f"got: {outcome.give_up_reason!r}"
    )


def test_build_maps_budget_exhausted(tmp_path: Path) -> None:
    messages = [_result("budget_exceeded")]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-5", audit_root=tmp_path)
        )
    assert outcome.status == "budget_exhausted"


def test_build_catches_sdk_exception(tmp_path: Path) -> None:
    async def boom(**_: Any) -> AgentRunOutcome:
        msg = "connection reset"
        raise RuntimeError(msg)

    with patch("cve_env.agent.loop.run_agent", boom):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-6", audit_root=tmp_path)
        )
    assert outcome.status == "error"
    assert "connection reset" in outcome.error


def test_build_exception_BudgetCapExceeded_with_verify_passed_is_budget_exhausted(
    tmp_path: Path,
) -> None:
    """BUG-008 sibling-3 fix (2026-05-10): build_outcome's exception handler
    must prioritize cap exceptions OVER the verify_passed branch. When
    BudgetCapExceeded propagates from run_agent with state.verify_passed=True
    set earlier in the run, the outcome must be 'budget_exhausted' (cap wins),
    NOT 'success_partial' / 'success' (verify-pass).

    Production-fire is theoretical today (llm.py:216 catches BudgetCapExceeded
    internally), but if a future change lets the exception propagate (or a
    non-SDK code path raises it), the priority must already be correct.
    Closes the BUG-008 family (commits 28d0068 + 4988143 + this fix).
    """
    from cve_env.agent.llm import BudgetCapExceeded

    async def fake_run_agent(*, on_message: Any = None, **_: Any) -> AgentRunOutcome:
        # Drive verify ToolUse + ToolResult to set state.verify_passed=True
        if on_message is not None:
            on_message(
                _assistant(
                    _tool_use(
                        "tu-v",
                        "mcp__cve_env__verify",
                        {"plan": [{"type": "container_status"}]},
                    )
                )
            )
            on_message(
                _user(
                    _tool_result(
                        "tu-v",
                        {
                            "passed": True,
                            "results": [{"type": "container_status", "passed": True}],
                        },
                    )
                )
            )
            # Drive a ResultMessage to set state.result_received=True
            on_message(_result("end_turn"))
        # Raise BudgetCapExceeded externally (mimic future scenario where
        # llm.py's catch doesn't cover this path).
        raise BudgetCapExceeded(
            "synthetic: state.last_cost_usd=$2.00 > max_cost_usd=$1.50"
        )

    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-bug008-s3-budget", audit_root=tmp_path)
        )
    assert outcome.status == "budget_exhausted", (
        f"BUG-008 sibling-3: BudgetCapExceeded propagating with verify_passed=True "
        f"must classify as 'budget_exhausted' (cap > verify-pass per the priority "
        f"reorder mirroring _map_status / _terminal_status_for_result in commit "
        f"4988143). Got status={outcome.status!r} reason={outcome.reason!r}"
    )


def test_build_exception_TurnCapReached_with_verify_passed_is_turn_cap(
    tmp_path: Path,
) -> None:
    """BUG-008 sibling-3 fix: same priority rule as the BudgetCapExceeded case
    above, applied to TurnCapReached. When the runtime turn-cap fires with
    verify_passed=True, status must be 'turn_cap', not 'success_partial'."""
    from cve_env.agent.llm import TurnCapReached

    async def fake_run_agent(*, on_message: Any = None, **_: Any) -> AgentRunOutcome:
        if on_message is not None:
            on_message(
                _assistant(
                    _tool_use(
                        "tu-v",
                        "mcp__cve_env__verify",
                        {"plan": [{"type": "container_status"}]},
                    )
                )
            )
            on_message(
                _user(
                    _tool_result(
                        "tu-v",
                        {
                            "passed": True,
                            "results": [{"type": "container_status", "passed": True}],
                        },
                    )
                )
            )
            on_message(_result("end_turn"))
        raise TurnCapReached("synthetic: max_turns=12 reached")

    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-bug008-s3-turn", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap", (
        f"BUG-008 sibling-3: TurnCapReached propagating with verify_passed=True "
        f"must classify as 'turn_cap' (cap > verify-pass). "
        f"Got status={outcome.status!r} reason={outcome.reason!r}"
    )


def test_build_exception_NoProgressReached_with_verify_passed_is_turn_cap(
    tmp_path: Path,
) -> None:
    """Anti-thrash (2026-06-02) handler mapping + priority lock: a
    NoProgressReached propagating into build()'s except handler must classify
    as 'turn_cap' (with a no_progress reason) EVEN when verify_passed=True —
    the same cap>verify-pass hoisting the TurnCap/Budget/Wall branches enforce.
    (In practice verify is productive so the detector wouldn't fire here; this
    locks the handler-branch priority, mirroring the BUG-008 sibling tests.)"""
    from cve_env.agent.llm import NoProgressReached

    async def fake_run_agent(*, on_message: Any = None, **_: Any) -> AgentRunOutcome:
        if on_message is not None:
            on_message(
                _assistant(
                    _tool_use(
                        "tu-v",
                        "mcp__cve_env__verify",
                        {"plan": [{"type": "container_status"}]},
                    )
                )
            )
            on_message(
                _user(
                    _tool_result(
                        "tu-v",
                        {
                            "passed": True,
                            "results": [{"type": "container_status", "passed": True}],
                        },
                    )
                )
            )
            on_message(_result("end_turn"))
        raise NoProgressReached(
            "synthetic: no productive progress for 84 turns "
            "(turn=84, last_productive_turn=0, threshold=80)"
        )

    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-noprog-prio", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap", (
        f"NoProgressReached must classify 'turn_cap' (cap > verify-pass). "
        f"Got status={outcome.status!r} reason={outcome.reason!r}"
    )
    assert "no_progress" in (outcome.reason or ""), (
        f"terminal reason must carry the no_progress signal; got {outcome.reason!r}"
    )


def test_no_progress_giveup_real_on_message_trigger_maps_to_turn_cap(
    tmp_path: Path,
) -> None:
    """Anti-thrash integration: drive the REAL on_message (build()'s closure)
    with non-productive turns past a low threshold. _check_no_progress must
    raise NoProgressReached itself, which — like WallBudgetExceeded — is NOT
    caught by run_agent's clean-stop list and propagates to build()'s handler →
    'turn_cap' + no_progress reason. Closes the propagation-path gap the unit
    helper/config/exception tests don't cover (knob patched to 3; 6 text turns
    → trips at turn 4 with last_productive_turn=0)."""

    async def fake_run_agent(*, on_message: Any = None, **_: Any) -> AgentRunOutcome:
        # Non-productive turns only — last_productive_turn stays 0, so the gap
        # grows every turn. The real _check_no_progress raises on turn > 3.
        for i in range(6):
            if on_message is not None:
                on_message(_assistant(_text_block(f"still researching {i}")))
        return AgentRunOutcome(
            stop_reason="end_turn",
            num_turns=6,
            total_cost_usd=0.0,
            is_error=False,
            session_id="s",
            final_text="",
            tool_uses=[],
        )

    with (
        patch("cve_env.agent.loop.run_agent", fake_run_agent),
        patch("cve_env.agent.loop.NO_PROGRESS_GIVEUP_TURNS", 3),
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-noprog-trigger", audit_root=tmp_path)
        )
    assert outcome.status == "turn_cap", (
        f"real on_message no-progress trigger must classify 'turn_cap'; "
        f"got status={outcome.status!r} reason={outcome.reason!r}"
    )
    assert "no_progress" in (outcome.reason or ""), (
        f"terminal reason must carry the no_progress signal; got {outcome.reason!r}"
    )


def test_build_exception_RuntimeError_with_verify_passed_still_classified_as_success(
    tmp_path: Path,
) -> None:
    """Regression-lock: the BUG-008 sibling-3 fix narrows the priority change
    to CAP exceptions only. A generic RuntimeError (non-cap) with
    verify_passed=True must STILL classify via _classify_verify_outcome.
    Locks the fix scope so it doesn't accidentally affect transport errors,
    connection drops, etc."""

    async def fake_run_agent(*, on_message: Any = None, **_: Any) -> AgentRunOutcome:
        if on_message is not None:
            on_message(
                _assistant(
                    _tool_use(
                        "tu-v",
                        "mcp__cve_env__verify",
                        {"plan": [{"type": "container_status"}]},
                    )
                )
            )
            on_message(
                _user(
                    _tool_result(
                        "tu-v",
                        {
                            "passed": True,
                            "results": [{"type": "container_status", "passed": True}],
                        },
                    )
                )
            )
            on_message(_result("end_turn"))
        # Generic non-cap exception
        msg = "connection reset (mid-stream transport drop)"
        raise RuntimeError(msg)

    with patch("cve_env.agent.loop.run_agent", fake_run_agent):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-bug008-s3-runtime", audit_root=tmp_path)
        )
    # _classify_verify_outcome with only container_status (no smoke, no version)
    # → success_partial. The key invariant: NOT 'error' — verify-pass branch
    # still fires for non-cap exceptions when result_received=True.
    assert outcome.status in {"success", "verified_partial"}, (
        f"Non-cap exception with verify_passed=True must NOT be re-classified "
        f"as budget_exhausted/turn_cap. Got status={outcome.status!r}"
    )


def test_build_exception_path_finalizes_refusal_scanner(tmp_path: Path) -> None:
    """Phase 31.4: refusal_scanner.finalize() must run on the exception path,
    not just on happy path. Otherwise refusal events captured before the SDK
    threw are lost from the audit log.
    """
    finalize_calls: list[dict[str, Any]] = []

    class _FakeScanner:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.events: list[dict[str, Any]] = []

        def finalize(self, *, final_outcome_status: str, verify_passed: bool) -> None:
            finalize_calls.append(
                {
                    "status": final_outcome_status,
                    "verify_passed": verify_passed,
                }
            )

        def observe(self, _event: dict[str, Any]) -> None:
            return None

        def scan_text(
            self, *, turn: int, text: str, tool_call: dict[str, Any] | None
        ) -> None:
            return None

    async def boom(**_: Any) -> AgentRunOutcome:
        msg = "transport drop"
        raise RuntimeError(msg)

    with (
        patch("cve_env.agent.loop.RefusalScanner", _FakeScanner),
        patch("cve_env.agent.loop.run_agent", boom),
    ):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-finalize", audit_root=tmp_path)
        )
    assert outcome.status == "error"
    # Exact assertion: finalize was called exactly once on the exception path.
    assert len(finalize_calls) == 1, (
        f"expected 1 finalize call, got {len(finalize_calls)}"
    )
    assert finalize_calls[0]["status"] == "error"
    assert finalize_calls[0]["verify_passed"] is False


# Fix #7: stream-close-after-give_up grace -----------------------------------


def test_build_exception_after_give_up_is_relabeled_unresolvable(
    tmp_path: Path,
) -> None:
    """If the agent already invoked give_up (terminal decision) AND a ResultMessage
    arrived, then a late stream-drain exception is cosmetic -- the run reached a
    logical conclusion and the Outcome should reflect that.

    Phase 11.5: ResultMessage is now required for the relabel; without it the
    run never converged and outcome stays 'error' (CVE-2024-5736 refusal class).
    """
    give_up_result = {
        "terminal": True,
        "reason": "proprietary",
        "detail": "no upstream",
    }
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__give_up", {"reason": "proprietary"})
        ),
        _user(_tool_result("tu1", give_up_result)),
        _result(stop_reason="end_turn"),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        # After the give_up was fully observed, simulate a late SDK crash
        # (the exact shape of the CVE-2019-11581 bench case).
        raise RuntimeError("stream closed unexpectedly after give_up")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-fix7-a", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert outcome.give_up_reason == "proprietary"
    assert outcome.give_up_detail == "no upstream"
    # No error field populated when we have a terminal state.
    assert outcome.error == ""


def test_build_exception_with_api_overload_is_classified_as_rate_limited(
    tmp_path: Path,
) -> None:
    """A 529 Overloaded exception from the Anthropic API is NOT a CVE-merit
    failure — the build never got a fair chance. Classify it as the dedicated
    ``rate_limited`` status (distinct from ``unresolvable`` / ``error``) so
    humans, the cards, and ``bench_select_retry`` treat it as re-runnable,
    not as "this CVE can't be built."

    Incident driver (2026-05-29): a 529 storm produced ``unresolvable``-labeled
    outcomes because ``give_up_reason="api_overload"`` fell into the generic
    give_up branch (loop.py:1855); the operator misread that as failure and
    halted the run. A first-class status makes the misread impossible — and
    lets best-of-N retry these correctly on quota recovery.

    RED until the dedicated ``elif state.give_up_reason == "api_overload":``
    branch is added BEFORE the generic give_up branch.
    """

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        # Canonical 529-overload signature matched by _classify_api_overload.
        raise RuntimeError(
            "API Error: Repeated 529 Overloaded errors. Please try again later."
        )

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-rl-a", audit_root=tmp_path)
        )
    assert outcome.status == "rate_limited", (
        f"529 Overloaded must classify as 'rate_limited' (re-runnable), got "
        f"{outcome.status!r}. Otherwise it buckets with unresolvable/error "
        f"and the operator/best-of-N misread it as a CVE-merit failure."
    )
    # The signal is preserved so post-hoc analysis can distinguish causes.
    assert outcome.give_up_reason == "api_overload"


def test_build_exception_path_preserves_num_turns_and_cost(tmp_path: Path) -> None:
    """P1 fix (2026-05-02): the exception-relabel path must preserve the
    accumulated cost + turn count from any ResultMessage(s) that arrived
    before the SDK raised. Pre-fix, the exception-path Outcome dropped
    these fields (defaulted to 0/0.0 from the dataclass), causing
    forensic data loss — e.g. CVE-2015-10111 in bench50-20260501-220337
    reported `num_turns=0, total_cost_usd=0.0` despite 73 tool calls and
    a passing verify.

    The fix adds ``last_cost_usd`` and ``last_num_turns`` to
    ``_StreamState`` (max-updated on every ResultMessage), and the
    exception-path Outcome reads them.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hello"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # ResultMessage with non-trivial cost + turn count, BEFORE the exception.
        _result(stop_reason="end_turn", cost_usd=0.42, turns=7),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("stream closed unexpectedly after ResultMessage")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-p1-acct",
                audit_root=tmp_path,
                max_cost_usd=10.0,
            )
        )
    # Status was already correctly relabeled by Phase 31.2 (status == "success").
    # The new contract: cost + turns must propagate from the ResultMessage we saw.
    assert outcome.num_turns == 7, (
        f"expected num_turns=7 from ResultMessage, got {outcome.num_turns}"
    )
    assert outcome.total_cost_usd == pytest.approx(0.42), (
        f"expected total_cost_usd≈0.42 from ResultMessage, got {outcome.total_cost_usd}"
    )


def test_build_exception_path_aggregates_cost_and_turns_across_results(
    tmp_path: Path,
) -> None:
    """P1 + I2: when the SDK emits multiple ResultMessages (Phase 46.1
    retry-storm pattern), the exception-path Outcome must:
      - SUM cost_usd (each ResultMessage's value is per-segment, NOT
        cumulative — observed in CVE-2018-16509 retry-storm 2026-05-02)
      - MAX num_turns (turn counter is cumulative across segments;
        last ResultMessage has the largest value)

    This corrects the Phase 46.1 assumption: max() gives the wrong
    cost when segments have non-monotonic costs (e.g., cheap retry
    after expensive failed segment).
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # Two ResultMessages — second has lower cost (cheap retry after
        # the expensive first segment); turn counter is cumulative.
        _result(stop_reason="end_turn", cost_usd=0.85, turns=15),
        _result(stop_reason="end_turn", cost_usd=0.10, turns=18),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("stream closed after 2 ResultMessages")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-p1-multi",
                audit_root=tmp_path,
                max_cost_usd=10.0,
            )
        )
    # turns: max (last segment's cumulative count)
    assert outcome.num_turns == 18, f"expected MAX turns=18, got {outcome.num_turns}"
    # cost: sum (per-segment costs added)
    assert outcome.total_cost_usd == pytest.approx(0.95), (
        f"expected SUM cost $0.95, got ${outcome.total_cost_usd:.4f}"
    )


def test_build_recovers_when_verify_passes_after_refusal_stop_reason(
    tmp_path: Path,
) -> None:
    """I3 fix (2026-05-02): the Phase 46.1 refusal latch
    (state.refusal_stop_reason_seen) makes _map_status return
    'incomplete' for ANY mid-run refusal — even if the agent recovered
    afterwards and the LATER ResultMessage carried a passing verify.

    Production observation (CVE-2018-16509 in bench50-20260502-025431):
    audit JSONL had final_* records at T98 (turn_cap, reason='tool_use'),
    T132 (turn_cap, reason='refusal' → latch SET), T185 (success,
    reason='end_turn'). State.verify_passed = True (set after T132).
    Engine returned status='incomplete' despite the recovery.

    Fix: track turn-of-latest-refusal and turn-of-latest-verify-pass.
    If verify_passed_turn > refusal_stop_reason_turn → agent recovered;
    fall through to the verify-passed classification path.
    """
    messages = [
        # T1: first ResultMessage hits turn cap (no refusal).
        _result(stop_reason="tool_use", cost_usd=0.50, turns=98),
        # T2: second ResultMessage is REFUSAL — latches the flag.
        _result(stop_reason="refusal", cost_usd=0.30, turns=132),
        # Then the agent retries; verify passes mid-retry.
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # T3: final ResultMessage is SUCCESS (end_turn) — agent recovered.
        _result(stop_reason="end_turn", cost_usd=0.40, turns=185),
    ]

    async def fake_run(**kwargs: Any) -> Any:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        from claude_agent_sdk import ResultMessage

        return ResultMessage(
            subtype="success",
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=185,
            session_id="sess-1",
            stop_reason="end_turn",
            total_cost_usd=0.40,
            usage=None,
        )

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-i3-recovery",
                audit_root=tmp_path,
                max_cost_usd=10.0,
            )
        )
    # Recovery: verify passed AFTER the refusal → success-class outcome,
    # NOT 'incomplete'. The exact label (success vs success_partial) is
    # determined by _classify_verify_outcome based on the verify plan.
    assert outcome.status in ("success", "verified_partial"), (
        f"expected success/success_partial after refusal-then-recovery, "
        f"got {outcome.status!r} reason={outcome.reason!r}"
    )
    # verify_passed must remain True (not affected by the latch).
    assert outcome.verify_passed is True


def test_build_keeps_incomplete_when_verify_passed_before_refusal(
    tmp_path: Path,
) -> None:
    """I3 corollary: Phase 44.1's original case is preserved. If verify
    passed BEFORE a later refusal, the run is incomplete (refusal
    corrupted the post-verify state). This is the case Phase 44.1 was
    written for (CVE-2017-5638 in bench50-20260429-173117)."""
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # First ResultMessage: success-shaped, but the LAST one will be refusal.
        _result(stop_reason="end_turn", cost_usd=0.50, turns=20),
        # Then a refusal arrives — corrupts the post-verify state.
        _result(stop_reason="refusal", cost_usd=0.10, turns=22),
    ]

    async def fake_run(**kwargs: Any) -> Any:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        from claude_agent_sdk import ResultMessage

        return ResultMessage(
            subtype="error",
            duration_ms=1000,
            duration_api_ms=800,
            is_error=True,
            num_turns=22,
            session_id="sess-1",
            stop_reason="refusal",
            total_cost_usd=0.10,
            usage=None,
        )

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-i3-corruption",
                audit_root=tmp_path,
                max_cost_usd=10.0,
            )
        )
    # Refusal AFTER verify → incomplete.
    assert outcome.status == "interrupted", (
        f"expected incomplete after verify-then-refusal, got {outcome.status!r}"
    )


def test_build_outcome_sums_cost_across_retry_storm_result_messages(
    tmp_path: Path,
) -> None:
    """I2 fix (2026-05-02): when the SDK emits MULTIPLE ResultMessages
    (auth_error retry storm, refusal-then-retry pattern), each message's
    ``total_cost_usd`` is the cost of THAT segment — not cumulative.
    Engine must SUM costs across segments so Outcome.total_cost_usd
    reflects the user's actual billed spend.

    Production observation (CVE-2018-16509 in bench50-20260502-025431):
    audit JSONL had 3 final_* records with costs $1.5199 / $0.4622 /
    $0.7386. Real spend = $2.72. Engine reported $0.74 (last segment
    via happy-path) or $1.52 (max via exception-path). Both wrong.

    The companion num_turns field is cumulative (turn counter is global
    within the run_agent call), so max() remains correct for it.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # Three ResultMessages — retry-storm shape.
        _result(stop_reason="end_turn", cost_usd=0.40, turns=10),
        _result(stop_reason="end_turn", cost_usd=0.50, turns=20),
        _result(stop_reason="end_turn", cost_usd=0.60, turns=30),
    ]

    captured_run: dict[str, Any] = {}

    async def fake_run(**kwargs: Any) -> Any:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        # Return value mirroring SDK behaviour: last ResultMessage's
        # cost ($0.60), cumulative turn counter ($30).
        from claude_agent_sdk import ResultMessage

        result = ResultMessage(
            subtype="success",
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=30,
            session_id="sess-1",
            stop_reason="end_turn",
            total_cost_usd=0.60,
            usage=None,
        )
        captured_run["result"] = result
        return result

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-i2-sum",
                audit_root=tmp_path,
                max_cost_usd=10.0,
            )
        )
    # Cost SUMS across segments: 0.40 + 0.50 + 0.60 = 1.50
    assert outcome.total_cost_usd == pytest.approx(1.50), (
        f"expected summed cost $1.50, got ${outcome.total_cost_usd:.4f}"
    )
    # Turns MAX (last cumulative counter): 30
    assert outcome.num_turns == 30, (
        f"expected max num_turns=30, got {outcome.num_turns}"
    )


def test_build_exception_path_handles_none_cost_and_turns_in_result_message(
    tmp_path: Path,
) -> None:
    """P1 edge case: a ResultMessage may have ``num_turns=None`` or
    ``total_cost_usd=None`` (the SDK can emit nulls under partial-failure
    paths). The fix at ``loop.py:on_message`` uses ``or 0`` / ``or 0.0``
    to coalesce; this test pins the contract — None inputs must NOT
    crash and must NOT corrupt previously-recorded values.
    """
    from claude_agent_sdk import ResultMessage

    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "apache2 -v"},
                        },
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "echo hi"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        # First ResultMessage: real values.
        _result(stop_reason="end_turn", cost_usd=0.50, turns=5),
        # Second ResultMessage: SDK emitted nulls (Phase 46.1 corner case).
        ResultMessage(
            subtype="success",
            duration_ms=1000,
            duration_api_ms=800,
            is_error=False,
            num_turns=None,  # type: ignore[arg-type]
            session_id="sess-1",
            stop_reason="end_turn",
            total_cost_usd=None,  # type: ignore[arg-type]
            usage=None,
        ),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("stream closed after None-valued ResultMessage")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-p1-none", audit_root=tmp_path)
        )
    # max() must keep the first ResultMessage's real values; the
    # None-valued one coalesces to 0/0.0 which loses the max comparison.
    assert outcome.num_turns == 5, (
        f"None-valued ResultMessage corrupted num_turns: {outcome.num_turns}"
    )
    assert outcome.total_cost_usd == pytest.approx(0.50), (
        f"None-valued ResultMessage corrupted total_cost_usd: {outcome.total_cost_usd}"
    )


def test_build_exception_after_full_verify_relabels_to_success(
    tmp_path: Path,
) -> None:
    """Phase 31.2 + Phase 52: when a passing verify includes version assertion
    AND functional smoke (3+ active checks) AND a ResultMessage arrived, the
    exception-relabel path produces ``success`` (full env build).
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        # Version assertion
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "drupal --version"},
                        },
                        # Functional smoke: trivial-use exec_check
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "drush status --format=json"},
                        },
                        # 3rd active check (smoke heuristic via >=3 active)
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        _result(stop_reason="end_turn"),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("stream closed unexpectedly after verify.passed")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-fix7-b", audit_root=tmp_path)
        )
    assert outcome.status == "success"
    assert outcome.verify_passed is True
    assert outcome.error == ""


def test_build_exception_after_lifecycle_only_verify_relabels_to_partial(
    tmp_path: Path,
) -> None:
    """Phase 52: when a passing verify used only lifecycle checks AND a
    ResultMessage arrived, the exception-relabel path produces
    ``success_partial`` (not ``success``)."""
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [{"type": "http_check", "passed": True}],
                    "reason": None,
                },
            )
        ),
        _result(stop_reason="end_turn"),
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("late drain after lifecycle-only verify pass")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-fix7-lifecycle", audit_root=tmp_path)
        )
    assert outcome.status == "verified_partial"
    assert outcome.verify_passed is True


def test_build_phase44_1_refusal_after_verify_pass_overrides_to_incomplete(
    tmp_path: Path,
) -> None:
    """Phase 44.1 (2026-04-29): a Claude Code safety refusal (stop_reason
    contains 'refusal' or 'usage policy') AFTER a passing verify must NOT
    classify as success. Forensic case: CVE-2017-5638 in
    bench50-20260429-173117 — agent had verify_passed=true earlier, then
    SDK terminated with refusal; pre-44.1 logic returned status=success.
    Post-44.1: status='incomplete' regardless of verify_passed.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result(
                "tu1",
                {
                    "passed": True,
                    "results": [
                        {"type": "container_status", "passed": True},
                        {
                            "type": "exec_check",
                            "passed": True,
                            "details": {"command": "openssl version"},
                        },
                        {"type": "http_request_check", "passed": True},
                    ],
                    "reason": None,
                },
            )
        ),
        _result("refusal"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-44.1", audit_root=tmp_path)
        )
    # The CRITICAL assertion: even though verify passed, status is
    # 'incomplete' because stop_reason='refusal' indicates the SDK was
    # forcibly terminated; the engine did NOT complete its work.
    assert outcome.status == "interrupted", (
        f"refusal must override verify_passed; got {outcome.status!r}"
    )
    assert outcome.verify_passed is True  # raw signal preserved for triage
    assert "refusal" in outcome.reason.lower(), (
        f"reason must mention refusal; got {outcome.reason!r}"
    )


def test_build_phase46_1_earlier_refusal_result_message_classifies_incomplete(
    tmp_path: Path,
) -> None:
    """Phase 46.1 (2026-04-30): the SDK can emit MULTIPLE ResultMessages
    during one run (auth_error retry storm; mid-run refusals). Phase 44.1
    only checked the FINAL run.stop_reason — but the final ResultMessage
    can be 'end_turn' (turn cap reached) while an EARLIER ResultMessage
    was 'refusal'. Forensic case: CVE-2018-16509 in
    bench50-20260430-000207 — audit shows three ResultMessages with
    stop_reasons 'refusal', 'refusal', 'end_turn'. Pre-46.1 logic
    classified as 'no_verify_pass'; post-46.1 must be 'incomplete'.
    """
    messages = [
        _result("refusal", turns=37),  # earlier ResultMessage: refusal
        _result("refusal", turns=55),  # another retry: refusal
        _assistant(_text_block("Sorry, I cannot help with this.")),
        _result("end_turn", turns=78),  # final survives in run.stop_reason
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-46.1", audit_root=tmp_path)
        )
    # Even though run.stop_reason='end_turn' (NOT refusal), the agent
    # session was forcibly refused mid-run — must be classified as
    # 'incomplete', not 'no_verify_pass'.
    assert outcome.status == "interrupted", (
        f"earlier refusal ResultMessage must override final end_turn; "
        f"got {outcome.status!r}"
    )
    assert "refusal" in outcome.reason.lower(), (
        f"reason must mention refusal; got {outcome.reason!r}"
    )
    # raw stop_reason preserved for triage
    assert outcome.stop_reason == "end_turn"


def test_build_exception_after_verify_pass_without_result_message_is_error(
    tmp_path: Path,
) -> None:
    """Phase 11.5: verify passed in a partial dead retry but no ResultMessage ever
    arrived → run never converged, must be 'error' not 'success'.

    Repro of CVE-2024-5736 in bench40: usage-policy refusal across 4 SDK retries
    left state.verify_passed=True with num_turns=0, mistagging refusal as success.
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(_tool_result("tu1", {"passed": True, "results": [], "reason": None})),
        # NOTE: NO ResultMessage — simulates the SDK crashing before final result.
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        on_msg = kwargs.get("on_message")
        if on_msg is not None:
            for m in messages:
                on_msg(m)
        raise RuntimeError("policy refusal: stream closed without ResultMessage")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-phase11.5", audit_root=tmp_path)
        )
    assert outcome.status == "error"
    assert "policy refusal" in outcome.error


def test_build_exception_after_give_up_without_result_message_is_unresolvable(
    tmp_path: Path,
) -> None:
    """Phase 11.5 + F-13 (2026-05-05): with the F-13 fix, give_up.terminal=True
    raises GiveUpReceived inside on_message, halting SDK iteration immediately.
    The "give_up then no ResultMessage" case is the EXPECTED state when F-13
    fires (we halt before the SDK would emit ResultMessage). Outcome must be
    'unresolvable', not 'error' — give_up was the agent's terminal decision.

    Pre-F-13 (Phase 11.5) this scenario was treated as 'error' because the
    only way to get there was an SDK mid-stream crash. F-13 makes it the
    happy path for unresolvable runs.
    """
    give_up_result = {
        "terminal": True,
        "reason": "proprietary",
        "detail": "no upstream",
    }
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__give_up", {"reason": "proprietary"})
        ),
        _user(_tool_result("tu1", give_up_result)),
        # NOTE: NO ResultMessage — F-13 halts SDK iteration before this point.
    ]

    async def fake_run(**kwargs: Any) -> AgentRunOutcome:
        # Mirror real _run_query_once: catch GiveUpReceived from on_message.
        from cve_env.agent.llm import GiveUpReceived

        on_msg = kwargs.get("on_message")
        try:
            if on_msg is not None:
                for m in messages:
                    on_msg(m)
        except GiveUpReceived:
            return AgentRunOutcome(
                stop_reason="end_turn",
                num_turns=0,
                total_cost_usd=0.0,
                is_error=False,
                session_id="",
                final_text="",
                tool_uses=[],
            )
        # If we got here, no give_up halted us — this is the unexpected case.
        raise RuntimeError("crashed mid-stream after give_up but before ResultMessage")

    with patch("cve_env.agent.loop.run_agent", fake_run):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-phase11.5-giveup", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert outcome.give_up_reason == "proprietary"


def test_build_exception_without_terminal_state_still_error(tmp_path: Path) -> None:
    """With no give_up and no verify pass, an exception remains 'error'."""

    async def boom(**_: Any) -> AgentRunOutcome:
        raise RuntimeError("boom")

    with patch("cve_env.agent.loop.run_agent", boom):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-fix7-c", audit_root=tmp_path)
        )
    assert outcome.status == "error"
    assert "boom" in outcome.error


def test_build_writes_per_cve_audit_jsonl(tmp_path: Path) -> None:
    messages = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__vulhub_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"hit": True})),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-7", audit_root=tmp_path)
        )
    assert outcome.audit_path is not None
    lines = outcome.audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 3  # at minimum: one llm_turn, one tool_ok, one terminal
    parsed = [json.loads(ln) for ln in lines if ln.strip()]
    terminal_entries = [p for p in parsed if p["status"].startswith("final_")]
    assert len(terminal_entries) == 1


# Fix #8: continuation-loop on premature end_turn ----------------------------
#
# Shipped + deleted 2026-04-25 (0 continuations across 3 de-risk runs of ONE
# CVE, CVE-2023-22515 — the commitment-enforcement prompt rule sufficed there),
# then REVIVED 2026-05-28 (commit 578ee63) scoped+extended: the 334-CVE run
# (refactor/docs/bench-analysis-2026-05-28.md) measured a follow-through gap the
# prompt rule alone does not close. These tests (un-skipped) are the behavioral
# spec for the revived ``_should_continue_for_verify`` + continuation loop in
# ``agent/loop.py``.


def _sequenced_run_agent_factory(message_batches: list[list[Any]]):
    """Fake that returns a different message stream per invocation.

    Each call to the fake consumes one batch from ``message_batches`` in order.
    Each batch is a full list of SDK messages terminating in a ResultMessage
    (or synthesizes one if omitted). The fake records the ``resume`` kwarg
    on each call into ``calls`` so tests can assert session-resume threading.
    """
    calls: list[dict[str, Any]] = []
    iterator = iter(message_batches)

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
        try:
            batch = next(iterator)
        except StopIteration as err:
            msg = "sequenced_run_agent consumed more calls than batches provided"
            raise AssertionError(msg) from err
        calls.append(
            {
                "user_prompt": user_prompt,
                "resume": resume,
                "max_turns": max_turns,
                "max_cost_usd": max_cost_usd,
            }
        )
        result_msg = None
        for m in batch:
            if on_message is not None:
                on_message(m)
            if type(m).__name__ == "ResultMessage":
                result_msg = m
        if result_msg is None:
            result_msg = _result("end_turn")
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

    return fake_run_agent, calls


def test_fix8_fires_on_premature_end_turn_after_staging_tool(tmp_path: Path) -> None:
    """When agent calls Bash, gets tool_ok, then end_turns without verify/give_up,
    the loop should re-query with ``resume=session_id``. The second call then
    verifies successfully."""
    first_batch = [
        _assistant(_tool_use("tu1", "Bash", {"command": "mkdir -p /tmp/x"})),
        _user(_tool_result("tu1", {"ok": True})),
        _assistant(_text_block("Now I'll docker_compose_up.")),
        _result("end_turn", cost_usd=0.05, turns=3),
    ]
    second_batch = [
        _assistant(_tool_use("tu2", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(_tool_result("tu2", {"passed": True, "results": [], "reason": None})),
        _result("end_turn", cost_usd=0.04, turns=2),
    ]
    fake, calls = _sequenced_run_agent_factory([first_batch, second_batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-a", audit_root=tmp_path)
        )
    # CF-3 (Phase 52, post-dates this 2026-04-25 test): a passed verify with
    # empty results grades as verified_partial, not plain success. The fix8
    # contract is "continuation fired → verify PASSED" — assert the verify-pass
    # class, not the exact grade (graded separately in _classify_verify_outcome tests).
    assert outcome.status in ("success", "verified_partial")
    assert outcome.verify_passed is True
    assert len(calls) == 2
    # Second call must carry the resume session id from the first.
    assert calls[1]["resume"] == "sess-1"
    # Accumulated cost combines across both calls (0.05 + 0.04).
    assert abs(outcome.total_cost_usd - 0.09) < 1e-9
    # num_turns is now the AUTHORITATIVE state.turn (one bump per on_message,
    # the counter the turn cap enforces + the audit "turn" field), = 4 + 3
    # messages across the two runs. Pre-2026-05-31 this asserted 5 (the SDK
    # cont_turns_acc sum 3+2) — the underreport bug this fix corrects.
    assert outcome.num_turns == 7


def test_fix8_does_not_fire_on_verify_pass(tmp_path: Path) -> None:
    """Verify already passed -> no continuation."""
    batch = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(_tool_result("tu1", {"passed": True, "results": [], "reason": None})),
        _result("end_turn"),
    ]
    fake, calls = _sequenced_run_agent_factory([batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-b", audit_root=tmp_path)
        )
    assert (
        outcome.verify_passed is True
    )  # CF-3: grade is verified_partial; the point is no continuation
    assert len(calls) == 1  # no continuation


def test_fix8_does_not_fire_on_give_up(tmp_path: Path) -> None:
    """Terminal give_up -> no continuation."""
    batch = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__give_up", {"reason": "proprietary"})
        ),
        _user(
            _tool_result(
                "tu1", {"terminal": True, "reason": "proprietary", "detail": ""}
            )
        ),
        _result("end_turn"),
    ]
    fake, calls = _sequenced_run_agent_factory([batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-c", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert len(calls) == 1


def test_fix8_does_not_fire_when_last_tool_is_not_staging(tmp_path: Path) -> None:
    """Last tool = verify (not a staging tool) means the agent already tried; no loop."""
    batch = [
        _assistant(_tool_use("tu1", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(
            _tool_result("tu1", {"passed": False, "results": [], "reason": "timeout"})
        ),
        _result("end_turn"),
    ]
    fake, calls = _sequenced_run_agent_factory([batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-d", audit_root=tmp_path)
        )
    assert outcome.status == "verify_failed"
    assert len(calls) == 1


def test_fix8_hard_caps_at_two_continuations(tmp_path: Path) -> None:
    """If every continuation also ends prematurely after a staging tool_ok,
    the loop must STOP at 2 continuations (3 total run_agent invocations)."""

    def premature_batch(tu_id: str) -> list[Any]:
        return [
            _assistant(_tool_use(tu_id, "Bash", {"command": "ls"})),
            _user(_tool_result(tu_id, {"ok": True})),
            _result("end_turn", cost_usd=0.02, turns=2),
        ]

    fake, calls = _sequenced_run_agent_factory(
        [premature_batch("tu1"), premature_batch("tu2"), premature_batch("tu3")]
    )
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-e", audit_root=tmp_path)
        )
    # Final outcome still no_verify_pass -- continuations didn't recover.
    assert outcome.status == "verify_failed"
    # Exactly 3 run_agent calls: 1 initial + 2 continuations.
    assert len(calls) == 3
    # Continuations carry the resume session id.
    assert calls[0]["resume"] is None
    assert calls[1]["resume"] == "sess-1"
    assert calls[2]["resume"] == "sess-1"


def test_fix8_respects_budget_fraction_gate(tmp_path: Path) -> None:
    """If the first query already burned through the cost threshold, do not
    continue -- the budget gate (< 70% of max_cost_usd) must be honored."""
    expensive_batch = [
        _assistant(_tool_use("tu1", "Bash", {"command": "ls"})),
        _user(_tool_result("tu1", {"ok": True})),
        # 0.40 of 0.50 = 80% -> over the 70% threshold, no continuation.
        _result("end_turn", cost_usd=0.40, turns=3),
    ]
    fake, calls = _sequenced_run_agent_factory([expensive_batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="fix8-f",
                audit_root=tmp_path,
                max_cost_usd=0.50,
            )
        )
    assert outcome.status == "verify_failed"
    assert len(calls) == 1


def test_fix8_continuation_uses_continuation_prompt(tmp_path: Path) -> None:
    """The continuation call must use CONTINUATION_USER_PROMPT (not the original)."""
    from cve_env.agent.prompts import CONTINUATION_USER_PROMPT

    first = [
        _assistant(_tool_use("tu1", "Write", {"path": "/tmp/a"})),
        _user(_tool_result("tu1", {"ok": True})),
        _result("end_turn", cost_usd=0.02, turns=2),
    ]
    second = [
        _assistant(_tool_use("tu2", "mcp__cve_env__give_up", {"reason": "no_image"})),
        _user(
            _tool_result("tu2", {"terminal": True, "reason": "no_image", "detail": ""})
        ),
        _result("end_turn", cost_usd=0.01, turns=2),
    ]
    fake, calls = _sequenced_run_agent_factory([first, second])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-g", audit_root=tmp_path)
        )
    assert outcome.status == "unresolvable"
    assert len(calls) == 2
    assert calls[0]["user_prompt"] != CONTINUATION_USER_PROMPT
    assert calls[1]["user_prompt"] == CONTINUATION_USER_PROMPT


def test_fix8_fires_on_source_build_ok_without_verify_and_logs_audit(
    tmp_path: Path,
) -> None:
    """Data-justified EXTENSION (bench-analysis-2026-05-28.md): source_build
    succeeded then end_turn without verify (10/15 such cases were near-builds).
    The original staging-only trigger missed source_build; the build-ok branch
    catches it. Also asserts the fix8_continuation audit fire-signal is written
    (the L-class check — 2026-04-25 saw 0 such entries)."""
    first = [
        _assistant(
            _tool_use("tu1", "mcp__cve_env__source_build", {"dockerfile": "FROM x"})
        ),
        _user(_tool_result("tu1", {"ok": True, "image_ref": "local/x:built"})),
        _result("end_turn", cost_usd=0.10, turns=4),
    ]
    second = [
        _assistant(_tool_use("tu2", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(_tool_result("tu2", {"passed": True, "results": [], "reason": None})),
        _result("end_turn", cost_usd=0.05, turns=2),
    ]
    fake, calls = _sequenced_run_agent_factory([first, second])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-sb", audit_root=tmp_path)
        )
    assert outcome.verify_passed is True
    assert len(calls) == 2  # continuation fired on source_build-ok-no-verify
    assert calls[1]["resume"] == "sess-1"
    parsed = [
        json.loads(ln)
        for ln in outcome.audit_path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert any(p["status"] == "fix8_continuation" for p in parsed)


def test_fix8_does_not_fire_on_research_only_no_build(tmp_path: Path) -> None:
    """Over-fire guard: a pure-research run (last tool = github_fetch, no build,
    no staging tool) that end_turns must NOT trigger a continuation — those are
    correctly-classified research-only give-ups, not near-builds."""
    batch = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("tu1", {"ok": True})),
        _assistant(_tool_use("tu2", "mcp__cve_env__github_fetch", {"q": "x"})),
        _user(_tool_result("tu2", {"ok": True})),
        _result("end_turn"),
    ]
    fake, calls = _sequenced_run_agent_factory([batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        _outcome = asyncio.run(
            build(_cve(), _host(), run_id="fix8-research", audit_root=tmp_path)
        )
    assert len(calls) == 1  # no continuation on research-only


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Locks current behavior on stable surfaces (state.turn semantics, final_text
# capture, per-CVE state-reset chain) so Phase 67.1/67.2 refactors cannot
# silently change observable behavior.


def test_phase67_state_turn_increments_per_message(tmp_path: Path) -> None:
    """Phase 67.0: ``state.turn`` increments once per ``on_message`` call,
    regardless of how many blocks the message contains.

    The name ``turn`` is misleading — it counts SDK messages, not logical
    agent turns. Every audit entry written from the same SDK message shares
    the same turn number. This test locks that invariant so 67.1's docstring
    cleanup or any future refactor cannot silently change the counter.
    """
    messages = [
        # Message 1: assistant with TWO ToolUseBlocks → 2 audit writes at turn=1
        _assistant(
            _tool_use("tu-a", "mcp__cve_env__nvd_lookup", {"cve_id": "X"}),
            _tool_use("tu-b", "mcp__cve_env__github_fetch", {"repo": "a/b"}),
        ),
        # Message 2: user reply → up to 2 audit writes at turn=2
        _user(
            _tool_result("tu-a", {"hit": True}),
            _tool_result("tu-b", {"hit": True}),
        ),
        # Message 3: assistant text → 1 audit write at turn=3
        _assistant(_text_block("done")),
        # Message 4: ResultMessage → 1 final_* audit write at turn=4
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="phase67-turn", audit_root=tmp_path)
        )

    audit_path = tmp_path / "phase67-turn" / "CVE-2018-7600.jsonl"
    entries = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # All entries from message 1 must have turn=1; message 2 → turn=2; etc.
    turns_per_message = [e["turn"] for e in entries]
    # Final turn should match the number of SDK messages we sent (4).
    assert max(turns_per_message) == 4, (
        f"max turn={max(turns_per_message)} expected 4; entries={entries!r}"
    )
    # Multiple writes within message 1 share turn=1.
    assert turns_per_message.count(1) >= 2, (
        f"expected >=2 entries at turn=1, got {turns_per_message.count(1)}"
    )
    assert outcome.status == "verify_failed"


def test_phase67_final_text_captures_last_text_block(tmp_path: Path) -> None:
    """Phase 67.0: ``state.final_text`` overwrites on each TextBlock,
    so multi-block runs surface only the LAST text. Locks current behavior;
    Phase 67.2 may change to accumulator (joined). If the change ships, this
    test will guide what the new contract looks like.
    """
    messages = [
        _assistant(_text_block("first explanation")),
        _assistant(_text_block("middle thought")),
        _assistant(_text_block("final summary")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="phase67-final-text", audit_root=tmp_path)
        )
    # Current behavior: only the LAST TextBlock survives.
    assert outcome.final_text == "final summary"


def test_phase67_build_resets_all_per_cve_state_in_order(tmp_path: Path) -> None:
    """Phase 67.0 / W1-4: ``build()`` resets all per-CVE tool state BEFORE the
    agent runs. Post-W1-4 (2026-06-02 review) this goes through
    ``tools.reset_all_tool_state()`` iterating ``_PER_CVE_RESET_HANDLERS``; this
    test locks that build() invokes the FULL registry in order, so a forgotten
    reset (missing handler) is caught at unit-test time (alongside
    test_reset_aggregator).
    """
    call_order: list[str] = []

    import cve_env.agent.tools as tools_mod

    expected_order = [
        "reset_failed_attempts",
        "reset_active_stacks",
        "reset_rate_limit_budget",
        "reset_nvd_lookup_state",
        "reset_docker_build_state",
    ]

    def make_recorder(name: str, original: Any) -> Any:
        def recorder(*args: Any, **kwargs: Any) -> Any:
            call_order.append(name)
            return original(*args, **kwargs)

        return recorder

    # Wrap each registered handler so we record invocation order. The names line
    # up with the registry order (locked by expected_order below).
    wrapped = tuple(
        make_recorder(name, handler)
        for name, handler in zip(
            expected_order, tools_mod._PER_CVE_RESET_HANDLERS, strict=True
        )
    )

    messages = [_result("end_turn")]
    with (
        patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)),
        patch.object(tools_mod, "_PER_CVE_RESET_HANDLERS", wrapped),
    ):
        asyncio.run(
            build(_cve(), _host(), run_id="phase67-resets", audit_root=tmp_path)
        )

    # All 5 resets must fire in registry order (expected_order, defined above).
    assert call_order == expected_order, (
        f"reset chain divergence — expected {expected_order}, got {call_order}"
    )


# ─── Stage 13.7: combined-Phase regression scenario ─────────────────────


def test_build_combined_refusal_latch_overrides_give_up_in_retry_storm(
    tmp_path: Path,
) -> None:
    """Combined regression scenario pinning the priority order when
    Phase 31 (give_up) + Phase 46.1 (multi-ResultMessage retry-storm with
    earlier refusal stop_reasons) + final end_turn ALL fire in one run:

      - Earlier ResultMessage stop_reason='refusal' (Phase 46.1 trigger)
      - give_up tool fires mid-stream (Phase 31: agent gives up)
      - Another ResultMessage stop_reason='refusal' (retry-storm)
      - Final ResultMessage stop_reason='end_turn' with high turn count

    Discovered priority (build() classification): refusal-latch from any
    EARLIER ResultMessage WINS over a give_up tool fire — outcome.status
    is 'incomplete' (not 'unresolvable'). Rationale: when the SDK was
    forcibly refused at any point, the engine session was disrupted, so
    a subsequent give_up tool fire is treated as fallout from the
    refusal rather than a clean engine decision.

    This pins down the priority so future refactors of build()'s
    classification logic don't silently invert it. Forensic CVEs that
    exhibit this combination (earlier refusal + later give_up) would
    re-classify if the order changed — breaking bench accounting that
    distinguishes 'SDK refused' from 'agent gave up'.

    NOTE: existing tests cover each Phase in isolation (test_build_unresolvable_when_give_up
    line 535 pins give_up alone; test_build_phase46_1_earlier_refusal_*
    line 1302 pins multi-ResultMessage refusal alone). This combined
    test catches priority-order regressions that no isolated test sees.
    """
    messages = [
        # Earlier ResultMessage: refusal (Phase 46.1 trigger)
        _result("refusal", turns=15, cost_usd=0.10),
        # Mid-stream: agent fires give_up tool (Phase 31 trigger)
        _assistant(
            _tool_use(
                "tu_give_up",
                "mcp__cve_env__give_up",
                {
                    "reason": "no_image",
                    "detail": "exhausted research; no buildable artifact",
                },
            )
        ),
        _user(
            _tool_result(
                "tu_give_up",
                {
                    "terminal": True,
                    "reason": "no_image",
                    "detail": "exhausted research; no buildable artifact",
                },
            )
        ),
        # Another retry-storm ResultMessage: refusal again
        _result("refusal", turns=22, cost_usd=0.05),
        # Final ResultMessage: end_turn with high turn count
        _result("end_turn", turns=45, cost_usd=0.08),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-combined-13.7", audit_root=tmp_path)
        )
    # Priority assertion: refusal-latch wins over give_up AND over final end_turn.
    # If this assertion fails, the build() classification priority has
    # changed — reconcile against the documented order in this test
    # or in the engine's source.
    assert outcome.status == "interrupted", (
        f"earlier refusal ResultMessage must override give_up + final end_turn; "
        f"got {outcome.status!r}"
    )
    assert "refusal" in outcome.reason.lower(), (
        f"reason must mention refusal; got {outcome.reason!r}"
    )
    # raw stop_reason from final ResultMessage preserved for triage
    assert outcome.stop_reason == "end_turn"


def test_num_turns_reports_authoritative_state_turn(tmp_path: Path) -> None:
    """Outcome.num_turns must reflect the engine's authoritative turn counter
    (``state.turn``, which on_message increments per message and which enforces
    the turn cap), NOT the SDK ResultMessage's lower ``num_turns``.

    Bug (bench-analysis-2026-05-28, confirmed 2026-05-31): CVE-2022-30518
    reported num_turns=51 while the audit log showed 138; CVE-2022-31945
    reported 35 while it actually hit the 96 cap. The Outcome was built from
    ``max(state.last_num_turns, ...)`` (the SDK counter) and omitted state.turn.

    Research-only tools + end_turn → no force-verify continuation → a single
    run, so state.turn is deterministic (one bump per on_message call).
    RED before the fix: outcome.num_turns == 2 (the SDK ResultMessage value,
    floored at tool-use count = 2). GREEN: == 5 (state.turn).
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("tu1", {"ok": True})),
        _assistant(_tool_use("tu2", "mcp__cve_env__github_fetch", {"url": "u"})),
        _user(_tool_result("tu2", {"ok": True})),
        _result("end_turn", turns=2),  # SDK UNDERREPORTS: num_turns=2
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-nt", audit_root=tmp_path)
        )
    assert outcome.num_turns == len(messages), (
        f"num_turns={outcome.num_turns} underreports the authoritative state.turn "
        f"(={len(messages)}, one per on_message call); the SDK ResultMessage said 2"
    )


# ── force-resolve-before-giveup (cascade-skip fix, 2026-05-31) ──────────────
# The cascade-skip detector (loop.py:1519) relabels give_up(no_image)-without-
# image_resolve → "skipped_image_lookup" but is DETECT-ONLY. force-resolve
# upgrades it to a bounded re-query continuation (mirrors Fix #8): the engine
# re-prompts the agent to actually call image_resolve (and source_build on
# not_found) before honoring the give_up. Adversarially reviewed; 3 must-fixes:
# (FLAW-1) skip if run.session_id is empty (give_up can raise before a
# ResultMessage); (FLAW-2) restore give_up_reason if the continuation doesn't
# improve; (FLAW-3) 0.5 budget slice so it doesn't starve Fix #8's 0.70 gate.


def _run_stub(stop_reason: str = "end_turn", session_id: str = "sess-1") -> Any:
    import types

    return types.SimpleNamespace(stop_reason=stop_reason, session_id=session_id)


def _state_cascade_skip() -> Any:
    """A _StreamState in the post-give_up state the detector leaves for a
    cascade-skip (give_up(no_image) without image_resolve)."""
    from cve_env.agent.loop import _StreamState

    st = _StreamState()
    st.give_up_reason = "skipped_image_lookup"
    st.tool_uses_seen = [{"name": "nvd_lookup"}, {"name": "give_up"}]
    return st


def test_force_resolve_predicate_fires_on_cascade_skip() -> None:
    from cve_env.agent.loop import _should_continue_for_resolve

    assert (
        _should_continue_for_resolve(_run_stub(), _state_cascade_skip(), 0, 0.1, 2.5)
        is True
    )


def test_force_resolve_predicate_skips_empty_session() -> None:
    """FLAW-1: give_up can raise before a ResultMessage → empty session_id →
    resume='' would break. Must NOT fire."""
    from cve_env.agent.loop import _should_continue_for_resolve

    run = _run_stub(session_id="")
    assert (
        _should_continue_for_resolve(run, _state_cascade_skip(), 0, 0.1, 2.5) is False
    )


def test_force_resolve_predicate_fires_on_captured_session() -> None:
    """The PRODUCTION case (2026-05-31 smoke): give_up raises mid-stream so
    run.session_id is empty, but a session id was captured from streaming
    AssistantMessages (state.last_session_id) → resume works → MUST fire.
    Without this, the fix is dead in production (the smoke proved it)."""
    from cve_env.agent.loop import _should_continue_for_resolve

    st = _state_cascade_skip()
    st.last_session_id = "sess-captured"
    run = _run_stub(session_id="")  # empty, as for a real give_up run
    assert _should_continue_for_resolve(run, st, 0, 0.1, 2.5) is True


def test_force_resolve_predicate_skips_non_cascade_giveup() -> None:
    from cve_env.agent.loop import _should_continue_for_resolve

    # proprietary is not eligible — never force a build (the critical guard)
    st = _state_cascade_skip()
    st.give_up_reason = "proprietary"
    assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is False
    # build-engagement gate (2026-05-31): no_image is now eligible, but a no_image
    # give-up that ALREADY attempted a real build (source_build) is a legitimate
    # cascade-exhausted finding → no fire. (no_image WITHOUT a build now FIRES —
    # see test_force_resolve_gate_fires_on_no_image_without_build.)
    st2 = _state_giveup(
        "no_image", ["nvd_lookup", "image_resolve", "source_build", "give_up"]
    )
    assert _should_continue_for_resolve(_run_stub(), st2, 0, 0.1, 2.5) is False


def test_force_resolve_predicate_skips_when_already_attempted() -> None:
    from cve_env.agent.loop import _should_continue_for_resolve

    st = _state_cascade_skip()
    st.force_resolve_attempted = True
    assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is False


def test_force_resolve_predicate_caps_at_max_and_budget() -> None:
    from cve_env import config
    from cve_env.agent.loop import _should_continue_for_resolve

    assert config.get_force_resolve_max() == 1  # default
    # count at the (default) cap → no fire
    assert (
        _should_continue_for_resolve(_run_stub(), _state_cascade_skip(), 1, 0.0, 2.5)
        is False
    )
    # cost at/over the slice → no fire (0.5 * 2.5 = 1.25)
    over = config.get_force_resolve_budget_fraction() * 2.5
    assert (
        _should_continue_for_resolve(_run_stub(), _state_cascade_skip(), 0, over, 2.5)
        is False
    )


def test_force_resolve_config_driven_max_and_budget(monkeypatch: Any) -> None:
    """The knobs are env-configurable (operator dial). CVE_ENV_FORCE_RESOLVE_MAX=0
    disables force-resolve entirely; a raised MAX re-enables a 2nd attempt; the
    budget fraction is tunable."""
    from cve_env import config
    from cve_env.agent.loop import _should_continue_for_resolve

    # MAX=0 → disabled even on a fresh cascade-skip (the cost-control dial)
    monkeypatch.setenv("CVE_ENV_FORCE_RESOLVE_MAX", "0")
    assert config.get_force_resolve_max() == 0
    assert (
        _should_continue_for_resolve(_run_stub(), _state_cascade_skip(), 0, 0.1, 2.5)
        is False
    )
    # MAX=2 → a 2nd attempt (count=1) is now allowed
    monkeypatch.setenv("CVE_ENV_FORCE_RESOLVE_MAX", "2")
    assert (
        _should_continue_for_resolve(_run_stub(), _state_cascade_skip(), 1, 0.1, 2.5)
        is True
    )
    # budget fraction raised to 0.9 → a cost that blocked at 0.5 now passes
    monkeypatch.setenv("CVE_ENV_FORCE_RESOLVE_BUDGET_FRACTION", "0.9")
    assert config.get_force_resolve_budget_fraction() == 0.9
    assert (
        _should_continue_for_resolve(
            _run_stub(), _state_cascade_skip(), 0, 0.6 * 2.5, 2.5
        )
        is True
    )


def test_force_resolve_predicate_skips_non_end_turn() -> None:
    from cve_env.agent.loop import _should_continue_for_resolve

    run = _run_stub(stop_reason="max_turns_reached")
    assert (
        _should_continue_for_resolve(run, _state_cascade_skip(), 0, 0.1, 2.5) is False
    )


# ── build-engagement gate (2026-05-31, intervention #1) ─────────────────────
# Generalizes force-resolve from the no_image/no-image_resolve cascade-skip to:
# "never honor a non-proprietary pre-build give-up until an actual BUILD tool
# (docker_build/dockerfile_gen/source_build) was attempted." Data: 99% of
# corpus wins reach a build tool vs 30% of losses; 19 'resolve-only' losses in
# bench50-20260531-183716 called image_resolve (not_found) then gave up WITHOUT
# pivoting to source_build. image_resolve alone is NOT a build.


def _state_giveup(reason: str, tool_names: list[str]) -> Any:
    """A _StreamState post-give_up with an explicit reason + tool-use set."""
    from cve_env.agent.loop import _StreamState

    st = _StreamState()
    st.give_up_reason = reason
    st.tool_uses_seen = [{"name": n} for n in tool_names]
    return st


def test_force_resolve_gate_fires_on_no_image_without_build() -> None:
    """give_up(no_image) after image_resolve returned not_found but WITHOUT a
    build pivot (source_build/dockerfile_gen) is a resolve-only cascade-skip —
    the gate must fire to force a build attempt."""
    from cve_env.agent.loop import _should_continue_for_resolve

    st = _state_giveup("no_image", ["nvd_lookup", "image_resolve", "give_up"])
    assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is True


def test_force_resolve_gate_fires_on_unresolvable_metadata_without_build() -> None:
    from cve_env.agent.loop import _should_continue_for_resolve

    st = _state_giveup("unresolvable_metadata", ["nvd_lookup", "give_up"])
    assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is True


def test_force_resolve_gate_skips_when_build_attempted() -> None:
    """If ANY real build tool was attempted, the agent engaged the cascade —
    do NOT force again (the 10/16 no_image that cascaded to source_build)."""
    from cve_env.agent.loop import _should_continue_for_resolve

    for tool in ("source_build", "dockerfile_gen", "docker_build"):
        st = _state_giveup("no_image", ["nvd_lookup", "image_resolve", tool, "give_up"])
        assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is False, tool


def test_force_resolve_gate_skips_proprietary_and_arch() -> None:
    """The critical guard: proprietary (closed-source, genuinely unbuildable),
    arch_incompatible (host-limited), and budget are NOT eligible — never force
    a build. Protects the ~53%-proprietary corpus slice from wasted compute."""
    from cve_env.agent.loop import _should_continue_for_resolve

    for reason in ("proprietary", "arch_incompatible", "budget"):
        st = _state_giveup(reason, ["nvd_lookup", "give_up"])
        assert _should_continue_for_resolve(_run_stub(), st, 0, 0.1, 2.5) is False, (
            reason
        )


def _sequenced_giveup_aware_factory(message_batches: list[list[Any]]):
    """Sequenced fake that ALSO catches GiveUpReceived → end_turn (mirrors the
    real _run_query_once, unlike _sequenced_run_agent_factory). session_id comes
    from the last ResultMessage seen before the give_up, or '' if none."""
    from cve_env.agent.llm import BudgetCapExceeded, GiveUpReceived, TurnCapReached

    calls: list[dict[str, Any]] = []
    iterator = iter(message_batches)

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
        batch = next(iterator)
        calls.append({"user_prompt": user_prompt, "resume": resume})
        result_msg = None
        early: str | None = None
        try:
            for m in batch:
                if on_message is not None:
                    on_message(m)
                if type(m).__name__ == "ResultMessage":
                    result_msg = m
        except GiveUpReceived:
            early = "end_turn"
        except TurnCapReached:
            early = "max_turns_reached"
        except BudgetCapExceeded:
            early = "budget_exceeded"
        if result_msg is None and early is None:
            result_msg = _result("end_turn")
            if on_message is not None:
                on_message(result_msg)
        return AgentRunOutcome(
            stop_reason=early or (result_msg.stop_reason if result_msg else ""),
            num_turns=result_msg.num_turns if result_msg else 0,
            total_cost_usd=(result_msg.total_cost_usd or 0.0) if result_msg else 0.0,
            is_error=False,
            session_id=result_msg.session_id if result_msg else "",
            final_text="",
            tool_uses=[],
        )

    return fake_run_agent, calls


def _assistant_sid(*blocks: Any, sid: str = "sess-1") -> Any:
    """AssistantMessage carrying a session_id (the real SDK sets it on every
    AssistantMessage). ``_assistant`` omits it — but force-resolve resumes from
    the session id captured off streaming AssistantMessages (run.session_id is
    empty for give_up runs), so the integration tests must carry one to model
    production faithfully."""
    from claude_agent_sdk import AssistantMessage

    return AssistantMessage(
        content=list(blocks),
        model="claude-opus-4-7",
        parent_tool_use_id=None,
        session_id=sid,
    )


def test_force_resolve_fires_on_cascade_skip_giveup(tmp_path: Path) -> None:
    """Integration: give_up(no_image) without image_resolve → force-resolve
    continuation fires (2nd run_agent call, resume threaded with the
    FORCE_RESOLVE_CONTINUATION_PROMPT). The give_up batch has NO ResultMessage
    before the give_up (as in production — the terminal ResultMessage arrives
    only at query END, after the give_up raises), so run.session_id is empty and
    resume MUST use the session id captured from the streamed AssistantMessages.
    (The 2026-05-31 smoke caught this: an early ResultMessage masked the gap.)"""
    from cve_env.agent.prompts import FORCE_RESOLVE_CONTINUATION_PROMPT

    first_batch = [
        _assistant_sid(
            _tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"cpe": "a:b:c"})),  # no proprietary_vendor_hint
        _assistant_sid(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "no_image", "detail": "no image"},
            )
        ),
        _user(
            _tool_result(
                "tu2", {"terminal": True, "reason": "no_image", "detail": "no image"}
            )
        ),
        # NO ResultMessage — give_up raises mid-stream → run.session_id == "".
    ]
    second_batch = [
        _assistant_sid(
            _tool_use(
                "ir", "mcp__cve_env__image_resolve", {"product": "p", "version": "v"}
            )
        ),
        _user(_tool_result("ir", {"ok": True, "digest_pinned_ref": "r@sha256:1"})),
        _assistant_sid(_tool_use("vf", "mcp__cve_env__verify", {"container_id": "c"})),
        _user(_tool_result("vf", {"passed": True, "results": [], "reason": None})),
        _result("end_turn", cost_usd=0.04, turns=3),
    ]
    fake, calls = _sequenced_giveup_aware_factory([first_batch, second_batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fr-fire", audit_root=tmp_path)
        )
    assert len(calls) == 2, f"expected a force-resolve continuation; calls={len(calls)}"
    assert (
        calls[1]["resume"] == "sess-1"
    )  # resumed via the CAPTURED session id, not run.session_id
    assert calls[1]["user_prompt"] == FORCE_RESOLVE_CONTINUATION_PROMPT
    assert outcome.verify_passed is True


def test_force_resolve_restores_giveup_on_no_improvement(tmp_path: Path) -> None:
    """FLAW-2: if the continuation resolves to not_found and end_turns without a
    build, the original give_up must be RESTORED so the status stays an
    unresolvable/give-up class — NOT relabeled verify_failed/research-only."""
    first_batch = [
        _assistant_sid(
            _tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu1", {"cpe": "a:b:c"})),
        _assistant_sid(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "no_image", "detail": "no image"},
            )
        ),
        _user(
            _tool_result(
                "tu2", {"terminal": True, "reason": "no_image", "detail": "no image"}
            )
        ),
    ]
    # Continuation: agent calls image_resolve (not_found, ok=False) then just end_turns.
    second_batch = [
        _assistant_sid(
            _tool_use(
                "ir", "mcp__cve_env__image_resolve", {"product": "p", "version": "v"}
            )
        ),
        _user(_tool_result("ir", {"ok": False, "decision": "not_found"})),
        _assistant_sid(_text_block("No image and no build path.")),
        _result("end_turn", cost_usd=0.03, turns=2),
    ]
    fake, calls = _sequenced_giveup_aware_factory([first_batch, second_batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fr-restore", audit_root=tmp_path)
        )
    assert len(calls) == 2  # continuation fired
    assert outcome.verify_passed is False
    # give_up was restored → unresolvable-class, NOT verify_failed/research-only.
    assert outcome.status != "verify_failed", (
        f"give_up_reason not restored; status={outcome.status}"
    )
    assert outcome.status in ("unresolvable", "incomplete"), (
        f"unexpected status={outcome.status}"
    )


def test_force_resolve_does_not_fire_on_proprietary_giveup(tmp_path: Path) -> None:
    """A proprietary give_up (reason='proprietary') is never relabeled to
    skipped_image_lookup → force-resolve must NOT fire (single run), even though
    a session id was captured."""
    batch = [
        _assistant_sid(
            _tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})
        ),
        _user(
            _tool_result(
                "tu1", {"cpe": "a:b:c", "proprietary_vendor_hint": "closed-source"}
            )
        ),
        _assistant_sid(
            _tool_use(
                "tu2",
                "mcp__cve_env__give_up",
                {"reason": "proprietary", "detail": "closed-source vendor"},
            )
        ),
        _user(
            _tool_result(
                "tu2",
                {
                    "terminal": True,
                    "reason": "proprietary",
                    "detail": "closed-source vendor",
                },
            )
        ),
    ]
    fake, calls = _sequenced_giveup_aware_factory([batch])
    with patch("cve_env.agent.loop.run_agent", fake):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="fr-prop", audit_root=tmp_path)
        )
    assert len(calls) == 1, (
        f"force-resolve wrongly fired on proprietary; calls={len(calls)}"
    )
    assert outcome.status in ("unresolvable", "incomplete")


# ── verify-phase refusal salvage (2026-06-01, intervention #1a) ─────────────
# Forensic (bench50-20260601): all 8 AUP refusals fired POST-launch (during
# verify against the live vuln), and the env was already built/launched. The
# old mapping lost the non-cap ones to the least-informative `interrupted`.
# Salvage (#1a): refusal + (launched_ok or docker_built_ok) + NOT verify_passed
# + NOT a current cap signal → the env IS up → 'launched_no_verify' (honest
# partial), not total-loss.
#
# SCOPE — two exclusions keep established invariants intact, each guarded below:
#   - NOT verify_passed → never touches Phase-44.1/46.1 (refusal-after-verify-
#     pass → interrupted).
#   - NOT cap-signal (budget/max_turns/turn_cap in the CURRENT stop_reason) →
#     budget keeps BUG-007 (budget_exhausted) and max_turns keeps BUG-008 +
#     B-TURN-CAP-AFTER-LAUNCH-4 (turn_cap, REGARDLESS). The cap is a hard
#     resource fact the operator must see; launched-ness is already surfaced via
#     the stuck_after_launch reason marker. The refusal→turn_cap spin (3/8) is
#     left to the agentic #1b benign-verify continuation (prevent, not relabel).


def _state_refused_launched() -> Any:
    from cve_env.agent.loop import _StreamState

    st = _StreamState()
    st.refusal_stop_reason_seen = True
    st.launched_ok = True
    st.verify_passed = False
    return st


def test_map_status_salvages_refused_launched_end_turn() -> None:
    from cve_env.agent.loop import _map_status

    status, _ = _map_status("end_turn", _state_refused_launched())
    assert status == "launched_no_verify"


def test_map_status_refused_launched_max_turns_stays_turn_cap() -> None:
    """GUARD (BUG-008 / B-TURN-CAP-AFTER-LAUNCH-4): a CURRENT max_turns cap
    signal wins over the salvage — refused+launched+!verify+max_turns is
    turn_cap (cap is a hard fact), NOT launched_no_verify. The salvage must
    not weaken the established cap-priority invariant."""
    from cve_env.agent.loop import _map_status

    status, _ = _map_status("max_turns_reached", _state_refused_launched())
    assert status == "turn_cap"


def test_map_status_refused_launched_budget_stays_budget_exhausted() -> None:
    """GUARD (BUG-007): a CURRENT budget cap signal wins over the salvage —
    refused+launched+!verify+budget is budget_exhausted, NOT launched_no_verify.
    bug007's replay fixture (deleted in the 2026-06-01 nuke) left launched_ok
    unset and so never exercised this launched+budget path; this unit guard
    covers it directly so the salvage can't silently regress BUG-007."""
    from cve_env.agent.loop import _map_status

    status, _ = _map_status("budget_exceeded", _state_refused_launched())
    assert status == "budget_exhausted"


def test_map_status_salvages_terminal_refusal_when_launched() -> None:
    from cve_env.agent.loop import _map_status, _StreamState

    st = _StreamState()
    st.launched_ok = True
    st.verify_passed = False
    status, _ = _map_status("refusal", st)
    assert status == "launched_no_verify"


def test_map_status_salvages_docker_built_too() -> None:
    from cve_env.agent.loop import _map_status, _StreamState

    st = _StreamState()
    st.refusal_stop_reason_seen = True
    st.docker_built_ok = True  # built but not launched
    st.verify_passed = False
    status, _ = _map_status("end_turn", st)
    assert status == "launched_no_verify"


def test_map_status_refused_not_launched_still_interrupted() -> None:
    """Guard: a refusal with NO build/launch is still interrupted (not salvaged)."""
    from cve_env.agent.loop import _map_status, _StreamState

    st = _StreamState()
    st.refusal_stop_reason_seen = True
    st.launched_ok = False
    st.docker_built_ok = False
    st.verify_passed = False
    status, _ = _map_status("end_turn", st)
    assert status == "interrupted"


def test_map_status_refused_verify_passed_unchanged() -> None:
    """Guard: verify_passed + refusal stays interrupted (Phase 44.1 — refusal
    corrupted the post-verify state); salvage requires NOT verify_passed."""
    from cve_env.agent.loop import _map_status

    st = _state_refused_launched()
    st.verify_passed = True
    status, _ = _map_status("refusal", st)
    assert status == "interrupted"


def test_terminal_status_salvages_refused_launched() -> None:
    """Audit-side consistency: refused+launched+!verify with a NON-cap
    stop_reason → final_no_verify (mirrors the _map_status salvage)."""
    from cve_env.agent.loop import _terminal_status_for_result

    assert (
        _terminal_status_for_result(_state_refused_launched(), "end_turn")
        == "final_no_verify"
    )


def test_terminal_status_refused_launched_max_turns_stays_turn_cap() -> None:
    """GUARD: the terminal salvage also excludes cap signals — refused+launched
    +max_turns → final_turn_cap (BUG-008 audit/outcome consistency)."""
    from cve_env.agent.loop import _terminal_status_for_result

    assert (
        _terminal_status_for_result(_state_refused_launched(), "max_turns_reached")
        == "final_turn_cap"
    )


# ── #1b: agentic benign-verify continuation gate (2026-06-01, default-off) ──
# Complements #1a's structural launched_no_verify floor: when a POST-LAUNCH
# refusal blocked verify (env up, verify never reached), RESUME the session
# with a benign-only verify prompt — an agentic recovery that can convert
# refused→verified (vs #1a which only relabels the loss honestly). Env-gated
# default-off; promote on bench A/B (M-rule, like the force-resolve dials).

ENV_BV = "CVE_ENV_ENABLE_BENIGN_VERIFY_CONTINUATION"


def _state_post_launch_refusal() -> Any:
    from cve_env.agent.loop import _StreamState

    st = _StreamState()
    st.refusal_stop_reason_seen = True
    st.launched_ok = True
    st.verify_passed = False
    st.verify_attempted = False
    st.last_session_id = "sess-resume"
    return st


def test_benign_verify_config_defaults_off() -> None:
    from cve_env import config

    assert config.get_enable_benign_verify_continuation() is False
    assert config.get_benign_verify_continuation_max() == 1


def test_benign_verify_config_env_enables(monkeypatch: Any) -> None:
    from cve_env import config

    monkeypatch.setenv(ENV_BV, "1")
    assert config.get_enable_benign_verify_continuation() is True
    monkeypatch.setenv("CVE_ENV_BENIGN_VERIFY_CONTINUATION_MAX", "2")
    assert config.get_benign_verify_continuation_max() == 2


def test_benign_verify_gate_off_by_default() -> None:
    """Default-off: even a textbook post-launch refusal does NOT fire (M)."""
    from cve_env.agent.loop import _should_continue_for_post_launch_refusal

    assert (
        _should_continue_for_post_launch_refusal(
            _run_stub(stop_reason="refusal"),
            _state_post_launch_refusal(),
            0,
            0.1,
            2.5,
        )
        is False
    )


def test_benign_verify_gate_fires_when_enabled(monkeypatch: Any) -> None:
    """A terminal refusal AND a latched-refusal+end_turn both qualify (env up,
    verify never reached) — the post-launch refusal is exactly what blocked it."""
    monkeypatch.setenv(ENV_BV, "1")
    from cve_env.agent.loop import _should_continue_for_post_launch_refusal

    for sr in ("refusal", "end_turn"):
        assert (
            _should_continue_for_post_launch_refusal(
                _run_stub(stop_reason=sr), _state_post_launch_refusal(), 0, 0.1, 2.5
            )
            is True
        ), sr


def test_benign_verify_gate_requires_refusal_launched_no_verify(
    monkeypatch: Any,
) -> None:
    monkeypatch.setenv(ENV_BV, "1")
    from cve_env.agent.loop import _should_continue_for_post_launch_refusal

    g = _should_continue_for_post_launch_refusal
    # no refusal → no fire
    st = _state_post_launch_refusal()
    st.refusal_stop_reason_seen = False
    assert g(_run_stub(), st, 0, 0.1, 2.5) is False
    # not launched → no fire (can't benign-verify an env that isn't up)
    st = _state_post_launch_refusal()
    st.launched_ok = False
    assert g(_run_stub(), st, 0, 0.1, 2.5) is False
    # verify already attempted → no fire (refusal didn't block verify-start)
    st = _state_post_launch_refusal()
    st.verify_attempted = True
    assert g(_run_stub(), st, 0, 0.1, 2.5) is False
    # verify passed → no fire
    st = _state_post_launch_refusal()
    st.verify_passed = True
    assert g(_run_stub(), st, 0, 0.1, 2.5) is False


def test_benign_verify_gate_bounds(monkeypatch: Any) -> None:
    monkeypatch.setenv(ENV_BV, "1")
    from cve_env.agent.loop import _should_continue_for_post_launch_refusal

    g = _should_continue_for_post_launch_refusal
    # count at the default max (1) → no fire
    assert g(_run_stub(), _state_post_launch_refusal(), 1, 0.1, 2.5) is False
    # cost at/over 85% of cap → no fire
    assert g(_run_stub(), _state_post_launch_refusal(), 0, 0.85 * 2.5, 2.5) is False
    # MAX=0 disables entirely
    monkeypatch.setenv("CVE_ENV_BENIGN_VERIFY_CONTINUATION_MAX", "0")
    assert g(_run_stub(), _state_post_launch_refusal(), 0, 0.1, 2.5) is False


def test_benign_verify_gate_requires_resumable_session(monkeypatch: Any) -> None:
    monkeypatch.setenv(ENV_BV, "1")
    from cve_env.agent.loop import _should_continue_for_post_launch_refusal

    st = _state_post_launch_refusal()
    st.last_session_id = ""
    # both session ids empty → not resumable → no fire
    assert (
        _should_continue_for_post_launch_refusal(
            _run_stub(session_id=""), st, 0, 0.1, 2.5
        )
        is False
    )
    # run.session_id present → resumable → fires
    assert (
        _should_continue_for_post_launch_refusal(
            _run_stub(session_id="sess-x"), st, 0, 0.1, 2.5
        )
        is True
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
