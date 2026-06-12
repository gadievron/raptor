"""Phase 54-deep.1 RED tests for the post-build refusal classifier.

Cand 1 from Phase 53-inv (commit 12c10f0): when an Anthropic-policy
refusal exception fires AFTER a successful build (state.launched_ok=True),
emit a NEW audit-row kind ``post_build_refusal`` so downstream forensic
can distinguish post-build refusals (verify-plan attack-language tripped
the safety classifier) from research-phase refusals (NVD-description
trigger).

Paired with prompts.py open-clause rule (separate commit) per
past-bench-lessons §1 #1 (never prompt-only for agent-behavior-under-
uncertainty; runtime classifier ships first, then prompt rule).

TDD discipline per Phase 35 / Phase 51B / Phase 53-impl.1.1 precedent:
xfail(strict=True) at RED, atomic removal at GREEN.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from cve_env.agent.audit import AuditEntry, AuditStatus, AuditWriter


def test_audit_status_includes_post_build_refusal() -> None:
    """The AuditStatus Literal must include "post_build_refusal" so the writer
    accepts it without falling back to a generic kind."""
    import typing

    args = typing.get_args(AuditStatus)
    assert "post_build_refusal" in args, (
        f"AuditStatus = {args}; missing post_build_refusal"
    )


def test_audit_writer_round_trips_post_build_refusal(tmp_path: Path) -> None:
    """AuditWriter.write must accept entries with status='post_build_refusal'
    and round-trip them via read.

    Regression-lock: the writer is permissive at runtime (no Literal
    enforcement), so this passes immediately. The TYPE-system guard is
    test_audit_status_includes_post_build_refusal (xfail until GREEN).
    """
    writer = AuditWriter(run_id="phase54-deep-1", root=tmp_path)
    entry = AuditEntry(
        turn=42,
        status="post_build_refusal",  # type: ignore[arg-type]
        reason="SDK terminated with refusal exception after launched_ok=True",
    )
    writer.write(cve_id="CVE-TEST-0001", entry=entry)

    entries = writer.read(cve_id="CVE-TEST-0001")
    assert len(entries) == 1
    assert entries[0]["status"] == "post_build_refusal"
    assert entries[0]["turn"] == 42
    assert "launched_ok=True" in entries[0]["reason"]


def test_loop_exception_handler_wires_post_build_refusal() -> None:
    """The loop.py refusal-exception branch (around the existing
    ``is_refusal_exc`` check) must emit a post_build_refusal audit entry
    when state.launched_ok=True before falling through to the existing
    'interrupted' terminal-status mapping.

    Source-inspection test: look for the post_build_refusal emission
    in the exception-handler region, paired with a launched_ok guard
    within 500 chars (proximity heuristic — proves the conditional is
    wired, not just a stray string).
    """
    import inspect

    from cve_env.agent import loop as loop_module

    src = inspect.getsource(loop_module)
    assert "post_build_refusal" in src, (
        "loop.py does not reference post_build_refusal anywhere"
    )
    idx = src.find("post_build_refusal")
    # launched_ok is the load-bearing guard — must be in the same conditional
    # block (500 chars upward covers the if-branch).
    window_up = src[max(0, idx - 500) : idx]
    assert "launched_ok" in window_up, (
        "post_build_refusal emission missing launched_ok guard within 500 chars upstream"
    )
    # Refusal co-location: looser proximity (1500 chars) since the
    # comment block + writer.write structure pushes apart.
    window_wide = src[max(0, idx - 1500) : idx]
    assert "is_refusal" in window_wide or "_is_refusal" in window_wide, (
        "post_build_refusal emission not co-located with refusal classification (1500 char window)"
    )


def test_prompts_contains_verify_plan_composition_rule() -> None:
    """prompts.py SYSTEM_PROMPT must contain an open-clause rule (post-Phase-41
    chain) directing the agent to compose verify-plan in build-functional
    terms (HTTP GET / container running / binary at path) OR equivalent
    functional checks; avoiding concrete attack-pattern descriptions.

    Per past-bench-lessons §N (no static lookup tables): the rule must NOT
    be a per-attack-type cookbook. It must use open-clause language.
    """
    from cve_env.agent.prompts import SYSTEM_PROMPT

    # Marker phrases proving the open-clause shape (not a static table).
    # Lower-cased substring match for resilience to formatting tweaks.
    sp_lower = SYSTEM_PROMPT.lower()
    # Must mention build-functional framing
    assert (
        "build-functional" in sp_lower or "functional check" in sp_lower
    ), "verify-plan composition rule missing build-functional framing"
    # Must contain an "OR equivalent" / "or ecosystem-appropriate" open clause
    assert (
        "or equivalent" in sp_lower or "or ecosystem-appropriate" in sp_lower
    ), "verify-plan composition rule missing open-clause language"
    # Must explicitly warn against attack-pattern descriptions
    assert (
        "attack-pattern" in sp_lower or "attack pattern" in sp_lower
    ), "verify-plan composition rule missing attack-pattern warning"


# ============================================================================
# Behavioral end-to-end test (Phase 54-deep.S.A.2 F-03 fix)
#
# Pass A surfaced that the exception-handler emission has NO behavioral
# test — only source-inspection (test_loop_exception_handler_wires_*).
# This test drives build() with a fake run_agent that simulates the
# Shellshock-like Anthropic-policy refusal AFTER state.launched_ok=True
# (achieved via on_message of a docker_run.ok=true tool_result), then
# reads the audit JSONL and asserts a post_build_refusal entry was
# written.
# ============================================================================


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
    return AssistantMessage(content=list(blocks), model="claude-opus-4-7", parent_tool_use_id=None)


def _user(*blocks: Any) -> Any:
    from claude_agent_sdk import UserMessage
    return UserMessage(content=list(blocks), parent_tool_use_id=None)


def _cve() -> Any:
    from cve_env.models import CveRecord
    return CveRecord(
        cve_id="CVE-TEST-POSTBUILDREFUSAL",
        product="testproduct",
        version="1.0.0",
        description="Test fixture for Phase 54-deep.1 behavioral assertion",
    )


def _host() -> Any:
    from cve_env.models import HostInfo
    return HostInfo(arch="arm64", os="darwin", rosetta_available=True)


def test_post_build_refusal_audit_entry_emitted_when_launched_ok_then_refusal(
    tmp_path: Path,
) -> None:
    """Phase 54-deep.1 behavioral end-to-end:

    Drive build() with a fake run_agent that:
    1. Sends an AssistantMessage+UserMessage pair simulating a successful
       docker_run.ok=True tool_result → state.launched_ok flips to True
       via the on_message handler.
    2. Raises a refusal-class exception (str() matches _REFUSAL_SIGNATURES)
       to simulate Anthropic's safety classifier tripping post-launch.

    The loop.py exception handler must emit an AuditEntry with
    status='post_build_refusal' BEFORE the terminal 'interrupted'
    mapping. Verify by reading the audit JSONL and finding the entry.
    """
    from cve_env.agent.loop import build

    msgs = [
        _assistant(_tool_use("tu1", "mcp__cve_env__docker_run", {"image": "test"})),
        _user(_tool_result("tu1", {"ok": True, "container_id": "c1"})),
        _assistant(_text_block("Now verifying...")),
    ]

    async def fake_run_agent_with_refusal(
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
    ) -> Any:
        # Drive the canned messages first so state.launched_ok flips True.
        if on_message is not None:
            for m in msgs:
                on_message(m)
        # Then raise an exception that _is_refusal will classify as refusal.
        # _REFUSAL_SIGNATURES includes "Claude Code is unable to respond"
        # (canonical Anthropic policy refusal signature).
        raise RuntimeError(
            "Claude Code is unable to respond to this request due to policy."
        )

    with patch("cve_env.agent.loop.run_agent", fake_run_agent_with_refusal):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="phase54-deep-postbuildrefusal",
                audit_root=tmp_path,
            )
        )

    # Terminal status should be "interrupted" per Phase 44.1 refusal mapping.
    assert outcome.status == "interrupted", (
        f"refusal exception should map to interrupted; got: {outcome.status!r}"
    )

    # Find the audit JSONL for this CVE.
    assert outcome.audit_path is not None
    audit_dir = Path(outcome.audit_path).parent
    audit_files = list(audit_dir.glob("CVE-TEST-POSTBUILDREFUSAL.jsonl"))
    assert audit_files, f"no audit JSONL found in {audit_dir}"

    # Scan the audit JSONL for a post_build_refusal entry.
    found_post_build_refusal = False
    with open(audit_files[0]) as fh:
        for line in fh:
            entry = json.loads(line)
            if entry.get("status") == "post_build_refusal":
                found_post_build_refusal = True
                # The reason field cites launched_ok=True
                assert "launched_ok=True" in entry.get("reason", ""), (
                    f"post_build_refusal reason missing launched_ok=True; "
                    f"got: {entry.get('reason')!r}"
                )
                break

    assert found_post_build_refusal, (
        f"post_build_refusal audit entry NOT found in {audit_files[0]}. "
        f"Phase 54-deep.1 exception-handler wiring is broken."
    )


def test_post_build_refusal_NOT_emitted_when_launched_ok_false(
    tmp_path: Path,
) -> None:
    """Regression-guard: refusal BEFORE any tool launch (launched_ok=False)
    must NOT emit post_build_refusal. The marker is specific to the
    post-build case, not generic research-phase refusals."""
    from cve_env.agent.loop import build

    async def fake_run_agent_pre_launch_refusal(
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
    ) -> Any:
        # No messages → launched_ok stays False
        raise RuntimeError(
            "Claude Code is unable to respond to this request."
        )

    with patch("cve_env.agent.loop.run_agent", fake_run_agent_pre_launch_refusal):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="phase54-deep-prelaunchrefusal",
                audit_root=tmp_path,
            )
        )

    assert outcome.status == "interrupted"

    # post_build_refusal MUST NOT appear. When fake run_agent raises before
    # any on_message call, the audit writer may have written zero entries
    # (no JSONL file). Either way, post_build_refusal must be absent.
    if outcome.audit_path is not None:
        audit_dir = Path(outcome.audit_path).parent
        for audit_file in audit_dir.glob("CVE-TEST-POSTBUILDREFUSAL.jsonl"):
            with open(audit_file) as fh:
                for line in fh:
                    entry = json.loads(line)
                    assert entry.get("status") != "post_build_refusal", (
                        f"post_build_refusal emitted with launched_ok=False; "
                        f"entry: {entry}"
                    )
