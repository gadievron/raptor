"""RED tests for bench200 bugs F-9, F-10, F-12 (planned fixes 2026-05-05).

These tests are designed to FAIL at HEAD and PASS after the planned fixes
in docs/bug-fix-plan-2026-05-05.md are applied. Each test name encodes the
bug it covers (F-XX) and the specific behaviour the fix must guarantee.

Tests run safely while the bench is in flight: they mock cve_env.agent.loop.run_agent
and never touch the running runtime.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cve_env.agent.llm import AgentRunOutcome
from cve_env.agent.loop import build
from cve_env.models import CveRecord, HostInfo

# ----- shared helpers (copied from test_loop.py to keep this file self-contained) -----
# SDK message helpers -- intentionally duplicated per FORBIDDEN-K. Keep
# defaults aligned with test_loop.py canonical copy.

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
    TurnCapReached from on_message and synthesizes an outcome (matches
    the catch site in src/cve_env/agent/llm.py).
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

# =============================================================================
# F-12 — SDK retry storm consumes cost past max_cost_usd cap
# =============================================================================
# Bug history: original plan was to integrate src/cve_env/agent/budget.py
# (a Budget class with charge() enforcement) into loop.py. That module was
# never wired up and was deleted as dead code in 2026-05-07c. The SDK retry
# loop in llm.py:227-291 retried on Exception without checking accumulated
# cost. Evidence: CVE-2022-32101 (bench200 26866) — total_cost_usd=$3.90
# vs cap=$1.50. Fix landed: accumulated cost-cap check at loop.py:958 +
# budget_exhausted mapping at loop.py:1068 (no Budget class needed).

def test_F12_retry_storm_does_not_exceed_cost_cap(tmp_path: Path) -> None:
    """RED: when SDK emits multiple ResultMessages whose costs sum past the
    max_cost_usd cap (real-world: SDK retried on transient and the per-attempt
    costs accumulate), build() must NOT report a total_cost_usd above the cap.

    Either:
      (a) outcome.total_cost_usd ≤ max_cost_usd (cap enforced), OR
      (b) outcome.status == "budget_exhausted" (early termination)

    HEAD will FAIL because state.last_cost_usd just sums per-segment costs
    without comparing against the cap (loop.py:595).
    """
    # 3 ResultMessages — each individually under $1.50 cap, total $3.90 (matches
    # observed F-12 case CVE-2022-32101).
    messages = [
        _result("end_turn", cost_usd=1.40),
        _result("end_turn", cost_usd=1.40),
        _result("end_turn", cost_usd=1.10),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F12-retry-storm",
                audit_root=tmp_path,
                max_cost_usd=1.50,
            )
        )
    assert outcome.total_cost_usd <= 1.50 or outcome.status == "budget_exhausted", (
        f"F-12 not fixed: total_cost_usd={outcome.total_cost_usd:.2f} "
        f"exceeded cap=$1.50 with status={outcome.status!r} "
        f"(reason={outcome.reason!r})"
    )

def test_F12_single_oversized_result_capped_or_flagged(tmp_path: Path) -> None:
    """RED: edge case where a single ResultMessage reports cost > cap.
    The loop must detect this and not silently report cost > cap as 'success'.
    """
    messages = [
        _assistant(
            _tool_use(
                "tu-v", "mcp__cve_env__verify", {"plan": [{"type": "container_status"}]}
            )
        ),
        _user(
            _tool_result(
                "tu-v",
                {
                    "passed": True,
                    "results": [{"type": "container_status", "passed": True}],
                },
            )
        ),
        _result("end_turn", cost_usd=3.90),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F12-oversized",
                audit_root=tmp_path,
                max_cost_usd=1.50,
            )
        )
    # If verify passed AND cost was capped properly, status="success".
    # If we want flagging, status must be "budget_exhausted" or include a warning.
    # At minimum: total_cost_usd should not silently report 3.90 with success status.
    if outcome.status == "success":
        assert outcome.total_cost_usd <= 1.50, (
            f"F-12 not fixed: success+cost-overrun reported "
            f"(cost={outcome.total_cost_usd:.2f}, cap=$1.50)"
        )

# =============================================================================
# F-13 — give_up tool called but agent doesn't terminate
# (renamed from "F-10" 09:13Z per canonical catalog reconciliation;
# 26866's F-10 = source-build no_verify owns the F-10 label)
# =============================================================================
# Bug: loop.py:495-498 sets state.give_up_reason but does NOT halt the SDK
# iterator. The on_message callback is purely observational; the SDK's query()
# keeps streaming until it emits a ResultMessage on its own.
# Evidence: CVE-2024-1677 (bench200 mine) — give_up at T83, agent continued
# to T168 (85 more tool calls).
# Fix: raise a custom GiveUpReceived exception inside on_message after
# state.give_up_reason is set; catch in run_agent's outer scope; treat as
# clean termination.

def test_F13_give_up_halts_subsequent_tool_calls(tmp_path: Path) -> None:
    """RED: when the agent calls give_up.terminal=True, subsequent tool calls
    in the same conversation must NOT be processed. The audit log should show
    the run terminating at the give_up turn, not 50 turns later.

    HEAD will FAIL because the loop continues processing every queued message.
    """
    # Sequence: give_up at turn-marker tu-give, then 50 more tool calls
    # (simulating the SDK stream not honoring the terminal signal).
    extra_tool_calls: list[Any] = []
    for i in range(50):
        extra_tool_calls.append(
            _assistant(_tool_use(f"tu-extra-{i}", "Bash", {"command": "echo nope"}))
        )
        extra_tool_calls.append(
            _user(_tool_result(f"tu-extra-{i}", {"stdout": "nope", "exit_code": 0}))
        )
    messages = [
        _assistant(
            _tool_use(
                "tu-give",
                "mcp__cve_env__give_up",
                {"reason": "budget", "detail": "out of money"},
            )
        ),
        _user(
            _tool_result(
                "tu-give",
                {"terminal": True, "reason": "budget", "detail": "out of money"},
            )
        ),
        *extra_tool_calls,
        _result("end_turn"),
    ]
    _audit_log_path = tmp_path / "audit-F10.jsonl"
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F10-halt",
                audit_root=tmp_path,
            )
        )
    # Outcome should still be unresolvable (give_up was called).
    assert outcome.status == "unresolvable", (
        f"F-10 baseline: outcome.status should be 'unresolvable', got {outcome.status!r}"
    )
    # KEY ASSERTION: the audit log must NOT contain tools called AFTER give_up.
    # If F-10 is unfixed, we'll see 50 'tu-extra-N' tool entries in the audit.
    audit_files = list(tmp_path.glob("**/*.jsonl"))
    extra_tool_names_in_audit: list[str] = []
    for af in audit_files:
        for line in af.read_text().splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            tn = entry.get("tool_name") or ""
            # Bash tool call after give_up = bug
            if entry.get("turn", 0) > 1 and tn == "Bash":
                extra_tool_names_in_audit.append(tn)
    assert len(extra_tool_names_in_audit) == 0, (
        f"F-10 not fixed: {len(extra_tool_names_in_audit)} Bash tool calls "
        f"appeared in audit AFTER give_up.terminal=True. The loop should have "
        f"halted at give_up turn but processed all subsequent messages."
    )

# =============================================================================
# F-9 — agent loops past max_turns; SIGALRM kills at 1200s
# =============================================================================
# Bug: max_turns is passed to ClaudeAgentOptions(max_turns=...) at llm.py:241.
# The SDK is supposed to enforce server-side, but evidence shows agents reach
# T186+ when nominal max_turns=80.
# loop.py on_message callback (line 401-525) only observes; never enforces
# locally.
# Evidence: 15 confirmed F-9 instances (bench200 mine + 26866). All audit
# files show tool calls past T80; bench script's 1200s wall is the actual cap.
# Fix: defensive runtime turn-cap check inside on_message: if state.turn >=
# max_turns, raise TurnCapReached; catch in run_agent's outer scope; map to
# status="turn_cap".

def test_F9_runtime_turn_cap_enforced_when_sdk_does_not_emit(tmp_path: Path) -> None:
    """RED: when the SDK emits assistant messages past max_turns without ever
    emitting a ResultMessage with stop_reason='max_turns_reached' (the actual
    F-9 case — SDK silently ignores its own cap), build() must enforce the
    cap LOCALLY and return outcome.status='turn_cap'.

    HEAD will FAIL: the loop processes all 30 emitted assistant messages and
    waits for a ResultMessage that never identifies the cap.
    """
    # max_turns=10; emit 30 tool-using assistant messages, then a final
    # ResultMessage with stop_reason='end_turn' (not 'max_turns_reached').
    # Simulates SDK ignoring its own max_turns parameter.
    messages: list[Any] = []
    for i in range(30):
        messages.append(
            _assistant(_tool_use(f"tu-{i}", "Bash", {"command": f"echo {i}"}))
        )
        messages.append(
            _user(_tool_result(f"tu-{i}", {"stdout": str(i), "exit_code": 0}))
        )
    messages.append(_result("end_turn"))

    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F9-runtime-cap",
                audit_root=tmp_path,
                max_turns=10,
            )
        )
    # If F-9 is fixed: status should be 'turn_cap' once the loop has seen
    # 10 turn-incrementing events.
    assert outcome.status == "turn_cap", (
        f"F-9 not fixed: status should be 'turn_cap' (local enforcement at "
        f"max_turns=10), got {outcome.status!r} after processing 30 tool calls"
    )

# =============================================================================
# F-11 — docker_build failure → end_turn classified as generic "verify_failed"
# =============================================================================
# Bug: loop.py:349-350 catches ALL end_turn-without-verify as "verify_failed".
# Distinct sub-pattern: agent attempted Docker build, it failed (transport),
# agent emitted end_turn without calling give_up. Currently indistinguishable
# from research-only dead-end.
# Evidence: 26866's bench classified 3 cases (CVE-2022-21165, -24803, -31313)
# with this pattern; previously misclassified as F-7.
# Fix: track tool categories in state; if docker_build was attempted AND no
# verify, emit distinct status like "build_failed_no_verify".

def test_F11_build_failure_then_end_turn_classified_distinctly(tmp_path: Path) -> None:
    """RED: when agent calls docker_build (fails with reason=transport) then
    emits end_turn without verify and without give_up, the outcome status
    must NOT be the same as research-only end_turn (F-8). They are distinct
    failure modes worth distinguishing in triage.

    HEAD will FAIL: both currently map to "verify_failed" indistinguishably.
    """
    messages = [
        _assistant(
            _tool_use(
                "tu-build",
                "mcp__cve_env__docker_build",
                {"dockerfile": "FROM scratch", "tag": "x"},
            )
        ),
        _user(
            _tool_result(
                "tu-build",
                {
                    "ok": False,
                    "reason": "transport",
                    "reason_class": "transport",
                    "error": "Docker Hub rate-limited",
                },
            )
        ),
        _assistant(_text_block("Build failed; nothing more I can do here.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F11-build-fail-end-turn",
                audit_root=tmp_path,
            )
        )
    # B-10 fix (2026-05-06): build-path silent end_turn is now synthesized
    # to give_up('quit_without_verify_or_giveup'); status='unresolvable'.
    # F-11's original distinguishment (vs research-only) is achieved
    # through the give_up_reason rather than a status difference.
    assert outcome.status == "unresolvable", (
        f"F-11 + B-10: end_turn after docker_build failure should be "
        f"unresolvable (synthesized give_up); got status={outcome.status!r}"
    )
    assert outcome.give_up_reason == "quit_without_verify_or_giveup", (
        f"F-11 + B-10: give_up_reason should be 'quit_without_verify_or_giveup' "
        f"(synthesized); got give_up_reason={outcome.give_up_reason!r}"
    )

# =============================================================================
# F-8 — research-only path ends without verify or give_up
# =============================================================================
# Bug: loop.py:349-350 classifies all end_turn-without-verify as
# "verify_failed". A research-only flow (nvd_lookup + web_fetch only,
# no Docker tools, no verify) is structurally distinct from F-11 but
# currently shares the same status.
# Evidence: 7+ instances in 26866's bench200 with path=research-only.
# Fix: distinguish "research_dead_end" via tool_categories tracking.

def test_B1_research_only_with_Bash_classifies_as_research(tmp_path: Path) -> None:
    """B-1 fix (2026-05-06): when the agent uses ONLY research/diagnostic
    tools (research_tools | image_resolve | ToolSearch | Bash | Read | Write)
    and never attempts a Docker build / source_build / verify, the
    no_verify_pass reason MUST cite "research-only path", not the generic
    fallback "agent ended without a successful verify".

    bench50-20260505-231537 evidence: 2/4 ⚠no_verify cases used Bash for
    diagnostic exploration alongside research tools, and the F-8 classifier
    fell through to the generic message because Bash wasn't in the
    research-or-diag set. B-1 widens the set to include Bash/Read/Write."""
    messages = [
        _assistant(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu-nvd", {"hit": True, "summary": "x"})),
        # Bash diagnostics — used to ls a hypothetical workdir, not for build.
        _assistant(_tool_use("tu-bash", "Bash", {"command": "ls /tmp"})),
        _user(_tool_result("tu-bash", {"stdout": "(empty)", "exit_code": 0})),
        _assistant(_text_block("No buildable artifact found, ending here.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-B1-bash-research",
                audit_root=tmp_path,
            )
        )
    assert outcome.status == "verify_failed", (
        f"B-1 baseline: status should be no_verify_pass, got {outcome.status!r}"
    )
    assert "research" in (outcome.reason or "").lower(), (
        f"B-1 not fixed: research-only-with-Bash flow mapped to generic "
        f"reason '{outcome.reason}', should cite 'research-only path'. "
        f"Bash should be in the research-or-diag classification set."
    )

def test_B2_give_up_branch_ordered_before_runtime_cap_exceptions() -> None:
    """B-2 fix (2026-05-06): in build()'s except handler, the
    `state.give_up_reason` branch MUST appear BEFORE the TurnCapReached and
    BudgetCapExceeded class-match branches. Otherwise a runtime cap
    exception that races a clean give_up gets the run mis-classified by
    exception type rather than by the agent's voluntary decision.

    CVE-2022-1813 incident: agent give_up at T24 → status=turn_cap
    num_turns=0 cost=0 because handler matched TurnCapReached's class first
    and never reached the give_up_reason branch. The fix consolidates the
    two prior give_up sub-branches (give_up + result_received vs give_up +
    GiveUpReceived class) into one give_up_reason check that wins
    unconditionally over runtime cap exceptions.

    Structural lock: catches any future re-split of the branches that
    re-introduces the race."""
    import inspect
    from cve_env.agent import loop as loop_mod

    src = inspect.getsource(loop_mod.build)
    # Find the give_up_reason branch in the except handler
    except_idx = src.index("except Exception as exc")
    handler_src = src[except_idx:]
    give_idx = handler_src.find("elif state.give_up_reason")
    turn_idx = handler_src.find("TurnCapReached")
    budget_idx = handler_src.find("BudgetCapExceeded")
    assert give_idx > 0, (
        "B-2 missing: no `elif state.give_up_reason:` branch in build()'s "
        "except handler — give_up classification will be skipped"
    )
    assert turn_idx > 0, "expected TurnCapReached branch in handler"
    assert budget_idx > 0, "expected BudgetCapExceeded branch in handler"
    assert give_idx < turn_idx, (
        f"B-2 not fixed: `state.give_up_reason` branch (at offset {give_idx}) "
        f"appears AFTER TurnCapReached branch (at offset {turn_idx}) — runtime "
        f"cap exception will win over voluntary give_up. Move the give_up "
        f"check BEFORE the cap-class checks."
    )
    assert give_idx < budget_idx, (
        f"B-2 not fixed: `state.give_up_reason` branch (at offset {give_idx}) "
        f"appears AFTER BudgetCapExceeded branch (at offset {budget_idx})."
    )
    # Also check there's no `and state.result_received` constraint that would
    # silently skip the give_up branch when result hasn't arrived yet.
    give_line_end = handler_src.index(":", give_idx)
    give_branch_header = handler_src[give_idx:give_line_end]
    assert "result_received" not in give_branch_header, (
        f"B-2 not fixed: give_up branch still gates on result_received: "
        f"{give_branch_header!r}. The fix should classify on give_up_reason "
        f"alone, since CVE-2022-1813 had give_up but no result_received."
    )

def test_F8_research_only_end_turn_classified_distinctly(tmp_path: Path) -> None:
    """RED: when agent uses ONLY research tools (nvd_lookup, web_fetch,
    github_fetch) and never attempts a Docker build, then emits end_turn
    without give_up, the outcome should be a distinct "research_dead_end"
    (or "verify_failed" with reason citing research-only). The agent
    SHOULD have called give_up(reason='no_image' / 'proprietary'); the
    fact that it didn't is itself a triage signal.

    HEAD will FAIL: research-only and build-attempt cases both map to
    plain "verify_failed" with the same generic reason.
    """
    messages = [
        _assistant(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})
        ),
        _user(_tool_result("tu-nvd", {"hit": True, "summary": "Some CVE"})),
        _assistant(
            _tool_use(
                "tu-fetch",
                "mcp__cve_env__github_fetch",
                {"url": "https://github.com/x/y"},
            )
        ),
        _user(_tool_result("tu-fetch", {"ok": True, "body": "..."})),
        _assistant(_text_block("No buildable artifact found, ending here.")),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F8-research-only",
                audit_root=tmp_path,
            )
        )
    # After fix: should be distinguishable from build-attempt case (F-11).
    # Acceptable: "research_dead_end", or "verify_failed" with reason
    # citing research-only / no build attempted.
    if outcome.status == "verify_failed":
        assert (
            "research" in (outcome.reason or "").lower()
            or "no_build" in (outcome.reason or "").lower()
        ), (
            f"F-8 not fixed: research-only end_turn mapped to plain "
            f"'no_verify_pass' (status={outcome.status!r}, "
            f"reason={outcome.reason!r}) — should signal research-only path"
        )
    else:
        assert outcome.status in {"research_dead_end", "no_artifacts_found"}, (
            f"F-8 unexpected status: {outcome.status!r}"
        )

# =============================================================================
# F-10 — source-build path ends without verify
# (26866's term per canonical catalog reconciliation 09:13Z; this is distinct
# from F-13 (give_up not honored) and F-11 (docker_build failure → end_turn))
# =============================================================================
# Bug: agent uses source_build tool successfully (or attempts it), then emits
# end_turn without calling verify and without give_up. Currently lumped under
# generic "verify_failed" — needs distinct status.
# Evidence: 26866's bench200 reports 1 instance.
# Fix: tool_categories tracking → if source_build was attempted (success or
# failure) AND no verify, emit "source_build_no_verify" or "verify_failed"
# with reason citing source-build.

def test_F10_source_build_end_turn_classified_distinctly(tmp_path: Path) -> None:
    """RED: when agent attempts source_build (with or without success) then
    emits end_turn without verify, classification must distinguish from
    research-only (F-8) and docker_build-failure (F-11).

    HEAD will FAIL: source_build path ends in plain "verify_failed" without
    indication that source-build was attempted.
    """
    messages = [
        _assistant(
            _tool_use(
                "tu-src",
                "mcp__cve_env__source_build",
                {"git_url": "https://github.com/x/y", "ref": "v1.0"},
            )
        ),
        _user(
            _tool_result(
                "tu-src",
                {"ok": True, "image_ref": "x:built", "next_step_hint": ""},
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F10-source-build-no-verify",
                audit_root=tmp_path,
            )
        )
    # B-10 fix (2026-05-06): source_build path silent end_turn is now
    # synthesized to give_up('quit_without_verify_or_giveup'); status='unresolvable'.
    # F-10's original distinguishment goes through give_up_reason +
    # give_up_detail rather than a status difference.
    assert outcome.status == "unresolvable", (
        f"F-10 + B-10: source_build silent end_turn should be unresolvable; "
        f"got status={outcome.status!r}"
    )
    assert outcome.give_up_reason == "quit_without_verify_or_giveup", (
        f"F-10 + B-10: give_up_reason should be 'quit_without_verify_or_giveup'; "
        f"got give_up_reason={outcome.give_up_reason!r}"
    )
    assert "source_build" in (outcome.give_up_detail or ""), (
        f"F-10 + B-10: give_up_detail should mention source_build; "
        f"got give_up_detail={outcome.give_up_detail!r}"
    )

# =============================================================================
# F-7 — docker_run.ok=true → end_turn without verify (Phase 37.6 prompt rule
# enforcement check)
# =============================================================================
# Bug: agent gets docker_run.ok=true (container running) and emits end_turn
# WITHOUT calling verify. The classification IS already distinct
# (loop.py:339-348 → "launched_no_verify") — confirmed by direct read.
# So F-7 is a *prompt-layer* problem (Phase 37.6 rule wasn't followed by
# the agent), not a runtime classification bug.
# Evidence: 1 instance — CVE-2019-3396 V1 smoke (per 26866's bug-log entry).
# This RED test pins the classification behaviour so the runtime guard
# remains in place.

def test_F7_docker_run_then_end_turn_classified_as_launched_unverified(
    tmp_path: Path,
) -> None:
    """REGRESSION-LOCK (already-passing): docker_run.ok=true → end_turn
    without verify must be classified as 'launched_unverified', NOT plain
    'no_verify_pass'. Phase 57 logic (loop.py:339-348) handles this. We
    lock the behaviour with this test so a future refactor can't regress it.

    Currently PASSES at HEAD (Phase 57 already shipped). Listed here for
    catalog completeness — F-7's actual fix is prompt-layer (out of scope
    for this runtime-fix pipeline).
    """
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
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-F7-launched-unverified",
                audit_root=tmp_path,
            )
        )
    assert outcome.status == "launched_no_verify", (
        f"F-7 regression: docker_run.ok=true + end_turn must classify as "
        f"'launched_unverified' (Phase 57), got {outcome.status!r}"
    )

# =============================================================================
# F-14 — verify ran with partial pass (e.g. 2/3 checks passed), agent
# end_turn without retry
# =============================================================================
# Bug: agent calls verify, some checks pass and some fail, agent emits
# end_turn without retrying or fixing. Currently maps to "verify_failed"
# (verify ran, but state.verify_passed is False). Distinct from F-8/F-10/F-11
# because verify WAS attempted; the issue is partial-pass with no retry.
# Evidence: 1 instance — CVE-2024-22087 ⚠no_verify t=28, custom-dockerfile,
# verify=2/3 passed.
# Fix: surface partial-pass as actionable signal — either distinct status
# "verify_partial_no_retry" or "verify_failed" reason mentioning partial.

def test_F14_verify_partial_pass_then_end_turn_surfaces_distinctly(
    tmp_path: Path,
) -> None:
    """RED: verify ran with some passing + some failing checks, agent emits
    end_turn without retry. Status should signal "partial-pass" specifically,
    not be generic "verify_failed" indistinguishable from never-verified.

    HEAD will FAIL: existing test_phase57_build_no_verify_pass_when_verify_was_attempted_but_failed
    locks plain "verify_failed" for full failure; partial pass shares that.
    """
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
                {
                    "plan": [
                        {"type": "container_status"},
                        {"type": "exec_check"},
                        {"type": "http_check"},
                    ]
                },
            )
        ),
        _user(
            _tool_result(
                "tu-verify",
                {
                    "passed": False,
                    "results": [
                        {"type": "container_status", "passed": True},
                        {"type": "exec_check", "passed": True},
                        {"type": "http_check", "passed": False},
                    ],
                },
            )
        ),
        _result("end_turn"),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-F14-partial-pass", audit_root=tmp_path)
        )
    # After fix: signal partial-pass distinctly. Acceptable: "verify_partial_no_retry"
    # or status="verify_failed" with reason citing partial pass + count.
    if outcome.status == "verify_failed":
        reason_lower = (outcome.reason or "").lower()
        assert (
            "partial" in reason_lower
            or "/3" in (outcome.reason or "")
            or "2/3" in (outcome.reason or "")
        ), (
            f"F-14 not fixed: verify-partial-pass + end_turn mapped to plain "
            f"'no_verify_pass' (status={outcome.status!r}, "
            f"reason={outcome.reason!r}) — should mention partial-pass count"
        )
    else:
        assert outcome.status in {"verify_partial_no_retry", "verify_incomplete"}, (
            f"F-14 unexpected status: {outcome.status!r}"
        )

def test_B10_runtime_synthesizes_give_up_when_build_path_ends_silent(
    tmp_path: Path,
) -> None:
    """B-10 fix (2026-05-06): when agent runs build-path tools
    (docker_build / dockerfile_gen / source_build) then emits end_turn
    WITHOUT verify-pass and WITHOUT explicit give_up, runtime synthesizes
    `give_up('quit_without_verify_or_giveup')` so the outcome reflects the agent's
    de-facto give-up rather than a silent classification.

    P0-X prompt rule alone had 0% follow-through across smoke arcs
    (5+ violations / 27 CVEs = 19%). This runtime gate closes the gap."""
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("tu1", {"hit": True})),
        _assistant(
            _tool_use(
                "tu2", "mcp__cve_env__dockerfile_gen", {"base_image": "ubuntu:22.04"}
            )
        ),
        _user(_tool_result("tu2", {"ok": True, "dockerfile": "FROM ubuntu:22.04"})),
        _assistant(
            _tool_use("tu3", "mcp__cve_env__docker_build", {"context_path": "/tmp/x"})
        ),
        _user(_tool_result("tu3", {"ok": True, "image_tag": "x:1"})),
        _assistant(_text_block("Built; not verifying further.")),
        _result("end_turn"),  # P0-X violation: end_turn without verify or give_up
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-B10-synthesized-give-up",
                audit_root=tmp_path,
            )
        )
    assert outcome.status == "unresolvable", (
        f"B-10 not fixed: build-path silent end_turn should synthesize "
        f"give_up → status='unresolvable'; got {outcome.status!r}"
    )
    # B-10's INTENT: runtime synthesizes give_up at end_turn (not silent).
    # Phase 51.B.2 (2026-05-17) added a more specific marker
    # `quit_without_verify_after_build` for the docker_build.ok=True
    # subcase that this fixture happens to exercise (docker_build at tu3
    # sets state.docker_built_ok=True). Either marker satisfies B-10:
    # the synthesis happened; the specific label refined.
    assert outcome.give_up_reason in {
        "quit_without_verify_or_giveup",  # legacy B-10 marker
        "quit_without_verify_after_build",  # Phase 51.B.2 refinement
    }, (
        f"B-10 not fixed: give_up_reason should be 'quit_without_verify_or_giveup' "
        f"or 'quit_without_verify_after_build' (Phase 51.B.2 refinement); "
        f"got {outcome.give_up_reason!r}"
    )
    # Should NOT be no_verify_pass anymore — that was the pre-fix shape
    assert outcome.status != "verify_failed"

def test_B8_audit_writes_final_no_verify_when_sdk_ends_via_end_turn(
    tmp_path: Path,
) -> None:
    """B-8 fix (2026-05-06): when SDK emits ResultMessage with
    stop_reason='end_turn' and verify wasn't passed and give_up wasn't
    issued, the audit terminal entry must be `final_no_verify` (NOT
    `final_turn_cap` as the pre-fix code wrote — no turn cap fired).

    Triage tools grepping for `final_turn_cap` were inflated by these
    misclassifications (4+ instances across smoke arcs).
    """
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("tu1", {"hit": True})),
        _result("end_turn"),  # SDK end_turn, no verify, no give_up
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-B8-no-verify-audit",
                audit_root=tmp_path,
            )
        )
    # Read audit JSONL — terminal entry must be final_no_verify.
    audit_path = outcome.audit_path
    assert audit_path is not None and audit_path.is_file()
    terminal_statuses = []
    for line in audit_path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        status = entry.get("status", "")
        if isinstance(status, str) and status.startswith("final_"):
            terminal_statuses.append(status)
    assert "final_no_verify" in terminal_statuses, (
        f"B-8 not fixed: SDK ended via end_turn but audit shows "
        f"{terminal_statuses!r} — expected final_no_verify"
    )
    assert "final_turn_cap" not in terminal_statuses, (
        "B-8 not fixed: audit wrote final_turn_cap when no turn cap fired"
    )

def test_B9_num_turns_floored_at_tool_uses_seen_when_sdk_reports_zero(
    tmp_path: Path,
) -> None:
    """B-9 fix (2026-05-06): when SDK emits a ResultMessage with num_turns=0
    yet the audit log shows real tool calls happened (CVE-2024-11664
    smoke12 reproduction: 35 tool calls but Outcome reported t=0 cost=$0
    wall=536s), Outcome.num_turns must be floored at len(tool_uses_seen).

    HEAD-of-fix: 4-tool sequence + ResultMessage with num_turns=0 →
    Outcome.num_turns >= 4 (was: == 0)."""
    messages = [
        _assistant(_tool_use("tu1", "mcp__cve_env__nvd_lookup", {"cve_id": "CVE-X"})),
        _user(_tool_result("tu1", {"hit": True})),
        _assistant(_tool_use("tu2", "mcp__cve_env__github_fetch", {"path": "x"})),
        _user(_tool_result("tu2", {"ok": True})),
        _assistant(_tool_use("tu3", "mcp__cve_env__image_resolve", {"product": "x"})),
        _user(_tool_result("tu3", {"ok": True})),
        # SDK reports num_turns=0 even though 3 tool calls happened
        _result("max_turns_reached", turns=0, cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(
                _cve(),
                _host(),
                run_id="run-B9-counter-floor",
                audit_root=tmp_path,
            )
        )
    # 3 tool_uses observed → num_turns must be ≥ 3 (the floor)
    assert outcome.num_turns >= 3, (
        f"B-9 not fixed: SDK reported t=0 but agent ran 3 tools — Outcome "
        f"should floor num_turns at len(tool_uses_seen). got num_turns="
        f"{outcome.num_turns}"
    )
    assert len(outcome.tool_names_called) == 3
