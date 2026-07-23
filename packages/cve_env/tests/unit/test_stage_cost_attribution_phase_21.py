"""Phase 21 (2026-05-12): token-derived stage_costs attribution (BUG-N1).

The Phase 12.1 ResultMessage-only attribution path failed for short
CVEs where the SDK emits cost via ``AssistantMessage.usage`` (tokens)
but reports ``total_cost_usd=0`` on the final ResultMessage. Empirical
evidence: Phase 19.7 + 20A.4 Heartbleed smokes showed ``stage_costs``
all zeros while ``outcome.total_cost_usd`` was non-zero (via the B-19
``max(reported, estimate_from_tokens)`` reconciliation).

Phase 21.2 added token-cost attribution on the AssistantMessage path,
with segment-based dedup against the existing ResultMessage path so
both-paths-fire segments aren't double-counted. These tests pin that
behavior; the originally-RED 4 were marked xfail(strict=True) in
Phase 21.1 so the pre-fix bug was visible in git history without
breaking the suite.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cve_env.agent.loop import build
from cve_env.models import CveRecord, HostInfo

# Phase 21.2 + 21.3 shipped: the originally-RED tests below are now GREEN.
# Phase 21.1's xfail markers (4 tests) were removed by Phase 21.2 impl;
# Phase 21.3.1's xfail markers (2 tests) were removed by Phase 21.3.2
# impl. The RED→GREEN→remove pattern with strict=True caught the moment
# each fix landed (XPASS flags markers that should be removed).

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

def _assistant_with_usage(*blocks: Any, usage: dict[str, int] | None) -> Any:
    """AssistantMessage with explicit ``usage`` dict.

    The shipped ``test_loop.py::_assistant`` helper doesn't expose usage;
    Phase 21 specifically exercises the usage path so we construct
    AssistantMessage directly here.
    """
    from claude_agent_sdk import AssistantMessage

    return AssistantMessage(
        content=list(blocks),
        model="claude-opus-4-7",
        parent_tool_use_id=None,
        usage=usage,
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
    )

def _cve() -> CveRecord:
    return CveRecord(
        cve_id="CVE-2014-0160",
        product="openssl",
        version="1.0.1f",
        description="Heartbleed",
    )

def _host() -> HostInfo:
    return HostInfo(arch="aarch64", os="darwin", docker_backend="colima")

def _fake_run_agent_factory(messages: list[Any], stop_reason: str = "end_turn"):
    """Drive on_message with canned messages. Lifted verbatim from
    ``test_loop.py:_fake_run_agent_factory`` so this test exercises the
    same shim shape used by Phase 12.1 tests.
    """
    from cve_env.agent.llm import (
        AgentRunOutcome,
        BudgetCapExceeded,
        GiveUpReceived,
        TurnCapReached,
    )

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

# ─── Contract tests: token-derived attribution (Phase 21 behaviour) ─

def test_phase_21_token_attribution_when_resultmessage_cost_zero(
    tmp_path: Path,
) -> None:
    """Heartbleed pattern: AssistantMessage has usage (tokens), final
    ResultMessage has cost_usd=0. Pre-Phase-21: stage_costs all zeros.
    Post-Phase-21: stage of the last tool gets non-zero cost.
    """
    # Turn 1: nvd_lookup tool call → tool result → AssistantMessage(usage)
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 5_000, "output_tokens": 800},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        # Subsequent AssistantMessage (after the user tool_result) does
        # the "thinking" step; this is where Phase 21 attributes cost.
        _assistant_with_usage(
            _text_block("analyzing"),
            usage={"input_tokens": 8_000, "output_tokens": 200},
        ),
        # Final ResultMessage with NO cost — typical Heartbleed pattern.
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-heartbleed", audit_root=tmp_path)
        )
    assert outcome.stage_costs is not None
    summed = sum(outcome.stage_costs.values())
    assert summed > 0, (
        f"Phase 21 should attribute token-derived cost; got all zeros: "
        f"{outcome.stage_costs}"
    )
    # The 2nd AssistantMessage's usage attributes to RESEARCH (the stage
    # of the just-completed nvd_lookup that motivated this LLM call).
    assert outcome.stage_costs.get("RESEARCH", 0.0) > 0, (
        f"RESEARCH should have token cost; got: {outcome.stage_costs}"
    )

def test_phase_21_token_attribution_credits_previous_turn_stage(tmp_path: Path) -> None:
    """Multi-turn: AssistantMessage cost credits the stage of the
    PREVIOUS turn's tool (whose result motivated this LLM call), NOT
    the new tools being requested in this very message.
    """
    messages = [
        # Turn 1: nvd_lookup (RESEARCH) — tokens for this call
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 4_000, "output_tokens": 100},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        # Turn 2: AssistantMessage with tokens AND new docker_run call.
        # Cost should attribute to RESEARCH (previous turn's tool),
        # NOT LAUNCH (the new tool being requested).
        _assistant_with_usage(
            _tool_use("tu-run", "mcp__cve_env__docker_run", {"image": "x"}),
            usage={"input_tokens": 6_000, "output_tokens": 300},
        ),
        _user(_tool_result("tu-run", {"ok": True})),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-multiturn", audit_root=tmp_path)
        )
    research = outcome.stage_costs.get("RESEARCH", 0.0)
    launch = outcome.stage_costs.get("LAUNCH", 0.0)
    assert research > 0, (
        f"RESEARCH should get cost from turn 2's AssistantMessage; got {outcome.stage_costs}"
    )
    # The first AssistantMessage's tokens attribute to OTHER (no previous tool).
    # The second's attribute to RESEARCH. The docker_run tool itself has no
    # ResultMessage cost — so LAUNCH gets nothing in this scenario.
    assert launch == 0.0 or launch < research, (
        f"LAUNCH should not be primary recipient; research={research}, launch={launch}"
    )

def test_phase_21_first_assistantmessage_attributes_to_other(tmp_path: Path) -> None:
    """First AssistantMessage has no prior tool → state.last_tool_stage
    is the default 'OTHER'. Cost attributes there.
    """
    messages = [
        _assistant_with_usage(
            _text_block("starting"),
            usage={"input_tokens": 3_000, "output_tokens": 100},
        ),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-first", audit_root=tmp_path)
        )
    assert outcome.stage_costs.get("OTHER", 0.0) > 0, (
        f"First AssistantMessage cost should attribute to OTHER; got: {outcome.stage_costs}"
    )

def test_phase_21_assistantmessage_no_usage_no_attribution(tmp_path: Path) -> None:
    """AssistantMessage with usage=None → no token-derived attribution.
    No double-credit of stale state.last_tool_stage with zero tokens.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage=None,
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-nousage", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    assert summed == 0.0, (
        f"usage=None should produce zero token-derived attribution; got: {outcome.stage_costs}"
    )

def test_phase_21_resultmessage_only_path_still_works(tmp_path: Path) -> None:
    """Backward compatibility: AssistantMessage(usage=None) +
    ResultMessage(cost_usd>0) → the existing Phase 12.1 ResultMessage
    attribution path still credits the stage.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage=None,
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _result("end_turn", cost_usd=0.50),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-rmonly", audit_root=tmp_path)
        )
    research = outcome.stage_costs.get("RESEARCH", 0.0)
    assert research > 0, (
        f"ResultMessage-only path must still attribute (Path 3 backward compat); "
        f"got: {outcome.stage_costs}"
    )
    # Sum should approximate $0.50 (ResultMessage path is exact).
    summed = sum(outcome.stage_costs.values())
    assert abs(summed - 0.50) < 0.05, f"sum {summed} should approximate $0.50"

def test_phase_21_stage_costs_sum_approximates_total_cost_usd(tmp_path: Path) -> None:
    """Sanity: post-fix, sum(stage_costs) approximates total_cost_usd.
    Pre-Phase-21 the sum was 0 for short CVEs while total was non-zero.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 10_000, "output_tokens": 500},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _assistant_with_usage(
            _tool_use("tu-run", "mcp__cve_env__docker_run", {"image": "x"}),
            usage={"input_tokens": 5_000, "output_tokens": 200},
        ),
        _user(_tool_result("tu-run", {"ok": True})),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-sumtotal", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # outcome.total_cost_usd = max(state.last_cost_usd=0, token_estimate).
    # Sum should match the token-estimate path exactly (since
    # last_cost_usd is 0). Tolerance: 1¢ for rounding.
    assert outcome.total_cost_usd > 0, "token estimate should be non-zero"
    assert abs(summed - outcome.total_cost_usd) < 0.01, (
        f"sum {summed:.6f} should approximate total_cost_usd "
        f"{outcome.total_cost_usd:.6f}; stage_costs={outcome.stage_costs}"
    )

def test_phase_21_dedup_avoids_doublecount_when_both_paths_fire(tmp_path: Path) -> None:
    """Path 1: SDK reports tokens on AssistantMessage AND cost on
    ResultMessage. Both attribution paths could fire — Phase 21 dedup
    must ensure the COST is counted exactly once per LLM-call segment.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 4_000, "output_tokens": 100},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        # AssistantMessage with usage  AND  ResultMessage with cost_usd.
        # Without dedup, both paths would credit the cost.
        _assistant_with_usage(
            _text_block("done"),
            usage={"input_tokens": 5_000, "output_tokens": 200},
        ),
        _result("end_turn", cost_usd=0.30),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-dedup", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # Upper bound: outcome.total_cost_usd × 1.5 (allows for some over-count
    # from estimate vs reported delta; full double-count would yield ~2x).
    # If the implementation correctly dedups, sum ≤ total + small slack.
    assert summed <= outcome.total_cost_usd * 1.5, (
        f"Suspected double-count: sum {summed:.6f} > total {outcome.total_cost_usd:.6f} × 1.5; "
        f"stage_costs={outcome.stage_costs}"
    )

# ─── Phase 21.3 RED tests: divergent AM/RM magnitudes (BUG #23 fix) ──
#
# Phase 22 (16-CVE bench) found that Phase 21.2's dedup logic is
# over-aggressive: when AssistantMessage attributes a tiny
# token-estimate, ResultMessage skips its (much larger) SDK-reported
# cost. Empirical evidence: sum/total ratio < 5% on 7 of 16 CVEs in
# bench `bench50-20260512-224511`. The Heartbleed smoke (Phase 21.4)
# accidentally matched because that CVE's total cost was tiny and
# matched the token-estimate.
#
# Phase 21.3 replaces the boolean dedup with per-segment residual:
# RM tops up AM's contribution so the final per-segment credit is
# max(AM_estimate, RM_reported_cost). These 3 tests pin the behavior.

def test_phase_21_3_rm_cost_dominates_when_larger_than_am_estimate(
    tmp_path: Path,
) -> None:
    """Most-common bench pattern: AM emits tokens worth ~$0.01 estimate,
    RM reports actual SDK cost of ~$0.50. Pre-Phase-21.3: dedup skips
    RM → stage_costs sum stuck at ~$0.01. Post-Phase-21.3: RM tops up
    AM → stage_costs sum ≈ $0.50.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            # Small token counts → tiny AM estimate (~$0.0008 at opus rates).
            usage={"input_tokens": 50, "output_tokens": 10},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        # Big SDK-reported segment cost — the realistic case.
        _result("end_turn", cost_usd=0.50),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-3-rmdom", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # Sum should approximate the RM-reported $0.50 (not be stuck at the
    # tiny AM estimate). Tolerance: 5% — accounts for the small AM
    # estimate getting credited first.
    assert abs(summed - 0.50) < 0.025, (
        f"RM should dominate when its cost exceeds AM estimate; "
        f"sum {summed:.6f} expected ≈ $0.50; stage_costs={outcome.stage_costs}"
    )

def test_phase_21_3_am_estimate_used_when_no_rm_cost(tmp_path: Path) -> None:
    """Heartbleed pattern (Phase 21.4 smoke): RM reports cost=0 but AM
    has token usage. AM's estimate must remain the credited value.
    Verifies Phase 21.3 doesn't regress the case Phase 21.2 was built
    to fix.
    """
    messages = [
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 1_000, "output_tokens": 200},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-3-amonly", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # AM-only contribution should approximate outcome.total_cost_usd
    # (which the B-19 fallback computes from the same tokens).
    assert outcome.total_cost_usd > 0, "token estimate must be non-zero"
    assert abs(summed - outcome.total_cost_usd) < 0.01, (
        f"AM-only sum should still ≈ total when RM cost=0; "
        f"sum={summed:.6f} total={outcome.total_cost_usd:.6f}"
    )

def test_phase_21_3_per_segment_max_in_multisegment_run(tmp_path: Path) -> None:
    """Multi-segment: each segment's stage_cost is max(AM_estimate,
    RM_cost). Two segments — first with big RM ($0.40), second with
    no RM cost (AM-only fallback ~$0.0008). Sum should ≈ $0.40.
    """
    messages = [
        # Segment 1: small AM estimate + big RM cost
        _assistant_with_usage(
            _tool_use("tu-nvd", "mcp__cve_env__nvd_lookup", {"cve_id": "x"}),
            usage={"input_tokens": 50, "output_tokens": 10},
        ),
        _user(_tool_result("tu-nvd", {"data": "..."})),
        _result("end_turn", cost_usd=0.40),
        # Segment 2: AM-only (Heartbleed-style follow-up)
        _assistant_with_usage(
            _tool_use("tu-run", "mcp__cve_env__docker_run", {"image": "x"}),
            usage={"input_tokens": 100, "output_tokens": 20},
        ),
        _user(_tool_result("tu-run", {"ok": True})),
        # Terminal give_up so the Fix #8 verify-continuation (revived 2026-05-28)
        # does NOT fire on this docker_run-ok-no-verify ending — this test is
        # about per-segment stage-cost, not continuation. Without it the
        # continuation re-runs run_agent and the replaying fake doubles the cost.
        _assistant_with_usage(
            _tool_use("tu-gu", "mcp__cve_env__give_up", {"reason": "no_image"}),
            usage=None,
        ),
        _user(
            _tool_result(
                "tu-gu", {"terminal": True, "reason": "no_image", "detail": ""}
            )
        ),
        _result("end_turn", cost_usd=0.0),
    ]
    with patch("cve_env.agent.loop.run_agent", _fake_run_agent_factory(messages)):
        outcome = asyncio.run(
            build(_cve(), _host(), run_id="run-21-3-multi", audit_root=tmp_path)
        )
    summed = sum(outcome.stage_costs.values())
    # Segment 1 max = $0.40 (RM dominates), segment 2 max ≈ $0.003 (AM only).
    # Sum ≈ $0.40 within 2%.
    assert 0.38 < summed < 0.42, (
        f"Multi-segment sum should be ≈ $0.40; got {summed:.6f}; "
        f"stage_costs={outcome.stage_costs}"
    )
