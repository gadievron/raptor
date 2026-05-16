"""Tests for ``core.llm.tool_use.types``.

These are immutability + construction-shape sanity checks. The types
have no logic of their own; behaviour assertions live in the loop and
provider tests where the types get used.
"""

from __future__ import annotations

import pytest

from core.llm.tool_use import (
    CacheControl,
    ContextOverflow,
    ContextPolicy,
    CostBudgetExceeded,
    LoopTerminated,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallDispatched,
    ToolCallReturned,
    ToolDef,
    ToolLoopResult,
    ToolResult,
    TurnCompleted,
    TurnResponse,
    TurnStarted,
)


# --- StopReason ---------------------------------------------------------

def test_stop_reason_has_six_provider_agnostic_values() -> None:
    """The six values cover what every provider can normalise to.
    Adding a seventh means re-checking the Anthropic / OpenAI / Gemini
    mapping tables in :mod:`core.llm.tool_use.providers`. PAUSE_TURN
    is Anthropic-specific (extended-thinking pause/resume) but lives
    here so the loop can recognise the continuation case without
    provider-specific branching."""
    assert {r.name for r in StopReason} == {
        "COMPLETE",
        "NEEDS_TOOL_CALL",
        "PAUSE_TURN",
        "MAX_TOKENS",
        "REFUSED",
        "ERROR",
    }


# --- ToolDef + ToolCall + ToolResult -----------------------------------

def test_tooldef_is_frozen() -> None:
    td = ToolDef(name="t", description="d",
                 input_schema={"type": "object"},
                 handler=lambda _: "ok")
    with pytest.raises(Exception):                  # FrozenInstanceError
        td.name = "different"                        # type: ignore[misc]


def test_toolcall_carries_provider_id() -> None:
    """``id`` is provider-supplied (Anthropic ``toolu_*``, OpenAI
    ``call_*``); the loop echoes it back verbatim on the matching
    :class:`ToolResult`."""
    call = ToolCall(id="toolu_abc", name="search", input={"q": "x"})
    assert call.id == "toolu_abc"
    assert call.name == "search"
    assert call.input == {"q": "x"}


def test_toolresult_default_is_not_error() -> None:
    """Most tool results are successful — ``is_error`` defaults to
    False so handlers don't have to remember to set it."""
    r = ToolResult(tool_use_id="toolu_abc", content="ok")
    assert r.is_error is False


def test_toolresult_error_path() -> None:
    r = ToolResult(tool_use_id="toolu_abc", content="boom",
                   is_error=True)
    assert r.is_error is True


# --- Message -----------------------------------------------------------

def test_message_carries_mixed_content() -> None:
    """One assistant message can carry text + tool_calls; one user
    message can carry text + tool_results — each provider's wire
    converter handles the heterogeneous list."""
    m = Message(
        role="assistant",
        content=[
            TextBlock(text="checking..."),
            ToolCall(id="t1", name="search", input={}),
        ],
    )
    assert m.role == "assistant"
    assert len(m.content) == 2
    assert isinstance(m.content[0], TextBlock)
    assert isinstance(m.content[1], ToolCall)


# --- TurnResponse ------------------------------------------------------

def test_turn_response_default_cache_tokens_zero() -> None:
    """Providers that lack prompt caching leave the cache fields at
    0 — capability check is via the provider's
    ``supports_prompt_caching()`` flag, not by sniffing this field."""
    r = TurnResponse(
        content=[TextBlock(text="hi")],
        stop_reason=StopReason.COMPLETE,
        input_tokens=10, output_tokens=5,
    )
    assert r.cache_read_tokens == 0
    assert r.cache_write_tokens == 0


# --- CacheControl ------------------------------------------------------

def test_cache_control_defaults() -> None:
    """v1 default: cache the static parts (system + tools), don't cache
    history (which rolls per turn). Callers who know the conversation
    has a stable suffix opt in via ``history_through_index``."""
    cc = CacheControl()
    assert cc.system is True
    assert cc.tools is True
    assert cc.history_through_index is None


def test_cache_control_per_region_opt_in() -> None:
    cc = CacheControl(system=False, tools=True, history_through_index=4)
    assert cc.system is False
    assert cc.tools is True
    assert cc.history_through_index == 4


# --- ContextPolicy -----------------------------------------------------

def test_context_policy_v1_values() -> None:
    """v1 ships RAISE + TRUNCATE_OLDEST. SUMMARISE is deferred until
    a real consumer asks (needs second-LLM summarisation pass)."""
    assert {p.name for p in ContextPolicy} == {"RAISE", "TRUNCATE_OLDEST"}


# --- Exception types ---------------------------------------------------

def test_exceptions_are_runtime_errors() -> None:
    """Both subclasses of ``RuntimeError`` so ``except RuntimeError``
    catches them by default — and so callers can be specific when they
    want differentiated handling."""
    assert issubclass(CostBudgetExceeded, RuntimeError)
    assert issubclass(ContextOverflow, RuntimeError)


# --- LoopEvent shapes --------------------------------------------------

def test_event_dataclasses_construct() -> None:
    """Smoke-check each event variant since they're discriminated only
    by class — a subscriber doing ``isinstance`` dispatch will only
    match instances that construct cleanly."""
    e1 = TurnStarted(iteration=0, input_token_estimate=100,
                     cache_breakpoints=2)
    assert e1.iteration == 0

    resp = TurnResponse(content=[], stop_reason=StopReason.COMPLETE,
                        input_tokens=0, output_tokens=0)
    e2 = TurnCompleted(iteration=0, response=resp, cost_usd=0.0)
    assert e2.cost_usd == 0.0

    call = ToolCall(id="t", name="x", input={})
    e3 = ToolCallDispatched(iteration=0, call=call)
    assert e3.call.id == "t"

    res = ToolResult(tool_use_id="t", content="ok")
    e4 = ToolCallReturned(iteration=0, call_id="t",
                          result=res, duration_s=0.05)
    assert e4.duration_s == 0.05

    e5 = LoopTerminated(reason="complete", iterations=3,
                        total_cost_usd=0.012)
    assert e5.reason == "complete"


# --- ToolLoopResult ---------------------------------------------------

def test_tool_loop_result_construction() -> None:
    """The loop assembles this at the end; the test pins the public
    shape so adding fields requires updating consumers explicitly."""
    out = ToolLoopResult(
        final_text="done",
        terminal_tool_input={"verdict": "match"},
        messages=[],
        iterations=5,
        tool_calls_made=3,
        total_input_tokens=1500,
        total_output_tokens=400,
        total_cost_usd=0.012,
        terminated_by="terminal_tool",
    )
    assert out.terminal_tool_input == {"verdict": "match"}
    assert out.terminated_by == "terminal_tool"
