"""Tests for ``core.llm.tool_use.loop.ToolUseLoop``.

Loop logic is exercised against an in-memory ``_FakeProvider`` that
replays a pre-scripted sequence of :class:`TurnResponse`\\ s. This
isolates loop behaviour from any specific provider's wire format —
those concerns are tested in the provider-specific test files.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from typing import Any

import pytest

from core.llm.tool_use import (
    CacheControl,
    ContextOverflow,
    ContextPolicy,
    CostBudgetExceeded,
    LoopEvent,
    LoopTerminated,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallDispatched,
    ToolCallReturned,
    ToolDef,
    TurnCompleted,
    TurnResponse,
    TurnStarted,
)
from core.llm.tool_use.loop import ToolUseLoop


# ---------------------------------------------------------------------------
# Fake provider — records calls, replays scripted responses
# ---------------------------------------------------------------------------


class _FakeProvider:
    """In-memory provider replaying a list of :class:`TurnResponse`\\ s.

    Each ``turn()`` call pops the next scripted response. Records all
    input messages so tests can assert wire-format behaviour.
    """

    def __init__(
        self,
        responses: list[TurnResponse],
        *,
        tool_use: bool = True,
        prompt_caching: bool = True,
        parallel_tools: bool = True,
        ctx_window: int = 200_000,
        price: tuple[float, float] = (3.0, 15.0),  # opus-ish
    ) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self._tool_use = tool_use
        self._prompt_caching = prompt_caching
        self._parallel_tools = parallel_tools
        self._ctx_window = ctx_window
        self._price = price

    def supports_tool_use(self) -> bool: return self._tool_use
    def supports_prompt_caching(self) -> bool: return self._prompt_caching
    def supports_parallel_tools(self) -> bool: return self._parallel_tools
    def context_window(self) -> int: return self._ctx_window
    def price_per_million(self) -> tuple[float, float]: return self._price
    def estimate_tokens(self, text: str) -> int: return max(len(text) // 4, 1)

    def compute_cost(self, response: TurnResponse) -> float:
        in_per_m, out_per_m = self._price
        return (response.input_tokens * in_per_m
                + response.output_tokens * out_per_m) / 1_000_000

    def turn(self, messages, tools, *, system, max_tokens, cache_control,
             **provider_specific) -> TurnResponse:
        self.calls.append({
            "messages": list(messages),
            "tools": list(tools),
            "system": system,
            "max_tokens": max_tokens,
            "cache_control": cache_control,
            "provider_specific": dict(provider_specific),
        })
        if not self._responses:
            raise RuntimeError("fake provider exhausted scripted responses")
        return self._responses.pop(0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _text_response(text: str, in_t: int = 100, out_t: int = 50) -> TurnResponse:
    return TurnResponse(
        content=[TextBlock(text=text)],
        stop_reason=StopReason.COMPLETE,
        input_tokens=in_t, output_tokens=out_t,
    )


def _tool_call_response(
    *calls: tuple[str, str, dict],
    in_t: int = 100, out_t: int = 50,
) -> TurnResponse:
    return TurnResponse(
        content=[ToolCall(id=cid, name=name, input=inp)
                 for cid, name, inp in calls],
        stop_reason=StopReason.NEEDS_TOOL_CALL,
        input_tokens=in_t, output_tokens=out_t,
    )


def _echo_tool(name: str = "echo") -> ToolDef:
    return ToolDef(
        name=name,
        description="echoes its input back as JSON",
        input_schema={"type": "object"},
        handler=lambda inp: f"echoed: {inp}",
    )


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------


def test_rejects_provider_without_tool_use() -> None:
    """A provider that says it doesn't support tool-use can't drive the
    loop — ValueError at construction, not a confusing failure mid-run."""
    fp = _FakeProvider([], tool_use=False)
    with pytest.raises(ValueError, match="tool-use"):
        ToolUseLoop(fp, [_echo_tool()])


def test_rejects_duplicate_tool_names() -> None:
    """Two tools with the same name would dispatch ambiguously — refuse
    at construction so the bug surfaces immediately."""
    fp = _FakeProvider([])
    with pytest.raises(ValueError, match="unique names"):
        ToolUseLoop(fp, [_echo_tool("dup"), _echo_tool("dup")])


def test_rejects_terminal_tool_not_in_tools() -> None:
    """A loop with ``terminal_tool="never_registered"`` would never
    terminate via that path — refuse rather than run forever."""
    fp = _FakeProvider([])
    with pytest.raises(ValueError, match="not in the registered tools"):
        ToolUseLoop(fp, [_echo_tool()], terminal_tool="missing")


# ---------------------------------------------------------------------------
# Termination paths
# ---------------------------------------------------------------------------


def test_terminates_on_complete_response() -> None:
    """Text-only + COMPLETE → loop returns immediately with final text."""
    fp = _FakeProvider([_text_response("done")])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run("start")
    assert out.terminated_by == "complete"
    assert out.final_text == "done"
    assert out.iterations == 1
    assert out.tool_calls_made == 0
    assert len(fp.calls) == 1


def test_terminates_on_terminal_tool_call() -> None:
    """Loop terminates after dispatching the designated terminal tool;
    its input is surfaced on the result."""
    submit = ToolDef(
        name="submit_result",
        description="terminate with payload",
        input_schema={"type": "object"},
        handler=lambda inp: "submitted",
    )
    fp = _FakeProvider([
        _tool_call_response(("c1", "submit_result",
                             {"verdict": "match", "sha": "abc"})),
    ])
    loop = ToolUseLoop(fp, [submit], terminal_tool="submit_result")
    out = loop.run("find it")
    assert out.terminated_by == "terminal_tool"
    assert out.terminal_tool_input == {"verdict": "match", "sha": "abc"}
    assert out.tool_calls_made == 1
    # Only one provider call — terminal-tool short-circuits before next turn.
    assert len(fp.calls) == 1


def test_max_tokens_no_tool_calls_terminates_distinctly() -> None:
    """Provider returns ``StopReason.MAX_TOKENS`` with no tool calls
    (model truncated mid-response). Should terminate with the
    ``max_tokens`` label, distinguishable from ``provider_error``."""
    fp = _FakeProvider([TurnResponse(
        content=[TextBlock(text="partial...")],
        stop_reason=StopReason.MAX_TOKENS,
        input_tokens=100, output_tokens=4096,
    )])
    out = ToolUseLoop(fp, [_echo_tool()]).run("go")
    assert out.terminated_by == "max_tokens"
    # final_text still reports the partial response.
    assert out.final_text == "partial..."


def test_refused_no_tool_calls_terminates_distinctly() -> None:
    """``StopReason.REFUSED`` (content filter / safety) terminates
    with the ``refused`` label — caller can choose to surface the
    refusal differently from a transport error."""
    fp = _FakeProvider([TurnResponse(
        content=[],
        stop_reason=StopReason.REFUSED,
        input_tokens=50, output_tokens=0,
    )])
    out = ToolUseLoop(fp, [_echo_tool()]).run("forbidden")
    assert out.terminated_by == "refused"


def test_provider_error_no_tool_calls_terminates_distinctly() -> None:
    """``StopReason.ERROR`` (transport failure after retries)
    terminates with ``provider_error``."""
    fp = _FakeProvider([TurnResponse(
        content=[],
        stop_reason=StopReason.ERROR,
        input_tokens=0, output_tokens=0,
    )])
    out = ToolUseLoop(fp, [_echo_tool()]).run("go")
    assert out.terminated_by == "provider_error"


def test_pause_turn_continues_to_next_iteration() -> None:
    """``StopReason.PAUSE_TURN`` is a continuation signal (Anthropic
    extended-thinking pause/resume), not a termination. Loop appends
    the partial assistant turn and proceeds; eventually a non-PAUSE
    response terminates normally."""
    fp = _FakeProvider([
        TurnResponse(
            content=[TextBlock(text="thinking...")],
            stop_reason=StopReason.PAUSE_TURN,
            input_tokens=50, output_tokens=20,
        ),
        _text_response("done"),
    ])
    out = ToolUseLoop(fp, [_echo_tool()]).run("go")
    assert out.terminated_by == "complete"
    assert out.iterations == 2                          # pause + complete
    # The partial assistant turn was appended to history; on the next
    # turn we sent it back to the provider so it can resume.
    second_call_messages = fp.calls[1]["messages"]
    # messages = [user "go", assistant "thinking..."]
    assert len(second_call_messages) == 2
    assert second_call_messages[1].role == "assistant"
    assert any(
        isinstance(b, TextBlock) and b.text == "thinking..."
        for b in second_call_messages[1].content
    )


def test_max_iterations_caps_runaway_loop() -> None:
    """A loop that keeps emitting tool_calls without terminating gets
    capped at ``max_iterations`` rather than running forever."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _tool_call_response(("c2", "echo", {})),
        _tool_call_response(("c3", "echo", {})),
        _tool_call_response(("c4", "echo", {})),  # never reached
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], max_iterations=3)
    out = loop.run("loop")
    assert out.terminated_by == "max_iterations"
    assert out.iterations == 3
    assert out.tool_calls_made == 3
    assert len(fp.calls) == 3


# ---------------------------------------------------------------------------
# Cost budget
# ---------------------------------------------------------------------------


def test_max_cost_usd_terminates_pre_flight() -> None:
    """Cost budget is checked before each turn — once the cumulative
    cost crosses the cap, ``CostBudgetExceeded`` fires before the next
    provider call."""
    # Each turn costs (1000 * 3 + 1000 * 15) / 1M = $0.018
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {}), in_t=1000, out_t=1000),
        _tool_call_response(("c2", "echo", {}), in_t=1000, out_t=1000),
        _text_response("never reached", in_t=1000, out_t=1000),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], max_cost_usd=0.020)
    with pytest.raises(CostBudgetExceeded):
        loop.run("expensive")
    # 2 turns made it through; the 3rd was budget-blocked.
    assert len(fp.calls) == 2


def test_cost_tracking_aggregates_across_turns() -> None:
    """``total_cost_usd`` reports the sum of provider.compute_cost()
    over all turns. With 2 turns at (100*3 + 50*15)/1M = $0.00105 each."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _text_response("ok"),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run("hi")
    assert out.iterations == 2
    expected = ((100 * 3) + (50 * 15)) / 1_000_000 * 2
    assert abs(out.total_cost_usd - expected) < 1e-9
    assert out.total_input_tokens == 200
    assert out.total_output_tokens == 100


# ---------------------------------------------------------------------------
# Context window
# ---------------------------------------------------------------------------


def test_context_overflow_raise_policy() -> None:
    """RAISE policy refuses to send a request that exceeds the window."""
    fp = _FakeProvider([_text_response("ok")], ctx_window=10)
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        system="x" * 1000,                       # 250 tokens at 4-chars/token
        context_policy=ContextPolicy.RAISE,
    )
    with pytest.raises(ContextOverflow):
        loop.run("y" * 1000)
    assert len(fp.calls) == 0                     # never reached the provider


def test_context_overflow_truncate_raises_when_exhausted() -> None:
    """TRUNCATE_OLDEST falls back to ContextOverflow when even the
    irreducible trailing message exceeds the window — silently
    sending an oversized request would mis-gate the policy."""
    fp = _FakeProvider([_text_response("ok")], ctx_window=10)
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        context_policy=ContextPolicy.TRUNCATE_OLDEST,
    )
    # Single trailing message larger than the whole window — nothing
    # to drop; truncation runs out of options.
    with pytest.raises(ContextOverflow, match="still exceeds"):
        loop.run("y" * 1000)
    assert len(fp.calls) == 0


def test_context_overflow_truncate_policy_drops_oldest() -> None:
    """TRUNCATE_OLDEST drops oldest history pairs until the request fits.
    The freshest user message is preserved so the model still has the
    immediate prompt to act on."""
    # Provider window 100; system + tools + initial prompt fit; we add
    # a long history that needs truncating.
    fp = _FakeProvider([_text_response("ok")], ctx_window=100)
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        context_policy=ContextPolicy.TRUNCATE_OLDEST,
    )
    history = [
        Message(role="user",
                content=[TextBlock(text="x" * 200)]),     # 50 tokens
        Message(role="assistant",
                content=[TextBlock(text="y" * 200)]),     # 50 tokens
        Message(role="user",
                content=[TextBlock(text="z" * 200)]),     # 50 tokens
    ]
    out = loop.run_with_history(history, "now")
    assert out.terminated_by == "complete"
    # Provider was called — truncation succeeded.
    assert len(fp.calls) == 1
    sent = fp.calls[0]["messages"]
    # Some old messages dropped; "now" prompt always preserved.
    assert sent[-1].role == "user"
    assert any(
        isinstance(b, TextBlock) and "now" in b.text
        for b in sent[-1].content
    )


# ---------------------------------------------------------------------------
# Tool dispatch
# ---------------------------------------------------------------------------


def test_handler_error_default_feeds_back_to_model() -> None:
    """A handler that raises returns ``ToolResult(is_error=True)`` to
    the model so it can adapt — matches cve-diff's existing behaviour."""
    def bad_handler(_inp: dict) -> str:
        raise RuntimeError("oops")

    bad = ToolDef(name="bad", description="d", input_schema={}, handler=bad_handler)
    fp = _FakeProvider([
        _tool_call_response(("c1", "bad", {})),
        _text_response("ok"),
    ])
    loop = ToolUseLoop(fp, [bad])
    out = loop.run("go")
    assert out.terminated_by == "complete"
    # Second turn's input messages include the error tool_result.
    second = fp.calls[1]["messages"]
    last_user_msg = second[-1]
    assert last_user_msg.role == "user"
    err = last_user_msg.content[0]
    assert err.is_error is True
    assert "oops" in err.content


def test_handler_error_terminate_on_error_propagates() -> None:
    """``terminate_on_handler_error=True`` re-raises rather than feeding
    the error back — for agents wrapping destructive ops. Loop emits
    ``LoopTerminated(reason="tool_error")`` before the exception
    propagates so observers see termination."""
    from core.llm.tool_use import LoopTerminated

    def bad_handler(_inp: dict) -> str:
        raise RuntimeError("must not retry")

    bad = ToolDef(name="bad", description="d", input_schema={}, handler=bad_handler)
    fp = _FakeProvider([_tool_call_response(("c1", "bad", {}))])
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [bad],
        terminate_on_handler_error=True,
        events=seen.append,
    )
    with pytest.raises(RuntimeError, match="must not retry"):
        loop.run("go")
    final = next(e for e in seen if isinstance(e, LoopTerminated))
    assert final.reason == "tool_error"


def test_unknown_tool_returns_error_result() -> None:
    """Model-emitted call to a name we don't know — synthetic
    ``is_error=True`` result; lets the model recover."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "nonexistent_tool", {})),
        _text_response("ok"),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run("go")
    assert out.terminated_by == "complete"
    second = fp.calls[1]["messages"]
    last = second[-1].content[0]
    assert last.is_error is True
    assert "unknown tool" in last.content


def test_tool_timeout_returns_error_result() -> None:
    """A handler that exceeds ``tool_timeout_s`` produces an
    ``is_error=True`` :class:`ToolResult` (sleeps in background but
    we stop waiting)."""
    def slow_handler(_inp: dict) -> str:
        time.sleep(0.5)
        return "too late"

    slow = ToolDef(name="slow", description="d", input_schema={}, handler=slow_handler)
    fp = _FakeProvider([
        _tool_call_response(("c1", "slow", {})),
        _text_response("ok"),
    ])
    loop = ToolUseLoop(fp, [slow], tool_timeout_s=0.05)
    out = loop.run("go")
    assert out.terminated_by == "complete"
    second = fp.calls[1]["messages"]
    last = second[-1].content[0]
    assert last.is_error is True
    assert "timeout" in last.content


def test_tool_timeout_terminate_on_handler_error_raises() -> None:
    """Aligned with handler-exception behaviour: when
    ``terminate_on_handler_error=True`` AND a tool times out, the
    loop emits ``LoopTerminated(reason="tool_error")`` and re-raises
    ``ToolHandlerTimeout`` instead of converting to a tool_result."""
    from core.llm.tool_use import LoopTerminated, ToolHandlerTimeout

    def slow_handler(_inp: dict) -> str:
        time.sleep(0.5)
        return "too late"

    slow = ToolDef(name="slow", description="d", input_schema={}, handler=slow_handler)
    fp = _FakeProvider([_tool_call_response(("c1", "slow", {}))])
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [slow],
        tool_timeout_s=0.05,
        terminate_on_handler_error=True,
        events=seen.append,
    )
    with pytest.raises(ToolHandlerTimeout, match="exceeded"):
        loop.run("go")

    # LoopTerminated event was emitted with reason="tool_error" before
    # the exception propagated.
    final = next(e for e in seen if isinstance(e, LoopTerminated))
    assert final.reason == "tool_error"


def test_parallel_tool_calls_in_one_turn() -> None:
    """Provider returns multiple tool_calls in one turn → loop dispatches
    each, accumulates results, sends all back as one user message."""
    fp = _FakeProvider([
        _tool_call_response(
            ("c1", "echo", {"x": 1}),
            ("c2", "echo", {"x": 2}),
            ("c3", "echo", {"x": 3}),
        ),
        _text_response("ok"),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run("multi")
    assert out.tool_calls_made == 3
    second = fp.calls[1]["messages"]
    # Last user message in the second call holds all 3 tool_results.
    last_user = second[-1]
    assert last_user.role == "user"
    assert len(last_user.content) == 3


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


def test_events_emit_in_order_for_simple_run() -> None:
    """Event sequence for one tool-call turn followed by a COMPLETE turn:
    TurnStarted → TurnCompleted → ToolCallDispatched → ToolCallReturned →
    TurnStarted → TurnCompleted → LoopTerminated(complete)."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _text_response("done"),
    ])
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_echo_tool()], events=seen.append)
    loop.run("go")
    types = [type(e).__name__ for e in seen]
    assert types == [
        "TurnStarted", "TurnCompleted",
        "ToolCallDispatched", "ToolCallReturned",
        "TurnStarted", "TurnCompleted",
        "LoopTerminated",
    ]
    final = seen[-1]
    assert isinstance(final, LoopTerminated)
    assert final.reason == "complete"


def test_events_carry_iteration_index() -> None:
    """Iteration counter increments per turn — telemetry consumers use
    it to correlate per-iteration tool calls."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _text_response("done"),
    ])
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_echo_tool()], events=seen.append)
    loop.run("go")
    started = [e for e in seen if isinstance(e, TurnStarted)]
    assert [s.iteration for s in started] == [0, 1]


def test_events_report_cost_and_tokens() -> None:
    """``TurnCompleted.cost_usd`` matches what
    ``provider.compute_cost`` returned — allows live cost surveillance
    from the event stream."""
    fp = _FakeProvider([_text_response("ok")])
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_echo_tool()], events=seen.append)
    loop.run("hi")
    completed = [e for e in seen if isinstance(e, TurnCompleted)]
    assert len(completed) == 1
    expected = (100 * 3 + 50 * 15) / 1_000_000
    assert abs(completed[0].cost_usd - expected) < 1e-9


# ---------------------------------------------------------------------------
# Provider-specific kwargs forwarded
# ---------------------------------------------------------------------------


def test_provider_specific_kwargs_forwarded_to_turn() -> None:
    """``ToolUseLoop(**provider_specific)`` flows through to every
    ``provider.turn()`` call — providers receive their opt-ins (and
    ignore unknown ones)."""
    fp = _FakeProvider([_text_response("ok")])
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        anthropic_task_budget_beta=True,
        custom_flag="value",
    )
    loop.run("hi")
    assert fp.calls[0]["provider_specific"] == {
        "anthropic_task_budget_beta": True,
        "custom_flag": "value",
    }


# ---------------------------------------------------------------------------
# History resumption
# ---------------------------------------------------------------------------


def test_run_with_history_continues_from_prior_messages() -> None:
    """``run_with_history`` accepts prior conversation; the result's
    ``messages`` includes both prior + new turns — caller can persist
    and resume."""
    prior = [
        Message(role="user", content=[TextBlock(text="earlier")]),
        Message(role="assistant", content=[TextBlock(text="earlier reply")]),
    ]
    fp = _FakeProvider([_text_response("now-reply")])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run_with_history(prior, "now")
    # Result messages: 2 prior + 1 new user prompt + 1 assistant reply.
    assert len(out.messages) == 4
    assert out.messages[0] is prior[0]
    assert out.messages[1] is prior[1]
    # Provider saw all messages on its single turn.
    sent = fp.calls[0]["messages"]
    assert len(sent) == 3                          # prior + new prompt
    assert sent[-1].content[0].text == "now"


def test_run_with_empty_history_works() -> None:
    """Empty history is the same as fresh ``run()``."""
    fp = _FakeProvider([_text_response("hi")])
    loop = ToolUseLoop(fp, [_echo_tool()])
    out = loop.run_with_history([], "first")
    assert out.iterations == 1
    assert out.messages[0].content[0].text == "first"


# ---------------------------------------------------------------------------
# Cache control + capability gating
# ---------------------------------------------------------------------------


def test_cache_breakpoint_count_zero_when_provider_lacks_caching() -> None:
    """``TurnStarted.cache_breakpoints`` reports 0 on a non-caching
    provider regardless of the loop's :class:`CacheControl` settings —
    capability flag governs reality."""
    fp = _FakeProvider([_text_response("ok")], prompt_caching=False)
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        system="hello",
        cache_control=CacheControl(system=True, tools=True),
        events=seen.append,
    )
    loop.run("go")
    started = next(e for e in seen if isinstance(e, TurnStarted))
    assert started.cache_breakpoints == 0


def test_cache_breakpoint_count_reflects_optins_when_supported() -> None:
    """With caching support: count reflects which regions opted in."""
    fp = _FakeProvider([_text_response("ok")], prompt_caching=True)
    seen: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        system="hello",                               # caches if opted in
        cache_control=CacheControl(system=True, tools=True),
        events=seen.append,
    )
    loop.run("go")
    started = next(e for e in seen if isinstance(e, TurnStarted))
    assert started.cache_breakpoints == 2             # system + tools
