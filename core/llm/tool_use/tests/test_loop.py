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


def test_max_seconds_terminates_pre_flight(monkeypatch) -> None:
    """Wall-clock budget caps the whole run. Pre-flight check before
    each iteration; once elapsed >= max_seconds, the loop returns a
    ``terminated_by="max_seconds"`` ToolLoopResult — distinct from
    cost / iteration / context termination so callers can treat
    "API was slow today" differently from "we made too many calls"."""
    # Fake clock: each ``time.monotonic()`` call advances 4 seconds.
    # First call (wall_start) → 0; second (iter 0 check) → 4;
    # third (iter 1 check) → 8 → triggers cap at max_seconds=6.
    clock = {"t": 0.0}
    def _tick() -> float:
        v = clock["t"]
        clock["t"] += 4.0
        return v
    monkeypatch.setattr("core.llm.tool_use.loop.time.monotonic", _tick)

    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _tool_call_response(("c2", "echo", {})),                   # never reached
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], max_seconds=6.0)
    out = loop.run("slow API")
    assert out.terminated_by == "max_seconds"
    assert len(fp.calls) == 1                                       # 1 turn before cap


def test_max_seconds_emits_loop_terminated_event() -> None:
    """The structured event stream surfaces ``LoopTerminated(reason=
    "max_seconds")`` so subscribers can distinguish wall-clock cap
    from other termination reasons."""
    events: list[Any] = []
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
    ] * 50)
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        max_seconds=0.0,                                            # immediate cap
        events=events.append,
    )
    out = loop.run("hi")
    assert out.terminated_by == "max_seconds"
    terminated = [e for e in events if isinstance(e, LoopTerminated)]
    assert len(terminated) == 1
    assert terminated[0].reason == "max_seconds"


def test_max_seconds_none_means_no_cap() -> None:
    """Default behaviour preserved: ``max_seconds=None`` (the default)
    leaves the wall-clock check disabled. The loop runs to natural
    completion regardless of how long it takes."""
    fp = _FakeProvider([_text_response("done")])
    loop = ToolUseLoop(fp, [_echo_tool()])                          # no max_seconds
    out = loop.run("hi")
    assert out.terminated_by == "complete"


# ---------------------------------------------------------------------------
# max_total_tokens — cumulative input+output token cap
# ---------------------------------------------------------------------------


def test_max_total_tokens_terminates_pre_flight() -> None:
    """Token budget caps the whole run on cumulative input+output.
    Each turn here costs 100+50 = 150 tokens; cap=400 fires after 3
    turns. Distinct termination reason from cost / iter / time so
    callers can distinguish "we exhausted the token allowance" from
    other budget classes."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {})),
        _tool_call_response(("c2", "echo", {})),
        _tool_call_response(("c3", "echo", {})),                   # never reached
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], max_total_tokens=400)
    out = loop.run("token-bounded")
    assert out.terminated_by == "max_total_tokens"
    assert len(fp.calls) <= 3                                       # gate fires before 3rd call


def test_max_total_tokens_emits_loop_terminated_event() -> None:
    """Subscribers see ``LoopTerminated(reason="max_total_tokens")``
    distinct from other termination reasons."""
    events: list[Any] = []
    fp = _FakeProvider([_tool_call_response(("c", "echo", {}))] * 50)
    loop = ToolUseLoop(
        fp, [_echo_tool()],
        max_total_tokens=1,                                         # immediate cap on iter 0+
        events=events.append,
    )
    out = loop.run("hi")
    # 1 token cap, 100+50 per turn → fires on iteration 1
    assert out.terminated_by == "max_total_tokens"
    terminated = [e for e in events if isinstance(e, LoopTerminated)]
    assert len(terminated) == 1
    assert terminated[0].reason == "max_total_tokens"


def test_max_total_tokens_none_means_no_cap() -> None:
    """Default behaviour preserved when ``max_total_tokens=None``."""
    fp = _FakeProvider([_text_response("done")])
    loop = ToolUseLoop(fp, [_echo_tool()])                          # no token cap
    out = loop.run("hi")
    assert out.terminated_by == "complete"


def test_provider_error_message_surfaces_on_loop_result() -> None:
    """When the provider returns ``StopReason.ERROR`` with an
    ``error_message`` populated, the loop forwards it onto both the
    ``LoopTerminated`` event and ``ToolLoopResult.error_message`` so
    callers can present the actual cause to operators rather than
    seeing it only in warning logs."""
    events: list[Any] = []
    fp = _FakeProvider([
        TurnResponse(
            content=[],
            stop_reason=StopReason.ERROR,
            input_tokens=0, output_tokens=0,
            error_message="permanent error after 1 attempt(s): 401 invalid api key",
        ),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], events=events.append)
    result = loop.run("hi")

    assert result.terminated_by == "provider_error"
    assert result.error_message is not None
    assert "401" in result.error_message
    terminated = [e for e in events if isinstance(e, LoopTerminated)]
    assert len(terminated) == 1
    assert terminated[0].error_message == result.error_message


def test_provider_error_with_no_message_yields_none() -> None:
    """Backward compat: providers that return ``ERROR`` without
    ``error_message`` produce ``ToolLoopResult.error_message=None``,
    same shape as pre-2026-05-04 behaviour. No spurious string."""
    fp = _FakeProvider([
        TurnResponse(
            content=[],
            stop_reason=StopReason.ERROR,
            input_tokens=0, output_tokens=0,
            # no error_message set
        ),
    ])
    loop = ToolUseLoop(fp, [_echo_tool()])
    result = loop.run("hi")
    assert result.terminated_by == "provider_error"
    assert result.error_message is None


def test_max_seconds_real_clock_e2e() -> None:
    """End-to-end against real ``time.monotonic`` (no monkeypatch).

    Verifies the gate fires on actual wall-clock — catches bugs the
    determinism-mocked tests above can't, e.g. ``time.time()`` vs
    ``time.monotonic()`` mixups, sign errors in the elapsed
    computation, or slipped imports of the clock function. ~1s of
    test time; a slow-handler provider sleeps 0.3s per turn, the
    cap fires after ~3 turns of a max_seconds=1.0 budget.
    """
    class _SlowProvider(_FakeProvider):
        """Sleep mid-turn to consume real wall-clock between cap checks."""
        def turn(self, messages, tools, *, system, max_tokens,
                 cache_control, **provider_specific) -> TurnResponse:
            time.sleep(0.3)
            return super().turn(
                messages, tools, system=system, max_tokens=max_tokens,
                cache_control=cache_control, **provider_specific,
            )

    fp = _SlowProvider([
        _tool_call_response(("c", "echo", {})) for _ in range(20)
    ])
    loop = ToolUseLoop(fp, [_echo_tool()], max_seconds=1.0)
    out = loop.run("slow-api day")

    assert out.terminated_by == "max_seconds"
    # Expected ~3 turns at 0.3s/turn under a 1.0s cap, but timing slop
    # under load (CI jitter, GC pauses) widens the window. The
    # invariant is "the cap fired and bounded iterations" — exact count
    # is timing-dependent.
    assert 1 <= out.iterations <= 6
    # Sanity: at least one turn ran (cap doesn't fire pre-flight on
    # iter 0 because elapsed is ~0).
    assert len(fp.calls) >= 1


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


# ---------------------------------------------------------------------------
# x-source provenance validation
# ---------------------------------------------------------------------------

from core.llm.tool_use import ToolCallBlocked


def _discovered_tool(name: str = "lookup") -> ToolDef:
    """Tool with a discovered field for x-source tests."""
    return ToolDef(
        name=name,
        description="looks up a repo by slug",
        input_schema={
            "type": "object",
            "properties": {
                "slug": {"type": "string", "x-source": "discovered"},
            },
            "required": ["slug"],
        },
        handler=lambda inp: f'{{"found": "{inp["slug"]}"}}',
    )


def _prompt_tool(name: str = "fetch_cve") -> ToolDef:
    """Tool with a prompt field for x-source tests."""
    return ToolDef(
        name=name,
        description="fetches a CVE by ID",
        input_schema={
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "x-source": "prompt"},
            },
            "required": ["cve_id"],
        },
        handler=lambda inp: f'{{"id": "{inp["cve_id"]}"}}',
    )


def _mixed_tool() -> ToolDef:
    """Tool with both prompt and discovered fields."""
    return ToolDef(
        name="check",
        description="cross-checks a CVE against a repo",
        input_schema={
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "x-source": "prompt"},
                "slug":   {"type": "string", "x-source": "discovered"},
                "sha":    {"type": "string", "x-source": "discovered"},
            },
            "required": ["cve_id", "slug", "sha"],
        },
        handler=lambda inp: '{"ok": true}',
    )


def test_xsource_blocks_hallucinated_discovered_field() -> None:
    """A discovered field value not in prompt or prior outputs is blocked."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "lookup", {"slug": "hallucinated/repo"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_discovered_tool()], events=events.append)
    result = loop.run("Analyze CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 1
    assert "slug" in blocked[0].blocked_fields
    assert blocked[0].blocked_fields["slug"] == "hallucinated/repo"

    returned = [e for e in events if isinstance(e, ToolCallReturned)]
    assert returned[0].result.is_error
    assert "x-source" in returned[0].result.content


def test_xsource_passes_value_from_prompt() -> None:
    """A discovered field whose value appears in the prompt is accepted."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "lookup", {"slug": "openssl/openssl"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_discovered_tool()], events=events.append)
    result = loop.run("Check openssl/openssl for CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0
    returned = [e for e in events if isinstance(e, ToolCallReturned)]
    assert not returned[0].result.is_error


def test_xsource_passes_value_from_prior_tool_output() -> None:
    """A discovered field value from a prior tool result is accepted."""
    source_tool = ToolDef(
        name="hints",
        description="returns hints",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "x-source": "prompt"},
        }},
        handler=lambda inp: '{"slug": "curl/curl", "sha": "abc123def"}',
    )
    fp = _FakeProvider([
        _tool_call_response(("c1", "hints", {"cve_id": "CVE-2024-1234"})),
        _tool_call_response(("c2", "lookup", {"slug": "curl/curl"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [source_tool, _discovered_tool()], events=events.append,
    )
    result = loop.run("Analyze CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0


def test_xsource_blocks_value_not_from_prior_output() -> None:
    """Discovered value not matching any prior tool output is blocked."""
    source_tool = ToolDef(
        name="hints",
        description="returns hints",
        input_schema={"type": "object", "properties": {
            "cve_id": {"type": "string", "x-source": "prompt"},
        }},
        handler=lambda inp: '{"slug": "curl/curl"}',
    )
    fp = _FakeProvider([
        _tool_call_response(("c1", "hints", {"cve_id": "CVE-2024-1234"})),
        _tool_call_response(("c2", "lookup", {"slug": "wrong/repo"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(
        fp, [source_tool, _discovered_tool()], events=events.append,
    )
    result = loop.run("Analyze CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 1
    assert blocked[0].blocked_fields["slug"] == "wrong/repo"


def test_xsource_prompt_field_not_validated() -> None:
    """Prompt-annotated fields are never blocked, even with novel values."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "fetch_cve", {"cve_id": "CVE-9999-0000"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_prompt_tool()], events=events.append)
    result = loop.run("go")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0


def test_xsource_no_annotations_means_no_validation() -> None:
    """Tools without x-source annotations are dispatched unconditionally."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "echo", {"anything": "hallucinated"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_echo_tool()], events=events.append)
    result = loop.run("go")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0
    returned = [e for e in events if isinstance(e, ToolCallReturned)]
    assert not returned[0].result.is_error


def test_xsource_mixed_tool_blocks_only_discovered() -> None:
    """Only discovered fields are validated; prompt fields pass through."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "check", {
            "cve_id": "CVE-2024-1234",
            "slug": "hallucinated/repo",
            "sha": "deadbeef123456",
        })),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_mixed_tool()], events=events.append)
    result = loop.run("Analyze CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 1
    assert "slug" in blocked[0].blocked_fields
    assert "sha" in blocked[0].blocked_fields
    assert "cve_id" not in blocked[0].blocked_fields


def test_xsource_known_values_grow_across_turns() -> None:
    """Values from turn N's output are available in turn N+1."""
    tool_a = ToolDef(
        name="search",
        description="search",
        input_schema={"type": "object", "properties": {
            "q": {"type": "string", "x-source": "prompt"},
        }},
        handler=lambda inp: '{"results": [{"slug": "new-org/new-repo"}]}',
    )
    tool_b = _discovered_tool("lookup")

    fp = _FakeProvider([
        _tool_call_response(("c1", "search", {"q": "CVE-2024-1234"})),
        _tool_call_response(("c2", "lookup", {"slug": "new-org/new-repo"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [tool_a, tool_b], events=events.append)
    result = loop.run("Analyze CVE-2024-1234")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0


def test_xsource_slash_split_matches_components() -> None:
    """Prompt text 'openssl/openssl' seeds both whole and components."""
    fp = _FakeProvider([
        _tool_call_response(("c1", "lookup", {"slug": "openssl"})),
        _text_response("done"),
    ])
    events: list[LoopEvent] = []
    loop = ToolUseLoop(fp, [_discovered_tool()], events=events.append)
    result = loop.run("Check openssl/openssl")

    blocked = [e for e in events if isinstance(e, ToolCallBlocked)]
    assert len(blocked) == 0
