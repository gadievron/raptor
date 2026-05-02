"""Tests for ``core.llm.tool_use.anthropic.AnthropicToolUseProvider``.

The provider is exercised against a stub ``Anthropic`` client whose
``messages.create`` records every call's kwargs and returns a
pre-scripted response object. This keeps the tests offline while still
asserting the wire-format conversion (Message → Anthropic message,
tool schemas, cache_control markers, response normalisation).
"""

from __future__ import annotations

from typing import Any

import pytest

# AnthropicToolUseProvider's constructor requires the anthropic SDK;
# CI matrix runs without it skip this whole file cleanly. Import
# checks happen here (module level) so collection doesn't fail.
pytest.importorskip("anthropic")

from core.llm.tool_use import (
    CacheControl,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
)
from core.llm.tool_use.anthropic import AnthropicToolUseProvider


# ---------------------------------------------------------------------------
# Stub SDK objects mirroring just enough of the anthropic SDK's shapes.
# ---------------------------------------------------------------------------


class _StubBlock:
    def __init__(self, type_: str, **fields: Any) -> None:
        self.type = type_
        for k, v in fields.items():
            setattr(self, k, v)


class _StubUsage:
    def __init__(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        cache_creation_input_tokens: int = 0,
    ) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = cache_read_input_tokens
        self.cache_creation_input_tokens = cache_creation_input_tokens


class _StubResponse:
    def __init__(
        self,
        content: list[_StubBlock],
        stop_reason: str = "end_turn",
        usage: _StubUsage | None = None,
    ) -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage or _StubUsage()


class _StubMessages:
    """Records calls; returns the next scripted response per call."""
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: list[_StubResponse] = []

    def create(self, **kwargs: Any) -> _StubResponse:
        self.calls.append(kwargs)
        if not self.responses:
            return _StubResponse([])
        return self.responses.pop(0)


class _StubBetaMessages(_StubMessages):
    """Used to validate the beta task-budget routing path."""


class _StubBeta:
    def __init__(self, messages: _StubBetaMessages) -> None:
        self.messages = messages


class _StubClient:
    def __init__(self) -> None:
        self.messages = _StubMessages()
        self.beta = _StubBeta(_StubBetaMessages())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _provider_with_stub() -> tuple[AnthropicToolUseProvider, _StubClient]:
    """Construct a provider then swap in our stub client."""
    p = AnthropicToolUseProvider("claude-opus-4-6")
    client = _StubClient()
    p._client = client                                  # type: ignore[attr-defined]
    return p, client


def _echo_tool() -> ToolDef:
    return ToolDef(
        name="echo",
        description="echoes input back",
        input_schema={"type": "object"},
        handler=lambda inp: f"echoed:{inp}",
    )


# ---------------------------------------------------------------------------
# Capability flags + lookup
# ---------------------------------------------------------------------------


def test_capabilities_advertised() -> None:
    p, _ = _provider_with_stub()
    assert p.supports_tool_use() is True
    assert p.supports_prompt_caching() is True
    assert p.supports_parallel_tools() is True


def test_unknown_model_at_construction_raises() -> None:
    """The model lookup happens via ``model_data.context_window_for``
    which raises ``KeyError`` for unknown models. We let that surface
    rather than papering over it — silently using a wrong window would
    mis-gate the loop's context policy."""
    with pytest.raises(KeyError, match="unknown model"):
        AnthropicToolUseProvider("model-that-does-not-exist")


def test_context_window_and_price_from_model_data() -> None:
    p, _ = _provider_with_stub()
    # claude-opus-4-6: 1M context, $0.005/$0.025 per-1K → $5/$25 per-M
    assert p.context_window() == 1_000_000
    assert p.price_per_million() == (5.0, 25.0)


# ---------------------------------------------------------------------------
# turn() — request shape
# ---------------------------------------------------------------------------


def test_system_string_passes_through_when_uncached() -> None:
    """``CacheControl(system=False)`` → system is sent as a plain string,
    not a list. Avoids the cache_control marker and the list-form
    overhead when caching isn't wanted."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="hi")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="ping")])],
        tools=[],
        system="be helpful",
        cache_control=CacheControl(system=False, tools=False),
    )
    assert c.messages.calls[0]["system"] == "be helpful"


def test_system_uses_list_form_when_cached() -> None:
    """``CacheControl(system=True)`` → system is sent as a content list
    so we can attach the cache_control marker to the system block."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="hi")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
        system="hello",
        cache_control=CacheControl(system=True, tools=False),
    )
    sys_arg = c.messages.calls[0]["system"]
    assert isinstance(sys_arg, list)
    assert sys_arg[0]["text"] == "hello"
    assert sys_arg[0]["cache_control"] == {"type": "ephemeral"}


def test_tools_cache_marker_on_last_tool() -> None:
    """``CacheControl(tools=True)`` places the marker on the last tool
    in the array — Anthropic caches everything up to and including
    the marked block."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool(), ToolDef(
            name="other", description="d", input_schema={},
            handler=lambda _: "x",
        )],
        cache_control=CacheControl(system=False, tools=True),
    )
    sent_tools = c.messages.calls[0]["tools"]
    assert "cache_control" not in sent_tools[0]
    assert sent_tools[1]["cache_control"] == {"type": "ephemeral"}


def test_tools_cache_skipped_when_disabled() -> None:
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
        cache_control=CacheControl(system=False, tools=False),
    )
    sent_tools = c.messages.calls[0]["tools"]
    assert "cache_control" not in sent_tools[0]


def test_history_through_index_attaches_cache_marker() -> None:
    """``CacheControl(history_through_index=i)`` puts the marker on the
    last content block of message ``i``, so Anthropic caches every
    turn ≤ i (the stable conversation prefix)."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    history = [
        Message(role="user", content=[TextBlock(text="first")]),
        Message(role="assistant", content=[TextBlock(text="reply")]),
        Message(role="user", content=[TextBlock(text="latest")]),
    ]
    p.turn(
        messages=history, tools=[],
        cache_control=CacheControl(
            system=False, tools=False, history_through_index=1,
        ),
    )
    sent_msgs = c.messages.calls[0]["messages"]
    # Marker on message[1] (assistant "reply"), not on [0] or [2].
    assert "cache_control" not in sent_msgs[0]["content"][-1]
    assert sent_msgs[1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
    assert "cache_control" not in sent_msgs[2]["content"][-1]


def test_message_with_tool_call_passes_through() -> None:
    """Assistant turn with a :class:`ToolCall` block gets converted to
    Anthropic's ``tool_use`` shape verbatim."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    history = [
        Message(role="user", content=[TextBlock(text="go")]),
        Message(role="assistant", content=[
            TextBlock(text="thinking..."),
            ToolCall(id="t1", name="echo", input={"x": 1}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="t1", content="echoed:{'x':1}"),
        ]),
    ]
    p.turn(messages=history, tools=[_echo_tool()])
    sent = c.messages.calls[0]["messages"]
    assert sent[1]["content"][1] == {
        "type": "tool_use", "id": "t1", "name": "echo", "input": {"x": 1},
    }
    assert sent[2]["content"][0] == {
        "type": "tool_result", "tool_use_id": "t1",
        "content": "echoed:{'x':1}", "is_error": False,
    }


# ---------------------------------------------------------------------------
# turn() — response normalisation
# ---------------------------------------------------------------------------


def test_response_text_block_normalises_to_textblock() -> None:
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="hello world")],
        stop_reason="end_turn",
        usage=_StubUsage(input_tokens=10, output_tokens=5),
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert len(out.content) == 1
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "hello world"
    assert out.stop_reason is StopReason.COMPLETE
    assert out.input_tokens == 10
    assert out.output_tokens == 5


def test_response_tool_use_block_normalises_to_toolcall() -> None:
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("tool_use",
                    id="toolu_abc", name="echo", input={"q": "y"})],
        stop_reason="tool_use",
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
    )
    assert len(out.content) == 1
    call = out.content[0]
    assert isinstance(call, ToolCall)
    assert call.id == "toolu_abc"
    assert call.name == "echo"
    assert call.input == {"q": "y"}
    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL


def test_unknown_block_types_dropped() -> None:
    """Non-text / non-tool_use blocks (e.g. ``thinking``) get dropped —
    they don't affect the loop's tool-dispatch logic. Future support
    is additive."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [
            _StubBlock("thinking", text="..."),
            _StubBlock("text", text="answer"),
        ],
        stop_reason="end_turn",
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert len(out.content) == 1
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "answer"


def test_stop_reason_mapping() -> None:
    p, c = _provider_with_stub()
    cases = [
        ("end_turn", StopReason.COMPLETE),
        ("stop_sequence", StopReason.COMPLETE),
        ("tool_use", StopReason.NEEDS_TOOL_CALL),
        ("pause_turn", StopReason.PAUSE_TURN),
        ("max_tokens", StopReason.MAX_TOKENS),
        ("refusal", StopReason.REFUSED),
        ("totally_unknown", StopReason.ERROR),
    ]
    for native, expected in cases:
        c.messages.responses.append(_StubResponse(
            [_StubBlock("text", text="x")],
            stop_reason=native,
        ))
        out = p.turn(
            messages=[Message(role="user", content=[TextBlock(text="p")])],
            tools=[],
        )
        assert out.stop_reason is expected, native


# ---------------------------------------------------------------------------
# Cost computation (cache-aware)
# ---------------------------------------------------------------------------


def test_compute_cost_no_cache() -> None:
    """Without cache reads/writes, cost is the standard input + output
    rates applied to per-million."""
    p, _ = _provider_with_stub()
    # opus-4-6: in $5/M, out $25/M
    from core.llm.tool_use.types import TurnResponse
    resp = TurnResponse(
        content=[], stop_reason=StopReason.COMPLETE,
        input_tokens=1000, output_tokens=500,
    )
    expected = (1000 * 5 + 500 * 25) / 1_000_000
    assert abs(p.compute_cost(resp) - expected) < 1e-12


def test_compute_cost_with_cache_reads() -> None:
    """Cache reads are 0.1x the input rate per Anthropic's documented
    multipliers."""
    p, _ = _provider_with_stub()
    from core.llm.tool_use.types import TurnResponse
    resp = TurnResponse(
        content=[], stop_reason=StopReason.COMPLETE,
        input_tokens=100, output_tokens=50,
        cache_read_tokens=10_000,
    )
    base = (100 * 5 + 50 * 25) / 1_000_000
    cache = (10_000 * 5 * 0.1) / 1_000_000
    assert abs(p.compute_cost(resp) - (base + cache)) < 1e-12


def test_compute_cost_with_cache_writes() -> None:
    """Cache writes are 1.25x the input rate per Anthropic's
    documented multipliers."""
    p, _ = _provider_with_stub()
    from core.llm.tool_use.types import TurnResponse
    resp = TurnResponse(
        content=[], stop_reason=StopReason.COMPLETE,
        input_tokens=100, output_tokens=50,
        cache_write_tokens=10_000,
    )
    base = (100 * 5 + 50 * 25) / 1_000_000
    cache = (10_000 * 5 * 1.25) / 1_000_000
    assert abs(p.compute_cost(resp) - (base + cache)) < 1e-12


# ---------------------------------------------------------------------------
# Beta task-budget routing
# ---------------------------------------------------------------------------


def test_beta_task_budget_routes_to_beta_messages() -> None:
    """``anthropic_task_budget_beta=True`` routes through
    ``client.beta.messages.create`` instead of the standard endpoint
    AND passes the ``betas=[...]`` parameter — without the parameter
    the beta endpoint accepts the request but doesn't actually
    activate the beta (the bug v1 of this code shipped with)."""
    from core.llm.tool_use.anthropic import _TASK_BUDGET_BETA

    p, c = _provider_with_stub()
    c.beta.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
        anthropic_task_budget_beta=True,
    )
    assert len(c.messages.calls) == 0                # standard endpoint not called
    assert len(c.beta.messages.calls) == 1           # beta endpoint called
    sent = c.beta.messages.calls[0]
    assert sent.get("betas") == [_TASK_BUDGET_BETA]


def test_standard_endpoint_does_not_carry_betas_kwarg() -> None:
    """Without ``anthropic_task_budget_beta=True`` the request goes
    via the standard endpoint and must NOT carry a ``betas`` kwarg —
    the standard endpoint rejects unknown parameters."""
    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert len(c.messages.calls) == 1
    assert "betas" not in c.messages.calls[0]


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


def test_api_error_returns_error_stop_reason() -> None:
    """Permanent API errors surface as ``StopReason.ERROR`` after
    retries are exhausted (or immediately for non-transient errors)."""
    from anthropic import APIConnectionError                # type: ignore[import-not-found]

    p, c = _provider_with_stub()

    def _raise(**_kwargs: Any) -> _StubResponse:
        raise APIConnectionError(request=None)             # type: ignore[arg-type]

    c.messages.create = _raise                             # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert out.stop_reason is StopReason.ERROR
    assert out.content == []


# ---------------------------------------------------------------------------
# Retry on transient errors
# ---------------------------------------------------------------------------


def test_retries_on_transient_then_succeeds(monkeypatch) -> None:
    """Connection errors are transient — retried with backoff. After
    one failure the next attempt succeeds and the loop sees the
    successful response (not ERROR)."""
    from anthropic import APIConnectionError                # type: ignore[import-not-found]

    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.tool_use.anthropic.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _flaky(**_kwargs: Any) -> _StubResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise APIConnectionError(request=None)         # type: ignore[arg-type]
        return _StubResponse(
            [_StubBlock("text", text="recovered")],
            stop_reason="end_turn",
        )

    c.messages.create = _flaky                             # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert attempts["n"] == 2                              # 1 fail + 1 success
    assert out.stop_reason is StopReason.COMPLETE
    assert out.content[0].text == "recovered"


def test_retries_exhausted_returns_error(monkeypatch) -> None:
    """Once ``max_retries`` transient failures have occurred, surface
    ERROR. Caller (the loop) reports it as ``provider_error``."""
    from anthropic import APIConnectionError                # type: ignore[import-not-found]

    p = AnthropicToolUseProvider("claude-opus-4-6", max_retries=2)
    p._client = _StubClient()                              # type: ignore[attr-defined]
    monkeypatch.setattr("core.llm.tool_use.anthropic.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _always_fail(**_kwargs: Any) -> _StubResponse:
        attempts["n"] += 1
        raise APIConnectionError(request=None)             # type: ignore[arg-type]

    p._client.messages.create = _always_fail               # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    # max_retries=2 → 1 initial + 2 retries = 3 attempts before giving up.
    assert attempts["n"] == 3
    assert out.stop_reason is StopReason.ERROR


def test_permanent_4xx_fails_fast_no_retry(monkeypatch) -> None:
    """4xx errors other than 429 are permanent — burning the retry
    budget on hopeless retries (auth, schema validation) helps no-one."""
    from anthropic import APIStatusError                    # type: ignore[import-not-found]

    p = AnthropicToolUseProvider("claude-opus-4-6", max_retries=5)
    p._client = _StubClient()                              # type: ignore[attr-defined]
    monkeypatch.setattr("core.llm.tool_use.anthropic.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _403(**_kwargs: Any) -> _StubResponse:
        attempts["n"] += 1
        # APIStatusError(message, response, body); we synthesise minimum
        # shape needed for status_code attr.
        err = APIStatusError.__new__(APIStatusError)
        err.status_code = 403                              # type: ignore[attr-defined]
        raise err

    p._client.messages.create = _403                       # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert attempts["n"] == 1                              # no retries
    assert out.stop_reason is StopReason.ERROR


def test_429_is_retried(monkeypatch) -> None:
    """429 (rate limit) is retryable — distinct from 4xx auth errors."""
    from anthropic import APIStatusError                    # type: ignore[import-not-found]

    p = AnthropicToolUseProvider("claude-opus-4-6", max_retries=2)
    p._client = _StubClient()                              # type: ignore[attr-defined]
    monkeypatch.setattr("core.llm.tool_use.anthropic.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _flaky(**_kwargs: Any) -> _StubResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            err = APIStatusError.__new__(APIStatusError)
            err.status_code = 429                          # type: ignore[attr-defined]
            raise err
        return _StubResponse(
            [_StubBlock("text", text="ok")],
            stop_reason="end_turn",
        )

    p._client.messages.create = _flaky                     # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert attempts["n"] == 2
    assert out.stop_reason is StopReason.COMPLETE


# ---------------------------------------------------------------------------
# Provider-specific kwargs handling
# ---------------------------------------------------------------------------


def test_unrecognised_provider_kwargs_logged_at_debug(caplog) -> None:
    """Typos in provider_specific kwargs (e.g.,
    ``anthropic_task_budget_bata=True``) are silently accepted but
    emit a debug log — discoverable when troubleshooting without
    breaking graceful degradation across providers."""
    import logging

    p, c = _provider_with_stub()
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")], stop_reason="end_turn",
    ))

    with caplog.at_level(logging.DEBUG, logger="core.llm.tool_use.anthropic"):
        p.turn(
            messages=[Message(role="user", content=[TextBlock(text="x")])],
            tools=[],
            anthropic_task_budget_bata=True,                # typo — silently accepted
            random_other_kwarg=42,
        )

    msgs = [r.getMessage() for r in caplog.records]
    assert any("ignoring unrecognised" in m for m in msgs)
    assert any("anthropic_task_budget_bata" in m for m in msgs)
