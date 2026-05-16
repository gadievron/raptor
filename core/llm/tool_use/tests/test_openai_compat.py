"""Tests for ``OpenAICompatibleProvider.turn``.

Function-calling tool-use over the OpenAI SDK. Same shape covers OpenAI
proper, Gemini (via ``/openai`` compatibility endpoint), Mistral, and
Ollama via ``base_url`` overrides — only the model name and endpoint
differ. Tests stub the OpenAI SDK client to avoid network.
"""

from __future__ import annotations

from typing import Any

import pytest

# OpenAICompatibleProvider's constructor requires the openai SDK;
# CI matrix runs without it skip cleanly.
pytest.importorskip("openai")

from core.llm.config import ModelConfig
from core.llm.providers import OpenAICompatibleProvider
from core.llm.tool_use import (
    CacheControl,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
)


# ---------------------------------------------------------------------------
# Fakes — minimal OpenAI SDK shape
# ---------------------------------------------------------------------------


class _FakeFunctionCall:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, id_: str, name: str, arguments: str) -> None:
        self.id = id_
        self.type = "function"
        self.function = _FakeFunctionCall(name, arguments)


class _FakeMessage:
    def __init__(
        self,
        content: str | None = None,
        tool_calls: list[_FakeToolCall] | None = None,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _FakeChoice:
    def __init__(self, message: _FakeMessage, finish_reason: str = "stop") -> None:
        self.message = message
        self.finish_reason = finish_reason


class _FakeUsage:
    def __init__(self, prompt_tokens: int = 100, completion_tokens: int = 50) -> None:
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


class _FakeResponse:
    def __init__(
        self,
        choices: list[_FakeChoice],
        usage: _FakeUsage | None = None,
    ) -> None:
        self.choices = choices
        self.usage = usage or _FakeUsage()


class _FakeChatCompletions:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: list[_FakeResponse] = []

    def create(self, **kwargs: Any) -> _FakeResponse:
        self.calls.append(kwargs)
        if not self.responses:
            return _FakeResponse([_FakeChoice(_FakeMessage(content=""))])
        return self.responses.pop(0)


class _FakeChat:
    def __init__(self, completions: _FakeChatCompletions) -> None:
        self.completions = completions


class _FakeOpenAIClient:
    def __init__(self) -> None:
        self.chat = _FakeChat(_FakeChatCompletions())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _provider_with_stub() -> tuple[OpenAICompatibleProvider, _FakeOpenAIClient]:
    """Construct an :class:`OpenAICompatibleProvider` then swap in our
    stub SDK client. Uses ``gpt-4o`` as the model so the model-data
    lookup (``context_window`` / pricing) succeeds."""
    config = ModelConfig(
        provider="openai",
        model_name="gpt-4o",
        api_key="test-key",
        timeout=1,
    )
    p = OpenAICompatibleProvider(config)
    client = _FakeOpenAIClient()
    p.client = client                                       # type: ignore[assignment]
    return p, client


def _echo_tool() -> ToolDef:
    return ToolDef(
        name="echo",
        description="echoes input back",
        input_schema={"type": "object", "properties": {"x": {"type": "string"}}},
        handler=lambda inp: f"echoed:{inp}",
    )


# ---------------------------------------------------------------------------
# Capability flags
# ---------------------------------------------------------------------------


def test_capabilities_advertised() -> None:
    p, _ = _provider_with_stub()
    assert p.supports_tool_use() is True
    # OpenAI-compat doesn't expose a per-region cache mechanism.
    # Server-side caching on real OpenAI is automatic and not driven
    # by request fields, so this returns False.
    assert p.supports_prompt_caching() is False
    assert p.supports_parallel_tools() is True


# ---------------------------------------------------------------------------
# turn() — request shape
# ---------------------------------------------------------------------------


def test_tools_sent_in_function_calling_shape() -> None:
    """OpenAI's function-calling shape:
    ``tools=[{type:"function", function:{name,description,parameters}}]``."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[_echo_tool()],
    )
    assert len(c.chat.completions.calls) == 1
    sent = c.chat.completions.calls[0]
    assert sent["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "echo",
                "description": "echoes input back",
                "parameters": {
                    "type": "object",
                    "properties": {"x": {"type": "string"}},
                },
            },
        },
    ]


def test_empty_tools_omits_kwarg() -> None:
    """Passing no tools means the ``tools`` kwarg shouldn't appear in
    the request — OpenAI accepts the absence; sending an empty list
    is also valid but we stay conservative."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )
    assert "tools" not in c.chat.completions.calls[0]


def test_system_prepended_as_role_system_message() -> None:
    """OpenAI takes the system prompt as the first message with
    ``role:"system"`` (unlike Anthropic's top-level ``system`` field)."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
        system="be helpful",
    )
    sent = c.chat.completions.calls[0]
    assert sent["messages"][0] == {"role": "system", "content": "be helpful"}
    assert sent["messages"][1]["role"] == "user"


def test_no_system_omits_system_message() -> None:
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )
    sent = c.chat.completions.calls[0]
    assert all(m["role"] != "system" for m in sent["messages"])


def test_assistant_with_tool_call_converts_correctly() -> None:
    """An assistant turn with a :class:`ToolCall` block becomes a single
    OpenAI message with ``tool_calls=[{...}]``; the JSON-encoded
    arguments string is the wire format OpenAI requires."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    history = [
        Message(role="user", content=[TextBlock(text="go")]),
        Message(role="assistant", content=[
            TextBlock(text="thinking..."),
            ToolCall(id="call_1", name="echo", input={"x": "y"}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="call_1", content="echoed"),
        ]),
    ]
    p.turn(messages=history, tools=[_echo_tool()])
    sent = c.chat.completions.calls[0]["messages"]
    # assistant turn — text content + tool_calls in one message
    assistant = next(m for m in sent if m["role"] == "assistant")
    assert assistant["content"] == "thinking..."
    assert assistant["tool_calls"] == [{
        "id": "call_1",
        "type": "function",
        "function": {"name": "echo", "arguments": '{"x": "y"}'},
    }]


def test_user_with_tool_results_splits_into_role_tool_messages() -> None:
    """OpenAI splits user messages with multiple :class:`ToolResult`
    blocks into N ``role:"tool"`` messages — distinct from Anthropic
    which packs them in one user message's content array."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    history = [
        Message(role="user", content=[
            ToolResult(tool_use_id="call_a", content="result_a"),
            ToolResult(tool_use_id="call_b", content="result_b"),
        ]),
    ]
    p.turn(messages=history, tools=[])
    sent = c.chat.completions.calls[0]["messages"]
    tool_msgs = [m for m in sent if m["role"] == "tool"]
    assert len(tool_msgs) == 2
    assert tool_msgs[0] == {
        "role": "tool", "tool_call_id": "call_a", "content": "result_a",
    }
    assert tool_msgs[1] == {
        "role": "tool", "tool_call_id": "call_b", "content": "result_b",
    }


def test_cache_control_silently_ignored() -> None:
    """OpenAI-compat doesn't support per-region caching. ``CacheControl``
    arguments are accepted but never reach the wire."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
    ))
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[_echo_tool()],
        cache_control=CacheControl(system=True, tools=True,
                                   history_through_index=0),
    )
    sent = c.chat.completions.calls[0]
    # No cache_control field anywhere in the request.
    serialised = repr(sent)
    assert "cache_control" not in serialised


# ---------------------------------------------------------------------------
# turn() — response normalisation
# ---------------------------------------------------------------------------


def test_text_response_normalises_to_textblock() -> None:
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(
            _FakeMessage(content="hello world"),
            finish_reason="stop",
        )],
        usage=_FakeUsage(prompt_tokens=20, completion_tokens=8),
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert out.stop_reason is StopReason.COMPLETE
    assert len(out.content) == 1
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "hello world"
    assert out.input_tokens == 20
    assert out.output_tokens == 8


def test_tool_calls_response_normalises_to_toolcalls() -> None:
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(
            _FakeMessage(
                content=None,
                tool_calls=[
                    _FakeToolCall("call_1", "echo", '{"x": "a"}'),
                    _FakeToolCall("call_2", "echo", '{"x": "b"}'),
                ],
            ),
            finish_reason="tool_calls",
        )],
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
    )
    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert len(out.content) == 2
    for block, expected_id, expected_x in zip(
        out.content, ["call_1", "call_2"], ["a", "b"],
    ):
        assert isinstance(block, ToolCall)
        assert block.id == expected_id
        assert block.name == "echo"
        assert block.input == {"x": expected_x}


def test_text_plus_tool_calls_in_single_response() -> None:
    """OpenAI returns text and tool_calls as parallel fields on the
    same message. Both must surface as separate content blocks."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(
            _FakeMessage(
                content="checking...",
                tool_calls=[_FakeToolCall("call_1", "echo", '{"x": "a"}')],
            ),
            finish_reason="tool_calls",
        )],
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
    )
    assert len(out.content) == 2
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "checking..."
    assert isinstance(out.content[1], ToolCall)


def test_finish_reason_mapping() -> None:
    p, c = _provider_with_stub()
    cases = [
        ("stop", StopReason.COMPLETE),
        ("tool_calls", StopReason.NEEDS_TOOL_CALL),
        ("function_call", StopReason.NEEDS_TOOL_CALL),     # legacy alias
        ("length", StopReason.MAX_TOKENS),
        ("content_filter", StopReason.REFUSED),
        ("unknown_reason", StopReason.ERROR),
    ]
    for native, expected in cases:
        c.chat.completions.responses.append(_FakeResponse(
            [_FakeChoice(_FakeMessage(content="x"), finish_reason=native)],
        ))
        out = p.turn(
            messages=[Message(role="user", content=[TextBlock(text="p")])],
            tools=[],
        )
        assert out.stop_reason is expected, f"native={native!r}"


def test_malformed_tool_arguments_become_empty_dict() -> None:
    """Defensive: if OpenAI returns invalid JSON in
    ``function.arguments`` (rare but observed in the wild on small
    models), we surface the call with empty input rather than
    crashing the loop."""
    p, c = _provider_with_stub()
    c.chat.completions.responses.append(_FakeResponse(
        [_FakeChoice(
            _FakeMessage(
                tool_calls=[_FakeToolCall("call_1", "echo", "not-json")],
            ),
            finish_reason="tool_calls",
        )],
    ))
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
    )
    assert isinstance(out.content[0], ToolCall)
    assert out.content[0].input == {}


# ---------------------------------------------------------------------------
# Cost computation
# ---------------------------------------------------------------------------


def test_compute_cost_no_cache() -> None:
    """Default ``compute_cost`` (inherited from ``LLMProvider``)
    handles standard input/output tokens. Cache fields are 0 because
    OpenAI-compat doesn't surface them."""
    p, _ = _provider_with_stub()
    # gpt-4o: $2.50/M input, $10/M output
    from core.llm.tool_use.types import TurnResponse
    resp = TurnResponse(
        content=[], stop_reason=StopReason.COMPLETE,
        input_tokens=1000, output_tokens=500,
    )
    expected = (1000 * 2.5 + 500 * 10) / 1_000_000
    assert abs(p.compute_cost(resp) - expected) < 1e-12


# ---------------------------------------------------------------------------
# Error handling + retries
# ---------------------------------------------------------------------------


def test_api_error_returns_error_stop_reason(monkeypatch) -> None:
    """Network errors bubble up to ``StopReason.ERROR`` after retries."""
    from openai import APIConnectionError                    # type: ignore[import-not-found]

    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    def _always_fail(**_kwargs: Any) -> _FakeResponse:
        raise APIConnectionError(request=None)              # type: ignore[arg-type]

    c.chat.completions.create = _always_fail                # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
        max_retries=1,
    )
    assert out.stop_reason is StopReason.ERROR


def test_transient_then_recovers(monkeypatch) -> None:
    """One transient failure, then success on retry — caller sees
    successful response, not ERROR."""
    from openai import APIConnectionError                    # type: ignore[import-not-found]

    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _flaky(**_kwargs: Any) -> _FakeResponse:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise APIConnectionError(request=None)          # type: ignore[arg-type]
        return _FakeResponse([_FakeChoice(
            _FakeMessage(content="recovered"), finish_reason="stop",
        )])

    c.chat.completions.create = _flaky                      # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
        max_retries=2,
    )
    assert attempts["n"] == 2
    assert out.stop_reason is StopReason.COMPLETE
    assert out.content[0].text == "recovered"


def test_permanent_4xx_fails_fast(monkeypatch) -> None:
    """Non-429 4xx errors are permanent — no retries even if
    ``max_retries`` is high."""
    from openai import APIStatusError                        # type: ignore[import-not-found]

    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    attempts = {"n": 0}

    def _403(**_kwargs: Any) -> _FakeResponse:
        attempts["n"] += 1
        # Construct via the proper signature so the SDK's own
        # retry-classifier sees `request` / `response` /
        # `status_code` consistently with production. See
        # cluster 726 / `_tool_unsupported_error` rationale.
        import httpx
        response = httpx.Response(
            status_code=403,
            request=httpx.Request("POST", "https://example.invalid/v1/chat/completions"),
        )
        err = APIStatusError("Forbidden", response=response, body={"error": "Forbidden"})
        raise err

    c.chat.completions.create = _403                         # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
        max_retries=5,
    )
    assert attempts["n"] == 1                                # no retries
    assert out.stop_reason is StopReason.ERROR


# ---------------------------------------------------------------------------
# Runtime detection — tool-use unsupported by the bound model
# ---------------------------------------------------------------------------


def _tool_unsupported_error(message: str = "model 'foo' does not support tools"):
    """Build a 400 APIStatusError whose body matches the heuristic.

    Cluster 726: pre-fix this used `APIStatusError.__new__(...)`
    to bypass the SDK constructor, then manually set
    `status_code` / `body` / `message`. The mock skipped the
    SDK's `__init__` which sets `request` and `response`
    attributes too — code paths that read `err.request` /
    `err.response` (the SDK's own retry-classification logic
    in newer versions) hit AttributeError instead of seeing
    the simulated 400. The mock contract drifted from the
    real API and tests could pass while production code
    silently skipped its branch on the same shape.
    Construct via the proper `__init__` signature
    `(message, *, response, body)` with a stub
    `httpx.Response` so the SDK sees the same attribute
    surface it does in real life.
    """
    from openai import APIStatusError                         # type: ignore[import-not-found]
    import httpx
    response = httpx.Response(
        status_code=400,
        request=httpx.Request("POST", "https://example.invalid/v1/chat/completions"),
    )
    body = {"error": {"message": message}}
    err = APIStatusError(message, response=response, body=body)
    return err


def test_unit_is_tool_use_unsupported_error_recognises_400_with_keyword() -> None:
    """The detection heuristic accepts only 4xx (not 429) errors whose
    body mentions a tool/function keyword paired with a not-supported
    phrase. Tested directly for clarity and to lock the heuristic."""
    from core.llm.providers import _is_tool_use_unsupported_error
    assert _is_tool_use_unsupported_error(
        _tool_unsupported_error("model X does not support tools")
    )
    assert _is_tool_use_unsupported_error(
        _tool_unsupported_error("function calling is not supported by this model")
    )


def test_unit_is_tool_use_unsupported_error_rejects_429() -> None:
    """429 is transient — never treat as tool-rejection."""
    from openai import APIStatusError
    from core.llm.providers import _is_tool_use_unsupported_error
    err = APIStatusError.__new__(APIStatusError)
    err.status_code = 429                                     # type: ignore[attr-defined]
    err.body = {"error": {"message": "rate limit exceeded; tools temporarily unavailable"}}  # type: ignore[attr-defined]
    assert not _is_tool_use_unsupported_error(err)


def test_unit_is_tool_use_unsupported_error_rejects_5xx() -> None:
    """5xx is server-side / transient — never treat as tool-rejection,
    even if the message happens to contain tool keywords."""
    from openai import APIStatusError
    from core.llm.providers import _is_tool_use_unsupported_error
    err = APIStatusError.__new__(APIStatusError)
    err.status_code = 503                                     # type: ignore[attr-defined]
    err.body = {"error": {"message": "tools backend unavailable"}}  # type: ignore[attr-defined]
    assert not _is_tool_use_unsupported_error(err)


def test_unit_is_tool_use_unsupported_error_rejects_unrelated_4xx() -> None:
    """A 401 auth failure or 400 schema error must NOT be treated as
    tool-unsupported — those are user-fixable problems with their own
    failure paths."""
    from openai import APIStatusError
    from core.llm.providers import _is_tool_use_unsupported_error
    err = APIStatusError.__new__(APIStatusError)
    err.status_code = 401                                     # type: ignore[attr-defined]
    err.body = {"error": {"message": "invalid API key"}}      # type: ignore[attr-defined]
    assert not _is_tool_use_unsupported_error(err)


def test_unit_is_tool_use_unsupported_error_requires_negation_phrase() -> None:
    """Pure mention of 'tools' / 'function' isn't enough — the error
    must also say something is not supported. Otherwise a generic 400
    that happens to mention tools (e.g., 'tools schema invalid') would
    trigger a wrong fallback."""
    from openai import APIStatusError
    from core.llm.providers import _is_tool_use_unsupported_error
    err = APIStatusError.__new__(APIStatusError)
    err.status_code = 400                                     # type: ignore[attr-defined]
    err.body = {"error": {"message": "tools[0].function.name: invalid"}}  # type: ignore[attr-defined]
    assert not _is_tool_use_unsupported_error(err)


def test_turn_falls_back_to_synthesis_on_tool_unsupported(monkeypatch) -> None:
    """First sign of a tool-rejection: the next ``turn()`` synthesises
    via the JSON-protocol fallback. Result is a valid TurnResponse —
    same shape native turn() emits — so the loop continues."""
    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    # generate() is what _tool_use_fallback calls — return a JSON
    # tool-call that the parser will recognise.
    def _generate(prompt, system_prompt=None, **kwargs):
        from core.llm.providers import LLMResponse
        return LLMResponse(
            content='{"tool": "echo", "input": {"x": "hi"}}',
            model="gpt-4o", provider="openai",
            tokens_used=10, cost=0.0, finish_reason="stop",
            input_tokens=4, output_tokens=6,
        )
    p.generate = _generate                                    # type: ignore[method-assign]

    attempts = {"native": 0}
    def _reject(**_kwargs: Any) -> Any:
        attempts["native"] += 1
        raise _tool_unsupported_error()

    c.chat.completions.create = _reject                       # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[_echo_tool()],
        max_retries=3,
    )
    assert attempts["native"] == 1                            # no retry on tool-rejection
    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert isinstance(out.content[0], ToolCall)
    assert out.content[0].name == "echo"
    assert p._tool_use_unsupported is True
    assert p.supports_tool_use() is False                     # capability flag flipped


def test_turn_subsequent_calls_skip_native_when_unsupported(monkeypatch) -> None:
    """After detection, subsequent turn() calls go straight to the
    fallback — no wasted round-trip per turn."""
    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    def _generate(prompt, system_prompt=None, **kwargs):
        from core.llm.providers import LLMResponse
        return LLMResponse(
            content="text reply", model="gpt-4o", provider="openai",
            tokens_used=10, cost=0.0, finish_reason="stop",
            input_tokens=4, output_tokens=6,
        )
    p.generate = _generate                                    # type: ignore[method-assign]

    # Pre-flip the flag (simulates "already detected on a prior call")
    p._tool_use_unsupported = True

    attempts = {"native": 0}
    def _spy(**_kwargs: Any) -> Any:
        attempts["native"] += 1
        return _FakeResponse([_FakeChoice(_FakeMessage(content="x"))])

    c.chat.completions.create = _spy                          # type: ignore[method-assign]

    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[_echo_tool()],
    )
    assert attempts["native"] == 0                            # never tried native


def test_turn_no_tools_uses_native_even_after_unsupported_flag(monkeypatch) -> None:
    """The flag only short-circuits when tools were actually requested.
    Plain text completions (``tools=[]``) keep using the native chat
    endpoint — the tool-rejection didn't apply to text-only paths."""
    p, c = _provider_with_stub()

    p._tool_use_unsupported = True

    attempts = {"native": 0}
    def _ok(**_kwargs: Any) -> Any:
        attempts["native"] += 1
        return _FakeResponse([_FakeChoice(_FakeMessage(content="text"))])

    c.chat.completions.create = _ok                           # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )
    assert attempts["native"] == 1
    assert out.stop_reason is StopReason.COMPLETE


def test_turn_unrelated_4xx_does_not_flip_flag(monkeypatch) -> None:
    """A 401 or schema-error 400 must NOT flip the flag. Existing
    fail-fast behaviour should be preserved."""
    p, c = _provider_with_stub()
    monkeypatch.setattr("core.llm.providers.time.sleep", lambda _s: None)

    from openai import APIStatusError
    err = APIStatusError.__new__(APIStatusError)
    err.status_code = 401                                     # type: ignore[attr-defined]
    err.body = {"error": {"message": "invalid api key"}}      # type: ignore[attr-defined]

    def _401(**_kwargs: Any) -> Any:
        raise err

    c.chat.completions.create = _401                          # type: ignore[method-assign]

    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[_echo_tool()],
        max_retries=3,
    )
    assert p._tool_use_unsupported is False                   # flag NOT flipped
    assert out.stop_reason is StopReason.ERROR                # falls through to existing 4xx path
