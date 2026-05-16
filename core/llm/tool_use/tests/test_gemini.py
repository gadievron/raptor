"""Tests for ``GeminiProvider.turn`` — JSON-protocol synthesis fallback.

The native google-genai SDK exposes Gemini's function-calling, but
``GeminiProvider`` doesn't wire that up; users wanting native
function-calling install ``openai`` alongside and the factory routes
them through :class:`OpenAICompatibleProvider` against Gemini's
OpenAI-compat endpoint.

This file covers the genai-only path: ``turn()`` delegates to the
ABC's :meth:`_tool_use_fallback`, identical to the synthesis path
:class:`ClaudeCodeLLMProvider` uses.
"""

from __future__ import annotations

from typing import Any

import pytest

# google-genai SDK gate — CI runs without it skip cleanly.
pytest.importorskip("google.genai")

from core.llm.config import ModelConfig
from core.llm.providers import GeminiProvider, LLMResponse
from core.llm.tool_use import (
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
)


def _config() -> ModelConfig:
    return ModelConfig(
        provider="gemini",
        model_name="gemini-2.5-pro",
        api_key="test-key",
        timeout=1,
    )


def _echo_tool() -> ToolDef:
    return ToolDef(
        name="echo",
        description="echo input back",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        handler=lambda inp: f"echoed:{inp.get('q', '')}",
    )


def _user(text: str) -> Message:
    return Message(role="user", content=[TextBlock(text=text)])


# ---------------------------------------------------------------------------
# Capability flags
# ---------------------------------------------------------------------------


def test_capabilities_advertise_synthesis_path() -> None:
    """``supports_tool_use`` is True (via synthesis), but
    ``supports_parallel_tools`` is False — the JSON-protocol fallback
    only handles one tool call per turn. Caching off — Gemini doesn't
    expose per-region cache breakpoints."""
    p = GeminiProvider(_config())
    assert p.supports_tool_use() is True
    assert p.supports_parallel_tools() is False
    assert p.supports_prompt_caching() is False


# ---------------------------------------------------------------------------
# turn() delegates to _tool_use_fallback
# ---------------------------------------------------------------------------


def _stub_generate(text: str) -> Any:
    """Replacement for ``self.generate`` that returns canned text without
    hitting the SDK."""
    def _g(prompt: str, system_prompt: Any = None, **_kw: Any) -> LLMResponse:
        return LLMResponse(
            content=text,
            model="gemini-2.5-pro",
            provider="gemini",
            tokens_used=10,
            cost=0.0,
            finish_reason="stop",
            input_tokens=4,
            output_tokens=6,
        )
    return _g


def test_turn_text_response_returns_complete() -> None:
    p = GeminiProvider(_config())
    p.generate = _stub_generate("just a plain answer")               # type: ignore[method-assign]
    out = p.turn(messages=[_user("hi")], tools=[])
    assert out.stop_reason is StopReason.COMPLETE
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "just a plain answer"


def test_turn_emits_tool_call_when_model_responds_with_json() -> None:
    """The fallback parses ```json fenced tool calls — same protocol
    as ClaudeCodeLLMProvider."""
    p = GeminiProvider(_config())
    p.generate = _stub_generate(                                     # type: ignore[method-assign]
        '```json\n{"tool": "echo", "input": {"q": "x"}}\n```'
    )
    out = p.turn(messages=[_user("hi")], tools=[_echo_tool()])
    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert isinstance(out.content[0], ToolCall)
    assert out.content[0].name == "echo"
    assert out.content[0].input == {"q": "x"}


def test_turn_propagates_cost_usd_through_fallback() -> None:
    """Same plumbing as ClaudeCodeLLMProvider: generate() cost flows
    onto the TurnResponse so loop budget tracking matches reality."""
    p = GeminiProvider(_config())
    def _g(prompt: str, system_prompt: Any = None, **_kw: Any) -> LLMResponse:
        return LLMResponse(
            content="ok",
            model="gemini-2.5-pro", provider="gemini",
            tokens_used=10, cost=0.0451, finish_reason="stop",
            input_tokens=4, output_tokens=6,
        )
    p.generate = _g                                                  # type: ignore[method-assign]
    out = p.turn(messages=[_user("hi")], tools=[])
    assert out.cost_usd == 0.0451
    assert p.compute_cost(out) == 0.0451
