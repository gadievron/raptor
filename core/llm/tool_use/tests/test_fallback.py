"""Tests for ``LLMProvider._tool_use_fallback`` — the JSON-in-prompt
synthesis used by providers that lack native tool/function calling
(e.g., the Claude Code subprocess transport).

The fallback is a pure-Python helper on the ABC; these tests use a
minimal in-memory ``LLMProvider`` subclass that records prompts and
returns canned text responses, exercising the protocol rendering,
message flattening, and tool-call extraction without any SDK or
subprocess machinery.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, LLMResponse
from core.llm.tool_use import (
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolDef,
    ToolResult,
)


# ---------------------------------------------------------------------------
# Test double — minimal LLMProvider that records prompts and returns canned
# responses. Exercises the ABC fallback without any provider-specific code.
# ---------------------------------------------------------------------------


class _RecordingProvider(LLMProvider):
    """In-memory provider for fallback tests.

    Each call to ``generate()`` returns the next canned response and
    records the prompt + system prompt into ``calls`` so tests can
    assert what the fallback rendered.
    """

    def __init__(self, responses: list[str]) -> None:
        super().__init__(ModelConfig(
            provider="anthropic",
            model_name="claude-opus-4-6",
            api_key="ignored",
            timeout=1,
        ))
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        self.calls.append({
            "prompt": prompt,
            "system_prompt": system_prompt,
            "max_tokens": kwargs.get("max_tokens"),
        })
        text = self._responses.pop(0) if self._responses else ""
        return LLMResponse(
            content=text,
            model="claude-opus-4-6",
            provider="test",
            tokens_used=10,
            cost=getattr(self, "_canned_cost", 0.0),
            finish_reason="stop",
            input_tokens=4,
            output_tokens=6,
        )

    def generate_structured(
        self,
        prompt: str,
        schema: Dict[str, Any],
        system_prompt: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str]:
        raise NotImplementedError("not exercised in fallback tests")


def _user(text: str) -> Message:
    return Message(role="user", content=[TextBlock(text=text)])


def _tool(name: str = "search") -> ToolDef:
    return ToolDef(
        name=name,
        description=f"the {name} tool",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        handler=lambda inp: f"result for {inp.get('q', '')}",
    )


# ---------------------------------------------------------------------------
# Tool-protocol rendering
# ---------------------------------------------------------------------------


def test_render_tool_protocol_lists_each_tool() -> None:
    rendered = LLMProvider._render_tool_protocol([_tool("search"), _tool("fetch")])
    assert "name: search" in rendered
    assert "name: fetch" in rendered
    assert "the search tool" in rendered
    assert "the fetch tool" in rendered


def test_render_tool_protocol_includes_call_format() -> None:
    rendered = LLMProvider._render_tool_protocol([_tool()])
    assert '{"tool":' in rendered.replace(" ", "")
    assert "input" in rendered


def test_render_tool_protocol_embeds_input_schema() -> None:
    t = ToolDef(
        name="echo",
        description="echo input",
        input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
        handler=lambda i: i.get("q", ""),
    )
    rendered = LLMProvider._render_tool_protocol([t])
    assert '"properties"' in rendered


# ---------------------------------------------------------------------------
# Message flattening
# ---------------------------------------------------------------------------


def test_render_messages_text_blocks_carry_role_label() -> None:
    msgs = [
        Message(role="user", content=[TextBlock(text="hello")]),
        Message(role="assistant", content=[TextBlock(text="hi")]),
    ]
    rendered = LLMProvider._render_messages_as_prompt(msgs)
    assert "user: hello" in rendered
    assert "assistant: hi" in rendered


def test_render_messages_tool_call_block() -> None:
    msgs = [
        Message(role="assistant", content=[
            ToolCall(id="x", name="search", input={"q": "y"}),
        ]),
    ]
    rendered = LLMProvider._render_messages_as_prompt(msgs)
    assert "search" in rendered
    assert '"q": "y"' in rendered


def test_render_messages_tool_result_block() -> None:
    msgs = [
        Message(role="user", content=[
            ToolResult(tool_use_id="x", content="42"),
        ]),
    ]
    rendered = LLMProvider._render_messages_as_prompt(msgs)
    assert "tool_result" in rendered
    assert "42" in rendered
    assert "[ERROR]" not in rendered


def test_render_messages_tool_result_error_marker() -> None:
    msgs = [
        Message(role="user", content=[
            ToolResult(tool_use_id="x", content="boom", is_error=True),
        ]),
    ]
    rendered = LLMProvider._render_messages_as_prompt(msgs)
    assert "[ERROR]" in rendered


# ---------------------------------------------------------------------------
# Response parsing — the heart of the fallback
# ---------------------------------------------------------------------------


def test_parse_plain_text_returns_textblock_complete() -> None:
    block, stop = LLMProvider._parse_fallback_response(
        "Just a regular answer.", [_tool()],
    )
    assert isinstance(block, TextBlock)
    assert block.text == "Just a regular answer."
    assert stop is StopReason.COMPLETE


def test_parse_valid_tool_call_returns_toolcall() -> None:
    raw = '```json\n{"tool": "search", "input": {"q": "x"}}\n```'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, ToolCall)
    assert block.name == "search"
    assert block.input == {"q": "x"}
    assert stop is StopReason.NEEDS_TOOL_CALL


def test_parse_tool_call_without_fences() -> None:
    raw = '{"tool": "search", "input": {"q": "x"}}'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, ToolCall)
    assert stop is StopReason.NEEDS_TOOL_CALL


def test_parse_tool_call_with_prose_preamble() -> None:
    """Models don't always emit clean JSON-only output even when asked.
    A short preamble before a fenced JSON block is the most common
    deviation; the parser should still recognise the call rather than
    silently dropping it as plain text. Backed by the more permissive
    ``cc_adapter.strip_json_fences``."""
    raw = (
        "Sure, I'll call the search tool now:\n"
        '```json\n{"tool": "search", "input": {"q": "x"}}\n```'
    )
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, ToolCall)
    assert block.name == "search"
    assert stop is StopReason.NEEDS_TOOL_CALL


def test_parse_tool_call_with_prose_postamble() -> None:
    """Symmetric: prose after the fenced block also tolerated."""
    raw = (
        '```json\n{"tool": "search", "input": {"q": "x"}}\n```\n'
        "Let me know if you need anything else."
    )
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, ToolCall)
    assert stop is StopReason.NEEDS_TOOL_CALL


def test_parse_unknown_tool_name_falls_back_to_text() -> None:
    """Hallucinated tool names shouldn't be dispatched. Surface the
    raw text so the loop sees what happened."""
    raw = '{"tool": "make_coffee", "input": {}}'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, TextBlock)
    assert stop is StopReason.COMPLETE


def test_parse_malformed_json_falls_back_to_text() -> None:
    raw = '{"tool": "search", "input": {q: missing_quotes}}'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, TextBlock)
    assert block.text == raw
    assert stop is StopReason.COMPLETE


def test_parse_json_array_not_object_falls_back_to_text() -> None:
    raw = '[1, 2, 3]'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, TextBlock)
    assert stop is StopReason.COMPLETE


def test_parse_missing_input_field_falls_back_to_text() -> None:
    raw = '{"tool": "search"}'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, TextBlock)
    assert stop is StopReason.COMPLETE


def test_parse_input_not_dict_falls_back_to_text() -> None:
    raw = '{"tool": "search", "input": "not_a_dict"}'
    block, stop = LLMProvider._parse_fallback_response(raw, [_tool("search")])
    assert isinstance(block, TextBlock)
    assert stop is StopReason.COMPLETE


def test_parse_no_tools_returns_text_unchanged() -> None:
    """With no tools defined, even valid-looking JSON is just text."""
    raw = '{"tool": "search", "input": {"q": "x"}}'
    block, stop = LLMProvider._parse_fallback_response(raw, [])
    assert isinstance(block, TextBlock)
    assert stop is StopReason.COMPLETE


def test_parse_empty_text() -> None:
    block, stop = LLMProvider._parse_fallback_response("", [_tool()])
    assert isinstance(block, TextBlock)
    assert block.text == ""
    assert stop is StopReason.COMPLETE


# ---------------------------------------------------------------------------
# End-to-end fallback() — integration of render+generate+parse
# ---------------------------------------------------------------------------


def test_fallback_text_response_returns_complete_turn() -> None:
    p = _RecordingProvider(["Final answer."])
    out = p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[_tool()],
    )
    assert out.stop_reason is StopReason.COMPLETE
    assert len(out.content) == 1
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "Final answer."
    assert out.input_tokens == 4
    assert out.output_tokens == 6


def test_fallback_tool_call_response_returns_needs_tool_call() -> None:
    canned = '```json\n{"tool": "search", "input": {"q": "x"}}\n```'
    p = _RecordingProvider([canned])
    out = p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[_tool("search")],
    )
    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert isinstance(out.content[0], ToolCall)
    assert out.content[0].name == "search"
    assert out.content[0].input == {"q": "x"}


def test_fallback_combines_system_and_tool_protocol() -> None:
    p = _RecordingProvider(["ok"])
    p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[_tool("search")],
        system="You are a careful agent.",
    )
    sys_prompt = p.calls[0]["system_prompt"]
    assert sys_prompt is not None
    assert "You are a careful agent." in sys_prompt
    assert "search" in sys_prompt           # tool protocol included
    assert "JSON object" in sys_prompt


def test_fallback_no_system_only_tool_protocol() -> None:
    p = _RecordingProvider(["ok"])
    p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[_tool("search")],
    )
    sys_prompt = p.calls[0]["system_prompt"]
    assert sys_prompt is not None
    assert "search" in sys_prompt


def test_fallback_no_tools_no_system_no_system_prompt() -> None:
    """Without tools or system, no system prompt is built."""
    p = _RecordingProvider(["plain text"])
    p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[],
    )
    assert p.calls[0]["system_prompt"] is None


def test_fallback_passes_max_tokens_through() -> None:
    p = _RecordingProvider(["ok"])
    p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[],
        max_tokens=2048,
    )
    assert p.calls[0]["max_tokens"] == 2048


def test_fallback_renders_full_message_history() -> None:
    """Multi-turn history (text + tool_call + tool_result) flattens
    into the prompt so the model has the context."""
    msgs = [
        Message(role="user", content=[TextBlock(text="find x")]),
        Message(role="assistant", content=[
            ToolCall(id="t1", name="search", input={"q": "x"}),
        ]),
        Message(role="user", content=[
            ToolResult(tool_use_id="t1", content="found 42"),
        ]),
    ]
    p = _RecordingProvider(["The answer is 42."])
    out = p._tool_use_fallback(messages=msgs, tools=[_tool("search")])

    rendered = p.calls[0]["prompt"]
    assert "find x" in rendered
    assert "search" in rendered
    assert "found 42" in rendered
    assert isinstance(out.content[0], TextBlock)
    assert "42" in out.content[0].text


def test_fallback_propagates_cost_usd_from_generate_response() -> None:
    """The whole point of plumbing cost_usd: providers that already
    know the exact cost (CC envelope, future API-side cost
    reporting) get it surfaced on the TurnResponse so the loop's
    budget tracking matches the actual ledger rather than a
    token-derived estimate."""
    p = _RecordingProvider(["ok"])
    p._canned_cost = 0.0729                                           # type: ignore[attr-defined]
    out = p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[],
    )
    assert out.cost_usd == 0.0729


def test_fallback_cost_usd_zero_propagates_as_zero_not_none() -> None:
    """``cost==0.0`` from a free local model (Ollama) is a known-zero,
    distinct from "cost unknown". Should propagate as 0.0, not None,
    so compute_cost returns 0.0 directly without falling back to the
    token formula."""
    p = _RecordingProvider(["ok"])
    p._canned_cost = 0.0                                              # type: ignore[attr-defined]
    out = p._tool_use_fallback(
        messages=[_user("hi")],
        tools=[],
    )
    assert out.cost_usd == 0.0


def test_fallback_default_turn_still_raises_when_not_overridden() -> None:
    """Adding ``_tool_use_fallback`` to the ABC must not silently turn
    the default ``turn()`` into synthesis. Providers must explicitly
    opt in by overriding ``turn`` to delegate to the fallback."""
    p = _RecordingProvider(["x"])
    with pytest.raises(NotImplementedError):
        p.turn(messages=[_user("hi")], tools=[])
