"""Tests for L1 streaming support: StreamChunk, turn_stream(), and
ToolUseLoop streaming mode."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import (
    LoopEvent,
    Message,
    StopReason,
    StreamChunk,
    StreamDelta,
    TextBlock,
    ToolCall,
    ToolDef,
    TurnResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cfg(**overrides: Any) -> ModelConfig:
    defaults = {
        "model_name": "test-model",
        "provider": "test",
        "api_key": "fake",
    }
    defaults.update(overrides)
    return ModelConfig(**defaults)


def _user(text: str) -> Message:
    return Message(role="user", content=[TextBlock(text=text)])


def _echo_tool() -> ToolDef:
    return ToolDef(
        name="echo",
        description="echo back",
        input_schema={"type": "object", "properties": {"msg": {"type": "string"}}},
        handler=lambda args: args.get("msg", ""),
    )


class _FakeBase(LLMProvider):
    def generate(self, prompt, system_prompt=None, **kw):
        raise NotImplementedError

    def generate_structured(self, prompt, schema, system_prompt=None, **kw):
        raise NotImplementedError

    def supports_tool_use(self):
        return True

    def context_window(self):
        return 128_000

    def price_per_million(self):
        return (1.0, 3.0)


class FakeStreamingProvider(_FakeBase):
    """Provider that yields pre-scripted StreamChunks."""

    def __init__(self, chunks_sequence: list[list[StreamChunk]]):
        super().__init__(_cfg())
        self._chunks_sequence = list(chunks_sequence)
        self._call_count = 0

    def supports_streaming(self):
        return True

    def turn(self, messages, tools, **kw):
        raise NotImplementedError("should not be called in streaming mode")

    def turn_stream(self, messages, tools, **kw) -> Iterator[StreamChunk]:
        idx = min(self._call_count, len(self._chunks_sequence) - 1)
        self._call_count += 1
        yield from self._chunks_sequence[idx]


class FakeNonStreamingProvider(_FakeBase):
    """Provider with tool use but no native streaming."""

    def __init__(self, responses: list[TurnResponse]):
        super().__init__(_cfg())
        self._responses = list(responses)
        self._call_count = 0

    def turn(self, messages, tools, **kw):
        idx = min(self._call_count, len(self._responses) - 1)
        self._call_count += 1
        return self._responses[idx]


# ---------------------------------------------------------------------------
# StreamChunk dataclass tests
# ---------------------------------------------------------------------------


class TestStreamChunk:
    def test_text_delta(self):
        c = StreamChunk(type="text_delta", text="hello")
        assert c.type == "text_delta"
        assert c.text == "hello"
        assert c.tool_call_id == ""

    def test_tool_call_start(self):
        c = StreamChunk(
            type="tool_call_start",
            tool_call_id="tc_1",
            tool_call_name="echo",
        )
        assert c.type == "tool_call_start"
        assert c.tool_call_id == "tc_1"
        assert c.tool_call_name == "echo"

    def test_usage(self):
        c = StreamChunk(
            type="usage",
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=20,
        )
        assert c.input_tokens == 100
        assert c.output_tokens == 50
        assert c.cache_read_tokens == 20
        assert c.cache_write_tokens == 0

    def test_done(self):
        c = StreamChunk(type="done", stop_reason=StopReason.COMPLETE)
        assert c.stop_reason is StopReason.COMPLETE

    def test_frozen(self):
        c = StreamChunk(type="text_delta", text="x")
        with pytest.raises(AttributeError):
            c.text = "y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ABC default turn_stream() (wraps turn())
# ---------------------------------------------------------------------------


class TestDefaultTurnStream:
    def test_text_only_response(self):
        resp = TurnResponse(
            content=[TextBlock(text="hello world")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=10,
            output_tokens=5,
        )
        provider = FakeNonStreamingProvider([resp])
        chunks = list(provider.turn_stream(
            [_user("hi")], [], system=None,
        ))

        types = [c.type for c in chunks]
        assert types == ["text_delta", "usage", "done"]
        assert chunks[0].text == "hello world"
        assert chunks[1].input_tokens == 10
        assert chunks[1].output_tokens == 5
        assert chunks[2].stop_reason is StopReason.COMPLETE

    def test_tool_call_response(self):
        resp = TurnResponse(
            content=[
                TextBlock(text="calling tool"),
                ToolCall(id="tc_1", name="echo", input={"msg": "hi"}),
            ],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=20,
            output_tokens=15,
        )
        provider = FakeNonStreamingProvider([resp])
        chunks = list(provider.turn_stream(
            [_user("hi")], [_echo_tool()],
        ))

        types = [c.type for c in chunks]
        assert types == [
            "text_delta",
            "tool_call_start",
            "tool_call_delta",
            "tool_call_end",
            "usage",
            "done",
        ]
        assert chunks[1].tool_call_name == "echo"
        assert chunks[2].tool_call_input_delta == '{"msg": "hi"}'
        assert chunks[3].tool_call_id == "tc_1"

    def test_empty_tool_input_skips_delta(self):
        resp = TurnResponse(
            content=[ToolCall(id="tc_1", name="noop", input={})],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=5,
            output_tokens=3,
        )
        provider = FakeNonStreamingProvider([resp])
        chunks = list(provider.turn_stream(
            [_user("hi")], [_echo_tool()],
        ))
        types = [c.type for c in chunks]
        assert "tool_call_delta" not in types

    def test_supports_streaming_false(self):
        provider = FakeNonStreamingProvider([])
        assert provider.supports_streaming() is False


# ---------------------------------------------------------------------------
# ToolUseLoop streaming mode
# ---------------------------------------------------------------------------


class TestLoopStreaming:
    def _text_complete_chunks(
        self, text: str = "done",
        input_tokens: int = 10,
        output_tokens: int = 5,
    ) -> list[StreamChunk]:
        return [
            StreamChunk(type="text_delta", text=text),
            StreamChunk(
                type="usage",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            ),
            StreamChunk(type="done", stop_reason=StopReason.COMPLETE),
        ]

    def _tool_call_chunks(
        self,
        tool_id: str = "tc_1",
        tool_name: str = "echo",
        args: dict | None = None,
    ) -> list[StreamChunk]:
        if args is None:
            args = {"msg": "hi"}
        return [
            StreamChunk(type="text_delta", text="let me call"),
            StreamChunk(
                type="tool_call_start",
                tool_call_id=tool_id,
                tool_call_name=tool_name,
            ),
            StreamChunk(
                type="tool_call_delta",
                tool_call_id=tool_id,
                tool_call_input_delta=json.dumps(args),
            ),
            StreamChunk(type="tool_call_end", tool_call_id=tool_id),
            StreamChunk(type="usage", input_tokens=20, output_tokens=15),
            StreamChunk(
                type="done", stop_reason=StopReason.NEEDS_TOOL_CALL,
            ),
        ]

    def test_streaming_text_complete(self):
        provider = FakeStreamingProvider([
            self._text_complete_chunks("final answer"),
        ])
        events: list[LoopEvent] = []
        loop = ToolUseLoop(
            provider, [], events=events.append, stream=True,
        )
        result = loop.run("hello")

        assert result.final_text == "final answer"
        assert result.terminated_by == "complete"

        stream_deltas = [e for e in events if isinstance(e, StreamDelta)]
        assert len(stream_deltas) == 3
        assert stream_deltas[0].chunk.type == "text_delta"
        assert stream_deltas[0].chunk.text == "final answer"

    def test_streaming_tool_call_then_complete(self):
        provider = FakeStreamingProvider([
            self._tool_call_chunks(),
            self._text_complete_chunks("all done"),
        ])
        events: list[LoopEvent] = []
        loop = ToolUseLoop(
            provider, [_echo_tool()],
            events=events.append, stream=True,
        )
        result = loop.run("test")

        assert result.terminated_by == "complete"
        assert result.final_text == "all done"
        assert result.tool_calls_made == 1
        assert result.iterations == 2

        stream_deltas = [e for e in events if isinstance(e, StreamDelta)]
        assert len(stream_deltas) > 0
        text_deltas = [
            e for e in stream_deltas
            if e.chunk.type == "text_delta"
        ]
        assert any(d.chunk.text == "let me call" for d in text_deltas)
        assert any(d.chunk.text == "all done" for d in text_deltas)

    def test_streaming_preserves_turn_events(self):
        provider = FakeStreamingProvider([
            self._text_complete_chunks(),
        ])
        events: list[LoopEvent] = []
        loop = ToolUseLoop(
            provider, [], events=events.append, stream=True,
        )
        loop.run("hello")

        event_types = [type(e).__name__ for e in events]
        assert "TurnStarted" in event_types
        assert "TurnCompleted" in event_types
        assert "StreamDelta" in event_types
        assert "LoopTerminated" in event_types

        started_idx = event_types.index("TurnStarted")
        completed_idx = event_types.index("TurnCompleted")
        delta_indices = [
            i for i, t in enumerate(event_types) if t == "StreamDelta"
        ]
        for di in delta_indices:
            assert started_idx < di < completed_idx

    def test_stream_false_does_not_call_turn_stream(self):
        provider = FakeStreamingProvider([])
        provider.turn = MagicMock(return_value=TurnResponse(
            content=[TextBlock(text="ok")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=5,
            output_tokens=3,
        ))
        loop = ToolUseLoop(
            provider, [], stream=False,
        )
        result = loop.run("hi")
        assert result.final_text == "ok"
        provider.turn.assert_called_once()

    def test_stream_flag_ignored_when_provider_lacks_support(self):
        resp = TurnResponse(
            content=[TextBlock(text="ok")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=5,
            output_tokens=3,
        )
        provider = FakeNonStreamingProvider([resp])
        loop = ToolUseLoop(
            provider, [], stream=True,
        )
        assert not loop._stream
        result = loop.run("hi")
        assert result.final_text == "ok"

    def test_streaming_accumulates_usage(self):
        provider = FakeStreamingProvider([
            self._text_complete_chunks(input_tokens=100, output_tokens=50),
        ])
        loop = ToolUseLoop(
            provider, [], stream=True,
        )
        result = loop.run("hi")
        assert result.total_input_tokens == 100
        assert result.total_output_tokens == 50

    def test_streaming_interleaved_text_and_tool(self):
        chunks = [
            StreamChunk(type="text_delta", text="before "),
            StreamChunk(
                type="tool_call_start",
                tool_call_id="tc_1",
                tool_call_name="echo",
            ),
            StreamChunk(
                type="tool_call_delta",
                tool_call_id="tc_1",
                tool_call_input_delta='{"msg":',
            ),
            StreamChunk(
                type="tool_call_delta",
                tool_call_id="tc_1",
                tool_call_input_delta='"yo"}',
            ),
            StreamChunk(type="tool_call_end", tool_call_id="tc_1"),
            StreamChunk(type="usage", input_tokens=30, output_tokens=20),
            StreamChunk(
                type="done", stop_reason=StopReason.NEEDS_TOOL_CALL,
            ),
        ]
        provider = FakeStreamingProvider([
            chunks,
            self._text_complete_chunks("after"),
        ])
        loop = ToolUseLoop(
            provider, [_echo_tool()], stream=True,
        )
        result = loop.run("test")
        assert result.terminated_by == "complete"
        assert result.tool_calls_made == 1

    def test_streaming_malformed_tool_json(self):
        chunks = [
            StreamChunk(
                type="tool_call_start",
                tool_call_id="tc_1",
                tool_call_name="echo",
            ),
            StreamChunk(
                type="tool_call_delta",
                tool_call_id="tc_1",
                tool_call_input_delta="{not valid json",
            ),
            StreamChunk(type="tool_call_end", tool_call_id="tc_1"),
            StreamChunk(type="usage", input_tokens=10, output_tokens=5),
            StreamChunk(
                type="done", stop_reason=StopReason.NEEDS_TOOL_CALL,
            ),
        ]
        provider = FakeStreamingProvider([
            chunks,
            self._text_complete_chunks("recovered"),
        ])
        loop = ToolUseLoop(
            provider, [_echo_tool()], stream=True,
        )
        result = loop.run("test")
        assert result.tool_calls_made == 1
        assert result.terminated_by == "complete"
