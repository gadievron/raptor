"""Mid-stream failures in ``turn_stream`` book spend and raise typed.

A mid-stream SSE disconnect used to escape the generator raw: the
usage chunk and the ``track_usage`` call at the end of the stream never
ran, so tokens the API had already billed went unbooked, and callers
saw a bare transport exception instead of the sanitised ``RuntimeError``
shape the non-streaming paths raise.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from typing import Any

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider


# ---------------------------------------------------------------------------
# OpenAI-compat provider
# ---------------------------------------------------------------------------


def _openai_provider():
    pytest.importorskip("openai")
    from core.llm.providers import OpenAICompatibleProvider
    p = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
    LLMProvider.__init__(p, ModelConfig(
        provider="openai", model_name="test-model", api_key="k",
        cost_per_1k_tokens=0.001,
    ))
    p._instructor_lock = threading.Lock()
    p._instructor_consec_failures = 0
    p._tool_use_unsupported = False
    return p


class _ExplodingStream:
    """Yields the scripted chunks, then raises mid-iteration."""

    def __init__(self, chunks: list[Any], exc: Exception) -> None:
        self._chunks = chunks
        self._exc = exc
        self.closed = False

    def __iter__(self):
        yield from self._chunks
        raise self._exc

    def close(self) -> None:
        self.closed = True


def _text_chunk(text: str, usage: Any = None) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(
            delta=SimpleNamespace(content=text, tool_calls=None),
            finish_reason=None,
        )],
        usage=usage,
    )


def test_openai_midstream_failure_books_usage_and_raises_typed() -> None:
    provider = _openai_provider()
    stream = _ExplodingStream(
        [_text_chunk(
            "hello",
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=4),
        )],
        ConnectionResetError("peer reset"),
    )
    provider.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=lambda **kw: stream),
    ))

    received: list[Any] = []
    with pytest.raises(RuntimeError, match="stream failed mid-turn"):
        for chunk in provider.turn_stream([], []):
            received.append(chunk)

    # The chunks yielded before the disconnect were delivered.
    assert any(c.type == "text_delta" for c in received)
    # Spend booked from the usage seen before the failure.
    assert provider.total_input_tokens == 11
    assert provider.total_output_tokens == 4
    assert provider.total_cost > 0.0
    # The stream was still closed (finally ran).
    assert stream.closed


def test_openai_midstream_failure_estimates_output_when_no_usage() -> None:
    """Compat servers deliver usage on the FINAL chunk — a disconnect
    before it books an estimate from the delta text received rather
    than nothing."""
    provider = _openai_provider()
    stream = _ExplodingStream(
        [_text_chunk("x" * 40)],
        ConnectionResetError("peer reset"),
    )
    provider.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=lambda **kw: stream),
    ))

    with pytest.raises(RuntimeError, match="stream failed mid-turn"):
        list(provider.turn_stream([], []))

    assert provider.total_output_tokens == 10   # 40 chars / 4
    assert provider.total_cost > 0.0


def test_openai_healthy_stream_unchanged() -> None:
    """The failure handling must not disturb a stream that completes."""
    provider = _openai_provider()
    chunks = [
        _text_chunk("hi"),
        SimpleNamespace(
            choices=[SimpleNamespace(
                delta=SimpleNamespace(content=None, tool_calls=None),
                finish_reason="stop",
            )],
            usage=None,
        ),
        SimpleNamespace(
            choices=[],
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=4),
        ),
    ]
    class _HealthyStream(_ExplodingStream):
        def __iter__(self):
            yield from self._chunks

    healthy = _HealthyStream(chunks, RuntimeError("never raised"))
    provider.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=lambda **kw: healthy),
    ))

    out = list(provider.turn_stream([], []))
    types = [c.type for c in out]
    assert types == ["text_delta", "usage", "done"]
    assert out[1].input_tokens == 11
    assert out[1].output_tokens == 4
    assert out[2].stop_reason.value == "complete"
    assert provider.total_input_tokens == 11
    assert provider.total_output_tokens == 4


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------


def _anthropic_provider():
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider
    return AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-opus-4-6",
        api_key="test-key", timeout=1,
    ))


class _FakeAnthropicStream:
    """Context manager + iterator matching ``messages.stream()``."""

    def __init__(self, events: list[Any], exc: Exception | None = None) -> None:
        self._events = events
        self._exc = exc
        self.exited = False

    def __enter__(self) -> "_FakeAnthropicStream":
        return self

    def __exit__(self, *args: Any) -> bool:
        self.exited = True
        return False

    def __iter__(self):
        yield from self._events
        if self._exc is not None:
            raise self._exc


def _message_start(input_tokens: int, cache_read: int = 0,
                   cache_write: int = 0) -> SimpleNamespace:
    return SimpleNamespace(type="message_start", message=SimpleNamespace(
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            cache_read_input_tokens=cache_read,
            cache_creation_input_tokens=cache_write,
        ),
    ))


def test_anthropic_midstream_failure_books_usage_and_raises_typed() -> None:
    provider = _anthropic_provider()
    stream = _FakeAnthropicStream(
        [
            _message_start(100, cache_read=7, cache_write=3),
            SimpleNamespace(type="text", text="p" * 80),
        ],
        exc=ConnectionResetError("peer reset"),
    )
    provider.client = SimpleNamespace(messages=SimpleNamespace(
        stream=lambda **kw: stream,
    ))

    received: list[Any] = []
    with pytest.raises(RuntimeError, match="stream failed mid-turn"):
        for chunk in provider.turn_stream([], []):
            received.append(chunk)

    assert any(c.type == "text_delta" for c in received)
    # Input/cache from message_start; output estimated from the 80
    # delta chars received (no message_delta usage arrived).
    assert provider.total_input_tokens == 100
    assert provider.total_output_tokens == 20
    assert provider.total_cache_read_tokens == 7
    assert provider.total_cache_write_tokens == 3
    assert provider.total_cost > 0.0
    assert stream.exited


def test_anthropic_healthy_stream_unchanged() -> None:
    provider = _anthropic_provider()
    stream = _FakeAnthropicStream([
        _message_start(100),
        SimpleNamespace(type="text", text="answer"),
        SimpleNamespace(
            type="message_delta",
            delta=SimpleNamespace(stop_reason="end_turn"),
            usage=SimpleNamespace(output_tokens=8),
        ),
    ])
    provider.client = SimpleNamespace(messages=SimpleNamespace(
        stream=lambda **kw: stream,
    ))

    out = list(provider.turn_stream([], []))
    types = [c.type for c in out]
    assert types == ["text_delta", "usage", "done"]
    assert out[0].text == "answer"
    assert out[1].input_tokens == 100
    assert out[1].output_tokens == 8
    assert out[2].stop_reason.value == "complete"
    assert provider.total_input_tokens == 100
    assert provider.total_output_tokens == 8
