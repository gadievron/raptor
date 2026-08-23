"""OpenAI-compat ``turn_stream`` usage accounting.

Without ``stream_options={"include_usage": True}`` the OpenAI
streaming API sends no usage payload at all — every streamed turn
recorded zero tokens and zero cost. The option must be requested, and
endpoints that reject it (older vLLM/Ollama builds) must degrade to
zero-usage streaming with a single operator-visible warning instead of
a dead stream.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

pytest.importorskip("openai")

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, OpenAICompatibleProvider


def _provider() -> OpenAICompatibleProvider:
    p = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
    LLMProvider.__init__(p, ModelConfig(
        provider="openai", model_name="test-model", api_key="k",
        cost_per_1k_tokens=0.001,
    ))
    p._instructor_lock = threading.Lock()
    p._instructor_consec_failures = 0
    p._tool_use_unsupported = False
    return p


class _Stream:
    def __init__(self, chunks):
        self._chunks = chunks
        self.closed = False

    def __iter__(self):
        return iter(self._chunks)

    def close(self):
        self.closed = True


def _chunks():
    return [
        SimpleNamespace(
            choices=[SimpleNamespace(
                delta=SimpleNamespace(content="hi", tool_calls=None),
                finish_reason=None,
            )],
            usage=None,
        ),
        SimpleNamespace(
            choices=[SimpleNamespace(
                delta=SimpleNamespace(content=None, tool_calls=None),
                finish_reason="stop",
            )],
            usage=None,
        ),
        # include_usage delivers the final empty-choices usage chunk.
        SimpleNamespace(
            choices=[],
            usage=SimpleNamespace(prompt_tokens=11, completion_tokens=4),
        ),
    ]


def _wire_client(create):
    return SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
    )


def test_turn_stream_requests_and_reports_usage():
    provider = _provider()
    captured: list[dict] = []

    def create(**kw):
        captured.append(kw)
        return _Stream(_chunks())

    provider.client = _wire_client(create)
    chunks = list(provider.turn_stream([], []))

    assert captured[0]["stream_options"] == {"include_usage": True}
    usage = [c for c in chunks if c.type == "usage"]
    assert len(usage) == 1
    assert usage[0].input_tokens == 11
    assert usage[0].output_tokens == 4
    # Booked on the provider ledger too.
    assert provider.total_input_tokens == 11
    assert provider.total_output_tokens == 4
    assert provider.total_cost > 0.0


def test_turn_stream_drops_rejected_stream_options():
    """An endpoint that 400s on stream_options gets it dropped and the
    call retried — zero-usage streaming, not a dead stream."""
    import httpx
    from openai import APIStatusError

    provider = _provider()
    captured: list[dict] = []

    def create(**kw):
        captured.append(kw)
        if "stream_options" in kw:
            request = httpx.Request("POST", "http://unit.test/v1")
            raise APIStatusError(
                "unexpected parameter: stream_options",
                response=httpx.Response(400, request=request),
                body=None,
            )
        return _Stream(_chunks()[:2])  # no usage chunk from this server

    provider.client = _wire_client(create)
    chunks = list(provider.turn_stream([], []))

    assert "stream_options" not in captured[-1]
    assert len(captured) == 2
    usage = [c for c in chunks if c.type == "usage"]
    assert usage and usage[0].input_tokens == 0 and usage[0].output_tokens == 0
    done = [c for c in chunks if c.type == "done"]
    assert done and done[0].stop_reason.value == "complete"


def test_turn_stream_drops_stream_options_on_old_sdk():
    """A TypeError from an SDK that doesn't know stream_options gets
    the same drop-and-retry treatment."""
    provider = _provider()
    captured: list[dict] = []

    def create(**kw):
        captured.append(kw)
        if "stream_options" in kw:
            raise TypeError(
                "create() got an unexpected keyword argument 'stream_options'",
            )
        return _Stream(_chunks()[:2])

    provider.client = _wire_client(create)
    chunks = list(provider.turn_stream([], []))

    assert "stream_options" not in captured[-1]
    done = [c for c in chunks if c.type == "done"]
    assert done and done[0].stop_reason.value == "complete"
