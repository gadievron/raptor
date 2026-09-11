"""Reasoning-token subtraction never produces negative output tokens.

OpenAI includes reasoning tokens inside ``completion_tokens``, so the
provider subtracts them for display. Some gateway shims report
``reasoning_tokens`` WITHOUT including them in ``completion_tokens`` —
unclamped, the subtraction went negative and polluted telemetry and
per-call token accounting.
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


def _response(completion_tokens: int, reasoning_tokens: int) -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(
                content="hi", refusal=None, reasoning_content="",
            ),
            finish_reason="stop",
        )],
        usage=SimpleNamespace(
            prompt_tokens=10,
            completion_tokens=completion_tokens,
            completion_tokens_details=SimpleNamespace(
                reasoning_tokens=reasoning_tokens,
            ),
            prompt_tokens_details=None,
        ),
    )


def _wire(provider: OpenAICompatibleProvider, resp: SimpleNamespace) -> None:
    provider.client = SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=lambda **kw: resp),
    ))


def test_output_tokens_clamped_when_reasoning_excluded_from_completion() -> None:
    provider = _provider()
    _wire(provider, _response(completion_tokens=5, reasoning_tokens=9))
    out = provider.generate("p")
    assert out.output_tokens == 0
    assert out.thinking_tokens == 9
    assert provider.total_output_tokens == 0


def test_output_tokens_subtraction_unchanged_when_reasoning_included() -> None:
    provider = _provider()
    _wire(provider, _response(completion_tokens=5, reasoning_tokens=2))
    out = provider.generate("p")
    assert out.output_tokens == 3
    assert out.thinking_tokens == 2
