"""The JSON-in-prompt fallback must run at the caller's sizing.

``_structured_fallback`` re-sends via ``self.generate()``; when only
``timeout_s`` was forwarded, a caller's ``max_tokens`` / ``temperature``
were dropped at every call site and the fallback ran at config defaults
— a caller that raised ``max_tokens`` for a long structured response
got a fallback that truncated at the default ceiling.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest

pytest.importorskip("openai")
pytest.importorskip("pydantic")

from core.llm.config import ModelConfig
from core.llm.providers import (
    LLMProvider,
    LLMResponse,
    OpenAICompatibleProvider,
    _dict_schema_to_pydantic,
)

_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def _provider() -> OpenAICompatibleProvider:
    p = OpenAICompatibleProvider.__new__(OpenAICompatibleProvider)
    LLMProvider.__init__(p, ModelConfig(
        provider="openai", model_name="test-model", api_key="k",
        cost_per_1k_tokens=0.001,
    ))
    p._instructor_lock = threading.Lock()
    p._instructor_consec_failures = 0
    p._tool_use_unsupported = False
    p.instructor_client = None
    return p


def _wire_recording_generate(
    provider: OpenAICompatibleProvider,
) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def generate(
        prompt: str, system_prompt: str | None = None, **kwargs: Any,
    ) -> LLMResponse:
        calls.append(dict(kwargs))
        return LLMResponse(
            content='{"x": "ok"}',
            model="test-model",
            provider="openai",
            tokens_used=3,
            cost=0.0,
            finish_reason="complete",
        )

    provider.generate = generate  # type: ignore[method-assign]
    return calls


def test_fallback_forwards_caller_sizing_params() -> None:
    provider = _provider()
    calls = _wire_recording_generate(provider)
    pyd = _dict_schema_to_pydantic(_SCHEMA)

    out = provider._structured_fallback(
        "p", _SCHEMA, pyd, None,
        timeout_s=5.0, max_tokens=777, temperature=0.3,
    )

    assert out.result == {"x": "ok"}
    assert calls[0]["max_tokens"] == 777
    assert calls[0]["temperature"] == 0.3
    assert calls[0]["timeout_s"] == 5.0


def test_generate_structured_call_site_forwards_sizing() -> None:
    """End-to-end through the call site: with instructor unavailable,
    ``generate_structured(max_tokens=..., temperature=...)`` reaches
    ``generate`` via the fallback."""
    provider = _provider()
    calls = _wire_recording_generate(provider)

    out = provider.generate_structured(
        "p", _SCHEMA, max_tokens=777, temperature=0.3,
    )

    assert out.result == {"x": "ok"}
    assert calls[0]["max_tokens"] == 777
    assert calls[0]["temperature"] == 0.3


def test_fallback_without_overrides_leaves_generate_defaults() -> None:
    """When the caller supplies no sizing params, none are passed —
    ``generate``'s own config-default resolution stays in effect."""
    provider = _provider()
    calls = _wire_recording_generate(provider)

    out = provider.generate_structured("p", _SCHEMA)

    assert out.result == {"x": "ok"}
    assert "max_tokens" not in calls[0]
    assert "temperature" not in calls[0]
