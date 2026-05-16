"""Pin-tests for two cross-provider invariants surfaced during PR #286
real-LLM testing:

1. **``turn()`` accumulates provider stats.** All four providers'
   ``turn()`` methods must call ``track_usage`` (directly or via
   delegation to ``generate()`` / ``generate_structured()``).
   Pre-fix, AnthropicProvider and OpenAICompatibleProvider skipped
   it, so ``LLMClient.get_stats()`` reported zero tool-use spend.
   Gemini and CC delegate; the delegation path was correct but
   untested. This file pins all four.

2. **Keyless-Anthropic factory routing.** When ``ANTHROPIC_SDK_AVAILABLE``
   is False but OpenAI SDK is present, the factory must build an
   ``OpenAICompatibleProvider`` against ``api.anthropic.com/v1``. Real-LLM
   testing proved Anthropic's OpenAI-compat shim accepts function-calling
   natively; this test pins the routing so a future refactor doesn't
   silently break the keyless path.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from core.llm.config import ModelConfig


# ---------------------------------------------------------------------------
# turn() track_usage — Anthropic + OpenAICompatible (direct calls)
# ---------------------------------------------------------------------------


@pytest.fixture
def _anthropic_provider_with_stub():
    """Reuse the Anthropic test stub plumbing without re-importing."""
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider
    from core.llm.tool_use.tests.test_anthropic import (
        _StubBlock, _StubClient, _StubResponse, _StubUsage,
    )
    p = AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-opus-4-6",
        api_key="test-key", timeout=1,
    ))
    c = _StubClient()
    p.client = c                                                    # type: ignore[assignment]
    return p, c, _StubBlock, _StubResponse, _StubUsage


def test_anthropic_turn_calls_track_usage(_anthropic_provider_with_stub) -> None:
    """``AnthropicProvider.turn`` must update provider running totals.
    Pre-#286 this was skipped, masking real spend in
    ``LLMClient.get_stats()`` no matter how many turns the loop ran for."""
    from core.llm.tool_use import Message, TextBlock

    p, c, _StubBlock, _StubResponse, _StubUsage = _anthropic_provider_with_stub
    c.messages.responses.append(_StubResponse(
        [_StubBlock("text", text="ok")],
        stop_reason="end_turn",
        usage=_StubUsage(input_tokens=100, output_tokens=50),
    ))

    assert p.total_cost == 0.0
    assert p.call_count == 0

    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )

    assert p.call_count == 1
    assert p.total_input_tokens == 100
    assert p.total_output_tokens == 50
    assert p.total_cost > 0.0                                       # exact value depends on pricing


def test_openai_turn_calls_track_usage() -> None:
    """``OpenAICompatibleProvider.turn`` must track usage symmetrically
    with Anthropic. Same pre-#286 gap."""
    pytest.importorskip("openai")
    from core.llm.providers import OpenAICompatibleProvider
    from core.llm.tool_use.tests.test_openai_compat import (
        _FakeOpenAIClient, _FakeResponse, _FakeChoice,
        _FakeMessage, _FakeUsage,
    )
    from core.llm.tool_use import Message, TextBlock

    p = OpenAICompatibleProvider(ModelConfig(
        provider="openai", model_name="gpt-4o",
        api_key="test-key", timeout=1,
    ))
    c = _FakeOpenAIClient()
    p.client = c                                                    # type: ignore[assignment]
    c.chat.completions.responses.append(_FakeResponse(
        choices=[_FakeChoice(_FakeMessage(content="ok"), finish_reason="stop")],
        usage=_FakeUsage(prompt_tokens=200, completion_tokens=80),
    ))

    assert p.call_count == 0
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )

    assert p.call_count == 1
    assert p.total_input_tokens == 200
    assert p.total_output_tokens == 80
    assert p.total_cost > 0.0


# ---------------------------------------------------------------------------
# turn() track_usage via delegation — Gemini + ClaudeCode
# ---------------------------------------------------------------------------


def test_gemini_turn_tracks_via_delegated_generate() -> None:
    """``GeminiProvider.turn`` delegates to ``_tool_use_fallback`` →
    ``self.generate()`` which tracks usage. Pin-test confirms the
    delegation chain hasn't broken."""
    pytest.importorskip("google.genai")
    from core.llm.providers import GeminiProvider, LLMResponse
    from core.llm.tool_use import Message, TextBlock

    p = GeminiProvider(ModelConfig(
        provider="gemini", model_name="gemini-2.5-pro",
        api_key="test-key", timeout=1,
    ))

    # Replace generate with a tracking spy so we don't hit the SDK.
    def _g(prompt: str, system_prompt: Any = None, **kw: Any) -> LLMResponse:
        # Mimic the real generate's track_usage call.
        p.track_usage(
            tokens=15, cost=0.001,
            input_tokens=10, output_tokens=5, duration=0.0,
        )
        return LLMResponse(
            content="ok", model="gemini-2.5-pro", provider="gemini",
            tokens_used=15, cost=0.001, finish_reason="stop",
            input_tokens=10, output_tokens=5,
        )
    p.generate = _g                                                 # type: ignore[method-assign]

    assert p.call_count == 0
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert p.call_count == 1
    assert p.total_cost > 0.0


def test_claudecode_turn_tracks_via_delegated_generate(monkeypatch) -> None:
    """``ClaudeCodeLLMProvider.turn`` delegates to ``generate`` (no tools)
    or ``generate_structured`` (with tools); both call ``track_usage``."""
    import json
    import subprocess
    from core.llm.providers import ClaudeCodeLLMProvider
    from core.llm.tool_use import Message, TextBlock, ToolDef
    from core.llm.tests.test_claude_code_llm_provider import (
        _FakeCompleted, _envelope, _structured_envelope,
    )

    # Path 1: tools=[] → generate() → track_usage
    p1 = ClaudeCodeLLMProvider(ModelConfig(
        provider="claudecode", model_name="claude-opus-4-6",
        api_key=None, timeout=10,
    ))
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout=_envelope(cost_usd=0.05)),
    )
    p1.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[],
    )
    assert p1.call_count == 1
    assert p1.total_cost == 0.05

    # Path 2: tools present → generate_structured() → track_usage
    p2 = ClaudeCodeLLMProvider(ModelConfig(
        provider="claudecode", model_name="claude-opus-4-6",
        api_key=None, timeout=10,
    ))
    tool = ToolDef("echo", "echo back",
                   {"type": "object"}, lambda i: "r")
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout=_structured_envelope(
            {"type": "complete", "final_text": "done"}, cost_usd=0.07,
        )),
    )
    p2.turn(
        messages=[Message(role="user", content=[TextBlock(text="x")])],
        tools=[tool],
    )
    assert p2.call_count == 1
    assert p2.total_cost == 0.07


# ---------------------------------------------------------------------------
# Factory routes anthropic → OpenAICompatibleProvider when SDK absent
# ---------------------------------------------------------------------------


def test_factory_routes_keyless_anthropic_to_openai_compat() -> None:
    """When the ``anthropic`` SDK is absent but OpenAI is installed,
    ``create_provider(ModelConfig(provider="anthropic"))`` must build
    an ``OpenAICompatibleProvider`` pointed at
    ``api.anthropic.com/v1``. Real-LLM verification (2026-05-04)
    confirmed Anthropic's OpenAI-compat shim accepts function-calling
    natively — i.e., this routing delivers working tool-use without
    the ``anthropic`` SDK installed. The test pins the routing
    against future refactors."""
    pytest.importorskip("openai")
    from core.llm.providers import OpenAICompatibleProvider, create_provider

    config = ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="test-anthropic-key",
        timeout=10,
    )

    with patch("core.llm.providers.ANTHROPIC_SDK_AVAILABLE", False):
        provider = create_provider(config)

    assert isinstance(provider, OpenAICompatibleProvider)
    from urllib.parse import urlparse
    assert urlparse(str(provider.client.base_url)).hostname == "api.anthropic.com"
    # API key threaded through correctly so requests authenticate.
    assert provider.client.api_key == "test-anthropic-key"


def test_factory_keyless_anthropic_raises_without_openai_sdk() -> None:
    """When neither anthropic nor openai SDK is available, the factory
    raises a clear error rather than silently returning a broken
    provider."""
    config = ModelConfig(
        provider="anthropic",
        model_name="claude-opus-4-6",
        api_key="test-key",
        timeout=10,
    )
    with patch("core.llm.providers.ANTHROPIC_SDK_AVAILABLE", False), \
         patch("core.llm.providers.OPENAI_SDK_AVAILABLE", False):
        from core.llm.providers import create_provider
        with pytest.raises(RuntimeError, match="anthropic"):
            create_provider(config)
