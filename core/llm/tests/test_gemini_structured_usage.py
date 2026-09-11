"""Gemini native-JSON structured responses must carry per-call usage.

The client books spend from the ``StructuredResponse``'s own
``cost``/token fields when present and only falls back to diffing the
provider's SHARED aggregate counters when they are absent — a diff
that multiply-books concurrent calls' spend under parallel workers.
The Gemini native path computed the per-call figures but returned a
``StructuredResponse`` without them, forcing every native Gemini
structured call onto the racy fallback.

The provider instance is assembled without the google-genai SDK
(``__new__`` + base-class init): the structured success path only
touches the SDK through the mocked per-thread client, so the test
stays hermetic on runners without the optional dependency.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider


def _gemini_provider(mock_response):
    from core.llm.providers import GeminiProvider
    provider = GeminiProvider.__new__(GeminiProvider)
    LLMProvider.__init__(provider, ModelConfig(
        provider="gemini", model_name="gemini-2.5-flash",
        api_key="test-key", max_tokens=1024, timeout=1,
    ))
    provider._safety_settings = []
    provider._clients_lock = threading.Lock()
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response
    provider._clients = {threading.get_ident(): mock_client}
    return provider


def _mock_response(text: str, *, prompt_tokens: int = 50,
                   out_tokens: int = 10, thoughts: int = 5):
    fr = MagicMock()
    fr.name = "STOP"
    candidate = MagicMock()
    candidate.finish_reason = fr
    usage = MagicMock()
    usage.prompt_token_count = prompt_tokens
    usage.candidates_token_count = out_tokens
    usage.thoughts_token_count = thoughts
    resp = MagicMock()
    resp.text = text
    resp.candidates = [candidate]
    resp.usage_metadata = usage
    resp.model_version = "gemini-2.5-flash-002"
    return resp


class TestGeminiNativeStructuredUsage:
    SCHEMA = {"verdict": "string"}

    def test_success_carries_cost_and_tokens(self):
        pytest.importorskip("pydantic")
        provider = _gemini_provider(_mock_response('{"verdict": "ok"}'))
        result = provider.generate_structured("p", self.SCHEMA)
        assert result.result == {"verdict": "ok"}
        assert result.cost > 0
        assert result.tokens_used == 50 + 10 + 5
        assert result.input_tokens == 50
        assert result.output_tokens == 10
        assert result.duration >= 0

    def test_response_figures_match_provider_booking(self):
        """The per-call figures on the response equal what the call
        added to the provider's own aggregate ledger — the response is
        an exact substitute for the counter diff, not an estimate."""
        pytest.importorskip("pydantic")
        provider = _gemini_provider(_mock_response('{"verdict": "ok"}'))
        cost_before = provider.total_cost
        tokens_before = provider.total_tokens
        result = provider.generate_structured("p", self.SCHEMA)
        assert result.cost == pytest.approx(provider.total_cost - cost_before)
        assert result.tokens_used == provider.total_tokens - tokens_before
