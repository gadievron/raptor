"""``max_retries=0`` semantics at the client layer.

The client's attempt loops count TOTAL attempts and clamp to at least
one, so ``max_retries=0`` means "single attempt, no retries" — the
same observable behaviour the providers give 0 in their
``range(max_retries + 1)`` loops.  Pre-fix, 0 produced an EMPTY loop
and the give-up log referenced the never-bound ``attempt`` variable:
``UnboundLocalError`` instead of the model-failure ``RuntimeError``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.providers import LLMResponse, StructuredResponse


def _client(max_retries: int) -> LLMClient:
    return LLMClient(LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="primary",
            api_key="test-key",
        ),
        fallback_models=[], enable_caching=False,
        enable_fallback=False, max_retries=max_retries,
    ))


def _numeric_counters(prov: MagicMock) -> None:
    """The structured path diffs these provider aggregates when the
    response carries no per-call figures."""
    prov.total_cost = 0.0
    prov.total_tokens = 0
    prov.total_input_tokens = 0
    prov.total_output_tokens = 0
    prov.total_cache_read_tokens = 0
    prov.total_cache_write_tokens = 0


class TestGenerateMaxRetriesZero:
    def test_failure_raises_model_error_not_unboundlocal(self):
        client = _client(max_retries=0)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = ValueError("parse failure")
            mock_get.return_value = prov
            with pytest.raises(RuntimeError, match="models failed"):
                client.generate("test prompt")
        # Exactly one attempt: 0 clamps to a single try, no retries.
        assert prov.generate.call_count == 1

    def test_success_single_attempt(self):
        client = _client(max_retries=0)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            _numeric_counters(prov)
            prov.generate.return_value = LLMResponse(
                content="hi", model="primary", provider="anthropic",
                tokens_used=1, cost=0.0, finish_reason="stop",
            )
            mock_get.return_value = prov
            response = client.generate("test prompt")
        assert response.content == "hi"
        assert prov.generate.call_count == 1


class TestGenerateStructuredMaxRetriesZero:
    SCHEMA = {"verdict": "string"}

    def test_failure_raises_model_error_not_unboundlocal(self):
        client = _client(max_retries=0)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            _numeric_counters(prov)
            prov.generate_structured.side_effect = ValueError("bad json")
            mock_get.return_value = prov
            with pytest.raises(RuntimeError, match="failed"):
                client.generate_structured("p", self.SCHEMA)
        assert prov.generate_structured.call_count == 1

    def test_success_single_attempt(self):
        client = _client(max_retries=0)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            _numeric_counters(prov)
            prov.generate_structured.return_value = StructuredResponse(
                result={"verdict": "ok"}, raw='{"verdict": "ok"}',
            )
            mock_get.return_value = prov
            result = client.generate_structured("p", self.SCHEMA)
        assert result.result == {"verdict": "ok"}
        assert prov.generate_structured.call_count == 1


class TestMaxRetriesPositiveUnchanged:
    def test_three_means_three_attempts(self, monkeypatch):
        """Other direction of the clamp: positive values keep their
        total-attempts meaning — the clamp must not add an attempt."""
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            # Retryable class (5xx) — exercises the full attempt budget.
            prov.generate.side_effect = RuntimeError(
                "503 service unavailable")
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt")
        assert prov.generate.call_count == 3
