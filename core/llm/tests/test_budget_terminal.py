"""Budget exhaustion mid-retry must surface as ``LLMBudgetExceededError``.

``_acquire_budget`` can fail inside the retry loop even when the
entry ``_check_budget`` passed (a concurrent dispatcher consumed the
remaining budget in between). That raise used to be swallowed by the
blanket per-attempt ``except Exception`` handler, which iterated
every fallback model (each failing the same budget check) and
finally raised a generic ``RuntimeError("All ... models failed")`` —
losing the typed terminal contract documented on
``LLMBudgetExceededError``.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import LLMBudgetExceededError, LLMClient
from core.llm.config import LLMConfig, ModelConfig

_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def _model(name: str) -> ModelConfig:
    return ModelConfig(provider="anthropic", model_name=name, api_key="test-key")


def _client() -> LLMClient:
    config = LLMConfig(
        primary_model=_model("primary-model"),
        fallback_models=[_model("fallback-a"), _model("fallback-b")],
        enable_caching=False,
    )
    return LLMClient(config)


def _budget_race(client: LLMClient):
    """Entry check passes, in-loop acquire fails — the concurrent-
    dispatcher race the reservation pre-debit exists for."""
    return (
        patch.object(client, "_check_budget", return_value=True),
        patch.object(client, "_acquire_budget", return_value=False),
        patch.object(client, "_get_provider", return_value=MagicMock()),
    )


class TestGenerateBudgetTerminal:
    def test_raises_typed_error(self):
        client = _client()
        check, acquire, get_provider = _budget_race(client)
        with check, acquire, get_provider, pytest.raises(LLMBudgetExceededError):
            client.generate("prompt")

    def test_does_not_iterate_fallback_models(self):
        client = _client()
        check, acquire, get_provider = _budget_race(client)
        with check, acquire, get_provider as gp, pytest.raises(LLMBudgetExceededError):
            client.generate("prompt")
        # Terminal on the FIRST model — no pointless walk through
        # fallbacks that fail the same budget check.
        assert gp.call_count == 1


class TestGenerateStructuredBudgetTerminal:
    def test_raises_typed_error(self):
        client = _client()
        check, acquire, get_provider = _budget_race(client)
        with check, acquire, get_provider, pytest.raises(LLMBudgetExceededError):
            client.generate_structured("prompt", _SCHEMA)

    def test_does_not_iterate_fallback_models(self):
        client = _client()
        check, acquire, get_provider = _budget_race(client)
        with check, acquire, get_provider as gp, pytest.raises(LLMBudgetExceededError):
            client.generate_structured("prompt", _SCHEMA)
        assert gp.call_count == 1


class TestIsBudgetExceededClassifier:
    """Typed check primary; string fallback structurally vetoed.

    Callers treat a budget verdict as TERMINAL for their whole
    dispatch loop, so model-authored text echoing 'budget exceeded'
    inside a response-shape failure must never classify — mirroring
    ``is_auth_refusal``'s shape veto.
    """

    def _classify(self, exc):
        from core.llm.client import is_budget_exceeded_error
        return is_budget_exceeded_error(exc)

    def test_typed_error_matches(self):
        assert self._classify(LLMBudgetExceededError("cap"))

    def test_typed_error_matches_through_wrapper_chain(self):
        inner = LLMBudgetExceededError("cap")
        try:
            raise RuntimeError("wrapped") from inner
        except RuntimeError as outer:
            assert self._classify(outer)

    def test_legacy_message_fallback_matches(self):
        assert self._classify(RuntimeError(
            "LLM budget exceeded: $10.00 spent > $10.00 limit"))

    def test_hostile_echo_in_json_decode_error_vetoed(self):
        import json as _json
        shape = _json.JSONDecodeError(
            "Expecting value", '{"note": "budget exceeded"}', 1)
        wrapped = RuntimeError(
            "structured parse failed: budget exceeded echo")
        wrapped.__cause__ = shape
        assert not self._classify(wrapped)

    def test_hostile_echo_in_schema_error_vetoed(self):
        from core.llm.response_validation import SchemaUnknownFieldError
        shape = SchemaUnknownFieldError(
            "unknown field 'budget exceeded'")
        wrapped = RuntimeError("schema failed: budget exceeded")
        wrapped.__cause__ = shape
        assert not self._classify(wrapped)

    def test_hostile_echo_in_validation_error_vetoed(self):
        class ValidationError(Exception):
            pass
        wrapped = RuntimeError("validation: budget exceeded")
        wrapped.__cause__ = ValidationError("budget exceeded field")
        assert not self._classify(wrapped)

    def test_unrelated_error_does_not_match(self):
        assert not self._classify(RuntimeError("connection reset"))
