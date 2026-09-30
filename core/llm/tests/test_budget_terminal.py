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


class TestBudgetRemedyWording:
    """The exhaustion message must name surfaces an operator can act
    on (CLI caps, tuning.json default) — not the ``LLMConfig``
    constructor spelling only a code caller can use — while keeping
    the ``LLM budget exceeded:`` prefix the legacy string classifier
    keys on.
    """

    def _entry_check_message(self, method, *args) -> str:
        client = _client()
        with patch.object(client, "_check_budget", return_value=False), \
                pytest.raises(LLMBudgetExceededError) as excinfo:
            method(client, *args)
        return str(excinfo.value)

    def _reservation_message(self, method, *args) -> str:
        client = _client()
        check, acquire, get_provider = _budget_race(client)
        with check, acquire, get_provider, \
                pytest.raises(LLMBudgetExceededError) as excinfo:
            method(client, *args)
        return str(excinfo.value)

    def _assert_remedy(self, msg: str) -> None:
        cap = _client().config.max_cost_per_scan
        suggested = max(cap * 2, 0.01)
        assert msg.startswith("LLM budget exceeded:")
        assert f"--max-cost-usd {suggested:.2f}" in msg
        assert f"--max-cost {suggested:.2f}" in msg
        assert '"default_max_cost_usd" in tuning.json' in msg
        assert "LLMConfig(" not in msg

    def test_generate_entry_check(self):
        self._assert_remedy(
            self._entry_check_message(LLMClient.generate, "prompt"))

    def test_generate_structured_entry_check(self):
        self._assert_remedy(self._entry_check_message(
            LLMClient.generate_structured, "prompt", _SCHEMA))

    def test_generate_reservation(self):
        msg = self._reservation_message(LLMClient.generate, "prompt")
        self._assert_remedy(msg)
        assert "estimated" in msg

    def test_generate_structured_reservation(self):
        msg = self._reservation_message(
            LLMClient.generate_structured, "prompt", _SCHEMA)
        self._assert_remedy(msg)
        assert "estimated" in msg

    def test_legacy_classifier_still_matches_new_wording(self):
        # A caller re-wrapping the message as a bare RuntimeError
        # (the legacy channel) must still classify.
        from core.llm.client import is_budget_exceeded_error
        msg = self._entry_check_message(LLMClient.generate, "prompt")
        assert is_budget_exceeded_error(RuntimeError(msg))

    def test_tiny_cap_never_suggests_fail_open_zero(self):
        # Both named CLI surfaces treat a 0 cap as "no cap"
        # (fail-open), so no cap — however tiny — may produce a
        # copy-pasteable 0.0 suggestion.
        import re

        from core.llm.client import _budget_remedy
        for cap in (0.001, 0.004, 0.02, 0.049):
            msg = _budget_remedy(cap)
            amounts = re.findall(r"--max-cost(?:-usd)? (\d+\.\d+)", msg)
            assert len(amounts) == 2, msg
            assert all(float(a) > 0 for a in amounts), msg

    def test_constructor_spelling_gone_from_source(self):
        # Source-level pin: no message site regrows the
        # code-caller-only remedy.
        import inspect

        import core.llm.client as client_mod
        assert "LLMConfig(max_cost_per_scan=" not in inspect.getsource(
            client_mod)
