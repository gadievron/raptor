"""Timeout retry policy at the client layer.

Timeout-class failures are classified distinctly (``is_timeout_error``)
and get at most ONE retry per model inside the ``generate`` /
``generate_structured`` attempt loops. Parse and 429 failures keep the
standard ``max_retries`` budget.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import LLMClient, is_timeout_error
from core.llm.config import LLMConfig, ModelConfig


def _model(provider: str, name: str) -> ModelConfig:
    return ModelConfig(
        provider=provider, model_name=name, api_key="test-key",
    )


def _config(primary: ModelConfig, *, max_retries: int = 3) -> LLMConfig:
    return LLMConfig(
        primary_model=primary, fallback_models=[],
        enable_caching=False, max_retries=max_retries,
        enable_fallback=False,
    )


def _client(max_retries: int = 3) -> LLMClient:
    return LLMClient(_config(_model("anthropic", "primary"),
                             max_retries=max_retries))


class TestIsTimeoutError:
    def test_timeout_error_instance(self):
        assert is_timeout_error(TimeoutError("boom")) is True

    def test_timeout_typename(self):
        class APITimeoutError(Exception):
            pass

        assert is_timeout_error(APITimeoutError("request aborted")) is True

    def test_cc_transport_timed_out_message(self):
        err = RuntimeError("claude -p timed out after 600s")
        assert is_timeout_error(err) is True

    def test_timeout_in_message(self):
        assert is_timeout_error(RuntimeError("read timeout on socket"))

    def test_quota_error_is_not_timeout(self):
        # 429s carry their own retry policy — never classify as timeout,
        # even when the message also mentions a retry window.
        err = RuntimeError("429 rate limit exceeded; timeout in 60s")
        assert is_timeout_error(err) is False

    def test_unrelated_error_is_not_timeout(self):
        assert is_timeout_error(ValueError("schema mismatch")) is False

    def test_connection_error_is_not_timeout(self):
        assert is_timeout_error(ConnectionError("refused")) is False


class TestGenerateTimeoutRetryCap:
    def test_timeout_capped_at_one_retry(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "claude -p timed out after 600s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt")

        # Initial attempt + exactly one retry — NOT max_retries (3).
        assert prov.generate.call_count == 2

    def test_non_timeout_retryable_keeps_full_budget(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "simulated 503 from upstream",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt")

        assert prov.generate.call_count == 3

    def test_timeout_then_success_recovers(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        good = MagicMock()
        good.cost = 0.0
        good.tokens_used = 1
        good.input_tokens = 1
        good.output_tokens = 0
        good.content = "ok"
        good.resolved_model = None
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = [
                RuntimeError("claude -p timed out after 600s"),
                good,
            ]
            mock_get.return_value = prov
            response = client.generate("test prompt")

        assert response is good
        assert prov.generate.call_count == 2


class TestPerCallTimeoutRetryCap:
    """``timeout_retry_cap`` kwarg tightens the timeout retry budget
    per call — the review path passes 0 so a timed-out review fails
    straight through to the orchestrator's reduced-context retry."""

    def test_cap_zero_means_no_identical_retry(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "claude -p timed out after 480s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt", timeout_retry_cap=0)

        assert prov.generate.call_count == 1

    def test_cap_zero_structured(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.total_cost = 0.0
            prov.total_tokens = 0
            prov.generate_structured.side_effect = RuntimeError(
                "claude -p timed out after 480s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate_structured(
                    "test prompt", {"type": "object"},
                    timeout_retry_cap=0,
                )

        assert prov.generate_structured.call_count == 1

    def test_cap_zero_leaves_non_timeout_budget_alone(self, monkeypatch):
        # timeout_retry_cap only constrains timeout-class failures;
        # 5xx-style retryables keep the full max_retries budget.
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "simulated 503 from upstream",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt", timeout_retry_cap=0)

        assert prov.generate.call_count == 3

    def test_invalid_cap_falls_back_to_default(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "claude -p timed out after 480s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("test prompt", timeout_retry_cap="bogus")

        # Default policy: initial attempt + one retry.
        assert prov.generate.call_count == 2

    def test_resolver_values(self):
        from core.llm.client import (
            _TIMEOUT_RETRY_CAP,
            _resolve_timeout_retry_cap,
        )
        assert _resolve_timeout_retry_cap(None) == _TIMEOUT_RETRY_CAP
        assert _resolve_timeout_retry_cap(0) == 0
        assert _resolve_timeout_retry_cap(2) == 2
        assert _resolve_timeout_retry_cap(-1) == _TIMEOUT_RETRY_CAP
        assert _resolve_timeout_retry_cap("1") == 1


class TestGenerateStructuredTimeoutRetryCap:
    def test_timeout_capped_at_one_retry(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.total_cost = 0.0
            prov.total_tokens = 0
            prov.generate_structured.side_effect = RuntimeError(
                "claude -p timed out after 600s",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate_structured("test prompt", {"type": "object"})

        assert prov.generate_structured.call_count == 2

    def test_parse_failure_keeps_full_budget(self, monkeypatch):
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        import json as _json

        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.total_cost = 0.0
            prov.total_tokens = 0
            prov.generate_structured.side_effect = _json.JSONDecodeError(
                "Expecting value", "not-json", 0,
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate_structured("test prompt", {"type": "object"})

        assert prov.generate_structured.call_count == 3
