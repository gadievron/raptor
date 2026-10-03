"""Non-dollar resource governor: wall-clock / call-count / token caps.

The dollar budget is inert for free/local runs ($0 cost) and for audit
runs that default the cap to infinity. The governor bounds such runs at
the same provider chokepoint, independently of ``enable_cost_tracking``.
It raises ``LLMGovernorExceededError`` — a subclass of
``LLMBudgetExceededError`` — so every existing budget catch site treats
it as terminal (no fallback walk).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import (
    LLMBudgetExceededError,
    LLMGovernorExceededError,
    LLMClient,
)
from core.llm.config import LLMConfig, ModelConfig

_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def _model(name: str) -> ModelConfig:
    return ModelConfig(provider="anthropic", model_name=name, api_key="test-key")


def _client(**governor) -> LLMClient:
    config = LLMConfig(
        primary_model=_model("primary-model"),
        fallback_models=[_model("fallback-a"), _model("fallback-b")],
        enable_caching=False,
        **governor,
    )
    return LLMClient(config)


class TestGovernorUnit:
    def test_off_by_default_never_fires(self):
        client = _client()
        # No limits set → _check_governor is a no-op even after many calls.
        for _ in range(100):
            client._check_governor()

    def test_call_cap_fires_terminal_type(self):
        client = _client(max_calls_per_scan=2)
        client._check_governor()  # call 1 — counts, ok
        client._check_governor()  # call 2 — counts, ok
        with pytest.raises(LLMGovernorExceededError):
            client._check_governor()  # 3rd would exceed

    def test_governor_error_is_a_budget_error(self):
        # Subclass relationship is the whole integration contract.
        client = _client(max_calls_per_scan=1)
        client._check_governor()
        with pytest.raises(LLMBudgetExceededError):
            client._check_governor()

    def test_wall_clock_cap(self):
        client = _client(max_seconds_per_scan=10.0)
        # _run_start is None until the first governor check (lazy-init).
        assert client._run_start is None
        # First check lazy-inits the start time.
        with patch("core.llm.client.time.monotonic", return_value=100.0):
            client._check_governor()
        assert client._run_start == 100.0
        # Just under the deadline — ok.
        with patch("core.llm.client.time.monotonic", return_value=109.0):
            client._check_governor()
        # At/over the deadline — fires.
        with patch("core.llm.client.time.monotonic", return_value=110.0):
            with pytest.raises(LLMGovernorExceededError):
                client._check_governor()

    def test_token_cap(self):
        client = _client(max_tokens_per_scan=1000)
        client._check_governor()          # tally still 0 — ok
        client._record_governed_tokens(1000)
        with pytest.raises(LLMGovernorExceededError):
            client._check_governor()       # tally >= cap

    def test_governor_fires_even_with_cost_tracking_off(self):
        # The whole point: a free run turns the dollar path off, the
        # governor must still bite.
        client = _client(max_calls_per_scan=1, enable_cost_tracking=False)
        client._check_governor()
        with pytest.raises(LLMGovernorExceededError):
            client._check_governor()

    def test_multiple_caps_first_to_fire(self):
        client = _client(max_calls_per_scan=5, max_tokens_per_scan=100)
        # Token cap fires first (before call cap is reached).
        client._check_governor()  # call 1
        client._record_governed_tokens(100)
        with pytest.raises(LLMGovernorExceededError, match="token limit"):
            client._check_governor()

    def test_record_zero_and_negative_tokens_ignored(self):
        client = _client(max_tokens_per_scan=100)
        client._record_governed_tokens(0)
        client._record_governed_tokens(-50)
        assert client._governed_tokens == 0

    def test_run_start_lazy_init_on_new_client(self):
        # Clients built via __new__ (test harness) have no _run_start.
        client = LLMClient.__new__(LLMClient)
        client.config = LLMConfig(max_seconds_per_scan=60.0)
        client._stats_lock = __import__("threading").Lock()
        # First check must lazy-init _run_start, not crash.
        client._check_governor()
        assert client._run_start is not None


class TestGovernorTerminalInGenerate:
    def _governor_tripped(self, client: LLMClient):
        # Governor raises at the chokepoint, after the provider object is
        # resolved but BEFORE any provider call. The contract: terminal
        # (no fallback walk) and the provider's generate/* is never hit.
        provider = MagicMock()
        return (
            patch.object(
                client, "_check_governor",
                side_effect=LLMGovernorExceededError("resource governor: test"),
            ),
            patch.object(client, "_get_provider", return_value=provider),
            provider,
        )

    def test_generate_terminal_no_fallback_walk(self):
        client = _client(max_calls_per_scan=1)
        gov, get_provider, provider = self._governor_tripped(client)
        with gov, get_provider as gp, pytest.raises(LLMBudgetExceededError):
            client.generate("prompt")
        # Resolved the primary provider once, did NOT walk fallbacks,
        # and never actually called the provider.
        assert gp.call_count == 1
        provider.generate.assert_not_called()

    def test_generate_structured_terminal_no_fallback_walk(self):
        client = _client(max_calls_per_scan=1)
        gov, get_provider, provider = self._governor_tripped(client)
        with gov, get_provider as gp, pytest.raises(LLMBudgetExceededError):
            client.generate_structured("prompt", _SCHEMA)
        assert gp.call_count == 1
        provider.generate_structured.assert_not_called()
