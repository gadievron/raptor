"""Exception-path cost handling in ``generate_structured``.

When a provider incurs cost and then raises (e.g. the JSON-fallback
made a real API call before the parse failed), the client releases the
budget reservation and books NOTHING into its own ledger: per-call
attribution from the provider's shared aggregate counters is impossible
under parallel workers (the before/after delta swallows every
concurrent call's spend — a live 8-worker run multiply-booked ~9x its
real spend and tripped the cap with most of the budget unspent).

The genuinely-spent money is not lost: it stays on the provider's own
ledger, which budget enforcement reads via
``max(total_cost, provider_spend_usd)`` and end-of-run reconciliation
surfaces as the unattributed residual.
"""

from __future__ import annotations

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


class _CostlyFailingProvider:
    """Incurs cost on each structured call, then raises (parse failure)."""

    def __init__(self):
        self.total_cost = 0.0
        self.total_tokens = 0
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_cache_read_tokens = 0
        self.total_cache_write_tokens = 0
        self.calls = 0

    def generate_structured(self, prompt, schema, system_prompt=None, **kwargs):
        self.calls += 1
        self.total_cost += 0.05
        raise ValueError("simulated post-API parse failure")


def _client(*, cost_tracking: bool) -> tuple[LLMClient, _CostlyFailingProvider]:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model", api_key="test-key",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=cost_tracking,
        max_retries=1,
    )
    client = LLMClient(config)
    provider = _CostlyFailingProvider()
    client._get_provider = lambda model_config: provider
    # Register the fake so the provider-ledger surface sees it (the
    # _get_provider stub bypasses the caching dict).
    client.providers["anthropic:test-model"] = provider
    return client, provider


_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def test_failure_books_nothing_into_client_ledger():
    client, provider = _client(cost_tracking=False)
    with pytest.raises(RuntimeError):
        client.generate_structured("prompt", _SCHEMA)
    assert provider.calls == 1
    # No per-call attribution on failure — the client ledger stays
    # untouched (the old delta booking charged concurrent workers'
    # spend to the failing call under parallelism).
    assert client.total_cost == pytest.approx(0.0)
    # The money is still visible on the provider-ledger surface.
    assert client.provider_spend_usd == pytest.approx(0.05)


def test_reservation_released_and_provider_ledger_enforced():
    client, provider = _client(cost_tracking=True)
    with pytest.raises(RuntimeError):
        client.generate_structured("prompt", _SCHEMA)
    assert provider.calls == 1
    # The pre-debited reservation was released in full — total_cost
    # returns to its pre-call value instead of stranding the hold or
    # booking a phantom delta.
    assert client.total_cost == pytest.approx(0.0)
    assert client.provider_spend_usd == pytest.approx(0.05)


def test_budget_enforcement_sees_failed_attempt_spend():
    """is_budget_exhausted gates on the provider ledger, so money spent
    by failed attempts still counts against the cap exactly once."""
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model", api_key="test-key",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=True,
        max_retries=1,
        max_cost_per_scan=1.0,
    )
    client = LLMClient(config)
    provider = _CostlyFailingProvider()
    client._get_provider = lambda model_config: provider
    client.providers["anthropic:test-model"] = provider
    assert not client.is_budget_exhausted(estimated_cost=0.5)
    # Simulate failed-attempt spend accumulating on the provider only.
    provider.total_cost = 0.9
    assert client.total_cost == pytest.approx(0.0)
    assert client.is_budget_exhausted(estimated_cost=0.5)
