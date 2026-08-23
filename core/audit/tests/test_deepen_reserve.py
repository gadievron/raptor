"""Deepen budget reserve.

Observed field failure: the deepen phase announced "4 suspicious
verdicts to re-review (workers=4)" but made zero LLM calls — the
discovery loop had already spent the whole --max-cost. A configurable
slice of the cap is now held back on the budget client while the main
loop runs and released when the deepen phase starts, so announced
re-reviews can actually execute. Hermetic — no LLM calls.
"""

from __future__ import annotations

import types
from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    _hold_deepen_reserve,
    _release_deepen_reserve,
)
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _real_client(cap: float) -> LLMClient:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="stub-model", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=True,
        max_cost_per_scan=cap,
        max_retries=1,
    )
    return LLMClient(config)


class TestClientReserve:
    def test_reserve_shrinks_effective_cap(self):
        client = _real_client(cap=25.0)
        client.hold_budget_reserve(5.0)
        client.total_cost = 19.5
        # 19.5 + 1.0 > 20.0 effective → exhausted even though the
        # configured cap ($25) still has room.
        assert client.is_budget_exhausted(estimated_cost=1.0)
        assert not client._check_budget(estimated_cost=0.6)
        assert not client._acquire_budget(1.0)

    def test_release_restores_headroom(self):
        client = _real_client(cap=25.0)
        client.hold_budget_reserve(5.0)
        client.total_cost = 21.0
        assert client.is_budget_exhausted(estimated_cost=1.0)
        released = client.release_budget_reserve()
        assert released == 5.0
        assert not client.is_budget_exhausted(estimated_cost=1.0)
        assert client._acquire_budget(1.0)

    def test_release_is_idempotent(self):
        client = _real_client(cap=25.0)
        client.hold_budget_reserve(5.0)
        assert client.release_budget_reserve() == 5.0
        assert client.release_budget_reserve() == 0.0

    def test_reserve_clamped_to_cap(self):
        client = _real_client(cap=10.0)
        held = client.hold_budget_reserve(50.0)
        assert held == 10.0
        held = client.hold_budget_reserve(-3.0)
        assert held == 0.0

    def test_no_reserve_no_behaviour_change(self):
        client = _real_client(cap=25.0)
        client.total_cost = 20.0
        assert not client.is_budget_exhausted(estimated_cost=1.0)
        assert client._acquire_budget(1.0)


class TestOrchestratorWiring:
    def _config(self, client, **kw):
        defaults = {
            "target_path": Path("."), "out_dir": None,
            "llm_budget_client": client,
        }
        defaults.update(kw)
        return OrchestratorConfig(**defaults)

    def test_hold_defaults_to_fifteen_percent(self):
        client = _real_client(cap=25.0)
        config = self._config(client)
        held = _hold_deepen_reserve(config)
        assert abs(held - 3.75) < 1e-9
        assert client._budget_reserve == held

    def test_no_hold_when_deepen_disabled(self):
        client = _real_client(cap=25.0)
        config = self._config(client, deepen_suspicious=False)
        assert _hold_deepen_reserve(config) == 0.0
        assert client._budget_reserve == 0.0

    def test_no_hold_when_fraction_zero(self):
        client = _real_client(cap=25.0)
        config = self._config(client, deepen_reserve_fraction=0.0)
        assert _hold_deepen_reserve(config) == 0.0

    def test_no_hold_without_budget_client(self):
        config = OrchestratorConfig(
            target_path=Path("."), out_dir=None,
        )
        assert _hold_deepen_reserve(config) == 0.0

    def test_no_hold_on_uncapped_client(self):
        client = _real_client(cap=25.0)
        client.config.max_cost_per_scan = float("inf")
        config = self._config(client)
        assert _hold_deepen_reserve(config) == 0.0

    def test_release_returns_reserve_to_dispatch(self):
        client = _real_client(cap=25.0)
        config = self._config(client)
        _hold_deepen_reserve(config)
        client.total_cost = 22.0
        # Discovery loop is gated out at cap - reserve…
        assert client.is_budget_exhausted(estimated_cost=1.0)
        _release_deepen_reserve(config)
        # …but the deepen phase still has its slice.
        assert not client.is_budget_exhausted(estimated_cost=1.0)

    def test_release_tolerates_plain_clients(self):
        config = self._config(types.SimpleNamespace())
        # No release_budget_reserve attribute — must not raise.
        _release_deepen_reserve(config)


class TestDeepenScenarioReplay:
    """Replay the observed failure: a $25 cap fully consumed by the
    discovery loop left $0 for four announced deepen re-reviews. With
    the reserve, the loop is refused before eating the deepen slice."""

    def test_reserve_guarantees_deepen_headroom(self):
        client = _real_client(cap=25.0)
        config = OrchestratorConfig(
            target_path=Path("."), out_dir=None,
            llm_budget_client=client,
        )
        _hold_deepen_reserve(config)

        # Discovery loop spends until the (effective) cap refuses.
        spent = 0.0
        while client._acquire_budget(2.5):
            spent += 2.5
        assert spent <= 25.0 * 0.85 + 2.5

        # Deepen begins: release, and its re-reviews fit.
        _release_deepen_reserve(config)
        deepen_calls = 0
        while client._acquire_budget(0.9) and deepen_calls < 4:
            deepen_calls += 1
        assert deepen_calls >= 4, (
            f"deepen must be able to run its announced re-reviews "
            f"(got {deepen_calls})"
        )
