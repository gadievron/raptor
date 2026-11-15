"""Malformed dispatch costs must not disable validator budget accounting."""
from types import SimpleNamespace

from packages.llm_analysis.dataflow_dispatch_client import DispatchClient
from packages.llm_analysis.dataflow_validation import _budget_exhausted
from packages.llm_analysis.orchestrator import CostTracker


def test_dispatch_costs_preserve_finite_budget_and_token_accounting():
    for malformed in (float("nan"), -2.0, float("inf"), True, "2", None):
        tracker = CostTracker(max_cost=1.0)
        responses = iter((SimpleNamespace(result={"ok": True}, cost=malformed),
                          SimpleNamespace(result={"ok": True}, cost=1.5)))
        client = DispatchClient(lambda *args: next(responses), "owned-model",
                                cost_tracker=tracker)
        assert client.generate_structured("owned", {}) == {"ok": True}
        assert client.generate_structured("owned", {}) == {"ok": True}
        assert tracker.total_cost == 1.5
        assert tracker.fraction_used == 1.5
        assert _budget_exhausted(tracker, 0.95)
        assert tracker._per_model == {"owned-model": 1.5}

        tracker.add_cost("token-only", malformed, tokens=3, thinking_tokens=2)
        assert tracker.total_cost == 1.5
        assert tracker._per_model["token-only"] == 0.0
        assert tracker._total_tokens == 3
        assert tracker._thinking_tokens == 2

    tracker = CostTracker(max_cost=2.0)
    for value in (0.0, 0.25, 0.5):
        tracker.add_cost("same-model", value, tokens=1)
    assert tracker.total_cost == 0.75
    assert tracker.fraction_used == 0.375
    assert tracker._per_model == {"same-model": 0.75}
    assert tracker._total_tokens == 3
    assert not _budget_exhausted(tracker, 0.95)
