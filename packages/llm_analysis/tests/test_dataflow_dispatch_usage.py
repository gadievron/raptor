"""Dataflow validation usage contributes to aggregate token telemetry."""
from types import SimpleNamespace

from packages.llm_analysis.dataflow_dispatch_client import DispatchClient
from packages.llm_analysis.orchestrator import CostTracker


def test_dataflow_dispatch_counts_paid_and_zero_cost_usage():
    tracker = CostTracker(max_cost=1.0)
    responses = iter((
        SimpleNamespace(result={"ok": True}, cost=0.25, tokens=7, thinking_tokens=2),
        SimpleNamespace(result={"error": "owned failure"}, cost=0.0, tokens=4, thinking_tokens=1),
        SimpleNamespace(result={"ok": True}, cost=0.0, tokens=True, thinking_tokens=-1),
    ))
    client = DispatchClient(lambda *args: next(responses), "owned-model", cost_tracker=tracker)
    assert client.generate_structured("owned", {}) == {"ok": True}
    assert tracker.total_cost == 0.25
    assert tracker._total_tokens == 7
    assert tracker._thinking_tokens == 2
    assert client.generate_structured("owned", {}) is None
    assert tracker.total_cost == 0.25
    assert tracker._total_tokens == 11
    assert tracker._thinking_tokens == 3
    assert client.generate_structured("owned", {}) == {"ok": True}
    assert tracker._total_tokens == 11
    assert tracker._thinking_tokens == 3
    assert tracker._per_model == {"owned-model": 0.25}
    assert tracker.get_summary()["total_tokens"] == 11
