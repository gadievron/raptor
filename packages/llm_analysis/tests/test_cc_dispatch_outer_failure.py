"""Outer CC failure status cannot be overridden by structured analysis."""
import json
from types import SimpleNamespace

from packages.llm_analysis import cc_dispatch
from packages.llm_analysis.dataflow_dispatch_client import DispatchClient
from packages.llm_analysis.orchestrator import CostTracker


def test_outer_failure_with_structured_payload_remains_failed(
    tmp_path, monkeypatch, cc_spawn_machinery_enabled,
):
    import core.sandbox as sandbox
    from core.llm import cc_proxy_hosts

    flags = iter(({"is_error": True}, {"is_error": "true"},
                  {"error": "owned terminal failure"},
                  {"is_error": False, "error": "false"}))

    def run(cmd, **kwargs):
        envelope = {"structured_output": {"finding_id": "owned", "is_true_positive": True},
                    "total_cost_usd": 0.25,
                    "usage": {"input_tokens": 2, "output_tokens": 1}, **next(flags)}
        return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")

    monkeypatch.setattr(sandbox, "run_untrusted_networked", run)
    monkeypatch.setattr(cc_dispatch, "cc_subprocess_env", lambda **kwargs: {})
    monkeypatch.setattr(cc_proxy_hosts, "readable_paths_for_cc_dispatch", lambda *args: [])
    monkeypatch.setattr(cc_proxy_hosts, "proxy_hosts_for_cc_dispatch", lambda *args: [])
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    schema = {"type": "object", "properties": {
        "finding_id": {"type": "string"}, "is_true_positive": {"type": "boolean"},
    }, "required": ["finding_id", "is_true_positive"], "additionalProperties": False}
    tracker = CostTracker(max_cost=2.0)
    for index in range(4):
        response = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
        assert response.cost == 0.25
        assert response.tokens == 3
        client = DispatchClient(lambda *args: response, "owned-model", cost_tracker=tracker)
        if index < 3:
            assert "error" in response.result
            assert "is_true_positive" not in response.result
            assert client.generate_structured("owned", {}) is None
        else:
            assert response.result == {"finding_id": "owned", "is_true_positive": True}
            assert client.generate_structured("owned", {}) == response.result
    assert tracker.total_cost == 1.0
    assert tracker.get_summary()["total_tokens"] == 12
