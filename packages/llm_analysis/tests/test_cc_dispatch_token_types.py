"""CC dispatch token metadata must satisfy the aggregate counter contract."""
import json
from types import SimpleNamespace

from packages.llm_analysis import cc_dispatch
from packages.llm_analysis.orchestrator import CostTracker


def test_cc_token_metadata_is_integer_before_aggregate_accounting(
    tmp_path, monkeypatch, cc_spawn_machinery_enabled,
):
    import core.sandbox as sandbox
    from core.llm import cc_proxy_hosts

    usage = iter(({"input_tokens": "2", "output_tokens": "1"},
                  {"input_tokens": 2, "output_tokens": 1}))

    def run(cmd, **kwargs):
        envelope = {"structured_output": {"finding_id": "owned", "ok": True},
                    "total_cost_usd": 0.25, "usage": next(usage)}
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
        "finding_id": {"type": "string"}, "ok": {"type": "boolean"},
    }, "required": ["finding_id", "ok"], "additionalProperties": False}
    tracker = CostTracker(max_cost=1.0)
    for expected in (0, 3):
        response = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
        assert response.result == {"finding_id": "owned", "ok": True}
        assert response.cost == 0.25
        assert type(response.tokens) is int
        assert response.tokens == expected
        tracker.add_cost("owned-model", response.cost, tokens=response.tokens)
    assert tracker.total_cost == 0.5
    assert tracker.get_summary()["total_tokens"] == 3
