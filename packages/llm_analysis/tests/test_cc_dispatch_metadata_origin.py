"""CC usage belongs to the outer envelope, not model-authored fields."""
import json
from types import SimpleNamespace

from packages.llm_analysis import cc_dispatch


def test_cc_metadata_ignores_inner_claims_and_keeps_outer_usage(
    tmp_path, monkeypatch, cc_spawn_machinery_enabled,
):
    import core.sandbox as sandbox
    from core.llm import cc_proxy_hosts

    inner = {"finding_id": "owned", "is_true_positive": True, "cost_usd": 999,
             "_tokens": 999, "analysed_by": "spoofed-model", "duration_seconds": 999}
    outputs = iter((
        {"structured_output": inner},
        {"structured_output": inner, "total_cost_usd": 0.25, "duration_ms": 2000,
         "usage": {"input_tokens": 2, "output_tokens": 1},
         "modelUsage": {"owned-model": {}}},
        {"result": "owned freeform", "total_cost_usd": 0.5,
         "usage": {"input_tokens": 4}, "modelUsage": {"owned-model": {}}},
    ))

    def run(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(next(outputs)), stderr="")

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
    first = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert first.result == {"finding_id": "owned", "is_true_positive": True}
    assert first.quality == 1.0
    assert first.cost == 0.0
    assert first.tokens == 0
    assert first.model == "claude-code"
    assert first.duration == 0
    second = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert second.result == first.result
    assert second.quality == 1.0
    assert (second.cost, second.tokens, second.model, second.duration) == (
        0.25, 3, "owned-model", 2.0,
    )
    freeform = cc_dispatch.invoke_cc_simple("owned", None, repo, "owned-claude", out)
    assert freeform.result == {"content": "owned freeform"}
    assert (freeform.cost, freeform.tokens, freeform.model) == (0.5, 4, "owned-model")
