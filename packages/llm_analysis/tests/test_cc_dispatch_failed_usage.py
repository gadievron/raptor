"""Nonzero CC exits keep failure status and reported usage."""
import json
from types import SimpleNamespace

from packages.llm_analysis import cc_dispatch


def test_nonzero_cc_exit_preserves_usage_without_accepting_payload(
    tmp_path, monkeypatch, cc_spawn_machinery_enabled,
):
    import core.sandbox as sandbox
    from core.llm import cc_proxy_hosts

    outputs = iter((json.dumps({
        "total_cost_usd": 0.25,
        "usage": {"input_tokens": 2, "output_tokens": 1},
        "modelUsage": {"owned-model": {}},
        "structured_output": {"is_true_positive": True},
    }), json.dumps({"structured_output": {
        "cost_usd": 999, "_tokens": 999, "analysed_by": "spoofed-model",
    }}), "owned truncated output {", "[" * 1200 + "0" + "]" * 1200))

    def run(cmd, **kwargs):
        return SimpleNamespace(returncode=1, stdout=next(outputs), stderr="owned failure")

    monkeypatch.setattr(sandbox, "run_untrusted_networked", run)
    monkeypatch.setattr(cc_dispatch, "cc_subprocess_env", lambda **kwargs: {})
    monkeypatch.setattr(cc_proxy_hosts, "readable_paths_for_cc_dispatch", lambda *args: [])
    monkeypatch.setattr(cc_proxy_hosts, "proxy_hosts_for_cc_dispatch", lambda *args: [])
    repo = tmp_path / "repo"
    repo.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    schema = {"type": "object", "properties": {}}
    response = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert response.result["error"] == "exit code 1: owned failure"
    assert "is_true_positive" not in response.result
    assert response.cost == 0.25
    assert response.tokens == 3
    assert response.model == "owned-model"
    assert (out / response.result["cc_debug_file"]).is_file()
    spoofed = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert spoofed.result["error"] == "exit code 1: owned failure"
    assert spoofed.cost == 0.0
    assert spoofed.tokens == 0
    assert spoofed.model != "spoofed-model"
    incomplete = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert incomplete.result["error"] == "exit code 1: owned failure"
    assert incomplete.cost == 0.0
    assert incomplete.tokens == 0
    assert (out / incomplete.result["cc_debug_file"]).is_file()
    nested = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
    assert nested.result["error"] == "exit code 1: owned failure"
    assert nested.cost == 0.0
    assert nested.tokens == 0
