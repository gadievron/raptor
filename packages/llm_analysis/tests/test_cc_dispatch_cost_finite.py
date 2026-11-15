"""Malformed CC cost metadata must not poison result artifacts."""
import json
from types import SimpleNamespace

from core.json import save_json
from packages.llm_analysis import cc_dispatch
from packages.llm_analysis.dispatch import DispatchTask
from packages.llm_analysis.orchestrator import _finalize_results_for_emit, _merge_results


def test_cc_cost_metadata_stays_finite_through_schema_and_artifact(tmp_path, monkeypatch, cc_spawn_machinery_enabled):
    import core.sandbox as sandbox
    from core.llm import cc_proxy_hosts

    schema = {"type": "object", "properties": {
        "finding_id": {"type": "string"},
        "is_true_positive": {"type": "boolean"},
        "is_exploitable": {"type": "boolean"},
    }, "required": ["finding_id", "is_true_positive", "is_exploitable"],
        "additionalProperties": False}
    current_cost = 0.25
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        envelope = {"total_cost_usd": current_cost, "structured_output": {
            "finding_id": "owned", "is_true_positive": True,
            "is_exploitable": False,
        }}
        return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")

    monkeypatch.setattr(sandbox, "run_untrusted_networked", run)
    monkeypatch.setattr(cc_dispatch, "cc_subprocess_env", lambda **kwargs: {})
    monkeypatch.setattr(cc_proxy_hosts, "readable_paths_for_cc_dispatch", lambda *args: [])
    monkeypatch.setattr(cc_proxy_hosts, "proxy_hosts_for_cc_dispatch", lambda *args: [])
    repo = tmp_path / "repo"
    repo.mkdir()
    for label, current_cost, expected in (
        ("nan", float("nan"), 0.0), ("infinity", float("inf"), 0.0),
        ("large-int", 10**400, 0.0), ("finite", 0.25, 0.25),
    ):
        out = tmp_path / label
        out.mkdir()
        response = cc_dispatch.invoke_cc_simple("owned", schema, repo, "owned-claude", out)
        assert "error" not in response.result
        assert response.quality == 1.0
        assert response.cost == expected
        processed = DispatchTask().process_result({}, response)
        merged = _merge_results({"results": [{"finding_id": "owned", "rule_id": "owned"}]},
                                [processed], no_exploits=True, no_patches=True)
        _finalize_results_for_emit(merged["results"])
        destination = out / "report.json"
        save_json(destination, merged)
        record = json.loads(destination.read_text())["results"][0]
        assert record.get("cost_usd", 0.0) == expected
    assert len(calls) == 4
