"""A full audit cannot reread one callee union under another stage name."""
import json

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


@pytest.mark.slow
def test_actual_pipeline_coalesces_both_callees_and_deduplicates_iterative_stage(tmp_path, monkeypatch):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text(
        "def callee_a(value):\n    return value\n\n"
        "def callee_b(value):\n    return value\n\n"
        "def caller(value):\n    return callee_b(callee_a(value))\n")
    checklist = {"files": [{"path": "unit.py", "items": [
        {"name": "callee_a", "kind": "function", "line_start": 1, "line_end": 2},
        {"name": "callee_b", "kind": "function", "line_start": 4, "line_end": 5},
        {"name": "caller", "kind": "function", "line_start": 7, "line_end": 8}]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    (out / "context-map.json").write_text(json.dumps({"call_edges": [
        {"caller_file": "unit.py", "caller": "caller", "callee_file": "unit.py", "callee": name}
        for name in ("callee_a", "callee_b")]}))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    current = {}
    prompts = []
    class Client:
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            name = current["ctx"]["function"]
            prompts.append((name, prompt))
            response = ({"status": "clean", "body": "Caller judgment remains provisional",
                "relies_on": [{"callee": callee, "assumption": "validates input"}
                              for callee in ("callee_a", "callee_b")]}
                if name == "caller" else {"status": "suspicious", "body": f"Prior concern for {name}",
                    "hypothesis": f"Unresolved concern in {name}"})
            return StructuredResponse(result=response, raw="", cost=0, model="scripted")
    client = Client()
    rendered = make_review_fn(client, escalate_clean=False)
    monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    def review(ctx, cfg):
        current["ctx"] = ctx
        return rendered(ctx, cfg)
    review._knowledge_observed_client_contract = True
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=checklist,
        max_workers=1, batch_sloc_threshold=0, resume=False, triage=False, prefilter=False,
        validate=False, immediate_verify=False, sweep_validate_findings=False, max_refinements=0,
        deepen_suspicious=False, clean_check=False, open_discovery=False, sage_recall=False,
        iris=False, adversarial=False, propagate_constraints=True,
        joern_overrides={"enabled": False}, llm_budget_client=client)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="canonical callee union"):
        result = orch.run_orchestrator(config, review)
    caller_prompts = [prompt for name, prompt in prompts if name == "caller"]
    assert len(caller_prompts) == 2
    assert "Unresolved concern in callee_a" in caller_prompts[1]
    assert "Unresolved concern in callee_b" in caller_prompts[1]
    assert len(prompts) == 4 and len(result.outcomes) == 3
    trace = json.loads((out / "knowledge-results.json").read_text())
    caller, = [unit for unit in trace["units"] if unit["unit"][:2] == ["unit.py", "caller"]]
    assert caller["all_model_calls"] == 2
    completed = [event for event in trace["events"] if event["event"] == "continuation_completed"]
    assert len(completed) == 1
