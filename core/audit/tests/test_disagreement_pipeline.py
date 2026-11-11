"""The actual post-loop disagreement uses the original run-owned runtime."""
import json

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.layer_resolution import Disagreement, DisagreementKind, LayerClaim, LayerVerdict
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline


@pytest.mark.slow
def test_actual_pipeline_keeps_owner_through_disagreement(tmp_path, monkeypatch):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text("def reviewed(value):\n    return value\n")
    checklist = {"files": [{"path": "unit.py", "items": [
        {"name": "reviewed", "kind": "function", "line_start": 1, "line_end": 2}]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    disagreement = Disagreement(file="unit.py", function="reviewed",
        kind=DisagreementKind.MECHANICAL_VS_LLM,
        mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL, reachable=True, has_flow=True),
        resolution="Controlled advisory signal needs source review", winner=LayerVerdict.MECHANICAL)
    monkeypatch.setattr(orch, "_check_layer_disagreement", lambda *a: disagreement)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    prompts = []
    class Client:
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            return StructuredResponse(result={"status": "clean" if len(prompts) == 1 else "suspicious",
                "body": "Independent scripted assessment", "hypothesis": "Unresolved validation concern"},
                raw="", cost=0, model="scripted")
    client = Client()
    monkeypatch.setattr(orch, "_run_llm_client", lambda config: client)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=checklist,
        max_workers=1, batch_sloc_threshold=0, resume=False, triage=False, prefilter=False,
        validate=False, immediate_verify=False, sweep_validate_findings=False, max_refinements=0,
        deepen_suspicious=False, clean_check=False, open_discovery=False, sage_recall=False,
        iris=False, adversarial=False, propagate_constraints=False,
        joern_overrides={"enabled": False}, llm_budget_client=client)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="owned disagreement pipeline"):
        result = orch.run_orchestrator(config, make_review_fn(client, escalate_clean=False))
    assert len(prompts) == 2
    assert "Advisory mechanical disagreement" in prompts[1]
    assert len(result.outcomes) == 1 and result.outcomes[0].status == "suspicious"
    trace = json.loads((out / "knowledge-results.json").read_text())
    assert trace["units"][0]["all_model_calls"] == 2
    completed = [e for e in trace["events"] if e["event"] == "continuation_completed"]
    assert len(completed) == 1 and completed[0]["delivered_request_ids"]
