"""Existing sink-classification re-reviews retain shared ownership and spend."""
import json
import threading

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.live_classifications import LiveClassifications
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline

pytestmark = pytest.mark.slow


def setup_pipeline(tmp_path, monkeypatch, *, functions=("caller",), sink="selected_sink", workers=1):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "\n".join(f"def {name}(value):\n    return value\n" for name in functions)
    (target / "unit.py").write_text(source)
    items = [{"name": name, "kind": "function", "line_start": 1 + index * 3,
              "line_end": 2 + index * 3} for index, name in enumerate(functions)]
    checklist = {"files": [{"path": "unit.py", "items": items}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    (out / "context-map.json").write_text(json.dumps({"call_edges": [
        {"caller_file": "unit.py", "caller": name, "callee": sink}
        for name in functions if name != sink]}))
    import core.audit.live_classifications as live
    classifications = LiveClassifications(sinks={sink})
    monkeypatch.setattr(live, "load_from_project_context", lambda *a, **k: classifications)
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=checklist,
        max_workers=workers, batch_sloc_threshold=0, resume=False, triage=False, prefilter=False,
        validate=False, immediate_verify=False, sweep_validate_findings=False, max_refinements=0,
        deepen_suspicious=False, clean_check=False, open_discovery=False, sage_recall=False,
        iris=False, adversarial=False, propagate_constraints=False, joern_overrides={"enabled": False})
    return config


def execute(config, client, monkeypatch, reviewer=None):
    monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    config.llm_budget_client = client
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="owned live-sink pipeline"):
        return orch.run_orchestrator(config, reviewer or make_review_fn(client, escalate_clean=False))


@pytest.mark.parametrize("journal_failure", [False, True], ids=["durable", "rejected"])
def test_actual_live_sink_review_waits_for_ack_and_books_spend(tmp_path, monkeypatch, journal_failure):
    config = setup_pipeline(tmp_path, monkeypatch)
    prompts = []
    class Client:
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            later = "Advisory live-sink classification leads" in prompt
            return StructuredResponse(result={"status": "suspicious" if later else "clean",
                "body": "Fresh live assessment" if later else "Initial independent assessment",
                "hypothesis": "Unresolved classification lead" if later else ""},
                raw="", cost=.25 if later else .10, model="scripted")
    if journal_failure:
        import core.audit.collector as collector
        actual_append = collector.append_journal_for_outcome
        def append(*args, **kwargs):
            if kwargs["outcome"].body == "Fresh live assessment":
                return None
            return actual_append(*args, **kwargs)
        monkeypatch.setattr(collector, "append_journal_for_outcome", append)
    result = execute(config, Client(), monkeypatch)
    assert len(prompts) == 2
    assert result.total_cost_usd == pytest.approx(.35)
    assert result.outcomes[0].status == ("clean" if journal_failure else "suspicious")
    if journal_failure:
        assert result.outcomes[0].body == "Initial independent assessment"
    trace = json.loads((config.out_dir / "knowledge-results.json").read_text())
    assert trace["units"][0]["all_model_calls"] == 2


def test_actual_ready_callee_live_and_disagreement_share_one_review(tmp_path, monkeypatch):
    config = setup_pipeline(tmp_path, monkeypatch, functions=("selected_sink", "caller"))
    from core.audit.layer_resolution import Disagreement, DisagreementKind, LayerClaim, LayerVerdict
    disagreement = Disagreement(file="unit.py", function="caller",
        kind=DisagreementKind.MECHANICAL_VS_LLM,
        mechanical_claim=LayerClaim(LayerVerdict.MECHANICAL, reachable=True, has_flow=True),
        resolution="Controlled advisory disagreement", winner=LayerVerdict.MECHANICAL)
    monkeypatch.setattr(orch, "_check_layer_disagreement",
                        lambda outcome, ctx, gap: disagreement if gap["name"] == "caller" else None)
    current = {}
    prompts = []
    class Client:
        def is_budget_exhausted(self):
            return False
        def generate_structured(self, prompt, schema, **kwargs):
            name = current["ctx"]["function"]
            prompts.append((name, prompt))
            response = ({"status": "suspicious", "body": "Prior callee concern", "hypothesis": "Unresolved callee condition"}
                if name == "selected_sink" else {"status": "clean", "body": "Independent caller assessment",
                    "relies_on": [{"callee": "selected_sink", "assumption": "validates input"}]})
            return StructuredResponse(result=response, raw="", cost=0, model="scripted")
    client = Client()
    rendered = make_review_fn(client, escalate_clean=False)
    def review(ctx, cfg):
        current["ctx"] = ctx
        return rendered(ctx, cfg)
    review._knowledge_observed_client_contract = True
    result = execute(config, client, monkeypatch, review)
    caller_prompts = [prompt for name, prompt in prompts if name == "caller"]
    assert len(caller_prompts) == 2 and len(result.outcomes) == 2
    assert "Advisory prior callee assessment" in caller_prompts[1]
    assert "Advisory live-sink classification leads" in caller_prompts[1]
    trace = json.loads((config.out_dir / "knowledge-results.json").read_text())
    completed = [e for e in trace["events"] if e["event"] == "continuation_completed"]
    assert len(completed) == 1
    delivered = completed[0]["delivered_request_ids"]
    assert any(item.startswith("context:callee_contract:") for item in delivered)
    assert any(item.startswith("context:live_sinks:") for item in delivered)
    assert any(item.startswith("context:disagreement:") for item in delivered)


def test_parallel_paid_live_reviews_are_all_harvested_after_budget_stop(tmp_path, monkeypatch):
    config = setup_pipeline(tmp_path, monkeypatch, functions=("first", "second"), workers=2)
    paid = threading.Barrier(2, timeout=5)
    exhausted = threading.Event()
    class Client:
        def is_budget_exhausted(self):
            return exhausted.is_set()
        def generate_structured(self, prompt, schema, **kwargs):
            later = "Advisory live-sink classification leads" in prompt
            if later:
                paid.wait()
                exhausted.set()
            return StructuredResponse(result={"status": "suspicious" if later else "clean",
                "body": "Scripted assessment", "hypothesis": "Unresolved lead" if later else ""},
                raw="", cost=.25 if later else 0, model="scripted")
    result = execute(config, Client(), monkeypatch)
    assert exhausted.is_set()
    assert result.total_cost_usd == pytest.approx(.5)
    assert result.suspicious == 2
