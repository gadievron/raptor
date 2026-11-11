"""Already-ready callee and Joern context share one actual caller review."""
from __future__ import annotations

from concurrent.futures import Future
import json
from time import monotonic

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.llm_review import make_review_fn
from core.evidence import EvidenceRecord
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline
from packages.joern.models import TaintFlow


@pytest.mark.slow
@pytest.mark.parametrize("ready_before_callee", [True, False], ids=["already-ready-union", "later-result"])
def test_actual_pipeline_coalesces_only_already_ready_context(tmp_path, monkeypatch, ready_before_callee):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    (target / "unit.py").write_text(
        "def caller(value):\n    return callee(value)\n\n"
        "def callee(value):\n    return value\n")
    checklist = {"files": [{"path": "unit.py", "items": [
        {"name": "caller", "kind": "function", "line_start": 1, "line_end": 2},
        {"name": "callee", "kind": "function", "line_start": 4, "line_end": 5},
    ]}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    future = Future()
    initial_units = set()
    contexts = []
    prompts = []
    drains = []
    current = {}
    actual_prep = orch._compute_audit_prep

    def prepare(*args, **kwargs):
        prepared = actual_prep(*args, **kwargs)
        prepared["joern_future"] = future
        prepared["joern_last_activity"] = [monotonic()]
        return prepared

    def drain(completed, evidence_index, *args, **kwargs):
        assert completed is future and future.done(), "an unfinished producer must not be drained"
        assert len(initial_units) == 2, "the result was scheduled before both initial reviews finished"
        drains.append(len(contexts))
        record = EvidenceRecord(file="unit.py", function="caller", line_start=1, line_end=2,
            joern_flows=[TaintFlow(source_method="caller", source_param="value",
                                  sink_call="selected_sink", sink_arg_idx=0)])
        return {**evidence_index, "unit.py:caller": record}

    def await_completed(producer, timeout):
        assert producer.done(), f"fixture producer not ready: units={initial_units}, contexts={contexts}"
        return producer

    monkeypatch.setattr(orch, "_await_joern_build", await_completed)
    monkeypatch.setattr(orch, "_compute_audit_prep", prepare)
    monkeypatch.setattr(orch, "_drain_joern_future", drain)
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))

    class Client:
        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append((current["ctx"]["function"], prompt))
            if current["ctx"]["function"] == "callee":
                response = {"status": "suspicious", "body": "Callee concern remains unresolved",
                            "hypothesis": "The supplied callee may not establish the caller assumption"}
            else:
                response = {"status": "clean", "body": "Independent caller assessment remains provisional",
                            "relies_on": [{"callee": "callee", "assumption": "validates the value"}]}
            return StructuredResponse(result=response, raw="", cost=0, model="scripted")

    client = Client()
    rendered = make_review_fn(client, escalate_clean=False)
    monkeypatch.setattr(orch, "_run_llm_client", lambda config: client)

    def review(ctx, config):
        current["ctx"] = ctx
        contexts.append(dict(ctx))
        is_continuation = bool(ctx.get("continuation_context_inputs"))
        outcome = rendered(ctx, config)
        if not is_continuation:
            initial_units.add((ctx["file"], ctx["function"], ctx.get("line_start")))
            if ready_before_callee and len(initial_units) == 2 and not future.done():
                future.set_result("scripted completed Joern output")
        elif ctx.get("callee_contract_violation") and not ready_before_callee:
            # This producer completes during the already-owned callee pass.
            # It is not available at that pass's admission boundary.
            assert not future.done()
            assert not ctx.get("mechanical_evidence") or "selected_sink" not in ctx["mechanical_evidence"]
            future.set_result("scripted later Joern output")
        return outcome

    review._knowledge_observed_client_contract = True
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=checklist,
        max_workers=1, batch_sloc_threshold=0, resume=False, triage=False, prefilter=False, validate=False,
        immediate_verify=False, sweep_validate_findings=False, max_refinements=0,
        deepen_suspicious=False, clean_check=False, open_discovery=False, sage_recall=False,
        iris=False, adversarial=False, propagate_constraints=False,
        joern_overrides={"enabled": False}, llm_budget_client=client)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="ready context union"):
        result = orch.run_orchestrator(config, review)

    caller_contexts = [ctx for ctx in contexts if ctx["function"] == "caller"]
    caller_prompts = [prompt for function, prompt in prompts if function == "caller"]
    assert len(drains) == 1
    assert len(result.outcomes) == 2
    assert len(caller_contexts) == (2 if ready_before_callee else 3)
    assert "Advisory prior callee assessment" in caller_prompts[1]
    if ready_before_callee:
        assert "selected_sink" in caller_prompts[1]
        assert drains[0] == 2
    else:
        assert "selected_sink" not in caller_prompts[1]
        assert "selected_sink" in caller_prompts[2]
        assert drains[0] == 3

    trace = json.loads((out / "knowledge-results.json").read_text())
    caller_unit, = [unit for unit in trace["units"] if unit["unit"][:2] == ["unit.py", "caller"]]
    assert caller_unit["all_model_calls"] == len(caller_contexts)
    completed = [event for event in trace["events"] if event["event"] == "continuation_completed"]
    assert len(completed) == (1 if ready_before_callee else 2)
    delivered = completed[0]["delivered_request_ids"]
    assert any(identifier.startswith("context:callee_contract:") for identifier in delivered)
    assert any(identifier.startswith("context:late_joern:") for identifier in delivered) is ready_before_callee
