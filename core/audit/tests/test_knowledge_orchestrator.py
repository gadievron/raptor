"""Normal scheduling links knowledge to one bounded reassessment."""
import json
import re

import pytest

from core.audit import capabilities, orchestrator as orch
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.wallclock import wall_deadline
from core.testing.treesitter import ts_parser_available


@pytest.mark.parametrize("workers,max_seconds", [(1, None), (2, 20)], ids=["serial", "parallel"])
@pytest.mark.parametrize("second_status", ["clean", "suspicious"])
def test_normal_audit_delivers_source_and_reference_then_retains_prior(tmp_path, monkeypatch, workers, max_seconds, second_status):
    parsed_selection = ts_parser_available("c")
    target = tmp_path / "target"
    target.mkdir()
    (target / "types.h").write_text("typedef struct { unsigned length; } foo_t;\n")
    (target / "owned.c").write_text('#include "types.h"\nunsigned f(foo_t item) { return item.length + 1; }\nint sibling(void) { return 0; }\n')
    out = tmp_path / "out"
    out.mkdir()
    (out / "checklist.json").write_text(json.dumps({"files": [{"path": "owned.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2}]}]}))
    monkeypatch.setattr(orch, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(orch, "_proactive_validate", lambda outcome, *a, **k: outcome)
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    calls = []

    class Client:
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            task = kwargs["task_type"]
            calls.append((task, prompt))
            if task == "study":
                assert "typedef struct" in prompt and "return item.length" in prompt
                request_id = re.search(r'"request_id"\s*:\s*"([^"]+)"', prompt).group(1)
                return {"subject_answers": [{"request_id": request_id, "status": "partial",
                    "explanation": "The target type carries length; callers are not supplied.",
                    "reason": "Other users are not supplied", "material_ids": ["material-0"]}]}
            assert task == "audit"
            if sum(t == "audit" for t, _ in calls) == 1:
                # Arithmetic selects definedness initially. Repeating that
                # request buys no pass; the source-study answer is new.
                assert "c.integer-promotion v1:" in prompt
                assert "c.integer-conversion v1:" in prompt
                assert ("c.integer-definedness v1:" in prompt) is parsed_selection
                payload = {"status": "suspicious", "body": "Length may wrap before its caller checks it.",
                    "hypothesis": "length wraps before caller validation", "confidence": "medium",
                    "reading_list": [{"subject": "foo_t", "resolution": "identifier", "context": "role of the target type"}],
                    "language_reference_requests": [{"topic": "integer arithmetic definedness",
                                                      "entry_id": "c.integer-definedness"}]}
            else:
                assert "The target type carries length" in prompt
                assert "c.integer-definedness v1:" in prompt
                assert "language reference" in prompt.lower()
                payload = {"status": second_status, "body": "The reviewer has reassessed it.",
                           "reading_list": [], "language_reference_requests": []}
                if second_status == "suspicious":
                    payload.update(hypothesis="a distinct conversion needs review", cwe="CWE-190",
                                   hypotheses=[{"mechanism": "a distinct conversion needs review",
                                                "confidence": "medium"}])
            return StructuredResponse(result=payload, raw="", cost=0, model="scripted")

    client = Client()
    monkeypatch.setattr(orch, "_run_llm_client", lambda cfg: client)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, max_workers=workers,
        resume=False, prefilter=False, validate=False, immediate_verify=False,
        sweep_validate_findings=False, max_refinements=0, deepen_suspicious=False,
        open_discovery=False, sage_recall=False, iris=False,
        joern_overrides={"enabled": False}, llm_budget_client=client, max_seconds=max_seconds)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float("inf"), what="normal knowledge continuation"):
        result = orch.run_orchestrator(config, make_review_fn(client, escalate_clean=False))
    assert [task for task, _ in calls] == ["audit", "study", "audit"]
    assert len(result.outcomes) == 1
    assert result.outcomes[0].status == "suspicious", "knowledge is not scoped refutation"
    assert result.reviewed == 1 and result.suspicious == 1 and not result.clean
    trace = json.loads((out / "knowledge-results.json").read_text())
    request_ids = {r["request_id"] for r in trace["requests"]}
    assert len(request_ids) == 2
    assert len({r["origin"]["pass_id"] for r in trace["requests"]}) == 1
    completed = [e for e in trace["events"] if e["event"] == "continuation_completed"]
    reason = "prior_retained" if second_status == "clean" else "new_unverified_candidates"
    assert len(completed) == 1 and completed[0]["reason"] == reason
    if second_status == "suspicious":
        canonical = result.outcomes[0]
        assert canonical.hypothesis == "length wraps before caller validation"
        added = next(h for h in canonical.hypotheses if h["mechanism"] == "a distinct conversion needs review")
        assert added["confidence"] == "medium" and not canonical.evidence_tool
    already = [event for event in trace["events"] if event["event"] == "reference_already_delivered"]
    assert len(already) == int(parsed_selection)
    assert set(completed[0]["delivered_request_ids"]) == request_ids - {
        event["request_id"] for event in already}
    assert completed[0]["published_status"] == "suspicious"
    assert trace["units"][0]["all_model_calls"] == 3
    assert trace["units"][0]["cycle"]["started"] == 1
    assessments = [e for e in trace["events"] if e["event"] == "review_assessment"]
    assert [e["status"] for e in assessments] == ["suspicious", second_status]
    assert assessments[1]["pass_id"] == completed[0]["pass_id"]
