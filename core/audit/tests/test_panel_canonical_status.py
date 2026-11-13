"""Panel status projection preserves the actual review producer's fallback."""
from copy import deepcopy

import pytest

from core.audit import orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.llm.providers import StructuredResponse


class _ScriptedClient:
    _attempt_admission_protocol = 1
    _call_cost_history = None

    def __init__(self, response):
        self.response = response
        self.calls = []
        self.admissions = []

    def is_budget_exhausted(self):
        return False

    def generate_structured(self, prompt, schema, **kwargs):
        admission = kwargs.pop("accounting_attempt_admission", None)
        if admission is not None:
            admitted = admission()
            self.admissions.append(admitted)
            assert admitted is True
        self.calls.append(prompt)
        return StructuredResponse(result=deepcopy(self.response), raw="", cost=0, model="scripted")


def test_actual_self_consistency_retains_producer_invalid_status_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "unsigned f(unsigned n) { return n; }\n"
    (target / "unit.c").write_text(source)
    ctx = {"file": "unit.c", "function": "f", "source": source, "line_start": 1, "line_end": 1, "language": "c"}
    response = {"status": "INVALID", "body": "Owned invalid model status", "reading_list": [],
                "language_reference_requests": []}
    direct_client = _ScriptedClient(response)
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, models=["scripted"],
                                     review_passes=2, max_refinements=0)
    direct = make_review_fn(direct_client)(ctx, config)
    assert direct.status == "suspicious" and direct.review_result["status"] == "INVALID"
    assert len(direct_client.calls) == 1
    panel_client = _ScriptedClient(response)
    config.llm_budget_client = panel_client
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        wrapped = runtime.wrap_review(make_review_fn(panel_client))
        produced = []

        def review(context, settings):
            outcome = wrapped(context, settings)
            assert outcome.review_input_scope is not None and outcome.review_input_scope.current(target)
            produced.append(outcome)
            return outcome

        panel = orch._multi_pass_review(review, ctx, config, 2, knowledge_runtime=runtime)
        assert len(panel_client.calls) == 2 and panel_client.admissions == [True, True]
        assert len(produced) == 2 and all(o.status == "suspicious" for o in produced)
        assert panel.status == "suspicious"
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("status", ["clean", "suspicious", "finding", "dormant", "dark", "error"])
def test_panel_projection_keeps_canonical_status_without_rewriting_raw_payload(status):
    raw = {"status": "RAW-UNNORMALISED", "verdict_rationale": "Owned retained claim"}
    outcome = orch.ReviewOutcome("unit.c", "f", status, "Owned canonical body", review_result=raw)
    projected = orch._outcome_to_panel_result(outcome, "scripted")
    assert projected["status"] == status and projected["body"] == outcome.body
    assert projected["verdict_rationale"] == "Owned retained claim"
    assert raw == {"status": "RAW-UNNORMALISED", "verdict_rationale": "Owned retained claim"}


def test_actual_producer_forgery_drop_still_protects_panel_identity_and_accounting(tmp_path):
    source = "unsigned f(unsigned n) { return n; }\n"
    (tmp_path / "unit.c").write_text(source)
    response = {"status": "clean", "body": "Owned ordinary review", "file": "foreign.c",
                "function": "foreign", "model": "forged", "cost_usd": 999, "duration_s": 999}
    client = _ScriptedClient(response)
    outcome = make_review_fn(client, escalate_clean=False)({
        "file": "unit.c", "function": "f", "source": source, "line_start": 1,
        "line_end": 1, "language": "c"}, orch.OrchestratorConfig(target_path=tmp_path, out_dir=None))
    assert len(client.calls) == 1
    projected = orch._outcome_to_panel_result(outcome, "scripted")
    assert projected["file"] == "unit.c" and projected["function"] == "f"
    assert projected["model"] == "scripted" and projected["cost_usd"] == 0
    assert projected["duration_s"] == outcome.duration_s and projected["duration_s"] != 999
    assert all(k not in outcome.review_result for k in ("file", "function", "model", "cost_usd", "duration_s"))


def test_actual_counter_escalation_stays_suspicious_in_panel_projection(tmp_path):
    source = "unsigned f(unsigned n) { return n; }\n"
    (tmp_path / "unit.c").write_text(source)
    client = _ScriptedClient({"status": "clean", "body": "Owned original rationale",
        "counter_hypothesis": "an attacker-controlled length reaching memcpy can overflow the stack buffer when the caller passes tainted input"})
    outcome = make_review_fn(client)({"file": "unit.c", "function": "f", "source": source,
        "line_start": 1, "line_end": 1, "language": "c"}, orch.OrchestratorConfig(target_path=tmp_path, out_dir=None))
    assert len(client.calls) == 1
    assert outcome.status == "suspicious" and outcome.review_result["status"] == "suspicious"
    projected = orch._outcome_to_panel_result(outcome, "scripted")
    assert projected["status"] == "suspicious" and projected["body"].startswith("[counter-hypothesis escalation:")
