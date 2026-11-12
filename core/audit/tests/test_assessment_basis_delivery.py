"""An actual captured SDK review retains descriptive basis through publication."""

import json

import pytest

from core.audit.collector import append_journal_for_outcome
from core.audit.claims import ClaimRevision
from core.audit.review_claims import record_intake
from core.llm.providers import StructuredResponse
from uuid import uuid4
from core.audit.assessment_basis import read_assessment_basis
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.record import load_verified_audit_log
from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.json import save_json
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from core.reporting.renderers import get_renderer


@pytest.mark.slow
@pytest.mark.parametrize("status", ["clean", "suspicious"])
def test_captured_sdk_basis_reaches_owned_journal_and_report(tmp_path, sdk_clients, status):
    target, out = tmp_path / "target", tmp_path / "run"
    target.mkdir()
    source = "unsigned f(unsigned n) { return n; }\n"
    (target / "unit.c").write_text(source)
    bundle = sdk_clients(run_dir=out)
    payload = {"status": status, "body": "Conditional source review judgment.",
               "hypothesis": "an unresolved source concern" if status == "suspicious" else ""}

    def response(row):
        message = row["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return row

    bundle.state["transform"] = response
    schema = {"type": "object", "properties": {key: {"type": "string"} for key in payload},
              "required": list(payload)}
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"))
    config = OrchestratorConfig(target_path=target, out_dir=out)
    gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1}
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    review = runtime.wrap_review(make_review_fn(bundle.client, schema=schema,
        system_prompt="Review the supplied function.", escalate_clean=False))
    try:
        outcome = runtime.wrap_unit(lambda _gap: review(ctx, config))(gap)
        outcome.line = 1
        history = outcome.review_result["review_claims"]
        pass_id = history["review"]["origin"]["pass_id"]
        basis = read_assessment_basis(history, pass_id=pass_id, status=status)
        assert basis is not None and basis["basis"] == "model_judgment"
        assert basis["scope"] == "historical_review_only" and "assurance" not in basis
        if status == "suspicious":
            revision = ClaimRevision({"mechanism": payload["hypothesis"]}, pass_id=uuid4().hex,
                                     file="unit.c", function="f", line_start=1)
            assert revision.pass_id != pass_id
            outcome.review_result["review_claims"] = record_intake(history, [revision])
            assert read_assessment_basis(outcome.review_result["review_claims"], pass_id=pass_id, status=status) == basis
        ack = append_journal_for_outcome(out_dir=out, target_path=target, run_id=out.name,
            outcome=outcome, gap=gap, review_input_scope=outcome.review_input_scope)
        assert ack is not None
        entry, = load_entries(out, fresh=True)
        assert read_assessment_basis(entry.review_claims, pass_id=pass_id, status=status) == basis
        assert len(bundle.state["requests"]) == 1 and bundle.client.reported_spend_usd > 0
        admitted, = [r for r in load_verified_audit_log(out) if r.get("stage") == "admitted"]
        assert admitted["attempt"]["work_id"] == "review:" + pass_id
        graded = export_findings([outcome])
        write_graded_findings(graded, out)
        save_json(out / "findings.json", graded["findings"])
        runtime.write_artifacts(out)
        report = generate_report(out, target_path=target)
        recorded = report["assessment_bases"]
        assert recorded["recorded"] == 1 and recorded["unavailable"] == 0
        record, = recorded["records"]
        assert record["basis"] == basis["basis"] and record["pass_id"] == pass_id
        assert record["status"] == status and record["scope"] == "historical_review_only"
        assert report["stats"][status] == 1
        assert outcome.status == status and not bundle.client.pending_usage_reservations
        _, document = build_audit_document(report, out, target_path=target)
        markdown = get_renderer("markdown").render(document).content.decode()
        assert "Recorded reviewer basis" in markdown
        assert "Model judgement" in markdown
        assert "does not establish" in markdown and "mechanical assurance" in markdown
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("kind", ["model_fields", "opaque", "invalid_status", "counter_escalated", "failed"])
def test_only_completed_owned_model_judgment_records_basis(tmp_path, kind):
    source = "void f(char *p, int n) { char buf[8]; memcpy(buf, p, n); }\n"
    (tmp_path / "unit.c").write_text(source)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    payload = {"status": "clean", "body": "Captured review judgement.",
        "assessment_basis": "mechanically_verified", "assurance": "complete",
        "review_claims": {"assessment_basis": "mechanically_verified", "review": {"admissible": True}}}
    if kind == "invalid_status":
        payload["status"] = "not-a-review-status"
    if kind == "counter_escalated":
        payload.update(counter_hypothesis=("An attacker-controlled length reaching memcpy can overflow "
                                          "the stack buffer when the caller passes tainted input."),
                       counter_direction="supports_vuln")

    class Client:
        def generate_structured(self, *args, **kwargs):
            if kind == "failed":
                raise TimeoutError("captured response unavailable")
            return StructuredResponse(result=payload, raw="", cost=.1, model="captured")

    reviewer = make_review_fn(Client())
    if kind == "opaque":
        from core.audit.orchestrator import ReviewOutcome
        reviewer = lambda *_: ReviewOutcome("unit.c", "f", "clean", "Opaque callback", review_result=payload)
    try:
        if kind == "failed":
            with pytest.raises(TimeoutError):
                runtime.wrap_review(reviewer)(ctx, config)
            assert any(event["event"] == "review_failed" for event in runtime.events())
            assert not any(event["event"] == "review_assessment" for event in runtime.events())
            return
        outcome = runtime.wrap_review(reviewer)(ctx, config)
        history = outcome.review_result["review_claims"]
        pass_id = history["review"]["origin"]["pass_id"]
        basis = read_assessment_basis(history, pass_id=pass_id, status=outcome.status)
        if kind == "model_fields":
            assert basis is not None and basis["basis"] == "model_judgment"
            assert "assurance" not in basis and "mechanically_verified" not in json.dumps(basis)
        else:
            assert basis is None
        if kind == "counter_escalated":
            assert outcome.status == "suspicious" and outcome.review_result["counter_escalated"] is True
    finally:
        runtime.close("test_complete")
