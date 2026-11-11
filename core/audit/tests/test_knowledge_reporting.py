"""Final reports distinguish saved knowledge processing from assessments."""

import copy
import json
from dataclasses import asdict

import pytest

from core.audit.knowledge_requests import KnowledgeOrigin, KnowledgeRequest
from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.reporting.renderers import get_renderer


def _captured(out_dir):
    origin = KnowledgeOrigin("initial-pass", "owned.c", "f", 1, 2, None)
    requests = [
        {**asdict(KnowledgeRequest(name, origin, "target_study", "owned_type", "", "normal")),
         "processing": {"state": state}}
        for name, state in (("delivered", "context_available"), ("late", "context_available"),
                            ("missing", "unavailable"))
    ]
    payload = {"schema_version": 1, "role": "context_provenance_not_verification_evidence",
               "requests": requests, "caller_context_requests": [], "bindings": [], "materials": {},
               "events": [{"event": "continuation_completed", "pass_id": "completed-pass",
                           "published_status": "clean", "delivered_request_ids": ["delivered"]}],
               "units": [{"unit": ["owned.c", "f", 1], "owned_dispatch_attempts": 2,
                          "all_model_calls": 2, "cycle": {"pending_ids": [], "delta_ids": ["late"],
                                                         "active_pass_id": None}}]}
    path = out_dir / "knowledge-results.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, payload


def test_final_report_keeps_answered_but_unconsumed_information_visible(tmp_path):
    path, payload = _captured(tmp_path)
    finding = {"id": "FIND-owned", "title": "Retained captured concern", "file": "owned.c",
               "line": 1, "severity": "medium", "evidence_tier": "heuristic"}
    (tmp_path / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    before = path.read_bytes()
    baseline = generate_report(tmp_path, final_status="completed")
    projection = baseline.get("knowledge_processing")
    assert projection is not None, "final report must expose saved knowledge processing"
    assert projection["requests"] == 3
    assert projection["delivered_requests"] == 1
    assert projection["available_requests_never_delivered"] == 1
    assert projection["unavailable_requests"] == 1
    assert projection["pending_delivery_requests"] == 1
    assert baseline["findings"] == [finding]
    assert "available requests with no recorded completed delivery" in baseline["summary"]
    assert "not verification evidence" in baseline["summary"]
    context, document = build_audit_document(baseline, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "available requests with no recorded completed delivery" in markdown
    assert any(item["path"] == str(path) for item in context.artifacts)
    assert path.read_bytes() == before and json.loads(before) == payload
    # Knowledge processing cannot change independently computed verdicts.
    without = copy.deepcopy(baseline)
    path.unlink()
    legacy = generate_report(tmp_path, final_status="completed")
    assert legacy["stats"] == without["stats"]
    assert legacy["findings"] == without["findings"]
    assert "knowledge_processing" not in legacy


def test_new_answer_to_previously_delivered_request_remains_pending(tmp_path):
    path, payload = _captured(tmp_path)
    # A completed pass consumed an earlier answer for this same request.
    # The saved cycle retains its newer useful answer as a pending update.
    payload["units"][0]["cycle"]["delta_ids"] = ["delivered"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = generate_report(tmp_path)
    projection = report["knowledge_processing"]
    assert projection["delivered_requests"] == 1
    assert projection["pending_delivery_requests"] == 1
    assert "Delivery totals are historical: newer updates may remain pending for the same request" in report["summary"]
    assert json.loads(path.read_text(encoding="utf-8")) == payload


@pytest.mark.parametrize("payload", ["{", '{"schema_version": 999}',
                                    '{"schema_version": true, "role": "context_provenance_not_verification_evidence"}'])
def test_invalid_present_knowledge_is_unavailable_not_empty_complete(tmp_path, payload):
    path = tmp_path / "knowledge-results.json"
    path.write_text(payload, encoding="utf-8")
    report = generate_report(tmp_path)
    assert report["knowledge_processing"]["state"] == "unavailable"
    assert "Knowledge processing record unavailable" in report["summary"]
    assert path.read_text(encoding="utf-8") == payload


def test_actual_empty_runtime_writer_is_not_an_unavailable_record(tmp_path):
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    runtime = AuditKnowledgeRuntime(tmp_path, None, deadline=float("inf"))
    runtime.close()
    runtime.write_artifacts(tmp_path)
    report = generate_report(tmp_path)
    assert report["knowledge_processing"]["state"] == "recorded"
    assert report["knowledge_processing"]["requests"] == 0
    assert report["knowledge_processing"]["delivered_requests"] == 0
    assert "not verification evidence" in report["summary"]


def test_actual_saved_external_context_is_not_a_dangling_request(tmp_path):
    from core.audit.continuation_context import context_version
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    source = "def owned(value):\n    return value\n"
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    context = {"file": "owned.py", "function": "owned", "line_start": 1, "line_end": 2,
               "source": source, "mechanical_evidence": "Captured context, no analysis executed"}
    runtime = AuditKnowledgeRuntime(tmp_path, None, deadline=float("inf"))
    try:
        assert runtime.offer_context_delta(context, kind="late_joern",
                                          version=context_version(context["mechanical_evidence"]))
        runtime.write_artifacts(tmp_path)
        path = tmp_path / "knowledge-results.json"
        before = path.read_bytes()
        payload = json.loads(before)
        assert payload["requests"] == [] and payload["caller_context_requests"] == []
        assert len(payload["units"][0]["cycle"]["delta_ids"]) == 1
        report = generate_report(tmp_path)
        processing = report["knowledge_processing"]
        assert processing["state"] == "recorded", "valid offered context is separate from request identities"
        assert processing["requests"] == 0 and processing["delivered_requests"] == 0
        assert processing["context_updates"] == 1 and processing["delivered_context_updates"] == 0
        assert processing["pending_delivery_context_updates"] == 1
        assert "context updates" in report["summary"]
        assert path.read_bytes() == before
    finally:
        runtime.close()


def test_same_context_version_is_counted_per_review_unit(tmp_path):
    from core.audit.continuation_context import context_version
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    source = "def first():\n    return 1\ndef second():\n    return 2\n"
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    runtime = AuditKnowledgeRuntime(tmp_path, None, deadline=float("inf"))
    try:
        for function, line in (("first", 1), ("second", 3)):
            context = {"file": "owned.py", "function": function, "line_start": line, "line_end": line + 1,
                       "source": source, "mechanical_evidence": "Identical captured context"}
            assert runtime.offer_context_delta(context, kind="late_joern",
                                              version=context_version(context["mechanical_evidence"]))
        runtime.write_artifacts(tmp_path)
        path = tmp_path / "knowledge-results.json"
        before = path.read_bytes()
        payload = json.loads(before)
        offered = [event for event in payload["events"] if event["event"] == "context_delta_offered"]
        assert len(offered) == 2 and offered[0]["context_id"] == offered[1]["context_id"]
        processing = generate_report(tmp_path)["knowledge_processing"]
        assert processing["context_updates"] == 2
        assert processing["pending_delivery_context_updates"] == 2
        assert path.read_bytes() == before
    finally:
        runtime.close()


def test_completed_prompt_receipt_does_not_consume_a_late_context_version(tmp_path, monkeypatch):
    from core.audit import llm_review
    from core.audit.continuation_context import context_version
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.late_joern_continuation import LateJoernContinuations
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig, StudyQueue
    from core.llm.providers import StructuredResponse

    source = "def owned(value):\n    return value\n"
    (tmp_path / "owned.py").write_text(source, encoding="utf-8")
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path,
                                enable_session_context=False, sweep_validate_findings=False)
    monkeypatch.setattr(llm_review, "_prompt_budget", lambda *args: 16000)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))

    class CapturedReply:
        calls = 0
        after = staticmethod(lambda: None)

        def generate_structured(self, prompt, schema, **kwargs):
            self.calls += 1
            self.after()
            return StructuredResponse(result={"status": "clean", "body": "Captured review judgment"},
                                      raw="", cost=0, model="captured-no-provider")

    client = CapturedReply()
    review = make_review_fn(client, escalate_clean=False)
    context = {"file": "owned.py", "function": "owned", "line_start": 1, "line_end": 2,
               "source": source, "language": "python"}
    owner = LateJoernContinuations(runtime, review, admission=lambda: True)
    try:
        runtime.wrap_review(review)(dict(context), config)
        context["mechanical_evidence"] = "Captured first context"
        frozen_id = "context:late_joern:" + context_version(context["mechanical_evidence"])
        later = {**context, "mechanical_evidence": "Captured later context"}
        late_id = "context:late_joern:" + context_version(later["mechanical_evidence"])

        def offer_late():
            assert runtime.offer_context_delta(later, kind="late_joern",
                                              version=context_version(later["mechanical_evidence"]))

        client.after = offer_late
        outcome = owner.dispatch(0, context, config)
        assert outcome.status == "clean" and owner.can_publish(0)
        assert owner.complete(0, "clean")
        runtime.write_artifacts(tmp_path)
        path = tmp_path / "knowledge-results.json"
        before = path.read_bytes()
        payload = json.loads(before)
        completed = [event for event in payload["events"] if event["event"] == "continuation_completed"]
        assert len(completed) == 1 and completed[0]["delivered_request_ids"] == [frozen_id]
        assert payload["units"][0]["cycle"]["delta_ids"] == [late_id]
        processing = generate_report(tmp_path)["knowledge_processing"]
        assert processing["requests"] == 0 and processing["delivered_requests"] == 0
        assert processing["context_updates"] == 2 and processing["delivered_context_updates"] == 1
        assert processing["pending_delivery_context_updates"] == 1
        assert path.read_bytes() == before and client.calls == 2
    finally:
        owner.close()
        runtime.close()


def test_unoffered_context_identity_remains_unavailable(tmp_path):
    path, payload = _captured(tmp_path)
    payload["units"][0]["cycle"]["delta_ids"] = ["context:late_joern:unoffered"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    processing = generate_report(tmp_path)["knowledge_processing"]
    assert processing["state"] == "unavailable" and "delivered_context_updates" not in processing
    assert path.read_bytes() == before
