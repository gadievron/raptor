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
