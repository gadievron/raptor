"""Persist delivery separately from assessments and verification authority."""

import json

from core.audit.tests.test_knowledge_runtime_coordinator import _runtime


def test_trace_retains_omission_and_failure_without_claiming_model_use(tmp_path, monkeypatch):
    runtime, ctx = _runtime(tmp_path)
    reservation = runtime.ready_continuations(admission=lambda: True)[0]
    request_id = reservation.packet.references[0].request_id
    ctx["language_reference_delivery"] = [{"request_id": request_id, "delivered": False,
                                           "reason": "token_budget"}]
    assert runtime.enrich_context(ctx, reservation)
    from core.audit.llm_review import make_review_fn
    from core.audit.orchestrator import OrchestratorConfig
    from core.llm.providers import StructuredResponse

    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100)

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            return StructuredResponse(result={"status": "clean", "body": "Scripted assessment"},
                                      raw="", cost=0, model="scripted")

    runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))(
        ctx, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
    assert runtime.fail(reservation, "scripted_failure", ctx)
    out = tmp_path / "out"
    out.mkdir()
    runtime.write_artifacts(out)
    payload = json.loads((out / "knowledge-results.json").read_text())
    assert payload["role"] == "context_provenance_not_verification_evidence"
    prompt = [row for row in payload["events"] if row["event"] == "review_prompt_context"][0]
    assert prompt["records"][0]["delivered"] is False
    assert prompt["records"][0]["request_id"] == request_id
    failed = [row for row in payload["events"] if row["event"] == "continuation_failed"][0]
    assert failed["pass_id"] == reservation.packet.pass_id
    assert failed["published_status"] == ""
    before = (out / "audit-log.jsonl").read_bytes() if (out / "audit-log.jsonl").exists() else None
    runtime.write_artifacts(out)
    if before is not None:
        assert (out / "audit-log.jsonl").read_bytes() == before


def test_report_material_fallback_uses_canonical_bytes_and_preserves_binding_ids(tmp_path):
    import hashlib
    from dataclasses import asdict

    from core.concepts.subject_study import SubjectExplanation, SubjectMaterial
    from core.json import dumps_canonical

    runtime, ctx = _runtime(tmp_path)
    runtime._register(runtime._origin(ctx), ctx, {"reading_list": [{"subject": "f"}]})
    request = next(row for row in runtime.requests() if row.kind == "target_study")
    unbound = SubjectMaterial("unbound", "unit.c", 1, "f", "/* café */", False)
    bound = SubjectMaterial("bound", "unit.c", 1, "f", ctx["source"], False,
                            binding_id="existing-binding-id")
    answer = SubjectExplanation(request.request_id, "unavailable", "", "No admitted explanation",
                                (), inputs=(unbound, bound), excluded_inputs=(unbound,))
    runtime.record_source_answers((answer,))
    out = tmp_path / "out"
    runtime.write_artifacts(out)
    payload = json.loads((out / "knowledge-results.json").read_text())
    expected = hashlib.sha256(dumps_canonical(asdict(unbound)).encode("utf-8")).hexdigest()
    event = next(row["answer"] for row in payload["events"] if row["event"] == "source_answer")
    assert event["inputs"] == [expected, bound.binding_id]
    assert event["excluded_inputs"] == [expected]
    assert payload["materials"][expected] == asdict(unbound)
    assert payload["materials"][bound.binding_id] == asdict(bound)
    assert payload["role"] == "context_provenance_not_verification_evidence"
    runtime.write_artifacts(out)
    assert json.loads((out / "knowledge-results.json").read_text()) == payload
