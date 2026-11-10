"""Draft affected-consumer control for retained reference subset receipts."""

from time import monotonic

from core.audit.knowledge_context import reference_delivery, reference_sections
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.reference_inputs import reference_inputs_from_delivery
from core.audit.refutation_source import capture_source_identity
from core.llm.providers import StructuredResponse


def test_owned_continuation_records_each_request_supplied_by_retained_bundle(tmp_path, monkeypatch):
    source = 'int f(int a) { const char *padding="' + "x" * 17500 + '"; return a; }'
    (tmp_path / "unit.c").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    origin = runtime._origin(ctx)
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *args, **kwargs: 6000)
    prompts = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            assert source in prompt
            assert all(entry.render_core() in prompt for entry in exact.entries)
            assert all(prompt.count(entry.render_core()) == 1 for entry in topic.entries)
            return StructuredResponse(result={"status": "clean", "body": "Scripted assessment",
                                               "language_reference_requests": []},
                                      raw="", cost=0, model="scripted")

    try:
        runtime._register(origin, ctx, {"language_reference_requests": [
            {"topic": "integer division", "entry_id": "c.integer-division"},
            {"topic": "integer conversion"},
        ]})
        accepted = runtime.requests()
        assert len(accepted) == 2
        request_ids = {request.request_id for request in accepted}
        reservation, = runtime.ready_continuations(admission=lambda: True, now=monotonic() + 20)
        assert runtime.enrich_context(ctx, reservation)
        exact, = (answer for answer in reservation.packet.references if answer.selection_kind == "entry_id")
        topic, = (answer for answer in reservation.packet.references if answer.selection_kind == "topic")
        assert {answer.request_id for answer in reservation.packet.references} == request_ids
        assert topic.entries and all(entry in exact.entries for entry in topic.entries)
        assert exact.status == topic.status == "needs_target_facts"
        assert exact.missing_facts == topic.missing_facts == ("language edition",)

        review = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))
        outcome = review(ctx, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
        assert len(prompts) == 1
        receipts = {row["request_id"]: row for row in outcome.review_result["language_reference_delivery"]}
        assert all(receipts[request_id]["delivered"] for request_id in request_ids)
        assert all(receipts[request_id]["reason"] == "delivered" for request_id in request_ids)
        expected_inputs = reference_inputs_from_delivery(
            reference_delivery((exact,), reference_sections((exact,))), (exact,))
        assert outcome.review_result["review_claims"]["reference_inputs"] == expected_inputs
        assert capture_source_identity(tmp_path, "unit.c") == origin.source_identity
        assert runtime.can_publish(reservation)
        assert not outcome.evidence_tool
        assert not outcome.review_result.get("immediate_verified")

        assert runtime.complete(reservation, ctx, published_status=outcome.status)
        completed, = (event for event in runtime.events() if event["event"] == "continuation_completed")
        assert set(completed["delivered_request_ids"]) == request_ids
        assert completed["published_status"] == "clean"
        prompt_event, = (event for event in runtime.events() if event["event"] == "review_prompt_context")
        observed = {row["request_id"] for row in prompt_event["records"] if row.get("delivered") is True}
        assert observed == request_ids
        assert runtime.ready_continuations(admission=lambda: True) == ()
        assert len(prompts) == 1
    finally:
        runtime.close("test_complete")
