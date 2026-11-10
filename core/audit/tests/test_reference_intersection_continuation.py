"""Draft consumer control for post-fit sharing of intersecting reference cores."""

from time import monotonic

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.refutation_source import capture_source_identity
from core.llm.providers import StructuredResponse


def test_owned_continuation_records_both_intersecting_reference_requests(tmp_path, monkeypatch):
    source = "int f(int n, int d) { return (n / d) << 1; }"
    (tmp_path / "unit.c").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"))
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    origin = runtime._origin(ctx)
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *args, **kwargs: 100_000)
    prompts = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            prompts.append(prompt)
            assert source in prompt
            assert "Shared rule cores above:" in prompt
            assert all(entry.render_core() in prompt for answer in references for entry in answer.entries)
            # Ordinary initial reading has a distinct envelope and may retain
            # another complete copy; global multiplicity is not this contract.
            return StructuredResponse(result={"status": "clean", "body": "Scripted assessment",
                                               "language_reference_requests": []},
                                      raw="", cost=0, model="scripted")

    try:
        runtime._register(origin, ctx, {"language_reference_requests": [
            {"topic": "integer division", "entry_id": "c.integer-division"},
            {"topic": "integer shift", "entry_id": "c.integer-shift"},
        ]})
        accepted = runtime.requests()
        assert len(accepted) == 2
        request_ids = {request.request_id for request in accepted}
        reservation, = runtime.ready_continuations(admission=lambda: True, now=monotonic() + 20)
        assert runtime.enrich_context(ctx, reservation)
        references = reservation.packet.references
        assert {answer.request_id for answer in references} == request_ids
        assert all(answer.selection_kind == "entry_id" for answer in references)
        assert all(answer.status == "needs_target_facts" for answer in references)
        assert all(answer.missing_facts == ("language edition",) for answer in references)
        assert set(references[0].entries) & set(references[1].entries)
        assert not all(entry in references[0].entries for entry in references[1].entries)
        assert not all(entry in references[1].entries for entry in references[0].entries)

        review = runtime.wrap_review(make_review_fn(Client(), escalate_clean=False))
        outcome = review(ctx, OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out"))
        assert len(prompts) == 1
        receipts = {row["request_id"]: row for row in outcome.review_result["language_reference_delivery"]}
        assert all(receipts[request_id]["delivered"] for request_id in request_ids)
        assert all(receipts[request_id]["reason"] == "delivered" for request_id in request_ids)
        manifest = outcome.review_result["review_claims"]["reference_inputs"]
        assert manifest["complete"]
        recorded = {(entry["id"], entry["version"], entry["pack_version"])
                    for entry in manifest["entries"]}
        expected = {(entry.entry_id, entry.version, answer.pack_version)
                    for answer in references for entry in answer.entries}
        assert expected <= recorded
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
