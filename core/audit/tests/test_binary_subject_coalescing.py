"""Ready recovered type facts coalesce across separate initial review contexts."""

from core.audit.binary_subjects import render_binary_subject_context
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.review_context_inputs import MAX_SNAPSHOT_BYTES
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.audit.tests.test_binary_subjects import subject_case as subject_case
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REType


def test_separate_initial_type_answers_coalesce_before_first_dispatch(subject_case):
    build, target, database = subject_case
    database.types.append(REType(name="Header", kind="struct", size=8,
        fields=[{"name": "kind", "type": "unsigned char", "offset": None}], source_tool="fixture"))
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            subject = ("Packet", "Header")[len(calls)]
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Recovered fields are advisory",
                "reading_list": [{"subject": subject, "context": "recorded fields",
                                  "resolution": "identifier"}]}, raw="", cost=.1, model="scripted")

    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        for _ in range(2):
            initial, config = build(None)
            assert not initial["type_definitions"]
            runtime.wrap_review(review)(initial, config)
            assert "binary_subject_context" not in initial, "shared initial context was mutated"
        assert len(runtime._requests) == 2
        assert all(status["state"] == "resolved_partial" for status in runtime._request_status.values())
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert not runtime._source_jobs and not runtime._pending_sources
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert len(reservation.packet.external_context_ids) == 1
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        payload = fresh["binary_subject_context"]
        assert {answer.subject for answer in payload.answers} == {"Packet", "Header"}
        rendered = render_binary_subject_context(payload, fresh)
        assert '"subject":"Packet"' in rendered and '"subject":"Header"' in rendered
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")


def test_oversized_union_retains_ready_packet_and_records_deferred_question(subject_case):
    build, target, database = subject_case
    database.types[0].name = "ZPacket"
    database.types[0].fields = [{"name": f"field{i}", "type": "x" * 512} for i in range(18)]
    database.types.append(REType(name="AHeader", kind="struct", size=8,
        fields=[{"name": f"field{i}", "type": "y" * 512} for i in range(18)], source_tool="fixture"))
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            subject = ("ZPacket", "AHeader")[len(calls)]
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Layout unknown",
                "reading_list": [{"subject": subject, "context": "recorded fields",
                                  "resolution": "identifier"}]}, raw="", cost=0, model="scripted")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    try:
        for _ in range(2):
            ctx, config = build(None)
            runtime.wrap_review(review)(ctx, config)
        first, second = runtime._requests
        assert runtime._request_status[first]["state"] == "resolved_partial"
        assert runtime._request_status[second] == {"state": "deferred", "reason": "binary_subject_context_budget"}
        producer_answers = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert len(producer_answers) == 2 and all(event["status"] == "partial" for event in producer_answers)
        assert any(event["event"] == "binary_subject_context_deferred" and event["request_id"] == second
                   for event in runtime.events())
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        assert {answer.subject for answer in fresh["binary_subject_context"].answers} == {"ZPacket"}
        assert len(fresh["binary_subject_context"].render().encode("utf-8")) <= MAX_SNAPSHOT_BYTES
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")
