"""Distinct ready related-code views survive separate initial review contexts."""

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REFunction, REXref


def test_distinct_recorded_callers_coalesce_before_first_dispatch(binary_abi_case):
    build, target = binary_abi_case
    seed, _ = build(None)
    database = seed["_binary_analysis_database"]
    database.functions.extend([
        REFunction(name="caller_a", address=8192, size=32, source_tool="fixture",
                   decompilation="long caller_a(long n) { return f(n); }"),
        REFunction(name="caller_b", address=12288, size=32, source_tool="fixture",
                   decompilation="long caller_b(long n) { return f(n + 1); }")])
    database.xrefs.extend([REXref(from_addr=8196, to_addr=4096, kind="call", source_tool="fixture"),
                           REXref(from_addr=12292, to_addr=4096, kind="call", source_tool="fixture")])
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            name, address = (("caller_a", 8192), ("caller_b", 12288))[len(calls)]
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Caller inputs remain provisional",
                "caller_context_requests": [{"file": seed["file"], "function": name, "address": address,
                    "line_start": 0, "reason": "Inspect recorded input handling"}]},
                raw="", cost=.1, model="scripted")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    try:
        for _ in range(2):
            initial, config = build(None)
            runtime.wrap_review(review)(initial, config)
            assert "binary_caller_context" not in initial
        assert len(runtime._caller_requests) == 2
        assert all(status["state"] == "resolved_partial" for status in runtime._request_status.values())
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert not runtime._source_jobs and not runtime._pending_sources
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert len(reservation.packet.external_context_ids) == 1
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        payload = fresh["binary_caller_context"]
        assert {answer.material["caller_address"] for answer in payload.answers} == {8192, 12288}
        assert {request.request_id for request in payload.requests} == set(runtime._caller_requests)
        assert payload.current(fresh)
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")
