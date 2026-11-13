"""Owned metadata controls for coalesced binary subject packets.

Scripted admission callbacks establish local adapter behavior, not SDK attempts
or extraction, native execution, signed publication, or evidence authority.
"""
import builtins
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, current_thread
from types import FunctionType, MethodType, ModuleType

import pytest

from core.audit import binary_subjects
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.audit.tests.test_binary_subjects import subject_case as subject_case
from core.llm.providers import StructuredResponse
from core.testing.module_views import module_function_view
from packages.ghidra.model import REType


def _case(subject_case, subjects=("Packet", "Header"), *, initial=False):
    build, target, database = subject_case
    database.types.append(REType(name="Header", kind="struct", size=8, source_tool="fixture",
        fields=[{"name": "kind", "type": "unsigned char", "offset": None}]))
    if initial:
        database.functions[0].signature = "long f(Packet *p, Header *h)"
        database.functions[0].decompilation = "long f(Packet *p, Header *h) { return 1; }"
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            subject = subjects[len(calls)]
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious" if subject else "clean",
                "body": "Recorded fields remain advisory",
                "reading_list": ([] if subject is None else [{"subject": subject,
                    "context": "recorded fields", "resolution": "identifier"}])},
                raw="", cost=0, model="scripted")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    return build, target, database, runtime, review, calls


def _resolver_view(runtime, resolver):
    """Own one instance's class-method imports without shared binding edits."""
    original = AuditKnowledgeRuntime._register_binary_subjects
    private_subjects = ModuleType(binary_subjects.__name__)
    vars(private_subjects).update(vars(binary_subjects))
    private_subjects.resolve_binary_subjects = resolver

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "binary_subjects":
            return private_subjects
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = dict(original.__globals__)
    namespace["__builtins__"] = dict(vars(builtins), __import__=import_local)
    local = FunctionType(original.__code__, namespace, original.__name__,
                         original.__defaults__, original.__closure__)
    local.__kwdefaults__ = original.__kwdefaults__
    return MethodType(local, runtime)


def test_concurrent_binary_subject_answers_keep_the_union_at_dispatch(subject_case, monkeypatch):
    build, _target, _database, runtime, review, calls = _case(subject_case)
    first_ctx, config = build(None)
    second_ctx, _ = build(None)
    first_offer, second_resolved, release = Event(), Event(), Event()
    original_offer = runtime.offer_context_delta
    threads = []

    def resolve(requests, *args, **kwargs):
        result = binary_subjects.resolve_binary_subjects(requests, *args, **kwargs)
        if requests[0].subject == "Header":
            second_resolved.set()
        return result

    def offer(ctx, *, kind, version):
        if {answer.subject for answer in ctx["binary_subject_context"].answers} == {"Packet"}:
            first_offer.set()
            assert release.wait(10), "first owned offer was not released"
        return original_offer(ctx, kind=kind, version=version)

    def run(ctx):
        threads.append(current_thread())
        return runtime.wrap_review(review)(ctx, config)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "_register_binary_subjects", _resolver_view(runtime, resolve))
            patch.setattr(runtime, "offer_context_delta", offer)
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(run, first_ctx)
                second = None
                try:
                    assert first_offer.wait(10), "first registration did not reach its owned offer"
                    second = pool.submit(run, second_ctx)
                    assert second_resolved.wait(10), "second resolver could not progress independently"
                    # The first thread holds only its unit's commit lock. This
                    # unrelated Runtime read must not be behind its callback.
                    assert len(runtime.requests()) == 2
                finally:
                    release.set()
                first.result(timeout=10)
                if second is not None:
                    second.result(timeout=10)
            assert threads and all(not thread.is_alive() for thread in threads)
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        assert {answer.subject for answer in fresh["binary_subject_context"].answers} == {"Packet", "Header"}
        assert "binary_subject_context" not in first_ctx and "binary_subject_context" not in second_ctx
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert not runtime._source_jobs and not runtime._pending_sources
        assert runtime.fail(reservation, "test_complete")
    finally:
        release.set()
        runtime.close("test_complete")


def test_late_binary_subject_answer_keeps_the_active_packet_immutable(subject_case):
    build, _target, _database, runtime, review, calls = _case(subject_case, ("Packet", "Header", None))
    try:
        initial, config = build(None)
        runtime.wrap_review(review)(initial, config)
        first, = runtime.ready_continuations(admission=lambda: True)
        current, _ = build(None)
        assert runtime.enrich_context(current, first)
        original = current["binary_subject_context"]
        assert {answer.subject for answer in original.answers} == {"Packet"}
        # This actual continuation sees Packet and asks for Header. The new
        # answer belongs to the next pending version, not its delivered input.
        outcome = runtime.wrap_review(review)(current, config)
        assert current["binary_subject_context"] is original
        assert {answer.subject for answer in original.answers} == {"Packet"}
        assert runtime.context_was_delivered(first)
        assert runtime.complete(first, current, published_status=outcome.status)
        second, = runtime.ready_continuations(admission=lambda: True)
        assert second.packet.external_context_ids != first.packet.external_context_ids
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, second)
        assert {answer.subject for answer in fresh["binary_subject_context"].answers} == {"Packet", "Header"}
        last = runtime.wrap_review(review)(fresh, config)
        assert runtime.complete(second, fresh, published_status=last.status)
        assert not runtime.ready_continuations(admission=lambda: pytest.fail("unchanged facts bought another pass"))
        cycle, = runtime._cycles.values()
        assert cycle.started == 2 and cycle.max_model_calls == 6
        assert len(calls) == sum(runtime._calls.values()) == 3
    finally:
        runtime.close("test_complete")


def test_coalesced_initial_answers_keep_each_original_visibility_receipt(subject_case):
    build, _target, _database, runtime, review, calls = _case(subject_case, initial=True)
    try:
        omitted, config = build(None)
        omitted["triage_bucket"] = "glance"
        visible, _ = build(None)
        assert {row["name"] for row in omitted["type_definitions"]} == {"Packet", "Header"}
        runtime.wrap_review(review)(omitted, config)
        runtime.wrap_review(review)(visible, config)
        requests = {request.subject: request for request in runtime._requests.values()}
        assert runtime._request_status[requests["Packet"].request_id]["state"] == "resolved_partial"
        assert runtime._request_status[requests["Header"].request_id] == {
            "state": "unavailable", "reason": "initial_type_delivery_unmeasured"}
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        payload = fresh["binary_subject_context"]
        assert {answer.subject: answer.status for answer in payload.answers} == {
            "Packet": "partial", "Header": "unavailable"}
        observations = {request_id: (inventory, delivery)
                        for request_id, inventory, delivery in payload.initial_observations}
        for name, expected in (("Packet", "omitted"), ("Header", "delivered")):
            request = requests[name]
            inventory, delivery = observations[request.request_id]
            assert inventory.origin == delivery.origin == request.origin
            assert {row["status"] for row in delivery.records()} == {expected}
        assert requests["Packet"].origin.pass_id != requests["Header"].origin.pass_id
        assert len([event for event in runtime.events() if event["event"] == "context_delta_offered"]) == 1
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("failure", ["read_error", "changed_input", "same_request_conflict"])
def test_binary_subject_union_refuses_read_drift_and_conflicting_observations(subject_case, failure):
    build, target, _database, runtime, review, _calls = _case(subject_case)
    try:
        first_ctx, config = build(None)
        runtime.wrap_review(review)(first_ctx, config)
        previous, = runtime._binary_subject_pending.values()
        second_ctx, _ = build(None)
        runtime.wrap_review(review)(second_ctx, config)
        aggregate, = runtime._binary_subject_pending.values()
        header, = [answer for answer in aggregate.answers if answer.subject == "Header"]
        incoming = replace(aggregate, answers=(header,),
            initial_observations=tuple(row for row in aggregate.initial_observations if row[0] == header.request_id))
        assert previous.current(second_ctx) and incoming.current(second_ctx)
        helper = binary_subjects.coalesce_binary_subject_contexts
        if failure == "read_error":
            def unreadable(*args, **kwargs):
                raise ValueError("owned projection became unreadable during union")
            view = module_function_view(binary_subjects, bindings={"_answers": unreadable})
            helper = view.coalesce_binary_subject_contexts
            expected = "binary_subject_context_unavailable"
        elif failure == "changed_input":
            target.write_bytes(target.read_bytes() + b"later owned revision")
            expected = "binary_subject_context_changed"
        else:
            old_id = previous.answers[0].request_id
            incoming = replace(incoming,
                answers=(replace(header, request_id=old_id),),
                initial_observations=tuple((old_id, inventory, delivery)
                    for _request_id, inventory, delivery in incoming.initial_observations))
            assert incoming.current(second_ctx), "collision must reach the union identity check"
            expected = "binary_subject_observation_conflict"
        merged, reason = helper(previous, incoming, second_ctx)
        assert merged is None and reason == expected
    finally:
        runtime.close("test_complete")
