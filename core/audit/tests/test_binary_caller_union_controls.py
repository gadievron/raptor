"""Owned inert recorded-caller controls; no SDK or execution proof."""
import builtins
from concurrent.futures import ThreadPoolExecutor
from threading import Event, current_thread
from types import FunctionType, MethodType, ModuleType

import pytest

from core.audit import binary_callers
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.review_context_inputs import MAX_SNAPSHOT_BYTES
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REFunction, REXref


def _case(binary_abi_case, batches=((0,), (1,)), *, count=2, body_padding=0):
    build, target = binary_abi_case
    seed, _ = build(None)
    database = seed["_binary_analysis_database"]
    callers = []
    for index in range(count):
        name = f"caller_{index}"
        address = 8192 + index * 4096
        body = f"long {name}(long n) {{ /*" + "x" * body_padding + "*/ return f(n); }"
        caller = REFunction(name=name, address=address, size=32, source_tool="fixture", decompilation=body)
        database.functions.append(caller)
        database.xrefs.append(REXref(from_addr=address + 4, to_addr=4096, kind="call", source_tool="fixture"))
        callers.append(caller)
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            selected = batches[len(calls)]
            calls.append(prompt)
            rows = [{"file": seed["file"], "function": callers[index].name,
                     "address": callers[index].address, "line_start": 0,
                     "reason": "Inspect recorded input handling"} for index in selected]
            return StructuredResponse(result={"status": "suspicious" if rows else "clean",
                "body": "Related pseudocode remains advisory", "caller_context_requests": rows},
                raw="", cost=0, model="scripted")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    return build, target, callers, runtime, review, calls


def _addresses(payload):
    return {answer.material["caller_address"] for answer in payload.answers if answer.status == "partial"}


def _resolver_view(runtime, resolver):
    """Own one instance's class-method import without changing shared modules."""
    original = AuditKnowledgeRuntime._register_binary_callers
    private = ModuleType(binary_callers.__name__)
    vars(private).update(vars(binary_callers))
    private.resolve_binary_callers = resolver

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "binary_callers":
            return private
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace = dict(original.__globals__)
    namespace["__builtins__"] = dict(vars(builtins), __import__=import_local)
    local = FunctionType(original.__code__, namespace, original.__name__,
                         original.__defaults__, original.__closure__)
    local.__kwdefaults__ = original.__kwdefaults__
    return MethodType(local, runtime)


def test_concurrent_recorded_callers_keep_the_union_at_dispatch(binary_abi_case, monkeypatch):
    build, _target, _callers, runtime, review, calls = _case(binary_abi_case)
    first_ctx, config = build(None)
    second_ctx, _ = build(None)
    first_offer, second_resolved, release = Event(), Event(), Event()
    original_offer = runtime.offer_context_delta
    threads = []

    def resolve(requests, *args, **kwargs):
        result = binary_callers.resolve_binary_callers(requests, *args, **kwargs)
        if requests[0].caller_address == 12288:
            second_resolved.set()
        return result

    def offer(ctx, *, kind, version):
        if _addresses(ctx["binary_caller_context"]) == {8192}:
            first_offer.set()
            assert release.wait(10), "first owned caller offer was not released"
        return original_offer(ctx, kind=kind, version=version)

    def run(ctx):
        threads.append(current_thread())
        return runtime.wrap_review(review)(ctx, config)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "_register_binary_callers", _resolver_view(runtime, resolve))
            patch.setattr(runtime, "offer_context_delta", offer)
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(run, first_ctx)
                second = None
                try:
                    assert first_offer.wait(10), "first registration did not reach its owned offer"
                    second = pool.submit(run, second_ctx)
                    assert second_resolved.wait(10), "second caller resolver could not progress"
                    # This read takes the Runtime lock while only the first
                    # unit's commit/offer lock is held by the blocked callback.
                    registered = [event for event in runtime.events()
                                  if event["event"] == "caller_requests_registered"]
                    assert len(registered) == 2 and len(runtime._caller_requests) == 2
                finally:
                    release.set()
                first.result(timeout=10)
                if second is not None:
                    second.result(timeout=10)
            assert threads and all(not thread.is_alive() for thread in threads)
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        assert _addresses(fresh["binary_caller_context"]) == {8192, 12288}
        assert "binary_caller_context" not in first_ctx and "binary_caller_context" not in second_ctx
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert not runtime._source_jobs and not runtime._pending_sources
        assert runtime.fail(reservation, "test_complete")
    finally:
        release.set()
        runtime.close("test_complete")


def test_late_recorded_caller_keeps_the_active_packet_immutable(binary_abi_case):
    build, _target, _callers, runtime, review, calls = _case(binary_abi_case, ((0,), (1,), ()))
    try:
        initial, config = build(None)
        runtime.wrap_review(review)(initial, config)
        first, = runtime.ready_continuations(admission=lambda: True)
        current, _ = build(None)
        assert runtime.enrich_context(current, first)
        original = current["binary_caller_context"]
        assert _addresses(original) == {8192}
        outcome = runtime.wrap_review(review)(current, config)
        assert current["binary_caller_context"] is original and _addresses(original) == {8192}
        assert runtime.context_was_delivered(first)
        assert runtime.complete(first, current, published_status=outcome.status)
        second, = runtime.ready_continuations(admission=lambda: True)
        assert second.packet.external_context_ids != first.packet.external_context_ids
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, second)
        assert _addresses(fresh["binary_caller_context"]) == {8192, 12288}
        last = runtime.wrap_review(review)(fresh, config)
        assert runtime.complete(second, fresh, published_status=last.status)
        assert not runtime.ready_continuations(admission=lambda: pytest.fail("unchanged facts bought another pass"))
        cycle, = runtime._cycles.values()
        assert cycle.started == 2 and cycle.max_model_calls == 6
        assert len(calls) == sum(runtime._calls.values()) == 3
    finally:
        runtime.close("test_complete")


def test_oversized_caller_union_preserves_ready_views_and_defers_new_questions(binary_abi_case):
    build, _target, callers, runtime, review, calls = _case(binary_abi_case,
        (tuple(range(4)), tuple(range(4, 8))), count=8, body_padding=2000)
    try:
        for _ in range(2):
            ctx, config = build(None)
            runtime.wrap_review(review)(ctx, config)
        assert len(runtime._caller_requests) == 8
        requests = tuple(runtime._caller_requests.values())
        assert all(runtime._request_status[request.request_id]["state"] == "resolved_partial"
                   for request in requests[:4])
        assert all(runtime._request_status[request.request_id] == {
            "state": "deferred", "reason": "binary_caller_context_budget"} for request in requests[4:])
        answers = [event for event in runtime.events() if event["event"] == "binary_caller_answer"]
        assert len(answers) == 8 and all(event["status"] == "partial" for event in answers)
        assert {event["request_id"] for event in runtime.events()
                if event["event"] == "binary_caller_context_deferred"} == {
                    request.request_id for request in requests[4:]}
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        payload = fresh["binary_caller_context"]
        assert _addresses(payload) == {caller.address for caller in callers[:4]}
        assert len(payload.render().encode("utf-8")) <= MAX_SNAPSHOT_BYTES
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("change", ["target", "caller_body"])
def test_retained_caller_union_cannot_publish_changed_inputs(binary_abi_case, change):
    build, target, callers, runtime, review, _calls = _case(binary_abi_case)
    try:
        for _ in range(2):
            ctx, config = build(None)
            runtime.wrap_review(review)(ctx, config)
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        payload = fresh["binary_caller_context"]
        if change == "target":
            target.write_bytes(target.read_bytes() + b"later owned revision")
        else:
            callers[0].decompilation = "long caller_0(long n) { return 0; }"
        assert not payload.current(fresh)
        assert not runtime.can_publish(reservation)
        assert runtime.fail(reservation, "changed_input")
    finally:
        runtime.close("test_complete")


def test_identical_recorded_caller_facts_do_not_offer_an_extra_version(binary_abi_case):
    build, _target, _callers, runtime, review, calls = _case(binary_abi_case, ((0,), (0,)))
    try:
        for _ in range(2):
            initial, config = build(None)
            runtime.wrap_review(review)(initial, config)
            assert "binary_caller_context" not in initial
        assert len(runtime._caller_requests) == 2
        assert len([event for event in runtime.events() if event["event"] == "context_delta_offered"]) == 1
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert len(reservation.packet.external_context_ids) == 1
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        assert _addresses(fresh["binary_caller_context"]) == {8192}
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")


def test_union_resolver_refusal_retains_the_ready_caller_packet(binary_abi_case, monkeypatch):
    build, _target, _callers, runtime, review, calls = _case(binary_abi_case)

    def refuse_union(requests, *args, **kwargs):
        if len(requests) > 1:
            return None
        return binary_callers.resolve_binary_callers(requests, *args, **kwargs)

    try:
        initial, config = build(None)
        runtime.wrap_review(review)(initial, config)
        with monkeypatch.context() as patch:
            patch.setattr(runtime, "_register_binary_callers", _resolver_view(runtime, refuse_union))
            second, _ = build(None)
            runtime.wrap_review(review)(second, config)
        old, new = runtime._caller_requests
        assert runtime._request_status[old]["state"] == "resolved_partial"
        assert runtime._request_status[new] == {"state": "deferred", "reason": "binary_caller_context_changed"}
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh, _ = build(None)
        assert runtime.enrich_context(fresh, reservation)
        assert _addresses(fresh["binary_caller_context"]) == {8192}
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime.fail(reservation, "test_complete")
    finally:
        runtime.close("test_complete")
