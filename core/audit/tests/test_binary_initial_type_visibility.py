"""Original visibility refusal must not hide a later owned omission.

Fake protocol admission and supplied binary metadata only; no SDK/wire/native
or provider-execution claim is made by these controls.
"""
import pytest

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.audit.tests.test_binary_subjects import subject_case as subject_case
from core.llm.providers import StructuredResponse


@pytest.mark.parametrize("initial_receipt", [True, False], ids=["visible", "unknown"])
def test_later_owned_omission_can_offer_metadata_after_visible_refusal(subject_case, initial_receipt):
    build, target, database = subject_case
    database.functions[0].signature = "long f(Packet *p)"
    database.functions[0].decompilation = "long f(Packet *p) { return 1; }"
    full, config = build(None)
    glance, _ = build(None)
    assert full["type_definitions"][0]["name"] == "Packet"
    assert glance["type_definitions"] == full["type_definitions"]
    glance["triage_bucket"] = "glance"
    prompts = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            prompts.append(prompt)
            return StructuredResponse(result={
                "status": "suspicious", "body": "Field layout is provisional",
                "reading_list": [{"subject": "Packet", "context": "field layout",
                                  "resolution": "identifier"}],
            }, raw="", cost=.1, model="scripted")

    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        def unknown_receipt(current, cfg):
            outcome = review(current, cfg)
            outcome.review_result.pop("binary_initial_type_delivery", None)
            return outcome
        unknown_receipt._knowledge_observed_client_contract = True
        first = runtime.wrap_review(review if initial_receipt else unknown_receipt)(full, config)
        first_rows = first.review_result.get("binary_initial_type_delivery", [])
        if initial_receipt:
            assert first_rows and all(row["status"] == "delivered" for row in first_rows)
        else:
            assert not first_rows
        first_answer, = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert first_answer["status"] == "unavailable"
        assert first_answer["reason"] == "initial_type_delivery_unmeasured"
        assert not runtime.ready_continuations(admission=lambda: True, required_calls=2)

        second = runtime.wrap_review(review)(glance, config)
        second_rows = second.review_result["binary_initial_type_delivery"]
        assert second_rows and all(row["status"] == "omitted" for row in second_rows)
        assert "Recovered binary type definitions" in prompts[0]
        assert "unsigned int length" in prompts[0]
        assert "Recovered binary type definitions" not in prompts[1]
        assert "unsigned int length" not in prompts[1]
        assert len(prompts) == sum(runtime._calls.values()) == 2
        assert not runtime._source_jobs and not runtime._pending_sources
        requests = tuple(runtime._requests.values())
        assert len(requests) == 2
        assert requests[0].context == requests[1].context == "field layout"
        assert requests[0].origin.binary_identity == requests[1].origin.binary_identity
        assert requests[0].origin.pass_id != requests[1].origin.pass_id
        assert runtime._request_status[requests[0].request_id] == {
            "state": "unavailable", "reason": "initial_type_delivery_unmeasured"}
        assert runtime._request_status[requests[1].request_id]["state"] == "resolved_partial"
        ready = runtime.ready_continuations(admission=lambda: True, required_calls=2)
        assert len(ready) == 1, "later measured omission was hidden by an earlier visibility refusal"
        assert len(ready[0].packet.external_context_ids) == 1
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("first_mode,second_mode,expected", [
    ("omitted", "omitted", "resolved_partial"),
    ("visible", "visible", "unavailable"),
    ("visible", "unknown", "unavailable"),
    ("ambiguous", "omitted", "unavailable"),
])
def test_visibility_progress_does_not_restart_completed_or_failed_lookups(
        subject_case, first_mode, second_mode, expected):
    from packages.ghidra.model import REType

    build, target, database = subject_case
    if first_mode == "ambiguous":
        database.types.append(REType(name="Packet", kind="struct", size=32))
    else:
        database.functions[0].signature = "long f(Packet *p)"
        database.functions[0].decompilation = "long f(Packet *p) { return 1; }"
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Layout unknown",
                "reading_list": [{"subject": "Packet", "context": "field layout",
                                  "resolution": "identifier"}]}, raw="", cost=0, model="scripted")

    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        for mode in (first_mode, second_mode):
            ctx, config = build(None)
            if mode in {"omitted", "ambiguous"}:
                ctx["triage_bucket"] = "glance"
            if mode == "unknown":
                def opaque(current, cfg):
                    outcome = review(current, cfg)
                    outcome.review_result.pop("binary_initial_type_delivery", None)
                    return outcome
                opaque._knowledge_observed_client_contract = True
                runtime.wrap_review(opaque)(ctx, config)
            else:
                runtime.wrap_review(review)(ctx, config)
        first, second = runtime._requests
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert runtime._request_status[first]["state"] == expected
        assert runtime._request_status[second] == {"state": "duplicate", "duplicate_of": first}
        answers = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert len(answers) == 1
        if first_mode == "ambiguous":
            assert answers[0]["reason"] == "ambiguous_recovered_type"
        assert not runtime._source_jobs and not runtime._pending_sources
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("first_visible", [True, False], ids=["visible-prefilter", "pending-omission"])
def test_concurrent_registration_only_replaces_a_guaranteed_initial_prefilter(subject_case, first_visible):
    import builtins
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event, current_thread
    from types import FunctionType, MethodType, ModuleType

    from core.audit import binary_subjects

    build, target, database = subject_case
    database.functions[0].signature = "long f(Packet *p)"
    database.functions[0].decompilation = "long f(Packet *p) { return 1; }"
    full, config = build(None)
    if not first_visible:
        full["triage_bucket"] = "glance"
    glance, _ = build(None)
    glance["triage_bucket"] = "glance"
    entered, release = Event(), Event()
    first_thread = []
    resolver_calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            return StructuredResponse(result={"status": "suspicious", "body": "Layout unknown",
                "reading_list": [{"subject": "Packet", "context": "field layout",
                                  "resolution": "identifier"}]}, raw="", cost=0, model="scripted")

    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    original = AuditKnowledgeRuntime._register_binary_subjects
    private_subjects = ModuleType(binary_subjects.__name__)
    vars(private_subjects).update(vars(binary_subjects))

    def resolve(*args, **kwargs):
        resolver_calls.append(args[0][0].request_id)
        if first_thread and current_thread() is first_thread[0]:
            entered.set()
            assert release.wait(10), "first owned resolver was not released"
        return binary_subjects.resolve_binary_subjects(*args, **kwargs)

    private_subjects.resolve_binary_subjects = resolve

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "binary_subjects":
            return private_subjects
        return builtins.__import__(name, globals, locals, fromlist, level)

    # The maintained module-function helper preserves class identities. Own
    # this one instance's method globals instead, retaining its actual code.
    namespace = dict(original.__globals__)
    namespace["__builtins__"] = dict(vars(builtins), __import__=import_local)
    local_method = FunctionType(original.__code__, namespace, original.__name__,
                                original.__defaults__, original.__closure__)
    local_method.__kwdefaults__ = original.__kwdefaults__
    runtime._register_binary_subjects = MethodType(local_method, runtime)

    def first_review():
        first_thread.append(current_thread())
        return runtime.wrap_review(review)(full, config)

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(first_review)
            try:
                assert entered.wait(10), "first owned registration did not reach resolver"
                runtime.wrap_review(review)(glance, config)
                old, new = runtime._requests
                if first_visible:
                    assert runtime._request_status[new]["state"] == "resolved_partial"
                    assert resolver_calls == [old, new]
                else:
                    assert runtime._request_status[new] == {"state": "duplicate", "duplicate_of": old}
                    assert resolver_calls == [old]
            finally:
                release.set()
            first.result(timeout=10)
        assert not first_thread[0].is_alive()
        assert sum(runtime._calls.values()) == 2
        assert runtime._request_status[old]["state"] == ("unavailable" if first_visible else "resolved_partial")
        assert runtime._semantic_requests[runtime._signature(runtime._requests[new], glance)] == (
            new if first_visible else old)
        reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
        assert len(reservation.packet.external_context_ids) == 1
        assert not runtime._source_jobs and not runtime._pending_sources
    finally:
        release.set()
        del runtime._register_binary_subjects
        runtime.close("test_complete")
