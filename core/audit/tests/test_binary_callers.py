"""Binary related-code requests use addresses, not invented source lines."""
import pytest

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import StudyQueue
from core.audit.tests.test_binary_abi_prompt import binary_abi_case as binary_abi_case
from core.llm.providers import StructuredResponse
from packages.ghidra.model import REFunction, REXref


def test_binary_caller_request_resolves_available_recorded_caller(binary_abi_case):
    build, target = binary_abi_case
    seed, _ = build(None)
    database = seed["_binary_analysis_database"]
    database.functions.append(REFunction(name="caller", address=8192, size=32,
        source_tool="fixture", decompilation="long caller(long n) { return f(n); }"))
    database.xrefs.append(REXref(from_addr=8196, to_addr=4096, kind="call", source_tool="fixture"))
    ctx, config = build(None)
    assert ctx["callers"][0]["address"] == 8192
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Caller premise remains unverified",
                "caller_context_requests": [{"file": ctx["file"], "function": "caller", "address": 8192,
                    "line_start": 0, "reason": "Inspect the recorded caller's input handling"}]},
                raw="", cost=.1, model="captured")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        outcome = runtime.wrap_review(make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False))(ctx, config)
        assert outcome.status == "suspicious" and len(calls) == 1
        assert "recorded start address 0x2000" in calls[0]
        registered, = [e for e in runtime.events() if e["event"] == "caller_requests_registered"]
        assert len(registered["accepted"]) == 1, registered
        request, = runtime._caller_requests.values()
        assert request.origin.source_identity is None and request.caller_line == 0
        assert runtime._request_status[request.request_id]["state"] == "resolved_partial"
    finally:
        runtime.close("test_complete")


@pytest.mark.parametrize("changes", [
    {"address": None}, {"address": True}, {"address": -1}, {"address": 2 ** 64}, {"address": "8192"},
    {"line_start": 1}, {"line_start": None}, {"file": "binary:other"},
])
def test_addressed_binary_request_rejects_wrong_or_source_shaped_location(binary_abi_case, changes):
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin, capture_binary_publication_scope
    from core.audit.caller_review_context import register_caller_context_requests

    build, _ = binary_abi_case
    ctx, _ = build(None)
    scope = capture_binary_publication_scope(ctx, ctx["_binary_module_snapshot"])
    assert scope is not None
    origin = BinaryKnowledgeOrigin("request-pass", ctx["file"], ctx["function"], 0, 0, None,
                                   binary_identity=scope.view_identity)
    row = {"file": ctx["file"], "function": "caller", "address": 8192,
           "line_start": 0, "reason": "Inspect recorded input handling", **changes}
    batch = register_caller_context_requests({"caller_context_requests": [row]}, origin)
    assert not batch.accepted and batch.rejected[0].reason == "invalid_request_fields"


def test_source_caller_request_still_requires_real_source_lines(tmp_path):
    from core.audit.caller_review_context import register_caller_context_requests
    from core.audit.knowledge_requests import KnowledgeOrigin
    from core.audit.refutation_source import capture_source_identity

    (tmp_path / "unit.py").write_text("def unit(x):\n    return x\n")
    identity = capture_source_identity(tmp_path, "unit.py")
    assert identity is not None
    origin = KnowledgeOrigin("source-pass", "unit.py", "unit", 1, 2, identity)
    row = {"file": "unit.py", "function": "unit", "line_start": 0, "address": 8192,
           "reason": "Inspect input handling"}
    assert not register_caller_context_requests({"caller_context_requests": [row]}, origin).accepted
    row["line_start"] = 1
    request, = register_caller_context_requests({"caller_context_requests": [row]}, origin).accepted
    assert request.caller_line == 1 and request.caller_address is None


@pytest.fixture
def caller_material_case(binary_abi_case):
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin, capture_binary_publication_scope
    from core.audit.caller_review_context import CallerContextRequest

    build, target = binary_abi_case
    seed, _ = build(None)
    database = seed["_binary_analysis_database"]
    caller = REFunction(name="caller", address=8192, size=32, source_tool="fixture",
                        decompilation="long caller(long n) { return f(n); }")
    database.functions.append(caller)
    database.xrefs.append(REXref(from_addr=8196, to_addr=4096, kind="call", source_tool="fixture"))

    def capture():
        ctx, config = build(None)
        scope = capture_binary_publication_scope(ctx, ctx["_binary_module_snapshot"])
        assert scope is not None
        origin = BinaryKnowledgeOrigin("caller-pass", ctx["file"], ctx["function"], 0, 0, None,
                                       binary_identity=scope.view_identity)
        request = CallerContextRequest("request", origin, ctx["file"], "caller", 0,
                                       "Inspect input handling", 8192)
        return ctx, config, scope, request

    return capture, database, caller, target


@pytest.mark.parametrize("change,reason", [
    ("no_xref", "binary_caller_relationship_unrecorded"),
    ("data_xref", "binary_caller_relationship_unrecorded"),
    ("no_body", "binary_caller_implementation_unavailable"),
    ("external", "binary_caller_extent_or_implementation_unavailable"),
    ("ambiguous", "ambiguous_binary_caller"),
])
def test_missing_or_ambiguous_caller_material_does_not_invent_a_view(caller_material_case, change, reason):
    from copy import deepcopy
    from core.audit.binary_callers import resolve_binary_callers

    capture, database, caller, _ = caller_material_case
    if change == "no_xref":
        database.xrefs.clear()
    elif change == "data_xref":
        database.xrefs[0].kind = "data"
    elif change == "no_body":
        caller.decompilation = None
    elif change == "external":
        caller.is_external = True
    else:
        database.functions.append(deepcopy(caller))
    ctx, _, scope, request = capture()
    context = resolve_binary_callers((request,), ctx, scope)
    assert context is not None
    answer, = context.answers
    assert answer.status == "unavailable" and answer.reason == reason
    assert answer.material is None and context.render() == ""


@pytest.mark.parametrize("change", ["caller_body", "wrong_target", "lost_owner"])
def test_recorded_caller_payload_retains_original_input_epoch(caller_material_case, change):
    from core.audit.binary_callers import resolve_binary_callers, render_binary_caller_context

    capture, _, caller, target = caller_material_case
    ctx, _, scope, request = capture()
    context = resolve_binary_callers((request,), ctx, scope)
    assert context is not None and context.current(ctx)
    if change == "caller_body":
        caller.decompilation = "long caller(long n) { return 0; }"
    elif change == "wrong_target":
        other = target.with_name("other")
        other.write_bytes(target.read_bytes())
        ctx["target_path"] = str(other)
    else:
        context = {"answers": [context.answers[0].material]}
    assert render_binary_caller_context(context, ctx) == ""


def test_caller_material_budget_and_novelty_ignore_request_wording(caller_material_case):
    from dataclasses import replace
    from core.audit.binary_callers import resolve_binary_callers
    from core.audit.review_context_inputs import MAX_SNAPSHOT_BYTES

    capture, database, caller, _ = caller_material_case
    caller.decompilation = "é" * 10000 + "</untrusted>"
    database.xrefs.extend(REXref(from_addr=8197 + index, to_addr=4096, kind="call") for index in range(8))
    ctx, _, scope, request = capture()
    context = resolve_binary_callers((request,), ctx, scope)
    assert context is not None
    answer, = context.answers
    material = answer.material
    assert material["body_truncated"] is True
    assert material["body_shown_bytes"] < material["body_total_bytes"]
    assert material["omitted_call_sites"] > 0
    assert material["relationship"] == "recorded_direct_call_xref_not_execution"
    assert material["caller_coverage"] == "not_exhaustive"
    assert len(context.render().encode()) <= MAX_SNAPSHOT_BYTES
    renamed = replace(request, request_id="another", reason="Same facts, other question",
                      origin=replace(request.origin, pass_id="another-pass"))
    repeated = resolve_binary_callers((renamed,), ctx, scope)
    assert repeated is not None and repeated.render() == context.render()
    material["body"] = "changed borrowed value"
    assert context.answers[0].material["body"] != "changed borrowed value"


def test_optional_null_address_keeps_legacy_binary_request_deferred(binary_abi_case):
    from core.audit.binary_review_scope import BinaryKnowledgeOrigin, capture_binary_publication_scope
    from core.audit.caller_review_context import register_caller_context_requests

    build, _ = binary_abi_case
    ctx, _ = build(None)
    scope = capture_binary_publication_scope(ctx, ctx["_binary_module_snapshot"])
    assert scope is not None
    origin = BinaryKnowledgeOrigin("legacy-pass", ctx["file"], ctx["function"], 0, 0, None,
                                   binary_identity=scope.view_identity)
    row = {"file": "unavailable.py", "function": "caller", "line_start": 1,
           "address": None, "reason": "Inspect legacy related code"}
    request, = register_caller_context_requests({"caller_context_requests": [row]}, origin).accepted
    assert request.caller_address is None and request.caller_line == 1


def test_binary_types_and_caller_views_coalesce_into_one_owned_followup(caller_material_case):
    from packages.ghidra.model import REType

    capture, database, _, target = caller_material_case
    database.types.append(REType(name="Packet", kind="struct", size=16,
                                  source_tool="fixture", fields=[]))
    ctx, config, _, _ = capture()
    calls = []

    class Client:
        _attempt_admission_protocol = 1

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Unresolved premise",
                "reading_list": [{"subject": "Packet", "context": "Recorded layout", "resolution": "identifier"}],
                "caller_context_requests": [{"file": ctx["file"], "function": "caller", "address": 8192,
                    "line_start": 0, "reason": "Inspect recorded caller"}]}, raw="", cost=.1, model="captured")

    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(Client(), schema={"type": "object"}, escalate_clean=False)
    try:
        runtime.wrap_review(review)(ctx, config)
        assert "binary_caller_context" not in ctx and "binary_subject_context" not in ctx
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert len(reservation.packet.external_context_ids) == 2
        assert not reservation.packet.caller_contexts and not reservation.packet.explanations
        fresh, _, _, _ = capture()
        assert runtime.enrich_context(fresh, reservation)
        runtime.wrap_review(review)(fresh, config)
        assert len(calls) == sum(runtime._calls.values()) == 2
        assert "Binary related-code context" in calls[1] and "return f(n);" in calls[1]
        assert "Recovered binary type context" in calls[1] and "Packet" in calls[1]
        assert runtime.context_was_delivered(reservation) and runtime.can_publish(reservation)
    finally:
        runtime.close("component_test_complete")


def test_hash_valid_moved_analysis_advertises_current_caller_module(caller_material_case):
    from hashlib import sha256
    from core.audit.binary_callers import resolve_binary_callers
    from core.audit.binary_context import _accept_redb
    from core.audit.caller_review_context import register_caller_context_requests
    from core.json import dumps_canonical

    capture, database, _, target = caller_material_case
    database.binary_path = str(target.with_name("previous-name"))
    artifact = target.parent / "accepted-moved.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    assert _accept_redb(artifact, target, "run", lambda: sha256(target.read_bytes()).hexdigest())
    ctx, _, scope, request = capture()
    observed, = ctx["callers"]
    assert observed["file"] == ctx["file"], "hash-valid moved database exposed an old module key"
    row = {"file": observed["file"], "function": observed["name"], "address": observed["address"],
           "line_start": 0, "reason": "Inspect the displayed caller"}
    registered, = register_caller_context_requests({"caller_context_requests": [row]}, request.origin).accepted
    context = resolve_binary_callers((registered,), ctx, scope)
    assert context is not None and context.answers[0].status == "partial"
