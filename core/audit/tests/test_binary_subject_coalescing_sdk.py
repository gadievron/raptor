"""Captured SDK coalescing retains distinct ready recovered type answers.

Owned bytes and supplied metadata exercise delivery/accounting adapters only;
no binary extraction, build correspondence or checker authority is established.
"""
import hashlib
import json

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.collector import Collector, journal_acknowledges_outcome
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.review_claims import read_history
from core.audit.tests.test_binary_subjects_sdk import _assert_attempt_joins, _review_origin, _user_prompt
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType


@pytest.mark.slow
def test_distinct_initial_binary_types_reach_one_captured_sdk_continuation(tmp_path, monkeypatch, sdk_clients):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder
    import core.llm.egress as egress

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(egress, "enable_llm_egress", lambda *args, **kwargs: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *args, **kwargs: pytest.fail("coalesced subject control dispatched a backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *args: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *args: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned coalesced recovered-type fixture, not executable"
    target.write_bytes(module_bytes)
    database = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(module_bytes).hexdigest()},
        functions=[REFunction(name="f", address=4096, size=32, source_tool="fixture",
            signature="long f(long n)", decompilation="long f(long n) { return n + 1; }")],
        types=[REType(name="Packet", kind="struct", size=16, source_tool="fixture",
                   fields=[{"name": "length", "type": "unsigned int", "offset": None}]),
               REType(name="Header", kind="struct", size=8, source_tool="fixture",
                   fields=[{"name": "kind", "type": "unsigned char", "offset": None}])])
    artifact = tmp_path / "accepted-analysis.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    read = load_redb_binding(artifact)
    checklist = build_binary_checklist(read.database, binary_path=target)
    save_checklist(out, checklist)
    entry = checklist["files"][0]
    gap = {**entry["items"][0], "file": entry["path"], "line_start": 0, "line_end": None}

    def context():
        return assemble_binary_context(target_path=target, file_path=entry["path"], function_name="f",
            checklist=checklist, db=read.database, out_dir=out, cached_only=True)

    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        index = len(bundle.state["requests"]) - 1
        payload = {"status": "suspicious" if index < 2 else "clean",
            "body": "Recovered fields are advisory; offsets and signedness remain unknown",
            "reading_list": ([{"subject": ("Packet", "Header")[index], "resolution": "identifier",
                               "context": "recorded fields"}] if index < 2 else [])}
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "reading_list": {"type": "array", "items": {"type": "object", "properties": {
            "subject": {"type": "string"}, "context": {"type": "string"},
            "resolution": {"type": "string"}}, "required": ["subject", "context", "resolution"]}},
    }, "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        initial_contexts = [context(), context()]
        assert all(ctx["type_definitions"] == [] for ctx in initial_contexts)
        first, second = [runtime.wrap_review(review)(ctx, config) for ctx in initial_contexts]
        assert first.status == second.status == "suspicious"
        assert all("binary_subject_context" not in ctx for ctx in initial_contexts)
        assert {request.subject for request in runtime._requests.values()} == {"Packet", "Header"}
        assert len(runtime._requests) == 2
        assert all(status["state"] == "resolved_partial" for status in runtime._request_status.values())
        answers = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert {event["subject"] for event in answers} == {"Packet", "Header"}
        assert all(event["status"] == "partial" and event["material"]["signedness"] == "unknown"
                   and "source_quote" not in event["material"] for event in answers)
        assert not runtime._source_jobs and not runtime._pending_sources
        first_origins = [_review_origin(outcome) for outcome in (first, second)]
        assert first_origins[0]["binary_identity"] == first_origins[1]["binary_identity"]
        assert all(origin["binary_identity"]["analysis_sha256"] == read.projection_sha256
                   for origin in first_origins)
        assert first_origins[0]["pass_id"] != first_origins[1]["pass_id"]
        initial_signed = _assert_attempt_joins(bundle, runtime, out, [first, second])
        assert len(initial_signed) > 0 and load_entries(out, fresh=True) == []
        reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=1)
        assert not reservation.packet.references and not reservation.packet.explanations
        assert not reservation.packet.caller_contexts
        assert len(reservation.packet.external_context_ids) == 1
        fresh = context()
        assert "binary_subject_context" not in fresh
        assert runtime.enrich_context(fresh, reservation)
        assert {answer.subject for answer in fresh["binary_subject_context"].answers} == {"Packet", "Header"}
        third = runtime.wrap_review(review)(fresh, config)
        assert third.status == "clean"
        third_origin = _review_origin(third)
        assert third_origin["pass_id"] == reservation.packet.pass_id
        assert third_origin["pass_id"] not in {origin["pass_id"] for origin in first_origins}
        assert third_origin["binary_identity"] == first_origins[0]["binary_identity"]
        prompt = _user_prompt(bundle.state["requests"][2])
        assert "Recovered binary type context" in prompt and "not a source quote" in prompt
        assert '"subject":"Packet"' in prompt and '"subject":"Header"' in prompt
        assert '"offset_bytes":null' in prompt and '"signedness":"unknown"' in prompt
        assert runtime.context_was_delivered(reservation) and runtime.can_publish(reservation)
        history = read_history(third.review_result["review_claims"])
        assert history is not None
        assert history["binary_inputs"]["origin"] == third_origin
        assert [row["kind"] for row in history["binary_inputs"]["contexts"]] == ["binary_target_semantics"]
        assert history["binary_inputs"]["contexts"][0]["context_id"] == reservation.packet.external_context_ids[0]
        signed = _assert_attempt_joins(bundle, runtime, out, [first, second, third])
        reported = [row for row in signed if row.get("stage") == "reported"]
        assert len(reported) == 3
        assert bundle.client._governed_tokens == 18
        assert sum(outcome.cost_usd for outcome in (first, second, third)) == pytest.approx(
            bundle.client.reported_spend_usd)
        assert not bundle.client.pending_usage_reservations and not bundle.client._prepared_resource_reservations
        collector = Collector(out_dir=out, target_path=target, run_id=out.name)
        acknowledgement = collector.submit(third, gap)
        assert acknowledgement is not None and journal_acknowledges_outcome(acknowledgement, third, gap)
        assert acknowledgement.source_hash.startswith("bin:ctx1:")
        rows = load_entries(out, fresh=True)
        assert len(rows) == 1 and rows[0].review_claims["review"]["origin"] == third_origin
        assert runtime.complete(reservation, fresh, published_status=third.status)
        assert not runtime.ready_continuations(admission=lambda: pytest.fail("same ready types bought another pass"))
        cycle, = runtime._cycles.values()
        assert cycle.started == 1 and not runtime._active
        assert len(bundle.state["requests"]) == bundle.client._governed_calls == sum(runtime._calls.values()) == 3
        assert target.read_bytes() == module_bytes
    finally:
        runtime.close("test_complete")
