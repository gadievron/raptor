"""Captured SDK binary-subject delivery joins actual attempts and publication.

Owned bytes, recovered metadata and HTTP MockTransport exercise these adapters;
none establishes binary extraction, build correspondence or checker authority.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.collector import Collector, journal_acknowledges_outcome
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.record import load_verified_audit_log
from core.audit.review_claims import read_history
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType


def _review_origin(outcome):
    history = read_history(outcome.review_result["review_claims"])
    assert history is not None
    origin = history["review"]["origin"]
    assert origin["source_identity"] is None and origin["line_start"] == 0
    return origin


def _assert_attempt_joins(bundle, runtime, out, outcomes):
    origins = [_review_origin(outcome) for outcome in outcomes]
    expected = {"review:" + origin["pass_id"]: origin["pass_id"] for origin in origins}
    count = len(outcomes)
    assert len(expected) == count
    assert len(bundle.state["requests"]) == bundle.client._governed_calls == count
    assert sum(runtime._calls.values()) == count
    signed = load_verified_audit_log(out)
    admitted = [row for row in signed if row.get("stage") == "admitted"]
    reported = [row for row in signed if row.get("stage") == "reported"]
    assert len(admitted) == len(reported) == count
    admitted_ids = {row["attempt"]["attempt_id"] for row in admitted}
    assert len(admitted_ids) == count
    assert admitted_ids == {row["attempt"]["attempt_id"] for row in reported}
    for rows in (admitted, reported):
        assert {row["attempt"]["work_id"] for row in rows} == set(expected)
        for row in rows:
            attempt = row["attempt"]
            assert attempt["beneficiaries"] == [expected[attempt["work_id"]]]
    projection = bundle.sink.attempt_projection()["attempts"]
    assert len(projection) == count
    assert {row["attempt_id"] for row in projection} == admitted_ids
    assert all(row["billing_state"] == "reported" and row["cost_usd"] > 0 for row in projection)
    assert sum(row["cost_usd"] for row in projection) == pytest.approx(bundle.client.reported_spend_usd)
    assert sum(row["cost_usd"] for row in reported) == pytest.approx(bundle.client.reported_spend_usd)
    assert sum(outcome.cost_usd for outcome in outcomes) == pytest.approx(bundle.client.reported_spend_usd)
    assert bundle.client._governed_tokens == sum(row["tokens_in"] + row["tokens_out"] for row in projection)
    assert not bundle.client.pending_usage_reservations
    assert not bundle.client._prepared_resource_reservations
    return signed


def _user_prompt(request):
    messages = json.loads(request.content)["messages"]
    user = [message["content"] for message in messages if message["role"] == "user"]
    assert user and all(isinstance(content, str) for content in user)
    return "\n".join(user)


@pytest.mark.slow
@pytest.mark.parametrize("case", ["healthy", "omitted", "changed"])
def test_captured_sdk_binary_subject_continuation_requires_current_fitted_context(
    tmp_path, monkeypatch, sdk_clients, case,
):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *args, **kwargs: pytest.fail("subject control dispatched a backend"))
    # Inventory construction is real; unrelated native provenance and module-ID
    # inspections are explicitly unavailable, never substituted with build facts.
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *args: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *args: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned SDK recovered-type context, not executable"
    target.write_bytes(module_bytes)
    database = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(module_bytes).hexdigest()},
        functions=[REFunction(name="f", address=4096, size=32, source_tool="fixture",
                              decompilation="long f(long n) { return n + 1; }")],
        types=[REType(name="Packet", kind="struct", size=16, source_tool="fixture",
                      fields=[{"name": "length", "type": "unsigned int", "offset": None}])])
    artifact = tmp_path / "accepted-analysis.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    read = load_redb_binding(artifact)
    checklist = build_binary_checklist(read.database, binary_path=target)
    save_checklist(out, checklist)
    entry = checklist["files"][0]
    item = entry["items"][0]
    gap = {**item, "file": entry["path"], "line_start": 0, "line_end": None}

    def context():
        return assemble_binary_context(target_path=target, file_path=entry["path"], function_name="f",
                                       checklist=checklist, db=read.database)

    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        first = len(bundle.state["requests"]) == 1
        payload = {
            "status": "suspicious" if first else "clean",
            "body": "Recovered metadata leaves offsets and signedness unknown; no verification is established",
            "reading_list": [{"subject": "Packet", "resolution": "identifier",
                              "context": "field layout" if first else "interpret the recorded fields"}],
        }
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
        initial = context()
        assert initial["type_definitions"] == []
        first = runtime.wrap_review(review)(initial, config)
        assert first.status == "suspicious"
        first_origin = _review_origin(first)
        assert first_origin["binary_identity"]["analysis_sha256"] == read.projection_sha256
        request, = runtime._requests.values()
        assert request.origin.pass_id == first_origin["pass_id"]
        assert runtime._request_status[request.request_id]["state"] == "resolved_partial"
        answer, = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert answer["status"] == "partial"
        assert answer["material"]["fields"][0]["offset_bytes"] is None
        assert answer["material"]["fields"][0]["size_bytes"] is None
        assert answer["material"]["signedness"] == "unknown"
        assert "source_quote" not in answer["material"]
        assert not runtime._source_jobs and not runtime._pending_sources
        assert "binary_subject_context" not in initial
        initial_signed = _assert_attempt_joins(bundle, runtime, out, [first])
        assert load_entries(out, fresh=True) == []
        reservation, = runtime.ready_continuations(admission=lambda: True)
        assert reservation.packet.pass_id != first_origin["pass_id"]
        assert not reservation.packet.references and not reservation.packet.explanations
        assert not reservation.packet.caller_contexts
        assert len(reservation.packet.external_context_ids) == 1
        cycle, = runtime._cycles.values()
        assert cycle.started == 1

        if case == "changed":
            read.database.types[0].fields[0]["offset"] = 4
            assert not read.current()
            fresh = context()
            assert not runtime.enrich_context(fresh, reservation)
            assert not runtime.can_publish(reservation)
            assert runtime.fail(reservation, "analysis_changed_before_dispatch")
            assert cycle.started == 1 and not runtime._active
            assert load_entries(out, fresh=True) == []
            assert _assert_attempt_joins(bundle, runtime, out, [first]) == initial_signed
            assert answer["material"]["fields"][0]["offset_bytes"] is None
            return

        fresh = context()
        assert "binary_subject_context" not in fresh
        assert runtime.enrich_context(fresh, reservation)
        if case == "omitted":
            fresh["triage_bucket"] = "glance"
        second = runtime.wrap_review(review)(fresh, config)
        second_origin = _review_origin(second)
        assert second_origin["pass_id"] == reservation.packet.pass_id
        assert second_origin["binary_identity"] == first_origin["binary_identity"]
        signed_after_dispatch = _assert_attempt_joins(bundle, runtime, out, [first, second])
        prompt = _user_prompt(bundle.state["requests"][1])
        collector = Collector(out_dir=out, target_path=target, run_id=out.name)
        if case == "omitted":
            assert "Recovered binary type context" not in prompt
            assert not runtime.context_was_delivered(reservation)
            assert not runtime.can_publish(reservation)
            # Neither the original producer nor the panel restoration path
            # may downgrade a missed input to a plain review acknowledgement.
            assert second.binary_publication_scope is None
            runtime.bind_review_input_scope(second)
            assert second.binary_publication_scope is None
            assert collector.submit(second, gap) is None
            assert load_entries(out, fresh=True) == []
            assert runtime.fail(reservation, "binary_subject_context_not_fitted")
            assert not any(event["event"] == "continuation_completed" for event in runtime.events())
        else:
            assert "Recovered binary type context" in prompt and "not a source quote" in prompt
            assert '"offset_bytes":null' in prompt and '"signedness":"unknown"' in prompt
            assert runtime.context_was_delivered(reservation) and runtime.can_publish(reservation)
            history = read_history(second.review_result["review_claims"])
            assert history is not None
            inputs = history["binary_inputs"]
            assert inputs["origin"] == second_origin
            assert [row["kind"] for row in inputs["contexts"]] == ["binary_target_semantics"]
            assert inputs["contexts"][0]["context_id"] == reservation.packet.external_context_ids[0]
            acknowledgement = collector.submit(second, gap)
            assert acknowledgement is not None and journal_acknowledges_outcome(acknowledgement, second, gap)
            assert acknowledgement.source_hash.startswith("bin:ctx1:")
            rows = load_entries(out, fresh=True)
            assert len(rows) == 1 and rows[0].review_claims["review"]["origin"] == second_origin
            assert runtime.complete(reservation, fresh, published_status=second.status)
            assert not runtime.ready_continuations(admission=lambda: pytest.fail("same type facts bought another pass"))
        assert not runtime._active and cycle.started == 1
        assert target.read_bytes() == module_bytes
        assert len([event for event in runtime.events() if event["event"] == "review_assessment"]) == 2
        assert len([event for event in runtime.events() if event["event"] == "continuation_completed"]) == int(case == "healthy")
        assert _assert_attempt_joins(bundle, runtime, out, [first, second]) == signed_after_dispatch
    finally:
        runtime.close("test_complete")
