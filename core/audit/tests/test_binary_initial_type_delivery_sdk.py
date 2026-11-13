"""Captured SDK initial omission can unlock bounded recovered-type context.

Supplied analysis and inert bytes establish delivery/accounting, not extraction,
source correspondence or mechanical verification.
"""
import hashlib
import json
from functools import wraps

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.collector import Collector, journal_acknowledges_outcome
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.review_claims import read_history
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.tests.test_binary_subjects_sdk import _assert_attempt_joins, _review_origin, _user_prompt
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType


@pytest.mark.slow
@pytest.mark.parametrize("case", ["omitted", "visible", "unknown", "removed"])
def test_initial_binary_type_delivery_controls_context_request(tmp_path, monkeypatch, sdk_clients, case):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder
    import core.llm.egress as egress

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(egress, "enable_llm_egress", lambda *args, **kwargs: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *args, **kwargs: pytest.fail("draft dispatched a binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *args: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *args: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned initial omission fixture, not executable"
    target.write_bytes(module_bytes)
    database = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(module_bytes).hexdigest()},
        functions=[REFunction(name="f", address=4096, size=32, source_tool="fixture",
            signature="long f(Packet *p)", decompilation="long f(Packet *p) { return 1; }")],
        types=[REType(name="Packet", kind="struct", size=16, source_tool="fixture",
            fields=[{"name": "length", "type": "unsigned int", "offset": None}])])
    artifact = tmp_path / "accepted-analysis.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    read = load_redb_binding(artifact)
    checklist = build_binary_checklist(read.database, binary_path=target)
    save_checklist(out, checklist)
    entry = checklist["files"][0]
    initial = assemble_binary_context(target_path=target, file_path=entry["path"], function_name="f",
        checklist=checklist, db=read.database, out_dir=out, cached_only=True)
    assert initial["type_definitions"][0]["name"] == "Packet"
    if case not in ("visible", "removed"):
        initial["triage_bucket"] = "glance"
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        payload = {"status": "suspicious" if len(bundle.state["requests"]) == 1 else "clean", "body": "Field layout remains unknown",
            "reading_list": [{"subject": "Packet", "resolution": "identifier", "context": "field layout"}]}
        if case == "visible":
            from core.audit.binary_initial_type_delivery import initial_type_delivery_rows
            payload["binary_initial_type_delivery"] = initial_type_delivery_rows(
                initial, [], omission_reason="glance_packet")
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    bundle.state["transform"] = transform
    if case == "removed":
        def remove_compatibility_after_render(request):
            assert "Recovered binary type definitions" in _user_prompt(request)
            initial.pop("type_definitions")

        bundle.state["handler"] = remove_compatibility_after_render
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "reading_list": {"type": "array", "items": {"type": "object", "properties": {
            "subject": {"type": "string"}, "context": {"type": "string"}, "resolution": {"type": "string"}},
            "required": ["subject", "context", "resolution"]}}}, "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    if case == "unknown":
        original_review = review

        @wraps(original_review)
        def lose_receipt(ctx, config):
            outcome = original_review(ctx, config)
            outcome.review_result.pop("binary_initial_type_delivery", None)
            return outcome

        review = lose_receipt
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        first = runtime.wrap_review(review)(initial, config)
        assert first.status == "suspicious"
        prompt = _user_prompt(bundle.state["requests"][0])
        if case == "removed":
            assert "type_definitions" not in initial
        else:
            assert initial["type_definitions"][0]["name"] == "Packet"
        _assert_attempt_joins(bundle, runtime, out, [first])
        answer, = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert len(bundle.state["requests"]) == 1
        assert not runtime._source_jobs and not runtime._pending_sources
        if case in ("visible", "unknown", "removed"):
            assert answer["status"] == "unavailable"
            assert answer["reason"] == "initial_type_delivery_unmeasured"
            assert not runtime.ready_continuations(admission=lambda: True)
            if case in ("visible", "removed"):
                assert "Recovered binary type definitions" in prompt and "unsigned int length" in prompt
                rows = first.review_result["binary_initial_type_delivery"]
                assert rows and all(row["status"] == "delivered" for row in rows)
            else:
                assert "Recovered binary type definitions" not in prompt and "unsigned int length" not in prompt
                assert "binary_initial_type_delivery" not in first.review_result
            return
        assert "Recovered binary type definitions" not in prompt and "unsigned int length" not in prompt
        assert answer["status"] == "partial"
        assert answer["material"]["fields"][0]["offset_bytes"] is None
        rows = first.review_result["binary_initial_type_delivery"]
        assert rows and all(row["status"] == "omitted" and row["reason"] == "glance_packet" for row in rows)
        first_origin = _review_origin(first)
        assessments = [event for event in runtime.events() if event["event"] == "review_assessment"]
        assert assessments[0]["binary_initial_type_delivery"] == rows
        reservation, = runtime.ready_continuations(admission=lambda: True)
        fresh = assemble_binary_context(target_path=target, file_path=entry["path"], function_name="f",
            checklist=checklist, db=read.database, out_dir=out, cached_only=True)
        assert fresh["type_definitions"] == initial["type_definitions"]
        assert runtime.enrich_context(fresh, reservation)
        second = runtime.wrap_review(review)(fresh, config)
        signed = _assert_attempt_joins(bundle, runtime, out, [first, second])
        assert len(signed) >= 4 and bundle.client._governed_calls == 2
        second_origin = _review_origin(second)
        assert second_origin["binary_identity"] == first_origin["binary_identity"]
        second_prompt = _user_prompt(bundle.state["requests"][1])
        assert "Recovered binary type context" in second_prompt
        assert '"offset_bytes":null' in second_prompt and '"signedness":"unknown"' in second_prompt
        assert runtime.context_was_delivered(reservation) and runtime.can_publish(reservation)
        history = read_history(second.review_result["review_claims"])
        assert history["binary_inputs"]["origin"] == second_origin
        collector = Collector(out_dir=out, target_path=target, run_id=out.name)
        gap = {**entry["items"][0], "file": entry["path"], "line_start": 0, "line_end": None}
        acknowledgement = collector.submit(second, gap)
        assert acknowledgement is not None and journal_acknowledges_outcome(acknowledgement, second, gap)
        assert acknowledgement.source_hash.startswith("bin:ctx1:")
        assert runtime.complete(reservation, fresh, published_status=second.status)
        assert not runtime.ready_continuations(admission=lambda: pytest.fail("same facts bought another call"))
        assert len(load_entries(out, fresh=True)) == 1
        assert not runtime._active and target.read_bytes() == module_bytes
    finally:
        runtime.close("test_complete")
