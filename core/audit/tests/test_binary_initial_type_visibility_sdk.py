"""Sequential captured SDK attempts preserve initial visibility and packet width.

Owned inert bytes and supplied analysis prove adapter/accounting joins only.
"""
import hashlib
import json
from collections import Counter

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.collector import Collector, journal_acknowledges_outcome
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.audit.record import load_verified_audit_log
from core.audit.review_claims import read_history
from core.audit.tests.test_binary_subjects_sdk import _review_origin, _user_prompt
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType


@pytest.mark.slow
def test_initial_visibility_transition_preserves_width_two_sdk_packet(tmp_path, monkeypatch, sdk_clients):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder
    import core.llm.egress as egress

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(egress, "enable_llm_egress", lambda *args, **kwargs: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *args, **kwargs: pytest.fail("review dispatched a binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *args: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *args: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned width-two visibility fixture, not executable"
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
    def context():
        return assemble_binary_context(target_path=target, file_path=entry["path"], function_name="f",
            checklist=checklist, db=read.database, out_dir=out, cached_only=True)

    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        payload = {"status": "suspicious" if len(bundle.state["requests"]) <= 2 else "clean",
            "body": "Recovered metadata leaves layout unknown; no verification",
            "reading_list": [{"subject": "Packet", "resolution": "identifier", "context": "field layout"}]}
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
            "subject": {"type": "string"}, "context": {"type": "string"}, "resolution": {"type": "string"}},
            "required": ["subject", "context", "resolution"]}}}, "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        first = runtime.wrap_review(review)(context(), config)
        old_request, = runtime._requests
        old_status = dict(runtime._request_status[old_request])
        assert old_status == {"state": "unavailable", "reason": "initial_type_delivery_unmeasured"}
        glance = context()
        glance["triage_bucket"] = "glance"
        second = runtime.wrap_review(review)(glance, config)
        assert first.status == second.status == "suspicious"
        assert runtime._request_status[old_request] == old_status
        new_request, = set(runtime._requests) - {old_request}
        assert runtime._request_status[new_request]["state"] == "resolved_partial"
        answers = [event for event in runtime.events() if event["event"] == "binary_subject_answer"]
        assert [(event["request_id"], event["status"]) for event in answers] == [
            (old_request, "unavailable"), (new_request, "partial")]
        for index, status in enumerate(("delivered", "omitted")):
            outcome = (first, second)[index]
            rows = outcome.review_result["binary_initial_type_delivery"]
            assert rows and all(row["status"] == status for row in rows)
        prompts = [_user_prompt(request) for request in bundle.state["requests"]]
        assert "Recovered binary type definitions" in prompts[0] and "unsigned int length" in prompts[0]
        assert "Recovered binary type definitions" not in prompts[1] and "unsigned int length" not in prompts[1]
        assert not runtime._source_jobs and not runtime._pending_sources
        reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=2)
        assert len(reservation.packet.external_context_ids) == 1
        fresh = context()
        assert runtime.enrich_context(fresh, reservation)
        third = runtime.wrap_review(review)(fresh, config)
        # Width reserves attempt capacity; it is not a renderer-delivery quorum.
        assert runtime.context_was_delivered(reservation)
        fourth_context = context()
        assert runtime.enrich_context(fourth_context, reservation)
        fourth = runtime.wrap_review(review)(fourth_context, config)
        assert third.status == fourth.status == "clean"
        assert runtime.context_was_delivered(reservation) and runtime.can_publish(reservation)
        outcomes = [first, second, third, fourth]
        origins = [_review_origin(outcome) for outcome in outcomes]
        pass_ids = [origin["pass_id"] for origin in origins]
        assert len(set(pass_ids)) == 3
        assert pass_ids[2] == pass_ids[3] == reservation.packet.pass_id
        assert all(origin["binary_identity"] == origins[0]["binary_identity"] for origin in origins)
        for outcome in (third, fourth):
            history = read_history(outcome.review_result["review_claims"])
            assert history["binary_inputs"]["origin"] == _review_origin(outcome)
            assert history["binary_inputs"]["contexts"][0]["context_id"] == reservation.packet.external_context_ids[0]
        for request in bundle.state["requests"][2:]:
            prompt = _user_prompt(request)
            assert "Recovered binary type context" in prompt and '\"offset_bytes\":null' in prompt
        expected_work = Counter("review:" + pass_id for pass_id in pass_ids)
        assert sorted(expected_work.values()) == [1, 1, 2]
        signed = load_verified_audit_log(out)
        admitted = [row for row in signed if row.get("stage") == "admitted"]
        reported = [row for row in signed if row.get("stage") == "reported"]
        assert len(admitted) == len(reported) == 4
        attempts = {row["attempt"]["attempt_id"] for row in admitted}
        assert len(attempts) == 4
        assert attempts == {row["attempt"]["attempt_id"] for row in reported}
        for rows in (admitted, reported):
            assert Counter(row["attempt"]["work_id"] for row in rows) == expected_work
            for row in rows:
                attempt = row["attempt"]
                assert attempt["beneficiaries"] == [attempt["work_id"].removeprefix("review:")]
        events = [event for event in runtime.events() if event["event"] == "review_attempt"]
        # Runtime review attempts and SDK transport attempts use separate IDs;
        # their actual join is the signed work/pass attribution, not ID equality.
        assert len(events) == len({event["attempt_id"] for event in events}) == 4
        assert Counter(event["origin"]["pass_id"] for event in events) == Counter(pass_ids)
        projection = bundle.sink.attempt_projection()["attempts"]
        assert len(projection) == 4 and {row["attempt_id"] for row in projection} == attempts
        assert all(row["billing_state"] == "reported" and row["cost_usd"] > 0 for row in projection)
        assert all(row["tokens_in"] == row["tokens_out"] == 3 for row in projection)
        spend = bundle.client.reported_spend_usd
        assert sum(row["cost_usd"] for row in projection) == pytest.approx(spend)
        assert sum(row["cost_usd"] for row in reported) == pytest.approx(spend)
        assert sum(outcome.cost_usd for outcome in outcomes) == pytest.approx(spend)
        assert len(bundle.state["requests"]) == bundle.client._governed_calls == sum(runtime._calls.values()) == 4
        assert bundle.client._governed_tokens == 24
        assert not bundle.client.pending_usage_reservations and not bundle.client._prepared_resource_reservations
        assert runtime._request_status[old_request] == old_status
        assert runtime._request_status[new_request]["state"] == "resolved_partial"
        collector = Collector(out_dir=out, target_path=target, run_id=out.name)
        gap = {**entry["items"][0], "file": entry["path"], "line_start": 0, "line_end": None}
        acknowledgement = collector.submit(fourth, gap)
        assert acknowledgement is not None and journal_acknowledges_outcome(acknowledgement, fourth, gap)
        assert acknowledgement.source_hash.startswith("bin:ctx1:")
        assert runtime.complete(reservation, fourth_context, published_status=fourth.status)
        assert not runtime.ready_continuations(required_calls=2,
            admission=lambda: pytest.fail("same Packet facts bought another continuation"))
        assert len(load_entries(out, fresh=True)) == 1
        assert not runtime._active and target.read_bytes() == module_bytes
    finally:
        runtime.close("test_complete")
