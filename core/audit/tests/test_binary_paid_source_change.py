"""A completed SDK attempt cannot publish a review of changed binary bytes."""
import hashlib
import json

import pytest

from core.audit import capabilities, orchestrator
from core.audit.binary_context import assemble_binary_context
from core.audit.journal import load_entries
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.audit.record import load_verified_audit_log
from core.inventory import save_checklist
from core.inventory.binary_builder import binary_path_key
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction


@pytest.mark.slow
@pytest.mark.parametrize("change", ["changed", "restored", "healthy"])
def test_paid_binary_review_keeps_charge_but_rejects_changed_module(tmp_path, monkeypatch, sdk_clients, change):
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    original = b"owned module fixture, not an executable"
    target.write_bytes(original)
    key = binary_path_key(target)
    item = {"name": "f", "kind": "function", "line_start": 0, "line_end": 0,
            "address": 4096, "size": 32, "pinned": True, "force_review": True}
    checklist = {"target_path": str(target), "files": [{"path": key,
        "sha256": hashlib.sha256(original).hexdigest(), "items": [item]}]}
    save_checklist(out, checklist)
    database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra",
                   decompilation="unsigned f(unsigned n) { return n + 1; }")])
    # The context assembler and its original byte capture are real. The
    # in-memory database is an explicit fixture, not extraction evidence.
    def build(*args, **kwargs):
        return assemble_binary_context(target_path=target, file_path=key,
                                       function_name="f", checklist=checklist, db=database)
    monkeypatch.setattr(orchestrator, "_build_context", build)
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    def during_wire(request):
        admitted = [row for row in load_verified_audit_log(out) if row.get("stage") == "admitted"]
        assert len(admitted) == 1
        if change != "healthy":
            target.write_bytes(b"owned changed module, not an executable")
            if change == "restored":
                target.write_bytes(original)
    bundle.state["handler"] = during_wire
    def clean_response(row):
        message = row["choices"][0]["message"]
        payload = {"status": "clean", "body": "Captured binary-view judgment."}
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return row
    bundle.state["transform"] = clean_response
    schema = {"type": "object", "properties": {"status": {"type": "string"},
        "body": {"type": "string"}}, "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema,
                            system_prompt="Review the supplied implementation view.", escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, review_passes=1,
        resume=False, max_workers=1, batch_sloc_threshold=0, prefilter=False,
        prefilter_skip=False, triage=False, vendored_triage=False,
        validate=False, sweep_validate_findings=False, deepen_suspicious=False,
        clean_check=False, adversarial=False, enable_session_context=False,
        propagate_constraints=False, on_demand_synthesis=False, open_discovery=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        iris=False, sage_recall=False, domain_model_import=False,
        dynamic_validation=False, library_replay=False, cross_run_import=False,
        annotations_read=False, llm_budget_client=bundle.client)
    result = run_orchestrator(config, review)
    assert len(bundle.state["requests"]) == bundle.client._governed_calls == 1
    signed = load_verified_audit_log(out)
    admitted = [row for row in signed if row.get("stage") == "admitted"]
    reported = [row for row in signed if row.get("stage") == "reported"]
    assert len(admitted) == len(reported) == 1
    assert admitted[0]["attempt"]["attempt_id"] == reported[0]["attempt"]["attempt_id"]
    assert reported[0]["tokens_in"] == reported[0]["tokens_out"] == 3
    assert bundle.client.reported_spend_usd > 0
    # total_cost_usd counts accepted outcomes; failed paid work belongs to
    # the existing authoritative provider/attempt projection floor instead.
    assert result.llm_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert result.cost_tracker.total_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    costs = json.loads((out / "cost-breakdown.json").read_text())
    projected = costs["attempt_accounting"]
    assert projected["status"] == "projected" and projected["gaps"] == []
    assert len(projected["attempts"]) == 1
    assert projected["attempts"][0]["attempt_id"] == reported[0]["attempt"]["attempt_id"]
    assert projected["attempts"][0]["cost_usd"] == pytest.approx(bundle.client.reported_spend_usd)
    assert bundle.client.pending_usage_reservations == []
    entries = load_entries(out, fresh=True)
    history = json.loads((out / "knowledge-results.json").read_text())
    attempts = [event for event in history["events"] if event["event"] == "review_attempt"]
    calls = [event for event in history["events"] if event["event"] == "client_call_attempt"]
    assert len(attempts) == len(calls) == 1
    pass_id = attempts[0]["origin"]["pass_id"]
    assert admitted[0]["attempt"]["work_id"] == "review:" + pass_id
    assert admitted[0]["attempt"]["beneficiaries"] == [pass_id]
    if change != "healthy":
        assert result.clean == 0, "changed module retained a current clean review after the paid attempt"
        assert not any(entry.verdict == "clean" for entry in entries)
        assessments = [event for event in history["events"] if event["event"] == "review_assessment"]
        assert len(assessments) == 1 and assessments[0]["binary_module_unchanged_after_call"] is False
        assert assessments[0]["body"] == "Captured binary-view judgment."
        rejected = [event for event in history["events"] if event["event"] == "review_input_invalidated"]
        assert len(rejected) == 1 and rejected[0]["pass_id"] == pass_id
        assert rejected[0]["domain"] == "binary" and rejected[0]["phase"] == "post_call"
    else:
        assert result.clean == 1
        assert len(entries) == 1 and entries[0].verdict == "clean"
        assert target.read_bytes() == original
        assert result.total_cost_usd == pytest.approx(bundle.client.reported_spend_usd)
        assert any(event["event"] == "review_assessment"
                   and event["binary_module_unchanged_after_call"] is True for event in history["events"])


def _runtime_binary_context(tmp_path):
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.orchestrator import StudyQueue

    target = tmp_path / "owned.bin"
    target.write_bytes(b"owned runtime fixture, not executable")
    db = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[
        REFunction(name="f", address=4096, size=32, source_tool="ghidra", decompilation="return n + 1;")])
    context = assemble_binary_context(target_path=target, file_path=binary_path_key(target),
                                      function_name="f", db=db)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    return target, context, runtime


def test_runtime_retains_original_module_stamp_when_callback_replaces_it(tmp_path):
    from core.audit.binary_review_scope import capture_binary_module
    from core.audit.knowledge_calls import KnowledgeCallRefused

    target, context, runtime = _runtime_binary_context(tmp_path)
    original = context["_binary_module_snapshot"]
    def callback(ctx, config):
        target.write_bytes(b"owned replacement bytes")
        ctx["_binary_module_snapshot"] = capture_binary_module(target)
        assert ctx["_binary_module_snapshot"].current()
        return orchestrator.ReviewOutcome(ctx["file"], "f", "clean", "Captured callback response", cost_usd=.1)
    try:
        with pytest.raises(KnowledgeCallRefused, match="binary_module_changed_or_unavailable"):
            runtime.wrap_review(callback)(context, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
        assert context["_binary_module_snapshot"] is not original
        assessments = [event for event in runtime.events() if event["event"] == "review_assessment"]
        assert len(assessments) == 1 and assessments[0]["binary_module_unchanged_after_call"] is False
        assert assessments[0]["body"] == "Captured callback response" and assessments[0]["cost_usd"] == .1
    finally:
        runtime.close("test_complete")


def test_active_callback_cancellation_keeps_identity_when_module_changes(tmp_path):
    target, context, runtime = _runtime_binary_context(tmp_path)
    failure = KeyboardInterrupt("owned callback cancellation")
    def callback(ctx, config):
        target.write_bytes(b"owned changed module")
        raise failure
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            runtime.wrap_review(callback)(context, OrchestratorConfig(target_path=target, out_dir=tmp_path / "out"))
        assert caught.value is failure
        assert any(event["event"] == "review_failed" for event in runtime.events())
        assert not any(event["event"] == "review_assessment" for event in runtime.events())
    finally:
        runtime.close("test_complete")
