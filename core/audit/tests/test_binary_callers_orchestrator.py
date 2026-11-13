"""Scripted caller requests through the actual scheduler and default analysis lookup.

The scripted response selects a recorded identity from the actual first prompt.
This tests metadata availability, request routing and publication, not model
judgment, binary extraction, build correspondence, native execution or concurrent
panels. The coalesced type request is fixture-scripted, not model discovery.
"""
import hashlib
import json
import re

import pytest

from core.audit import capabilities, orchestrator
from core.audit.binary_context import load_redb_binding
from core.audit.journal import load_entries
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.audit.record import load_verified_audit_log
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType, REXref


@pytest.mark.slow
@pytest.mark.parametrize("change", ["healthy", "changed_caller", "coalesced",
                                    "coalesced_omitted_subject", "coalesced_omitted_caller"])
def test_binary_caller_request_reaches_main_scheduler(tmp_path, monkeypatch, sdk_clients, change):
    import core.audit.binary_context as context_module
    import core.audit.llm_review as review_module
    import core.inventory.binary_builder as builder

    coalesced = change.startswith("coalesced")
    omitted_field = {"coalesced_omitted_subject": "binary_subject_context",
                     "coalesced_omitted_caller": "binary_caller_context"}.get(change)
    formatted_omissions = []
    if omitted_field is not None:
        original_formatter = review_module.format_context_for_prompt

        def omit_one_context(ctx, **kwargs):
            if "binary_subject_context" in ctx and "binary_caller_context" in ctx:
                omitted_context = ctx[omitted_field]
                fitted_ctx = dict(ctx)
                del fitted_ctx[omitted_field]
                prompt = original_formatter(fitted_ctx, **kwargs)
                assert ctx[omitted_field] is omitted_context
                formatted_omissions.append(omitted_field)
                return prompt
            return original_formatter(ctx, **kwargs)

        # Own only the review consumer binding; the real formatter and all
        # invocation-owned delivery sinks still decide what reached the prompt.
        monkeypatch.setattr(review_module, "format_context_for_prompt", omit_one_context)

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *a, **k: pytest.fail("caller control dispatched a binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned scheduler caller fixture, not executable"
    target.write_bytes(module_bytes)
    database = REDatabase(source_tool="fixture", binary_path=str(target.with_name("previous-name.bin")),
        metadata={"binary_sha256": hashlib.sha256(module_bytes).hexdigest()},
        functions=[
            REFunction(name="f", address=4096, size=32, source_tool="fixture",
                       decompilation="unsigned f(unsigned n) { return n + 1; }"),
            REFunction(name="caller", address=8192, size=32, source_tool="fixture",
                       decompilation="unsigned caller(unsigned n) { return f(n); }"),
        ], xrefs=[REXref(from_addr=8196, to_addr=4096, kind="call", source_tool="fixture")])
    if coalesced:
        database.types.append(REType(name="Packet", kind="struct", size=16, source_tool="fixture",
            fields=[{"name": "length", "type": "unsigned int", "offset": None}]))
    checklist = build_binary_checklist(database, binary_path=target)
    entry, = checklist["files"]
    # This is an explicitly scoped one-unit audit, not whole-module coverage.
    entry["items"] = [item for item in entry["items"] if item["address"] == 4096]
    item, = entry["items"]
    checklist.update(total_items=1, total_functions=1)
    item.update(pinned=True, force_review=True)
    save_checklist(out, checklist)
    artifact = out / "re-database.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    original_analysis = load_redb_binding(artifact).projection_sha256
    original_artifact_bytes = artifact.read_bytes()
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    changed = []
    selected_caller = {}

    def during_wire(request):
        count = len(bundle.state["requests"])
        admitted = [row for row in load_verified_audit_log(out) if row.get("stage") == "admitted"]
        assert len(admitted) == count
        assert count <= 2, "unchanged related-code facts bought another call"
        if change == "changed_caller" and count == 2:
            # The review owns the selected parsed snapshot, not a promise
            # that its former disk path stays unchanged after selection.
            accepted = load_redb_binding(artifact)
            assert accepted.projection_sha256 == original_analysis
            caller, = [function for function in accepted.database.functions if function.address == 8192]
            caller.decompilation = "unsigned caller(unsigned n) { return f(n + 9); }"
            assert accepted.file_current() and not accepted.current()
            assert artifact.read_bytes() == original_artifact_bytes
            changed.append(True)

    bundle.state["handler"] = during_wire

    def transform(response):
        first = len(bundle.state["requests"]) == 1
        if first:
            messages = json.loads(bundle.state["requests"][0].content)["messages"]
            prompt = "\n".join(message["content"] for message in messages if message["role"] == "user")
            index_text = prompt.split("### Binary caller identities\n", 1)[1]
            lines = index_text.splitlines()
            start = next(index for index, line in enumerate(lines) if re.fullmatch(r"`{3,}json", line))
            fence = lines[start][:-4]
            end = next(index for index in range(start + 1, len(lines)) if lines[index] == fence)
            identities = json.loads("\n".join(lines[start + 1:end]))
            assert identities["role"] == "recorded_binary_caller_identities_not_code_or_execution"
            assert identities["caller_coverage"] == "not_exhaustive"
            assert identities["module_file"] == entry["path"]
            assert "previous-name" not in identities["module_file"]
            caller, = identities["callers"]
            assert caller == {"function": "caller", "address": 8192}
            assert "return f(n);" not in prompt and "Binary related-code context" not in prompt
            if coalesced:
                assert "Packet" not in prompt and "Recovered binary type context" not in prompt
            selected_caller.update(file=identities["module_file"], function=caller["function"],
                                   address=caller["address"], line_start=0)
        assert len(selected_caller) == 4
        payload = {"status": "clean", "body": "Recorded related code is partial context, not verification.",
                   "caller_context_requests": [{**selected_caller,
                       "reason": "Inspect input handling" if first else "Inspect the same recorded caller"}]}
        if coalesced:
            payload["reading_list"] = [{"subject": "Packet", "resolution": "identifier",
                "context": "field layout" if first else "interpret the same recorded fields"}]
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "caller_context_requests": {"type": "array", "items": {"type": "object", "properties": {
            "file": {"type": "string"}, "function": {"type": "string"},
            "address": {"type": "integer", "minimum": 0}, "line_start": {"type": "integer", "minimum": 0},
            "reason": {"type": "string"}}, "required": ["file", "function", "address", "line_start", "reason"]}},
    }, "required": ["status", "body"]}
    if coalesced:
        schema["properties"]["reading_list"] = {"type": "array", "items": {"type": "object", "properties": {
            "subject": {"type": "string"}, "context": {"type": "string"},
            "resolution": {"type": "string"}}, "required": ["subject", "context", "resolution"]}}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
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
    assert len(bundle.state["requests"]) == bundle.client._governed_calls == 2
    prompts = [json.loads(request.content)["messages"] for request in bundle.state["requests"]]
    second = "\n".join(message["content"] for message in prompts[1] if message["role"] == "user")
    if omitted_field == "binary_caller_context":
        assert "Binary related-code context" not in second and "return f(n);" not in second
        assert '"caller_address":8192' not in second
    else:
        assert "Binary related-code context" in second and "return f(n);" in second
        assert '"caller_address":8192' in second
        assert "recorded_direct_call_xref_not_execution" in second
    assert "binary:previous-name" not in second
    if omitted_field == "binary_subject_context":
        assert "Recovered binary type context" not in second
        assert '"subject":"Packet"' not in second and '"name":"length"' not in second
    elif coalesced:
        assert "Recovered binary type context" in second
        assert '"subject":"Packet"' in second and '"name":"length"' in second
        assert "recovered_binary_type_context_not_evidence" in second
    assert formatted_omissions == ([omitted_field] if omitted_field is not None else [])
    history = json.loads((out / "knowledge-results.json").read_text())
    attempts = [event for event in history["events"] if event["event"] == "review_attempt"]
    assert len(attempts) == 2
    unit, = history["units"]
    assert unit["unit"] == [entry["path"], "f", 0]
    assert unit["owned_dispatch_attempts"] == unit["all_model_calls"] == 2
    origins = [event["origin"] for event in attempts]
    assert all(origin["function"] == "f" and origin["source_identity"] is None for origin in origins)
    assert all(origin["binary_identity"]["analysis_sha256"] == original_analysis for origin in origins)
    assert not any(outcome.function == "caller" for outcome in result.outcomes)
    signed = load_verified_audit_log(out)
    admitted = [row for row in signed if row.get("stage") == "admitted"]
    reported = [row for row in signed if row.get("stage") == "reported"]
    assert len(admitted) == len(reported) == 2
    attempt_ids = {row["attempt"]["attempt_id"] for row in admitted}
    assert len(attempt_ids) == 2 and attempt_ids == {row["attempt"]["attempt_id"] for row in reported}
    expected = {"review:" + origin["pass_id"]: origin["pass_id"] for origin in origins}
    assert len(expected) == 2
    for rows in (admitted, reported):
        assert {row["attempt"]["work_id"] for row in rows} == set(expected)
        assert all(row["attempt"]["beneficiaries"] == [expected[row["attempt"]["work_id"]]] for row in rows)
    assert all(row["tokens_in"] == row["tokens_out"] == 3 for row in reported)
    assert bundle.client._governed_tokens == 12
    assert sum(row["cost_usd"] for row in reported) == pytest.approx(bundle.client.reported_spend_usd)
    assert result.llm_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert result.cost_tracker.total_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert bundle.client.reported_spend_usd > 0
    assert not bundle.client.pending_usage_reservations and not bundle.client._prepared_resource_reservations
    entries = load_entries(out, fresh=True)
    context_entries = [row for row in entries if row.source_hash.startswith("bin:ctx1:")]
    completed = [event for event in history["events"] if event["event"] == "continuation_completed"]
    caller_answers = [event for event in history["events"] if event["event"] == "binary_caller_answer"]
    assert caller_answers and caller_answers[0]["material"]["caller_address"] == 8192
    if coalesced:
        assert all(answer["status"] == "partial" for answer in caller_answers)
        subject_answers = [event for event in history["events"] if event["event"] == "binary_subject_answer"]
        assert subject_answers and all(answer["status"] == "partial" for answer in subject_answers)
        material = subject_answers[0]["material"]
        assert material["subject"] == "Packet" and material["fields"][0]["name"] == "length"
        assert material["fields"][0]["offset_bytes"] is None
        assert material["fields"][0]["size_bytes"] is None and material["signedness"] == "unknown"
        assert "source_quote" not in material
    if change in ("healthy", "coalesced"):
        assert not changed and result.clean == 1
        assert len(context_entries) == len(completed) == 1
        assert completed[0]["pass_id"] == origins[1]["pass_id"]
        assert completed[0]["published_status"] == "clean"
        context = context_entries[0].review_claims["binary_inputs"]
        assert context["origin"] == origins[1]
        if coalesced:
            assert {row["kind"] for row in context["contexts"]} == {
                "binary_target_semantics", "binary_callers"}
            assert len(context["contexts"]) == 2
        else:
            assert [row["kind"] for row in context["contexts"]] == ["binary_callers"]
    elif omitted_field is not None:
        assert not changed
        assert not context_entries and not completed
        accepted = load_redb_binding(artifact)
        assert accepted.current() and accepted.projection_sha256 == original_analysis
        assert artifact.read_bytes() == original_artifact_bytes
        # A producer answer is historical availability, not evidence that both
        # contexts reached this invocation. Earlier ordinary assessments remain.
    else:
        assert changed == [True]
        assert not context_entries and not completed
        invalidated = [event for event in history["events"] if event["event"] == "review_input_invalidated"]
        assert any(event["pass_id"] == origins[1]["pass_id"] and event["phase"] == "post_call"
                   for event in invalidated)
        assessments = [event for event in history["events"] if event["event"] == "review_assessment"]
        assert any(event["pass_id"] == origins[1]["pass_id"]
                   and event["binary_view_unchanged_after_call"] is False for event in assessments)
        # Earlier paid assessments/ordinary journal rows remain historical;
        # absence of a new context acknowledgement does not erase them.
    assert target.read_bytes() == module_bytes
