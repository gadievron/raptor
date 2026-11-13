"""Recorded callee advice through the actual binary review scheduler.

Owned inert bytes and captured SDK transport establish routing and accounting,
not extraction, execution, build correspondence or mechanical verification.
"""
import hashlib
import json
import re
from functools import wraps

import pytest

from core.audit import capabilities, orchestrator
from core.audit.binary_context import load_redb_binding
from core.audit.journal import load_entries
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.audit.record import load_verified_audit_log
from core.audit.review_claims import read_history
from core.audit.tests.test_binary_subjects_sdk import _review_origin, _user_prompt
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REXref


@pytest.mark.slow
@pytest.mark.parametrize("case", ["healthy", "omitted", "changed_assessment"])
def test_binary_callee_assessment_reaches_main_scheduler(tmp_path, monkeypatch, sdk_clients, case):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder
    import core.audit.decomp_sweep as decomp_sweep
    import core.llm.egress as egress
    import core.audit.llm_review as review_module

    omissions = []
    if case == "omitted":
        original_formatter = review_module.format_context_for_prompt

        def omit_callee_context(ctx, **kwargs):
            field = "binary_callee_assessment_context"
            if field not in ctx:
                return original_formatter(ctx, **kwargs)
            owned_context = ctx[field]
            fitted = dict(ctx)
            del fitted[field]
            prompt = original_formatter(fitted, **kwargs)
            assert ctx[field] is owned_context
            omissions.append(field)
            return prompt

        # Retain every invocation-owned receipt sink; only the supplied
        # formatter input loses the section before the actual fit decision.
        monkeypatch.setattr(review_module, "format_context_for_prompt", omit_callee_context)

    # Captured transport owns network responses; proxy/process startup and the
    # unrelated tree-wide mechanical sweep are outside this acceptance boundary.
    monkeypatch.setattr(egress, "enable_llm_egress", lambda *a, **k: None)
    swept = []

    def omit_mechanical_sweep(**kwargs):
        swept.append(kwargs)
        return None

    monkeypatch.setattr(decomp_sweep, "run_decomp_tree_sweep", omit_mechanical_sweep)

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *a, **k: pytest.fail("callee control dispatched a binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned scheduler callee fixture, not executable"
    target.write_bytes(module_bytes)
    database = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(module_bytes).hexdigest()},
        functions=[
            REFunction(name="f", address=4096, size=32, source_tool="fixture",
                       decompilation="unsigned f(unsigned n) { return n + 1; }"),
            REFunction(name="caller", address=8192, size=32, source_tool="fixture",
                       decompilation="unsigned caller(unsigned n) { return f(n); }"),
        ], xrefs=[REXref(from_addr=8196, to_addr=4096, kind="call", source_tool="fixture")])
    checklist = build_binary_checklist(database, binary_path=target)
    entry, = checklist["files"]
    assert {item["name"] for item in entry["items"]} == {"f", "caller"}
    for item in entry["items"]:
        item.update(pinned=True, force_review=True)
    save_checklist(out, checklist)
    artifact = out / "re-database.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    original_analysis = load_redb_binding(artifact).projection_sha256
    original_artifact_bytes = artifact.read_bytes()
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    target_names = []

    def transform(response):
        prompt = _user_prompt(bundle.state["requests"][-1])
        headings = re.findall(r"^## " + re.escape(entry["path"]) + r":(f|caller)\s*$", prompt, re.M)
        assert len(headings) == 1, "response must select the actual reviewed target heading"
        name, = headings
        target_names.append(name)
        assert len(target_names) <= 3, "unchanged callee advice bought another review"
        payload = {"status": "suspicious" if name == "f" else "clean",
                   "body": "Callee may omit an input bound" if name == "f" else
                           "Caller remains provisional; callee advice is not verification."}
        if name == "caller" and case == "changed_assessment" and len(target_names) == 3:
            payload.update(status="suspicious",
                body="Caller may rely on an unverified input bound; concern remains provisional.")
        if name == "caller":
            payload["relies_on"] = [{"callee": "f", "file": entry["path"], "line_start": 0,
                                    "assumption": "callee enforces its input bound"}]
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    def during_wire(request):
        count = len(bundle.state["requests"])
        admitted = [row for row in load_verified_audit_log(out) if row.get("stage") == "admitted"]
        assert len(admitted) == count
        assert count <= 3

    bundle.state["handler"] = during_wire
    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "relies_on": {"type": "array", "items": {"type": "object", "properties": {
            "callee": {"type": "string"}, "file": {"type": "string"},
            "line_start": {"type": "integer", "minimum": 0}, "assumption": {"type": "string"}},
            "required": ["callee", "file", "line_start", "assumption"]}},
    }, "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    observed = []

    @wraps(review)
    def capture_review(ctx, cfg):
        outcome = review(ctx, cfg)
        observed.append(outcome)
        return outcome

    config = OrchestratorConfig(target_path=target, out_dir=out, review_passes=1,
        resume=False, max_workers=1, batch_sloc_threshold=0, prefilter=False,
        prefilter_skip=False, triage=False, vendored_triage=False,
        validate=False, immediate_verify=False, sweep_validate_findings=False, deepen_suspicious=False,
        clean_check=False, adversarial=False, enable_session_context=False,
        propagate_constraints=False, on_demand_synthesis=False, open_discovery=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        iris=False, sage_recall=False, domain_model_import=False,
        dynamic_validation=False, library_replay=False, cross_run_import=False,
        annotations_read=False, llm_budget_client=bundle.client)
    result = run_orchestrator(config, capture_review)
    assert len(bundle.state["requests"]) == bundle.client._governed_calls == 3
    assert sorted(target_names[:2]) == ["caller", "f"] and target_names[2] == "caller"
    assert len(observed) == 3
    third_prompt = _user_prompt(bundle.state["requests"][2])
    if case != "omitted":
        assert "Related binary callee assessments" in third_prompt
        assert "Callee may omit an input bound" in third_prompt
        assert not omissions
    else:
        assert "Related binary callee assessments" not in third_prompt
        assert "Callee may omit an input bound" not in third_prompt
        assert omissions == ["binary_callee_assessment_context"]
    history = json.loads((out / "knowledge-results.json").read_text())
    attempts = [event for event in history["events"] if event["event"] == "review_attempt"]
    assert len(attempts) == 3
    units = {unit["unit"][1]: unit for unit in history["units"]}
    # Unit rows describe enrichment cycles, not every initial review.
    assert set(units) == {"caller"}
    assert units["caller"]["owned_dispatch_attempts"] == units["caller"]["all_model_calls"] == 2
    assert sorted(event["origin"]["function"] for event in attempts) == ["caller", "caller", "f"]
    origins = [_review_origin(outcome) for outcome in observed]
    assert all(origin["source_identity"] is None and origin["line_start"] == 0 for origin in origins)
    assert all(origin["binary_identity"]["analysis_sha256"] == original_analysis for origin in origins)
    expected = {"review:" + origin["pass_id"]: origin["pass_id"] for origin in origins}
    assert len(expected) == 3
    signed = load_verified_audit_log(out)
    admitted = [row for row in signed if row.get("stage") == "admitted"]
    reported = [row for row in signed if row.get("stage") == "reported"]
    assert len(admitted) == len(reported) == 3
    admitted_ids = {row["attempt"]["attempt_id"] for row in admitted}
    assert len(admitted_ids) == 3 and admitted_ids == {row["attempt"]["attempt_id"] for row in reported}
    for rows in (admitted, reported):
        assert {row["attempt"]["work_id"] for row in rows} == set(expected)
        assert all(row["attempt"]["beneficiaries"] == [expected[row["attempt"]["work_id"]]] for row in rows)
    assert all(row["tokens_in"] == row["tokens_out"] == 3 for row in reported)
    assert bundle.client._governed_tokens == 18
    assert sum(row["cost_usd"] for row in reported) == pytest.approx(bundle.client.reported_spend_usd)
    assert result.llm_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert result.cost_tracker.total_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert bundle.client.reported_spend_usd > 0
    assert not bundle.client.pending_usage_reservations and not bundle.client._prepared_resource_reservations
    canonical_callee, = [outcome for outcome in result.outcomes if outcome.function == "f"]
    assert canonical_callee.status == "suspicious"
    contextual = [row for row in load_entries(out, fresh=True) if row.source_hash.startswith("bin:ctx1:")]
    completed = [event for event in history["events"] if event["event"] == "continuation_completed"]
    assert len(swept) == 1 and swept[0]["target_path"] == target
    assert artifact.read_bytes() == original_artifact_bytes and target.read_bytes() == module_bytes
    if case == "omitted":
        assert not contextual and not completed
        failed = [event for event in history["events"] if event["event"] == "continuation_failed"]
        assert any(event["reason"] == "callee_context_not_delivered" for event in failed)
        caller, = [outcome for outcome in result.outcomes if outcome.function == "caller"]
        assert caller.status == "clean"
        prior_origin = next(origin for origin in origins[:2] if origin["function"] == "caller")
        assert _review_origin(caller)["pass_id"] == prior_origin["pass_id"]
        return
    assert len(contextual) == len(completed) == 1
    assert completed[0]["pass_id"] == origins[2]["pass_id"]
    assert completed[0]["reason"] == "callee_context_reviewed"
    inputs = contextual[0].review_claims["binary_inputs"]
    assert inputs["origin"] == origins[2]
    assert [context["kind"] for context in inputs["contexts"]] == ["binary_callee_assessments"]
    canonical_caller, = [outcome for outcome in result.outcomes if outcome.function == "caller"]
    assert canonical_caller.status == contextual[0].verdict == (
        "suspicious" if case == "changed_assessment" else "clean")
    canonical_history = read_history(canonical_caller.review_result["review_claims"])
    assert canonical_history is not None and canonical_history["binary_inputs"] == inputs
    if case == "changed_assessment":
        assert canonical_caller is observed[2]
        assert canonical_history["review"]["origin"]["pass_id"] == origins[2]["pass_id"]
    else:
        assert canonical_history["review"] is None

