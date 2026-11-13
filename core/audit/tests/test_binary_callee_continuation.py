"""Recorded binary callee assessments should wake dependent caller review.

The scripted assessments and inert owned module exercise the existing adapter,
not model judgement, extraction, build correspondence or checker authority.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from functools import wraps

import pytest

from core.audit import orchestrator as orch
from core.audit.binary_context import load_redb_binding
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.record import load_verified_audit_log
from core.audit.tests.test_binary_subjects_sdk import _assert_attempt_joins, _review_origin, _user_prompt
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REXref


@pytest.mark.slow
@pytest.mark.parametrize("case", ["healthy", "changed_callee", "replaced_callee", "omitted", "replaced_during_append", "changed_assessment", "graph_disabled", "explicit_graph_disabled"])
def test_recorded_binary_callee_assessment_requeues_owned_caller(tmp_path, monkeypatch, sdk_clients, case):
    import core.audit.binary_context as context_module
    import core.audit.llm_review as review_module
    import core.inventory.binary_builder as builder

    formatted_omissions = []
    if case == "omitted":
        original_formatter = review_module.format_context_for_prompt

        def omit_callee_context(ctx, **kwargs):
            field = "binary_callee_assessment_context"
            if field in ctx:
                original_context = ctx[field]
                fitted_ctx = dict(ctx)
                del fitted_ctx[field]
                prompt = original_formatter(fitted_ctx, **kwargs)
                assert ctx[field] is original_context
                formatted_omissions.append(field)
                return prompt
            return original_formatter(ctx, **kwargs)

        monkeypatch.setattr(review_module, "format_context_for_prompt", omit_callee_context)

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *a, **k: pytest.fail("callee control dispatched a binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    module_bytes = b"owned callee advisory fixture, not executable"
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
    save_checklist(out, checklist)
    artifact = out / "re-database.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    accepted = load_redb_binding(artifact)
    original_artifact_bytes = artifact.read_bytes()
    entry, = checklist["files"]
    items = {item["name"]: item for item in entry["items"]}
    gaps = {name: {**item, "file": entry["path"], "line_start": 0, "line_end": None}
            for name, item in items.items()}
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        count = len(bundle.state["requests"])
        assert count <= 3, "unchanged callee assessments bought another dispatch"
        payload = {"status": "suspicious" if count == 2 else "clean",
                   "body": "Callee may omit an input bound" if count == 2 else
                           "Caller assessment remains provisional; callee notes are advisory."}
        if case == "changed_assessment" and count == 3:
            payload.update(status="suspicious",
                body="Caller may rely on an unverified input bound; this concern remains provisional.")
        if count != 2 and case != "graph_disabled":
            payload["relies_on"] = [{"callee": "f", "file": entry["path"], "line_start": 0,
                                    "assumption": "callee enforces its input bound"}]
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    faults = []

    def during_wire(request):
        count = len(bundle.state["requests"])
        admitted = [row for row in load_verified_audit_log(out) if row.get("stage") == "admitted"]
        assert len(admitted) == count
        if count != 3:
            return
        if case == "changed_callee":
            recorded, = [function for function in accepted.database.functions if function.address == 4096]
            recorded.decompilation = "unsigned f(unsigned n) { return n + 9; }"
            assert accepted.file_current() and not accepted.current()
            assert artifact.read_bytes() == original_artifact_bytes
            faults.append(case)
        elif case == "replaced_callee":
            assert result.outcomes[1] is callee
            replacement = replace(callee, body="A competing canonical callee assessment")
            assert replacement is not callee
            result.outcomes[1] = replacement
            assert callee.body == "Callee may omit an input bound"
            assert accepted.current() and callee.binary_publication_scope.current(target)
            faults.append(case)

    bundle.state["handler"] = during_wire
    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "relies_on": {"type": "array", "items": {"type": "object", "properties": {
            "callee": {"type": "string"}, "file": {"type": "string"},
            "line_start": {"type": "integer", "minimum": 0}, "assumption": {"type": "string"}},
            "required": ["callee", "file", "line_start", "assumption"]}},
    }, "required": ["status", "body"]}
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, review_passes=1,
        enable_session_context=False, immediate_verify=False, sweep_validate_findings=False,
        annotations_read=False, propagate_constraints=case not in ("graph_disabled", "explicit_graph_disabled"),
        llm_budget_client=bundle.client,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        iris=False, sage_recall=False, domain_model_import=False)
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    observed = []

    @wraps(review)
    def capture_review(ctx, cfg):
        outcome = review(ctx, cfg)
        observed.append(outcome)
        return outcome

    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    try:
        owned_review = runtime.wrap_review(capture_review)
        caller_ctx = orch._build_context(config, gaps["caller"], checklist, None, {})
        callee_ctx = orch._build_context(config, gaps["f"], checklist, None, {})
        caller = owned_review(caller_ctx, config)
        callee = owned_review(callee_ctx, config)
        assert caller.status == "clean" and callee.status == "suspicious"
        assert caller.binary_publication_scope is not None and callee.binary_publication_scope is not None
        assert caller.binary_publication_scope.current(target) and callee.binary_publication_scope.current(target)
        assert _review_origin(caller)["binary_identity"]["analysis_sha256"] == accepted.projection_sha256
        assert _review_origin(callee)["binary_identity"]["analysis_sha256"] == accepted.projection_sha256
        assert caller_ctx["_binary_module_snapshot"].current() and accepted.current()
        initial_signed = _assert_attempt_joins(bundle, runtime, out, observed)
        assert len(initial_signed) >= 4
        assert load_entries(out, fresh=True) == []
        result = orch.OrchestratorResult(outcomes=[caller, callee], reviewed=2, clean=1, suspicious=1,
                                        total_cost_usd=caller.cost_usd + callee.cost_usd)
        for outcome in observed:
            result.cost_tracker.record_call("review", cost_usd=outcome.cost_usd,
                                            wall_time_s=outcome.duration_s)
        initial_cost = result.total_cost_usd
        changed_publication_acks = []
        if case == "changed_assessment":
            import core.audit.collector as collector_module

            original_append = collector_module.append_journal_for_outcome

            def observe_changed_publication(**kwargs):
                # The changed caller must remain a candidate until the real
                # writer returns its checked acknowledgement.
                assert kwargs["outcome"] is observed[2]
                assert kwargs["outcome"].status == "suspicious"
                assert result.outcomes[0] is caller and caller.status == "clean"
                acknowledgement = original_append(**kwargs)
                assert acknowledgement is not None
                assert acknowledgement.verdict == "suspicious"
                assert result.outcomes[0] is caller
                changed_publication_acks.append(acknowledgement)
                return acknowledgement

            monkeypatch.setattr(collector_module, "append_journal_for_outcome", observe_changed_publication)
        if case == "replaced_during_append":
            import core.audit.collector as collector_module

            original_append = collector_module.append_journal_for_outcome

            def replace_after_append(**kwargs):
                acknowledgement = original_append(**kwargs)
                assert acknowledgement is not None
                assert result.outcomes[1] is callee
                result.outcomes[1] = replace(callee, body="Canonical callee changed during append")
                assert accepted.current() and callee.binary_publication_scope.current(target)
                faults.append(case)
                return acknowledgement

            monkeypatch.setattr(collector_module, "append_journal_for_outcome", replace_after_append)
        orch._callee_contract_requeue(result, config, capture_review, checklist=checklist,
            context_map=None, fuzz_coverage=None, evidence_index={}, start_time=time.monotonic(),
            knowledge_runtime=runtime)

        if case == "graph_disabled":
            assert not caller.review_result.get("relies_on")
            assert len(bundle.state["requests"]) == bundle.client._governed_calls == 2
            assert result.outcomes[0] is caller and result.total_cost_usd == pytest.approx(initial_cost)
            assert not load_entries(out, fresh=True)
            assert not any(event["event"] == "continuation_completed" for event in runtime.events())
            assert not runtime._active and accepted.current()
            assert target.read_bytes() == module_bytes
            return
        assert len(bundle.state["requests"]) == 3, "recorded binary callee assessment never reached its caller"
        assert len(observed) == 3 and observed[2].function == "caller"
        assert sum(runtime._calls.values()) == 3
        assert sorted(runtime._calls.values()) == [1, 2]
        signed = _assert_attempt_joins(bundle, runtime, out, observed)
        assert len([row for row in signed if row.get("stage") == "reported"]) == 3
        if case == "changed_callee":
            # Runtime rejects the paid result before an outcome returns to the
            # phase owner. Failed/refused spend is reconciled from the client;
            # do not invent a per-phase attribution or refund that charge.
            assert result.total_cost_usd == pytest.approx(initial_cost)
            assessments = [event for event in runtime.events() if event["event"] == "review_assessment"]
            assert sum(event["cost_usd"] for event in assessments) == pytest.approx(bundle.client.reported_spend_usd)
            orch._reconcile_cost_ledgers(config, result)
            assert result.llm_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
        else:
            assert result.total_cost_usd == pytest.approx(initial_cost + observed[2].cost_usd)
        assert result.cost_tracker.total_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
        prompt = _user_prompt(bundle.state["requests"][2])
        if case == "omitted":
            assert formatted_omissions == ["binary_callee_assessment_context"]
            assert "Related binary callee assessments" not in prompt
            assert "Callee may omit an input bound" not in prompt
        else:
            assert not formatted_omissions
            assert "Related binary callee assessments" in prompt
            assert "Callee may omit an input bound" in prompt
        completed = [event for event in runtime.events() if event["event"] == "continuation_completed"]
        contextual = [row for row in load_entries(out, fresh=True) if row.source_hash.startswith("bin:ctx1:")]
        if case in ("healthy", "changed_assessment", "explicit_graph_disabled"):
            assert not faults
            assert len(completed) == 1 and completed[0]["reason"] == "callee_context_reviewed"
            assert completed[0]["pass_id"] == _review_origin(observed[2])["pass_id"]
            assert len(contextual) == 1
            if case == "changed_assessment":
                assert len(changed_publication_acks) == 1
                assert result.outcomes[0] is observed[2] and result.outcomes[0] is not caller
                assert result.outcomes[0].status == contextual[0].verdict == "suspicious"
                assert contextual[0].review_claims["binary_inputs"]["origin"]["pass_id"] == _review_origin(observed[2])["pass_id"]
            else:
                assert not changed_publication_acks
        else:
            assert result.outcomes[0] is caller
            assert not completed
            if case == "replaced_during_append":
                # The real writer already retained a historical context row.
                # It must not acknowledge a new canonical caller or complete
                # the continuation after the contributor ownership changed.
                assert len(contextual) == 1
            else:
                assert not contextual
            assert faults == ([case] if case in ("changed_callee", "replaced_callee", "replaced_during_append") else [])
        if case == "changed_callee":
            assert not accepted.current()
        else:
            assert accepted.current()
        assert artifact.read_bytes() == original_artifact_bytes and target.read_bytes() == module_bytes
        assert not runtime._active
    finally:
        runtime.close()
