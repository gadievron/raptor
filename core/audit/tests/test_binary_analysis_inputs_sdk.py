"""Paid SDK review publication retains its original parsed analysis inputs.

The SDK transport and analysis data are captured fixtures, not provider or
binary-extraction evidence.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.collector import Collector
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
from packages.ghidra.model import REDatabase, REFunction


@pytest.mark.slow
@pytest.mark.parametrize("change", ["healthy", "signature"])
def test_paid_sdk_review_cannot_publish_changed_analysis_inputs(tmp_path, monkeypatch, sdk_clients, change):
    import core.audit.binary_context as context_module

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *args, **kwargs: pytest.fail("analysis-input control dispatched a backend"))
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    original_module = b"owned SDK module input, not executable"
    target.write_bytes(original_module)
    database = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(original_module).hexdigest()},
        functions=[REFunction(name="f", address=4096, size=32, source_tool="fixture",
            signature="unsigned f(unsigned n)",
            decompilation="unsigned f(unsigned n) { return n + 1; }")])
    artifact = tmp_path / "re-database.json"
    artifact.write_text(dumps_canonical(database.to_dict()))
    read = load_redb_binding(artifact)
    checklist = build_binary_checklist(read.database, binary_path=target)
    save_checklist(out, checklist)
    key = checklist["files"][0]["path"]
    item = checklist["files"][0]["items"][0]
    gap = {**item, "file": key, "line_start": 0, "line_end": None}
    ctx = assemble_binary_context(target_path=target, file_path=key, function_name="f",
                                  checklist=checklist, db=read.database)
    original_source = ctx["source"]
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        message = response["choices"][0]["message"]
        payload = {"status": "clean", "body": "Captured SDK analysis-input review"}
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"}},
        "required": ["status", "body"]}
    review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, enable_session_context=False,
        immediate_verify=False, sweep_validate_findings=False, llm_budget_client=bundle.client)
    runtime = AuditKnowledgeRuntime(target, StudyQueue(), deadline=float("inf"), window=0)
    try:
        outcome = runtime.wrap_review(review)(ctx, config)
        assert outcome.status == "clean"
        history = read_history(outcome.review_result["review_claims"])
        assert history is not None
        origin = history["review"]["origin"]
        assert origin["binary_identity"]["analysis_sha256"] == read.projection_sha256
        scope = outcome.binary_publication_scope
        assert scope is not None and scope.current(target)

        # The response, signed usage and paid assessment all exist BEFORE the
        # only adverse mutation. No refund or cancelled-wire claim is made.
        signed = load_verified_audit_log(out)
        admitted = [row for row in signed if row.get("stage") == "admitted"]
        reported = [row for row in signed if row.get("stage") == "reported"]
        assert len(admitted) == len(reported) == len(bundle.state["requests"]) == 1
        assert admitted[0]["attempt"]["attempt_id"] == reported[0]["attempt"]["attempt_id"]
        assert admitted[0]["attempt"]["work_id"] == "review:" + origin["pass_id"]
        assert admitted[0]["attempt"]["beneficiaries"] == [origin["pass_id"]]
        assessments = [event for event in runtime.events() if event["event"] == "review_assessment"]
        assert len(assessments) == 1 and assessments[0]["body"] == outcome.body
        assert outcome.cost_usd == pytest.approx(bundle.client.reported_spend_usd)
        assert outcome.cost_usd > 0
        assert bundle.client._governed_calls == sum(runtime._calls.values()) == 1
        assert not bundle.client.pending_usage_reservations
        assert not bundle.client._prepared_resource_reservations

        if change == "signature":
            read.database.functions[0].signature = "long f(long n)"
            assert not read.current()
            assert not scope.current(target)
        else:
            assert read.current()
        assert target.read_bytes() == original_module and ctx["source"] == original_source
        acknowledgement = Collector(out_dir=out, target_path=target, run_id=out.name).submit(outcome, gap)
        rows = load_entries(out, fresh=True)
        if change == "signature":
            assert acknowledgement is None and rows == []
        else:
            assert acknowledgement is not None and len(rows) == 1
            assert rows[0].source_hash.startswith("bin:inputs1:" + read.projection_sha256 + ":")
            assert rows[0].review_claims["review"]["origin"]["pass_id"] == origin["pass_id"]
        assert len(bundle.state["requests"]) == bundle.client._governed_calls == 1
        assert load_verified_audit_log(out) == signed
        assert outcome.cost_usd == pytest.approx(bundle.client.reported_spend_usd)
        assert [event for event in runtime.events() if event["event"] == "review_assessment"] == assessments
    finally:
        runtime.close("test_complete")
