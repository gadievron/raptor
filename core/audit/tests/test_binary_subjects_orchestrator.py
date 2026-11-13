"""Captured SDK recovered-type requests through the actual audit scheduler."""
import hashlib
import json

import pytest

from core.audit import capabilities, orchestrator
from core.audit.binary_context import assemble_binary_context, load_redb_binding
from core.audit.journal import load_entries
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.audit.record import load_verified_audit_log
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.json import dumps_canonical
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from packages.ghidra.model import REDatabase, REFunction, REType


@pytest.mark.slow
@pytest.mark.parametrize("context_source", ["explicit", "default", "foreign"])
def test_binary_subject_request_reaches_scheduler_continuation(tmp_path, monkeypatch, sdk_clients, context_source):
    import core.audit.binary_context as context_module
    import core.inventory.binary_builder as builder

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)
    monkeypatch.setattr(context_module, "_lazy_decompile",
                        lambda *a, **k: pytest.fail("unexpected binary backend"))
    monkeypatch.setattr(builder, "_binary_provenance_block", lambda *a: {"probe": "not_requested"})
    monkeypatch.setattr(builder, "_module_identity_block", lambda *a: {})
    target, out = tmp_path / "owned.bin", tmp_path / "out"
    original = b"owned recovered metadata fixture, not executable"
    target.write_bytes(original)
    db = REDatabase(source_tool="fixture", binary_path=str(target),
        metadata={"binary_sha256": hashlib.sha256(original).hexdigest()},
        functions=[REFunction(name="f", address=4096, size=32, source_tool="fixture",
                              decompilation="unsigned f(unsigned n) { return n + 1; }")],
        types=[REType(name="Packet", kind="struct", size=16, source_tool="fixture",
                      fields=[{"name": "length", "type": "unsigned int", "offset": None}])])
    artifact = tmp_path / "accepted.json"
    artifact.write_text(dumps_canonical(db.to_dict()))
    accepted = load_redb_binding(artifact)
    checklist = build_binary_checklist(accepted.database, binary_path=target)
    item = checklist["files"][0]["items"][0]
    item.update(pinned=True, force_review=True)
    save_checklist(out, checklist)
    key = checklist["files"][0]["path"]
    contexts = []

    def build(*args, **kwargs):
        ctx = assemble_binary_context(target_path=target, file_path=key, function_name="f",
                                      checklist=checklist, db=accepted.database)
        assert ctx["type_definitions"] == []
        contexts.append(ctx)
        return ctx

    if context_source == "explicit":
        monkeypatch.setattr(orchestrator, "_build_context", build)
    else:
        recorded = db.to_dict()
        if context_source == "foreign":
            recorded["metadata"]["binary_sha256"] = "0" * 64
        (out / "re-database.json").write_text(dumps_canonical(recorded))
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(row):
        payload = {"status": "clean", "body": "Partial recovered field metadata only.",
                   "reading_list": [{"subject": "Packet", "resolution": "identifier", "context": "field layout"}]}
        message = row["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return row

    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {"status": {"type": "string"}, "body": {"type": "string"},
        "reading_list": {"type": "array", "items": {"type": "object", "properties": {
            "subject": {"type": "string"}, "resolution": {"type": "string"}, "context": {"type": "string"}},
            "required": ["subject", "resolution", "context"]}}}, "required": ["status", "body"]}
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
    if context_source == "foreign":
        assert not bundle.state["requests"]
        assert result.clean == result.findings == 0
        assert len(result.outcomes) == 1 and result.outcomes[0].status == "deferred"
        assert "implementation view" in result.outcomes[0].body
        assert result.reviewed == 0
        assert result.outcomes[0].body in result.processing_limitations
        assert not load_entries(out, fresh=True)
        assert not any(row.get("stage") in {"admitted", "reported"}
                       for row in load_verified_audit_log(out))
        assert bundle.client.reported_spend_usd == 0
        return
    assert len(bundle.state["requests"]) == 2, "binary request did not receive one scheduler-owned continuation"
    prompts = [json.loads(req.content)["messages"] for req in bundle.state["requests"]]
    second = "\n".join(msg["content"] for msg in prompts[1] if msg["role"] == "user")
    assert "Packet" in second and "length" in second and "offset_bytes" in second
    assert result.clean == 1
    rows = load_verified_audit_log(out)
    admitted = [row for row in rows if row.get("stage") == "admitted"]
    reported = [row for row in rows if row.get("stage") == "reported"]
    assert len(admitted) == len(reported) == 2
    assert {r["attempt"]["attempt_id"] for r in admitted} == {r["attempt"]["attempt_id"] for r in reported}
    assert len({r["attempt"]["work_id"] for r in admitted}) == 2
    assert result.llm_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert not bundle.client.pending_usage_reservations
    entries = load_entries(out, fresh=True)
    assert any(entry.source_hash.startswith("bin:ctx1:") for entry in entries)
    history = json.loads((out / "knowledge-results.json").read_text())
    assert any(e["event"] == "binary_subject_answer" for e in history["events"])
    completed = [e for e in history["events"] if e["event"] == "continuation_completed"]
    assert len(completed) == 1 and completed[0]["published_status"] == "clean"
    passes = {e["origin"]["pass_id"] for e in history["events"] if e["event"] == "review_attempt"}
    assert {r["attempt"]["work_id"] for r in admitted} == {"review:" + p for p in passes}
