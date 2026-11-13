"""A source edit after actual journal ACK retains prior review and paid usage.

Captured SDK transport and owned source bytes exercise publication/accounting;
no provider, execution, checker or atomic filesystem guarantee is established.
"""
import builtins
import json
from functools import wraps
from time import monotonic
from types import ModuleType

import pytest

from core.audit import collector, orchestrator as orch
from core.audit.collector import Collector, journal_acknowledges_outcome
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.record import load_verified_audit_log
from core.audit.refutation_source import capture_source_identity
from core.audit.review_claims import read_history
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.coverage.journal import load_entries
from core.inventory import save_checklist
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.slow
def test_source_candidate_post_ack_edit_retains_prior_and_sdk_spend(tmp_path, monkeypatch, sdk_clients):
    import core.llm.egress as egress

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setattr(egress, "enable_llm_egress", lambda *args, **kwargs: None)
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    path = target / "owned.c"
    source = "unsigned f(unsigned n) { return n + 1; }\n"
    path.write_text(source)
    identity = capture_source_identity(target, "owned.c")
    checklist = {"files": [{"path": "owned.c", "items": [
        {"name": "f", "line_start": 1, "line_end": 1}]}]}
    save_checklist(out, checklist)
    gap = {"file": "owned.c", "name": "f", "line_start": 1, "line_end": 1}
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)

    def transform(response):
        initial = len(bundle.state["requests"]) == 1
        hypothesis = "H1 initial concern" if initial else "H2 independent concern"
        payload = {"status": "suspicious", "body": hypothesis, "hypothesis": hypothesis,
                   "hypotheses": [{"mechanism": hypothesis, "confidence": "medium"}],
                   "language_reference_requests": ([{"topic": "integer shifts",
                       "entry_id": "c.integer-shift"}] if initial else [])}
        message = response["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return response

    bundle.state["transform"] = transform
    schema = {"type": "object", "properties": {
        "status": {"type": "string"}, "body": {"type": "string"},
        "hypothesis": {"type": "string"},
        "hypotheses": {"type": "array", "items": {"type": "object", "properties": {
            "mechanism": {"type": "string"}, "confidence": {"type": "string"}},
            "required": ["mechanism", "confidence"]}},
        "language_reference_requests": {"type": "array", "items": {"type": "object",
            "properties": {"topic": {"type": "string"}, "entry_id": {"type": "string"}},
            "required": ["topic", "entry_id"]}}}, "required": ["status", "body"]}
    real_review = make_review_fn(bundle.client, schema=schema, escalate_clean=False)
    captured = []

    @wraps(real_review)
    def review(ctx, config):
        outcome = real_review(ctx, config)
        captured.append(outcome)
        return outcome

    config = orch.OrchestratorConfig(target_path=target, out_dir=out,
        immediate_verify=False, sweep_validate_findings=False, enable_session_context=False,
        prefilter=False, validate=False, deepen_suspicious=False, open_discovery=False,
        sage_recall=False, iris=False, joern_overrides={"enabled": False},
        no_binary_oracle=True, llm_budget_client=bundle.client)
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    acknowledgements = []
    original_append = collector.append_journal_for_outcome

    def append_then_edit(**kwargs):
        acknowledgement = original_append(**kwargs)
        assert acknowledgement is not None
        acknowledgements.append(acknowledgement)
        path.write_text(source + "/* owned revision after journal ACK */\n")
        return acknowledgement

    private_collector = ModuleType(collector.__name__)
    vars(private_collector).update(vars(collector))
    private_collector.append_journal_for_outcome = append_then_edit

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "collector":
            return private_collector
        return builtins.__import__(name, globals, locals, fromlist, level)

    private = module_function_view(orch, import_hook=import_local)
    try:
        ctx = {"file": "owned.c", "function": "f", "line_start": 1, "line_end": 1,
               "source": source.rstrip(), "language": "c"}
        prior = runtime.wrap_review(review)(ctx, config)
        prior.line = 1  # Geometry normally assigned by the review collector.
        assert prior.status == "suspicious"
        initial_ack = Collector(out_dir=out, target_path=target, run_id=out.name).submit(prior, gap)
        assert journal_acknowledges_outcome(initial_ack, prior, gap)
        assert len(load_entries(out, fresh=True)) == 1
        reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=1)
        # This topic was requested by the actual initial source review; it is
        # absent from mechanical initial selection for this addition-only body.
        assert "c.integer-shift" in {entry.entry_id for answer in reservation.packet.references
                                     for entry in answer.entries}
        result = orch.OrchestratorResult(outcomes=[prior], reviewed=1, suspicious=1,
                                         total_cost_usd=prior.cost_usd)
        with monkeypatch.context() as patch, isolated_audit_shutdown(orch):
            patch.setattr(orch, "_publish_study_candidates", private._publish_study_candidates)
            orch._re_review_study_enriched(result, config, review, checklist, None, {}, None,
                set(), {("owned.c", "f", 1)}, monotonic(), None, max_workers=1,
                knowledge_runtime=runtime, knowledge_reservation=reservation)
        assert len(captured) == 2
        fresh = captured[1]
        assert fresh.status == prior.status == "suspicious"
        assert fresh.hypothesis != prior.hypothesis
        assert result.outcomes[0] is prior and len(result.outcomes) == 1
        assert result.reviewed == result.suspicious == 1 and result.clean == 0
        assert len(acknowledgements) == 1
        assert len(load_entries(out, fresh=True)) == 2
        assert capture_source_identity(target, "owned.c") != identity
        assert any(event.get("reason") == "source_changed" for event in runtime.events())
        assert not runtime._active
        origins = [read_history(outcome.review_result["review_claims"])["review"]["origin"]
                   for outcome in captured]
        assert all(origin["source_identity"] is not None for origin in origins)
        assert origins[1]["pass_id"] == reservation.packet.pass_id
        expected = {"review:" + origin["pass_id"]: origin["pass_id"] for origin in origins}
        assert len(expected) == 2
        assert len(bundle.state["requests"]) == bundle.client._governed_calls == 2
        assert sum(runtime._calls.values()) == 2
        signed = load_verified_audit_log(out)
        admitted = [row for row in signed if row.get("stage") == "admitted"]
        reported = [row for row in signed if row.get("stage") == "reported"]
        assert len(admitted) == len(reported) == 2
        ids = {row["attempt"]["attempt_id"] for row in admitted}
        assert len(ids) == 2 and ids == {row["attempt"]["attempt_id"] for row in reported}
        for rows in (admitted, reported):
            assert {row["attempt"]["work_id"] for row in rows} == set(expected)
            for row in rows:
                attempt = row["attempt"]
                assert attempt["beneficiaries"] == [expected[attempt["work_id"]]]
        projection = bundle.sink.attempt_projection()["attempts"]
        assert len(projection) == 2 and {row["attempt_id"] for row in projection} == ids
        assert all(row["billing_state"] == "reported" and row["cost_usd"] > 0 for row in projection)
        paid = bundle.client.reported_spend_usd
        assert sum(row["cost_usd"] for row in projection) == pytest.approx(paid)
        assert sum(row["cost_usd"] for row in reported) == pytest.approx(paid)
        assert sum(outcome.cost_usd for outcome in captured) == pytest.approx(paid)
        assert result.total_cost_usd == pytest.approx(paid)
        assert bundle.client._governed_tokens == 12
        assert not bundle.client.pending_usage_reservations
        assert not bundle.client._prepared_resource_reservations
    finally:
        runtime.close("test_complete")
