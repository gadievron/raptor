"""Owned late-context publication retains original inputs across writer ACK."""
from time import monotonic
from types import SimpleNamespace

import pytest

from core.audit import collector as collector_mod, orchestrator as orch
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.review_input_scope import ReviewInputScope
from core.audit.record import load_audit_log
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.coverage.journal import load_entries
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("change", ["none", "revision", "rewrite_restore", "write_refused",
    "invalid_ack", "finalized", "prior_replaced", "cancel_before", "cancel_after"])
def test_late_joern_rechecks_original_scope_after_actual_ack(tmp_path, monkeypatch, change):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    path = target / "unit.c"
    source = "unsigned f(unsigned value) { return value; }\n"
    path.write_text(source)
    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source, "language": "c"}
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        _call_cost_history = None

        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "clean" if len(calls) == 1 else "suspicious",
                "body": "Owned scripted assessment", "reading_list": [],
                "language_reference_requests": [],
                "hypothesis": "" if len(calls) == 1 else "Owned late concern"},
                raw="", cost=.125, model="scripted")

    client = Client()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out,
        enable_session_context=False, sweep_validate_findings=False,
        llm_budget_client=client, joern_overrides={"enabled": False})
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    review = make_review_fn(client, escalate_clean=False)
    private = module_function_view(orch, bindings={
        "_build_context": lambda *a, **k: dict(ctx),
        # Incidental host environment checking is outside this owned-file test.
        "_make_dispatch_gate": lambda *a, **k: lambda: None,
    })
    acknowledgements, proposed = [], []
    original_append = collector_mod.append_journal_for_outcome

    def append_then_change(**kwargs):
        outcome = kwargs["outcome"]
        proposed.append(outcome)
        assert isinstance(outcome.review_input_scope, ReviewInputScope)
        assert outcome.review_input_scope.current(target)
        if change == "write_refused":
            return None
        acknowledgement = original_append(**kwargs)
        assert acknowledgement is not None
        acknowledgements.append(acknowledgement)
        if change in {"revision", "rewrite_restore"}:
            path.write_text(source + "/* after actual ACK */\n")
            if change == "rewrite_restore":
                path.write_text(source)
        if change == "invalid_ack":
            return object()
        if change == "finalized":
            config._verdicts_finalized = True
        if change == "prior_replaced":
            result.outcomes[0] = replacement
        if change == "cancel_before":
            raise KeyboardInterrupt("owned cancellation before canonical publication")
        return acknowledgement

    monkeypatch.setattr(collector_mod, "append_journal_for_outcome", append_then_change)
    original_record = private._record_acknowledged_outcome

    def record_then_cancel(*args, **kwargs):
        original_record(*args, **kwargs)
        raise KeyboardInterrupt("owned cancellation after canonical publication")

    if change == "cancel_after":
        private._record_acknowledged_outcome = record_then_cancel
    try:
        prior = runtime.wrap_review(review)(dict(ctx), config)
        prior.line = 1
        replacement = orch.ReviewOutcome(file="unit.c", function="f", line=1,
            status="clean", body="Separately owned canonical replacement")
        result = orch.OrchestratorResult()
        orch._tally_outcome(result, prior)
        ctx["mechanical_evidence"] = "Joern CPG: owned parameter value reaches owned_sink()"
        gap = {"file": "unit.c", "name": "f", "line_start": 1, "line_end": 1}
        def run():
            return private._re_review_joern_enriched(result, config, review,
                checklist={"files": []}, context_map=None, fuzz_coverage=None,
                evidence_index={"unit.c:f": SimpleNamespace(all_joern_flows=lambda: ["owned saved flow"])},
                sarif_cache=None, entry_points=set(), gaps_before_joern=[gap],
                start_time=monotonic(), on_progress=None, knowledge_runtime=runtime)

        with isolated_audit_shutdown(private):
            if change in {"cancel_before", "cancel_after"}:
                with pytest.raises(KeyboardInterrupt, match="owned cancellation"):
                    run()
            else:
                run()
        assert len(calls) == 2 and "owned_sink" in calls[-1]
        assert len(proposed) == 1
        assert len(acknowledgements) == (0 if change == "write_refused" else 1)
        assert [entry.verdict for entry in load_entries(out, fresh=True)] == (
            [] if change == "write_refused" else ["suspicious"])
        assert result.total_cost_usd == pytest.approx(.25)
        if change in {"none", "cancel_after"}:
            assert proposed[0].review_input_scope.current(target)
            assert result.outcomes == proposed
            assert result.clean == 0 and result.suspicious == 1
            assert any(row.get("action") == "orchestrator_review" for row in load_audit_log(out))
        else:
            if change in {"revision", "rewrite_restore"}:
                assert not proposed[0].review_input_scope.current(target)
            assert result.outcomes == ([replacement] if change == "prior_replaced" else [prior])
            assert result.clean == 1 and result.suspicious == 0
            assert not any(row.get("action") == "orchestrator_review" for row in load_audit_log(out))
            assert not any(event["event"] == "continuation_completed" for event in runtime.events())
        terminal = [event for event in runtime.events()
                    if event["event"] in {"continuation_completed", "continuation_failed"}]
        assert len(terminal) == 1
    finally:
        runtime.close("owned_test_complete")
