"""Deepen uses existing claim withdrawal admission and durable publication."""

from dataclasses import replace
from functools import wraps
import re
from time import monotonic

import pytest

from core.audit import collector, orchestrator as orch
from core.audit.claims import ClaimRevision
from core.audit.journal import load_entries
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.review_claims import begin_review, record_intake
from core.llm.providers import StructuredResponse
from core.testing.audit_shutdown import isolated_audit_shutdown


@pytest.mark.parametrize("fault", ["none", "no_withdrawal", "wrong_id", "unknown_caller", "source_changed",
                                  "journal_unacknowledged", "history_ack_stripped", "mechanical_support",
                                  "scoped_refutation", "independent_concern", "pending_reference", "refutation_basis_cancelled",
                                  "validation_cancelled", "before_commit", "after_commit",
                                  "advisory_after_commit", "advisory_competing_writer"])
def test_deepen_claim_withdrawal_requires_current_identity_and_publication(tmp_path, monkeypatch, fault):
    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    out.mkdir()
    source = "unsigned f(unsigned n) {\n" + "    /* owned context */\n" * 24 + "    return n + 1;\n}\n"
    path = target / "unit.c"
    path.write_text(source)
    end = len(source.splitlines())
    checklist = {"files": [{"path": "unit.c", "items": [
        {"kind": "function", "name": "f", "line_start": 1, "line_end": end}]}]}
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, immediate_verify=False,
        sweep_validate_findings=False, enable_session_context=False, propagate_constraints=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True)
    prior = orch.ReviewOutcome(file="unit.c", function="f", line=1, status="suspicious",
        body="A negative signed n reaches this return", hypothesis="a negative signed n reaches this return",
        cost_usd=.5, review_result={"body": "Prior concern", "cwe": "CWE-195"})
    prior.context_reduced = fault == "no_withdrawal"
    runtime = AuditKnowledgeRuntime(target, orch.StudyQueue(), deadline=float("inf"), window=0)
    origin = runtime._origin({"file": "unit.c", "function": "f", "line_start": 1, "source": source})
    revision = ClaimRevision(orch._extract_all_hypotheses(prior)[0], pass_id=origin.pass_id,
                             file="unit.c", function="f", line_start=1)
    prior.review_result["review_claims"] = record_intake(begin_review(origin, "initial-review"), [revision])
    reference = revision.reference()
    result = orch.OrchestratorResult(outcomes=[prior], reviewed=1, suspicious=1, total_cost_usd=.5)
    calls = []
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            payload = {"status": "clean", "body": "The signedness premise was mistaken.", "hypothesis": ""}
            if fault not in {"no_withdrawal", "scoped_refutation", "independent_concern", "pending_reference", "refutation_basis_cancelled",
                              "advisory_after_commit", "advisory_competing_writer"}:
                assert "claim_withdrawals" in schema["properties"]
                assert reference["revision_id"] in prompt
                fragment = re.search(r"Source fragment:\*\* ([a-f0-9]{32})", prompt)[1]
                payload["claim_withdrawals"] = [{"claim_id": reference["claim_id"],
                    "revision_id": "a" * 32 if fault == "wrong_id" else reference["revision_id"],
                    "corrected_premise": "The declaration gives n an unsigned type.",
                    "reason": "The negative signed input theory does not describe this declaration.",
                    "source_anchors": [{"fragment_id": fragment, "line_start": 1, "line_end": 1}],
                    "remaining_unknowns": ["caller contract"] if fault == "unknown_caller" else []}]
            if fault in {"independent_concern", "advisory_after_commit", "advisory_competing_writer"}:
                payload["hypotheses"] = [{"mechanism": "n + 1 wraps before a later copy", "confidence": "high"}]
            if fault == "pending_reference":
                payload["language_reference_requests"] = [{"topic": "integer shifts", "entry_id": "c.integer-shift",
                    "needed_for": "Interpret a remaining condition", "priority": "normal"}]
            if fault == "source_changed":
                path.write_text(source + "/* changed during review */\n")
            return StructuredResponse(result=payload, raw="", cost=.2, model="captured")

    if fault == "mechanical_support":
        # Existing verification-role evidence floor, not a live tool proof.
        prior.evidence_tool = "frida:runtime"
    if fault == "journal_unacknowledged":
        monkeypatch.setattr(collector, "append_journal_for_outcome", lambda **_: None)
    elif fault == "history_ack_stripped":
        append = collector.append_journal_for_outcome

        def stripped(**kwargs):
            actual = append(**kwargs)
            assert actual is not None
            return replace(actual, review_claims=None)

        monkeypatch.setattr(collector, "append_journal_for_outcome", stripped)
    reviewer = make_review_fn(Client(), escalate_clean=False)
    if fault in {"scoped_refutation", "independent_concern", "pending_reference", "refutation_basis_cancelled",
                 "advisory_after_commit", "advisory_competing_writer"}:
        from core.audit.refutation_source import capture_source_identity
        from core.audit.verification_results import ClaimRefutation, ProbeOutcome
        render = reviewer

        @wraps(render)
        def with_scoped_receipt(ctx, cfg):
            fresh = render(ctx, cfg)
            fresh.line = ctx["line_start"]
            identity = capture_source_identity(target, "unit.c")
            # An admitted scoped-result fixture, not a claim that a
            # backend or solver executed in this publication test.
            fresh.claim_refutations = (ClaimRefutation("unit.c", "f", 1, prior.hypothesis,
                (ProbeOutcome("joern", "refuted", "test-scoped-negative"),), identity),)
            assert orch.claims_refuted(fresh, [prior.hypothesis], source_identity=identity, claim_outcome=prior)
            return fresh

        reviewer = with_scoped_receipt
    abort = KeyboardInterrupt(fault)
    competing = []
    if fault == "validation_cancelled":
        def cancel_validation(*args):
            raise abort
        monkeypatch.setattr(orch, "_model_withdrawal_assessment", cancel_validation)
    elif fault == "refutation_basis_cancelled":
        import core.audit.refutation_assessment_basis as basis_recorder
        def cancel_basis(*args, **kwargs):
            raise abort
        monkeypatch.setattr(basis_recorder, "record_refutation_basis", cancel_basis)
    elif fault == "before_commit":
        def cancel_append(**kwargs):
            raise abort
        monkeypatch.setattr(collector, "append_journal_for_outcome", cancel_append)
    elif fault == "after_commit":
        publish = orch._publish_study_outcome
        def cancel_after_publish(*args):
            assert publish(*args) == "published"
            raise abort
        monkeypatch.setattr(orch, "_publish_study_outcome", cancel_after_publish)
    elif fault in {"advisory_after_commit", "advisory_competing_writer"}:
        publish_advisory = orch._publish_study_candidates

        def cancel_after_advisory(*args, **kwargs):
            assert publish_advisory(*args, **kwargs) == "published"
            if fault == "advisory_competing_writer":
                with result._lock:
                    other = replace(prior, body="A competing canonical assessment")
                    result.outcomes[0] = other
                    competing.append(other)
            raise abort

        monkeypatch.setattr(orch, "_publish_study_candidates", cancel_after_advisory)

    def run():
        with isolated_audit_shutdown(orch):
            orch._deepen_suspicious(result, config, reviewer,
                checklist, None, None, [], None, set(), monotonic(), None, knowledge_runtime=runtime)

    try:
        if fault in {"validation_cancelled", "before_commit", "after_commit",
                     "advisory_after_commit", "advisory_competing_writer", "refutation_basis_cancelled"}:
            with pytest.raises(KeyboardInterrupt) as caught:
                run()
            assert caught.value is abort
        else:
            run()
        assert len(calls) == 1
        assert result.total_cost_usd == pytest.approx(.7) and result.reviewed == 1
        completed = [e for e in runtime.events() if e["event"] == "continuation_completed"]
        if fault in {"none", "scoped_refutation", "after_commit"}:
            assert result.clean == 1 and result.suspicious == 0
            assert result.outcomes[0].status == "clean" and result.outcomes[0] is not prior
            entry, = load_entries(out, fresh=True)
            if fault == "scoped_refutation":
                assert result.outcomes[0].clean_basis == "gate_resolved"
                assert len(result.outcomes[0].claim_refutations) == 1
                from core.audit.assessment_basis_reporting import journal_assessment_basis
                scoped_basis = journal_assessment_basis(entry, out)
                assert scoped_basis is not None
                assert scoped_basis["basis"] == "enumerated_claims_refuted"
                assert scoped_basis["scope"] == "historical_review_only"
                assert scoped_basis["refutations"]["hypotheses"] == [prior.hypothesis]
                assert scoped_basis["refutations"]["records"][0]["checks"][0]["verdict"] == "refuted"
            else:
                assert entry.review_claims["assessment_basis"] == "model_judgment_withdrawal"
                assert entry.review_claims["withdrawal_decisions"]["accepted"][0]["adjudication"] == "model_withdrawn"
                from core.audit.assessment_basis_reporting import journal_assessment_basis
                recorded_basis = journal_assessment_basis(entry, out)
                assert recorded_basis is not None
                assert recorded_basis["basis"] == "model_judgment_withdrawal"
                assert recorded_basis["scope"] == "historical_review_only"
            assert entry.evidence_tools == []
            assert len(completed) == 1 and completed[0]["published_status"] == "clean"
        else:
            current, = result.outcomes
            assert current.hypothesis == prior.hypothesis
            assert (current.status, result.suspicious, result.clean) == ("suspicious", 1, 0)
            assert not any(e["published_status"] == "clean" for e in completed)
            advisory = fault in {"no_withdrawal", "wrong_id", "unknown_caller", "mechanical_support",
                                 "independent_concern", "pending_reference", "advisory_after_commit", "advisory_competing_writer"}
            if advisory:
                entries = load_entries(out, fresh=True)
                assert len(entries) == 1, [(e["event"], e["reason"]) for e in runtime.events() if e.get("reason")]
                entry, = entries
                assert entry.verdict == "suspicious"
                if fault in {"independent_concern", "advisory_after_commit"}:
                    assert any(h["mechanism"] == "n + 1 wraps before a later copy" for h in current.hypotheses)
                if fault == "pending_reference":
                    assert any(r.subject == "integer shifts" for r in runtime.requests())
                if fault == "advisory_after_commit":
                    assert len(completed) == 1 and completed[0]["published_status"] == "suspicious"
                if fault == "advisory_competing_writer":
                    assert current is competing[0]
                    assert completed == []
                    failures = [e for e in runtime.events() if e["event"] == "continuation_failed"]
                    assert failures[-1]["reason"] == "deepen_advisory_publication_cancelled"
            else:
                assert current is prior
                if fault == "refutation_basis_cancelled":
                    failures = [e for e in runtime.events() if e["event"] == "continuation_failed"]
                    assert len(failures) == 1 and failures[0]["reason"] == "deepen_publication_incomplete"
                if fault != "history_ack_stripped":
                    assert load_entries(out, fresh=True) == []
    finally:
        runtime.close("test_complete")
