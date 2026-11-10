"""Study context does not grant authority to withdraw prior claims."""

from time import monotonic

import pytest

from core.audit import orchestrator as orch
from core.audit.record import load_audit_log, load_verified_audit_log
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ClaimRefutation, ProbeOutcome
from core.testing.audit_shutdown import isolated_audit_shutdown
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def _owned_review_caches():
    from collections import OrderedDict

    with isolated_module_state(orch, {
        "_sink_guard_cache": {}, "_parse_wrapper_cache": {},
        "_line_end_cache": {}, "_file_lines_cache": OrderedDict(),
        "_file_lines_cache_bytes": 0,
    }, lock=orch._file_lines_cache_lock):
        yield


@pytest.fixture
def study_case(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "owned.c").write_text("unsigned f(unsigned n) { return n + 1; }\n")
    out = tmp_path / "out"
    out.mkdir()
    config = orch.OrchestratorConfig(target_path=target, out_dir=out,
        sweep_validate_findings=False, enable_session_context=False,
        joern_overrides={"enabled": False})
    hypotheses = [{"mechanism": "length overflows before validation", "confidence": "high"},
                  {"mechanism": "narrowed length controls a later copy", "confidence": "high"}]
    prior = orch.ReviewOutcome("owned.c", "f", "suspicious", "Prior concerns",
        line=1, hypothesis=hypotheses[0]["mechanism"], hypotheses=hypotheses, cost_usd=0.5)
    result = orch.OrchestratorResult(outcomes=[prior], reviewed=1, suspicious=1, total_cost_usd=0.5)
    checklist = {"files": [{"path": "owned.c", "items": [{"name": "f", "line_start": 1, "line_end": 1}]}]}
    return {"config": config, "prior": prior, "result": result, "checklist": checklist, "calls": []}


def _candidate(**kwargs):
    return orch.ReviewOutcome("owned.c", "f", "clean", "The model now believes this is safe.",
                             cost_usd=0.2, review_result={"status": "clean"}, **kwargs)


def _reassess(case, candidate):
    def review(ctx, cfg):
        case["calls"].append(ctx)
        return candidate

    with isolated_audit_shutdown(orch):
        orch._re_review_study_enriched(case["result"], case["config"], review,
            case["checklist"], None, {}, None, set(), {"owned.c:f"}, monotonic(), None, max_workers=1)
    assert len(case["calls"]) == 1


def _refutations(case):
    identity = capture_source_identity(case["config"].target_path, "owned.c")
    # Model a pipeline checker's admitted results; this tests publication
    # scope, not the correctness or execution of a native checker.
    return tuple(ClaimRefutation("owned.c", "f", 1, h["mechanism"],
        (ProbeOutcome("joern", "refuted", "test-scoped-negative"),), identity)
        for h in case["prior"].hypotheses)


def _diagnostic(case):
    events = [e for e in load_audit_log(case["config"].out_dir) if e.get("action") == "study_reassessment"]
    assert len(events) == 1
    event = events[0]
    assert event in load_verified_audit_log(case["config"].out_dir)
    assert event["adjudication"] == "unverified" and event["prior_retained"]
    assert event["proposed_status"] == "clean"
    assert not orch.get_reviewed_set(case["config"].out_dir), "a diagnostic cannot suppress a future review"
    return event


def _retained(case):
    result = case["result"]
    assert result.outcomes == [case["prior"]] and result.outcomes[0] is case["prior"]
    assert result.clean == 0 and result.reviewed == 1
    assert result.total_cost_usd == 0.7


def test_model_clean_after_study_cannot_erase_prior_claims(study_case):
    case = study_case
    case["prior"].status = "finding"
    case["prior"].evidence_tool = "frida:runtime"
    case["result"].suspicious = 0
    case["result"].findings = 1
    _reassess(case, _candidate())
    _retained(case)
    assert case["result"].findings == 1
    event = _diagnostic(case)
    assert event["prior_status"] == "finding"
    assert event["prior_claims"] == [h["mechanism"] for h in case["prior"].hypotheses]


@pytest.mark.parametrize("fault", ["missing_secondary", "other_claim", "wrong_occurrence", "stale_source", "forged_dictionary"])
def test_partial_or_misbound_refutation_cannot_withdraw_prior(study_case, fault):
    from dataclasses import replace

    case = study_case
    receipts = _refutations(case)
    if fault == "missing_secondary":
        receipts = receipts[:1]
    elif fault == "other_claim":
        receipts = tuple(replace(r, hypothesis="unrelated concern") for r in receipts)
    elif fault == "wrong_occurrence":
        receipts = tuple(replace(r, line_start=2) for r in receipts)
    elif fault == "stale_source":
        path = case["config"].target_path / "owned.c"
        path.write_text(path.read_text() + "/* changed after checking */\n")
    else:
        receipts = tuple(r.to_record() for r in receipts)
    _reassess(case, _candidate(claim_refutations=receipts))
    _retained(case)
    assert case["result"].suspicious == 1
    assert _diagnostic(case)["reason"] == "prior_claims_lack_scoped_refutation"


def test_complete_current_refutations_can_withdraw_unconfirmed_concerns(study_case):
    case = study_case
    candidate = _candidate(claim_refutations=_refutations(case))
    _reassess(case, candidate)
    result = case["result"]
    assert result.outcomes == [candidate]
    assert result.clean == 1 and result.suspicious == 0 and result.reviewed == 1
    assert result.total_cost_usd == 0.7
    assert not [e for e in load_audit_log(case["config"].out_dir) if e.get("action") == "study_reassessment"]


def test_negative_checks_do_not_erase_conflicting_confirmation(study_case):
    case = study_case
    case["prior"].evidence_tool = "frida:runtime"
    _reassess(case, _candidate(claim_refutations=_refutations(case)))
    _retained(case)
    event = _diagnostic(case)
    assert event["reason"] == "conflicting_verification_evidence"
    assert len(event["claim_refutations"]) == 2
    assert event["prior_evidence_tool"] == "frida:runtime"


def test_assessment_write_failure_preserves_prior_and_spend(study_case, monkeypatch, caplog):
    def fail_write(*args, **kwargs):
        raise OSError("scripted assessment write failure")

    monkeypatch.setattr(orch, "append_audit_log", fail_write)
    _reassess(study_case, _candidate())
    _retained(study_case)
    assert "study reassessment event could not be written" in caplog.text


def _knowledge_reassess(case, candidate, *, during_review=None, verify=False, review_fn=None):
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime

    case["config"].immediate_verify = verify
    runtime = AuditKnowledgeRuntime(case["config"].target_path, orch.StudyQueue(),
                                    deadline=float("inf"), window=0)
    source = (case["config"].target_path / "owned.c").read_text().rstrip("\n")
    ctx = {"file": "owned.c", "function": "f", "line_start": 1,
           "source": source, "language": "c"}
    runtime._register(runtime._origin(ctx), ctx, {
        "language_reference_requests": [{"topic": "integer promotion"}]})
    reservation, = runtime.ready_continuations(admission=lambda: True)

    def review(context, config):
        if during_review is not None:
            during_review()
        return review_fn(context, config) if review_fn is not None else candidate

    if getattr(review_fn, "_knowledge_observed_client_contract", None) is True:
        setattr(review, "_knowledge_observed_client_contract", True)
    with isolated_audit_shutdown(orch):
        orch._re_review_study_enriched(case["result"], case["config"], review,
            case["checklist"], None, {}, None, set(), {("owned.c", "f", 1)}, monotonic(), None,
            max_workers=1, knowledge_runtime=runtime, knowledge_reservation=reservation)
    return runtime


def test_same_status_study_retains_new_independent_hypotheses(study_case):
    case = study_case
    case["config"].immediate_verify = False  # isolate publication, not checker correctness
    mechanism = "a distinct ownership transition leaves a stale reference"
    fresh = orch.ReviewOutcome("owned.c", "f", "suspicious", "New concern after learning",
        line=1, hypothesis=mechanism, cost_usd=0.2,
        hypotheses=[{"mechanism": mechanism, "confidence": "medium", "cwe": "CWE-416"}],
        review_result={"status": "suspicious", "hypothesis": mechanism, "cwe": "CWE-416"})
    _knowledge_reassess(case, fresh)
    canonical = case["result"].outcomes[0]
    assert mechanism in {h["mechanism"] for h in canonical.hypotheses}
    assert canonical.hypothesis == "length overflows before validation"
    assert canonical.body == "Prior concerns" and not canonical.evidence_tool
    assert case["result"].reviewed == case["result"].suspicious == 1
    assert case["result"].total_cost_usd == 0.7


def _new_suspicion():
    mechanism = "new independent candidate"
    return orch.ReviewOutcome("owned.c", "f", "suspicious", "New assessment",
        line=1, hypothesis=mechanism, cost_usd=0.2,
        hypotheses=[{"mechanism": mechanism, "confidence": "medium"}],
        review_result={"hypothesis": mechanism, "cwe": "CWE-416"})


def test_same_status_candidates_survive_journal_and_next_context(study_case):
    from core.coverage.journal import load_entries

    case = study_case
    fresh = _new_suspicion()
    _knowledge_reassess(case, fresh)
    canonical = case["result"].outcomes[0]
    entries = load_entries(case["config"].out_dir, fresh=True)
    assert entries[-1].hypotheses == canonical.hypotheses
    assert entries[-1].cost_usd == canonical.cost_usd == 0.7
    assert canonical.review_result["hypotheses"] == canonical.hypotheses
    assert fresh.hypothesis in {h["mechanism"] for h in orch._prior_hypotheses_for(canonical)}
    assert canonical.hypotheses[-1]["confidence"] == "medium"
    _knowledge_reassess(case, _new_suspicion())
    assert len(load_entries(case["config"].out_dir, fresh=True)) == len(entries)
    assert len(case["result"].outcomes[0].hypotheses) == 3
    assert case["result"].reviewed == case["result"].suspicious == 1
    assert case["result"].total_cost_usd == pytest.approx(0.9)


def test_same_status_copy_preserves_prior_and_excludes_fresh_proof_fields(study_case):
    from copy import deepcopy

    case = study_case
    case["prior"].review_result = {"study_receipts": [{"locations": ["prior-only"]}]}
    case["prior"].tools_dispatched = {"semgrep"}
    case["prior"].tools_inconclusive = {"semgrep"}
    before = deepcopy(case["prior"].hypotheses)
    fresh = _new_suspicion()
    case["prior"].tokens_in = 10
    fresh.tokens_in = 5
    fresh.review_result["immediate_verified"] = True
    fresh.hypotheses[0]["evidence_tool"] = "smt:unrelated"
    fresh.hypotheses[0]["claim_refutations"] = ["forged"]
    _knowledge_reassess(case, fresh)
    canonical = case["result"].outcomes[0]
    assert canonical is not case["prior"]
    assert canonical.tokens_in == 15 and case["prior"].tokens_in == 10
    assert case["prior"].hypotheses == before
    assert canonical.hypotheses[:2] == before
    assert canonical.tools_dispatched == canonical.tools_inconclusive == {"semgrep"}
    assert not canonical.evidence_tool and not canonical.claim_refutations
    assert "immediate_verified" not in canonical.review_result
    assert set(canonical.hypotheses[-1]) == {"mechanism", "cwe", "confidence"}
    fresh.hypotheses[0]["mechanism"] = "mutated"
    case["prior"].review_result["study_receipts"][0]["locations"].append("mutated")
    assert canonical.hypotheses[-1]["mechanism"] == "new independent candidate"
    assert canonical.review_result["study_receipts"][0]["locations"] == ["prior-only"]


@pytest.mark.parametrize("fault", ["prior_verified", "fresh_verified", "wrong_occurrence", "source_changed"])
def test_same_status_unsafe_candidate_merge_is_refused(study_case, monkeypatch, fault):
    case = study_case
    fresh = _new_suspicion()
    callback = None
    if fault == "prior_verified":
        case["prior"].evidence_tool = "frida:runtime"
    elif fault in ("fresh_verified", "wrong_occurrence"):
        # Inject at the checker-result boundary, after model sanitisation
        # and pipeline-owned line stamping; no native checker is exercised.
        def checker_result(outcome, *args, **kwargs):
            if fault == "fresh_verified":
                outcome.evidence_tool = "frida:runtime"
            else:
                outcome.line = 2
            return outcome
        monkeypatch.setattr(orch, "_verify_hypotheses_immediate", checker_result)
    else:
        path = case["config"].target_path / "owned.c"
        callback = lambda: path.write_text(path.read_text() + "/* changed */\n")
    _knowledge_reassess(case, fresh, during_review=callback,
                        verify=fault in ("fresh_verified", "wrong_occurrence"))
    _retained(case)
    assert case["result"].suspicious == 1


def test_same_status_failed_journal_does_not_publish_candidates(study_case, monkeypatch):
    case = study_case

    def refuse(*args, **kwargs):
        raise OSError("scripted candidate journal failure")

    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", refuse)
    runtime = _knowledge_reassess(case, _new_suspicion())
    _retained(case)
    assert any(e.get("reason") == "candidate_journal_write_failed" for e in runtime.events())


def test_same_status_requires_actual_journal_acknowledgement(study_case, monkeypatch):
    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", lambda **kwargs: None)
    runtime = _knowledge_reassess(study_case, _new_suspicion())
    _retained(study_case)
    assert any(e.get("reason") == "candidate_journal_write_failed" for e in runtime.events())


def test_same_status_changed_canonical_is_not_written(study_case, monkeypatch):
    from dataclasses import replace

    case = study_case
    newer = replace(case["prior"], body="Another pipeline update")
    calls = []
    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", lambda **kwargs: calls.append(kwargs))
    runtime = _knowledge_reassess(case, _new_suspicion(),
        during_review=lambda: case["result"].outcomes.__setitem__(0, newer))
    assert case["result"].outcomes == [newer] and not calls
    assert any(e.get("reason") == "canonical_outcome_changed" for e in runtime.events())
    assert case["result"].total_cost_usd == 0.7


def test_same_status_journal_writer_holds_canonical_ownership(study_case, monkeypatch):
    from core.audit.collector import append_journal_for_outcome

    def owned_write(**kwargs):
        assert not study_case["result"]._lock.acquire(blocking=False)
        assert kwargs["verification_scope"].source_identity is not None
        return append_journal_for_outcome(**kwargs)

    merge = orch._merge_unverified_study_candidates

    def owned_merge(*args):
        assert not study_case["result"]._lock.acquire(blocking=False)
        return merge(*args)

    monkeypatch.setattr(orch, "_merge_unverified_study_candidates", owned_merge)
    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", owned_write)
    _knowledge_reassess(study_case, _new_suspicion())
    assert study_case["result"].outcomes[0] is not study_case["prior"]


def test_same_status_finalized_run_refuses_candidate_publication(study_case, monkeypatch):
    calls = []
    monkeypatch.setattr("core.audit.collector.append_journal_for_outcome", lambda **kwargs: calls.append(kwargs))
    runtime = _knowledge_reassess(study_case, _new_suspicion(),
        during_review=lambda: setattr(study_case["config"], "_verdicts_finalized", True))
    _retained(study_case)
    assert not calls
    assert any(e.get("reason") == "verdicts_finalized" for e in runtime.events())


@pytest.mark.parametrize("multi_model,passes,expected", [(False, 1, 0), (True, 1, 1), (False, 2, 1)])
def test_study_preserves_requested_review_mode(study_case, monkeypatch, multi_model, passes, expected):
    case = study_case
    case["config"].models = ["first", "second"]
    case["config"].multi_model = multi_model
    case["config"].review_passes = passes
    dispatched = []

    def panel_dispatch(review, context, config, count, **kwargs):
        # Test the dispatch decision, not provider or panel execution.
        dispatched.append(count)
        return review(context, config)

    monkeypatch.setattr(orch, "_multi_pass_review", panel_dispatch)
    _knowledge_reassess(case, _new_suspicion())
    assert len(dispatched) == expected
    assert not dispatched or dispatched == [passes]


def test_status_change_requires_journal_acknowledgement(study_case, monkeypatch):
    from core.audit import collector

    case = study_case
    case["config"].immediate_verify = False
    case["prior"].status = "clean"
    case["result"].clean, case["result"].suspicious = 1, 0
    monkeypatch.setattr(collector, "append_journal_for_outcome", lambda **kwargs: None)
    runtime = _knowledge_reassess(case, _new_suspicion())
    assert case["result"].outcomes == [case["prior"]]
    assert case["result"].outcomes[0] is case["prior"]
    assert case["result"].clean == 1 and case["result"].suspicious == 0
    assert case["result"].total_cost_usd == 0.7
    assert not orch.get_reviewed_set(case["config"].out_dir)
    assert any(e.get("reason") == "study_journal_write_failed" for e in runtime.events())


def _clean_prior(case):
    case["config"].immediate_verify = False
    case["prior"].status = "clean"
    case["result"].clean, case["result"].suspicious = 1, 0


def test_status_change_publication_keeps_journal_and_counters_together(study_case):
    from core.coverage.journal import load_entries

    case = study_case
    _clean_prior(case)
    fresh = _new_suspicion()
    runtime = _knowledge_reassess(case, fresh)
    assert case["result"].outcomes == [fresh]
    assert case["result"].clean == 0 and case["result"].suspicious == 1
    assert case["result"].reviewed == 1 and case["result"].total_cost_usd == 0.7
    entry, = load_entries(case["config"].out_dir, fresh=True)
    assert entry.verdict == "suspicious" and entry.hypotheses[0]["mechanism"] == fresh.hypothesis
    assert any(e.get("published_status") == "suspicious" for e in runtime.events())


@pytest.mark.parametrize("fault", ["canonical_replaced", "finalized", "source_during_hash", "wrong_ack", "exception"])
def test_status_change_publication_refuses_unowned_or_unacknowledged_updates(study_case, monkeypatch, fault):
    from core.audit import collector, record
    from core.coverage.journal import load_entries

    case = study_case
    _clean_prior(case)
    fresh = _new_suspicion()
    callback = None
    replacement = _new_suspicion()
    if fault == "canonical_replaced":
        callback = lambda: case["result"].outcomes.__setitem__(0, replacement)
    elif fault == "finalized":
        callback = lambda: setattr(case["config"], "_verdicts_finalized", True)
    elif fault == "source_during_hash":
        original = record._compute_hash
        def changed(*args, **kwargs):
            path = case["config"].target_path / "owned.c"
            path.write_text(path.read_text() + "/* changed */\n")
            return original(*args, **kwargs)
        monkeypatch.setattr(record, "_compute_hash", changed)
    elif fault == "wrong_ack":
        from types import SimpleNamespace
        monkeypatch.setattr(collector, "append_journal_for_outcome", lambda **kwargs: SimpleNamespace(
            file="owned.c", function="f", line_start=1, verdict="suspicious"))
    else:
        def fail(**kwargs):
            raise OSError("owned append failure")
        monkeypatch.setattr(collector, "append_journal_for_outcome", fail)
    runtime = _knowledge_reassess(case, fresh, during_review=callback)
    expected = replacement if fault == "canonical_replaced" else case["prior"]
    assert case["result"].outcomes[0] is expected
    assert case["result"].clean == 1 and case["result"].suspicious == 0
    assert case["result"].total_cost_usd == 0.7
    assert not load_entries(case["config"].out_dir, fresh=True)
    assert not any(e.get("published_status") == "suspicious" for e in runtime.events())


def test_status_change_publication_holds_canonical_lock_until_ack(study_case, monkeypatch):
    from threading import Thread
    from core.audit import collector

    case = study_case
    _clean_prior(case)
    original = collector.append_journal_for_outcome
    ownership = []
    def append(**kwargs):
        def probe():
            acquired = case["result"]._lock.acquire(blocking=False)
            ownership.append(acquired)
            if acquired:
                case["result"]._lock.release()
        thread = Thread(target=probe)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        return original(**kwargs)
    monkeypatch.setattr(collector, "append_journal_for_outcome", append)
    _knowledge_reassess(case, _new_suspicion())
    assert ownership == [False]


def test_status_change_cancellation_retains_prior_and_books_completed_call(study_case, monkeypatch):
    from core.audit import collector

    case = study_case
    _clean_prior(case)
    def cancel(**kwargs):
        raise KeyboardInterrupt("owned cancellation")
    monkeypatch.setattr(collector, "append_journal_for_outcome", cancel)
    with pytest.raises(KeyboardInterrupt, match="owned cancellation"):
        _knowledge_reassess(case, _new_suspicion())
    assert case["result"].outcomes[0] is case["prior"]
    assert case["result"].clean == 1 and case["result"].suspicious == 0
    assert case["result"].total_cost_usd == 0.7


def test_status_change_source_drift_after_append_cannot_replace_canonical(study_case, monkeypatch):
    from core.audit import collector
    from core.coverage.journal import load_entries

    case = study_case
    _clean_prior(case)
    original = collector.append_journal_for_outcome
    def append_then_change(**kwargs):
        acknowledgement = original(**kwargs)
        assert acknowledgement is not None
        path = case["config"].target_path / "owned.c"
        path.write_text(path.read_text() + "/* changed after append */\n")
        return acknowledgement
    monkeypatch.setattr(collector, "append_journal_for_outcome", append_then_change)
    runtime = _knowledge_reassess(case, _new_suspicion())
    assert case["result"].outcomes[0] is case["prior"]
    assert case["result"].clean == 1 and case["result"].suspicious == 0
    assert case["result"].total_cost_usd == 0.7
    # The acknowledged row remains historical and source-bound, not rolled back.
    assert len(load_entries(case["config"].out_dir, fresh=True)) == 1
    assert any(e.get("reason") == "source_changed" for e in runtime.events())


@pytest.mark.parametrize("stage", ["untally", "tally"])
@pytest.mark.parametrize("prior_state", ["clean", "error", "reused"])
def test_status_change_retally_cancellation_rolls_back_without_double_spend(study_case, monkeypatch, stage, prior_state):
    case = study_case
    _clean_prior(case)
    if prior_state == "error":
        case["prior"].status, case["prior"].error_class = "error", "api_error"
        case["result"].clean, case["result"].errors = 0, 1
        case["result"].error_counts = {"api_error": 1}
    elif prior_state == "reused":
        case["prior"].reused = True
        case["result"].reviewed, case["result"].reused_from_prior = 0, 1
    expected = (case["result"].clean, case["result"].errors, dict(case["result"].error_counts),
                case["result"].reviewed, case["result"].reused_from_prior)
    name = "_untally_outcome_unlocked" if stage == "untally" else "_tally_outcome_unlocked"
    original = getattr(orch, name)
    def interrupt(*args, **kwargs):
        original(*args, **kwargs)
        raise KeyboardInterrupt("owned retally cancellation")
    monkeypatch.setattr(orch, name, interrupt)
    with pytest.raises(KeyboardInterrupt, match="owned retally cancellation"):
        _knowledge_reassess(case, _new_suspicion())
    assert case["result"].outcomes[0] is case["prior"]
    assert case["result"].suspicious == 0
    assert (case["result"].clean, case["result"].errors, case["result"].error_counts,
            case["result"].reviewed, case["result"].reused_from_prior) == expected
    assert case["result"].total_cost_usd == 0.7


def test_status_change_cancel_after_commit_keeps_one_spend_and_committed_state(study_case, monkeypatch):
    case = study_case
    _clean_prior(case)
    candidate = _new_suspicion()
    original = orch._publish_study_outcome
    def commit_then_cancel(*args, **kwargs):
        assert original(*args, **kwargs) == "published"
        raise KeyboardInterrupt("owned post-commit cancellation")
    monkeypatch.setattr(orch, "_publish_study_outcome", commit_then_cancel)
    with pytest.raises(KeyboardInterrupt, match="owned post-commit cancellation"):
        _knowledge_reassess(case, candidate)
    assert case["result"].outcomes[0] is candidate
    assert case["result"].clean == 0 and case["result"].suspicious == 1
    assert case["result"].reviewed == 1 and case["result"].total_cost_usd == 0.7


@pytest.mark.parametrize("fault", ["none", "journal_unacknowledged", "history_ack_stripped", "source_changed", "wrong_id", "mechanical_support", "unknown_caller", "validation_cancelled"])
def test_explicit_source_grounded_model_withdrawal_uses_owned_journal_publication(study_case, monkeypatch, fault):
    import re
    from dataclasses import replace

    from core.audit import collector
    from core.audit.claims import ClaimRevision
    from core.audit.knowledge_runtime import AuditKnowledgeRuntime
    from core.audit.llm_review import make_review_fn
    from core.audit.review_claims import begin_review, record_intake
    from core.coverage.journal import load_entries
    from core.llm.providers import StructuredResponse

    case = study_case
    prior, config = case["prior"], case["config"]
    prior.hypothesis = "a negative signed n reaches this return"
    prior.hypotheses = None
    prior.review_result = {"cwe": "CWE-195"}
    source = (config.target_path / "owned.c").read_text()
    ctx = {"file": "owned.c", "function": "f", "line_start": 1, "source": source}
    origin = AuditKnowledgeRuntime(config.target_path, orch.StudyQueue(), deadline=float("inf"))._origin(ctx)
    revisions = [ClaimRevision(h, pass_id="owned-intake", file="owned.c", function="f", line_start=1)
                 for h in orch._extract_all_hypotheses(prior)]
    prior.review_result["review_claims"] = record_intake(begin_review(origin, "first-review"), revisions)
    reference = revisions[0].reference()
    monkeypatch.setattr("core.audit.llm_review._prompt_budget", lambda *_: 100000)
    calls = []
    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            assert "claim_withdrawals" in schema["properties"]
            assert reference["revision_id"] in prompt
            fragment_id = re.search(r"Source fragment:\*\* ([a-f0-9]{32})", prompt)[1]
            if fault == "source_changed":
                path = config.target_path / "owned.c"
                path.write_text(source + "/* edited during review */\n")
            return StructuredResponse(result={"status": "clean", "body": "The prior signedness premise was mistaken.",
                "hypothesis": "", "claim_withdrawals": [{"claim_id": reference["claim_id"],
                    "revision_id": "a" * 32 if fault == "wrong_id" else reference["revision_id"],
                    "corrected_premise": "The declaration gives n an unsigned type.",
                    "reason": "The negative signed input theory does not describe this declaration.",
                    "source_anchors": [{"fragment_id": fragment_id, "line_start": 1, "line_end": 1}],
                    "remaining_unknowns": ["caller contract"] if fault == "unknown_caller" else []}]},
                raw="", cost=0.2, model="scripted")
    if fault == "journal_unacknowledged":
        monkeypatch.setattr(collector, "append_journal_for_outcome", lambda **_: None)
    elif fault == "history_ack_stripped":
        original = collector.append_journal_for_outcome
        def stripped(**kwargs):
            actual = original(**kwargs)
            assert actual is not None and actual.review_claims
            return replace(actual, review_claims=None)
        monkeypatch.setattr(collector, "append_journal_for_outcome", stripped)
    elif fault == "mechanical_support":
        prior.evidence_tool = "frida:runtime"
    if fault == "validation_cancelled":
        def cancel_validation(*args):
            raise KeyboardInterrupt("cancelled during local judgment validation")
        monkeypatch.setattr(orch, "_model_withdrawal_assessment", cancel_validation)
        with pytest.raises(KeyboardInterrupt, match="local judgment validation"):
            _knowledge_reassess(case, None, review_fn=make_review_fn(Client(), escalate_clean=False))
        assert len(calls) == 1
        assert case["result"].total_cost_usd == 0.7
        assert case["result"].outcomes[0] is prior and case["result"].suspicious == 1
        assert load_entries(config.out_dir, fresh=True) == []
        return
    runtime = _knowledge_reassess(case, None, review_fn=make_review_fn(Client(), escalate_clean=False))
    assert len(calls) == 1
    result = case["result"]
    assert result.total_cost_usd == 0.7 and result.reviewed == 1
    if fault == "none":
        assert result.clean == 1 and result.suspicious == 0
        assert result.outcomes[0].status == "clean" and result.outcomes[0] is not prior
        assert not result.outcomes[0].claim_refutations and not result.outcomes[0].evidence_tool
        entry, = load_entries(config.out_dir, fresh=True)
        assert entry.review_claims["assessment_basis"] == "model_judgment_withdrawal"
        assert entry.review_claims["withdrawal_decisions"]["accepted"][0]["adjudication"] == "model_withdrawn"
        assert entry.evidence_tools == []
        assert any(e.get("published_status") == "clean" for e in runtime.events())
    else:
        assert result.outcomes[0] is prior and result.clean == 0 and result.suspicious == 1
        if fault == "history_ack_stripped":
            # Actual row remains historical when its acknowledgement fails.
            entry, = load_entries(config.out_dir, fresh=True)
            assert entry.review_claims["withdrawal_decisions"]
            assert any(e.get("reason") == "study_history_ack_mismatch" for e in runtime.events())
        else:
            assert load_entries(config.out_dir, fresh=True) == []


def test_label_only_negative_cannot_withdraw_distinct_prior_assumptions(study_case):
    case = study_case
    primary = case['prior'].hypothesis
    case['prior'].hypotheses = [
        {'mechanism': primary, 'confidence': 'high', 'counter_scope': 'local',
         'assumed_property': 'local declaration'},
        {'mechanism': primary, 'confidence': 'high', 'counter_scope': 'cross_function',
         'assumed_property': 'caller declaration'},
    ]
    candidate = _candidate()
    candidate.claim_refutations = _refutations(case)[:1]
    _reassess(case, candidate)
    _retained(case)
    _diagnostic(case)
