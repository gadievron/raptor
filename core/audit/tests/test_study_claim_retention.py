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
