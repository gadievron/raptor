"""Immediate verification cannot manufacture evidence from missing checks."""

import pytest

from core.audit import orchestrator as orch
from core.audit.verification_results import ToolChainResult


def run_case(tmp_path, monkeypatch, *, status, state):
    (tmp_path / "out").mkdir(exist_ok=True)
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.immediate_verify = True
    outcome = orch.ReviewOutcome(
        file="record.c", function="Read", status=status, body="review completed",
        hypothesis="integer overflow in conversion",
        review_result={"hypothesis": "integer overflow in conversion", "cwe": "CWE-190"},
    )
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: (
        [] if state == "no-checker" else [{"type": "smt", "config": {}}]
    ))

    def run_chain(chain, **kwargs):
        slot = {"skipped": "skipped_types", "error": "errored_types",
                "inconclusive": "inconclusive_types"}.get(state)
        if slot:
            kwargs[slot].add("smt")
        if state == "negative":
            result = ToolChainResult(file=kwargs["file_path"], function=kwargs["function_name"],
                                     line_start=kwargs["line_start"], hypothesis=kwargs["hypothesis"])
            result.observe("smt", "refuted", "check-overflow", "overflow condition is unsatisfiable")
            return result
        return []

    monkeypatch.setattr(orch, "_run_tool_chain", run_chain)
    result = orch.OrchestratorResult()
    return orch._verify_hypotheses_immediate(outcome, config, result)


@pytest.mark.parametrize("status", ["clean", "suspicious", "finding"])
@pytest.mark.parametrize("state", ["no-checker", "skipped", "error", "inconclusive", "legacy-empty"])
def test_unknown_result_preserves_review_and_does_not_claim_verification(
    tmp_path, monkeypatch, status, state,
):
    outcome = run_case(tmp_path, monkeypatch, status=status, state=state)
    assert outcome.status == status
    assert not outcome.review_result.get("immediate_verified")
    assert not outcome.review_result.get("ihv_all_refuted")
    if state == "skipped":
        assert "smt" not in (outcome.tools_dispatched or set())
        assert outcome.tools_skipped == {"smt"}


@pytest.mark.parametrize("status", ["clean", "suspicious", "finding"])
def test_completed_negative_check_still_resolves_clean(tmp_path, monkeypatch, status):
    outcome = run_case(tmp_path, monkeypatch, status=status, state="negative")
    assert outcome.status == "clean"
    assert outcome.review_result["immediate_verified"] is True
    assert outcome.review_result["ihv_all_refuted"] is True
    from core.audit.record import load_audit_log

    records = [r for r in load_audit_log(tmp_path / "out") if r["action"] == "ihv_refutation"]
    assert len(records) == 1
    assert records[0]["hypothesis"] == outcome.hypothesis
    assert records[0]["checks"][0]["rule_id"] == "check-overflow"
    assert records[0]["checks"][0]["verdict"] == "refuted"


def test_failed_refutation_write_cannot_mark_a_claim_verified(tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("refutation output unavailable")

    monkeypatch.setattr(orch, "append_audit_log", fail)
    outcome = run_case(tmp_path, monkeypatch, status="suspicious", state="negative")
    assert outcome.status == "suspicious"
    assert not outcome.review_result.get("immediate_verified")
