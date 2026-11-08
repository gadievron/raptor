"""Immediate synthesis must retain the reviewed source binding."""

import pytest

from core.audit import checker_synthesis, cwe_dispatch
from core.audit import orchestrator as orch
from core.audit.findings_export import export_findings, write_graded_findings
from core.json import load_json


SOURCE = "int f(int n) { return n; }"
RECEIPT = "semgrep:synth-other.c.g.CWE-252.0"


def test_stale_review_input_does_not_dispatch_immediate_synthesis(tmp_path, monkeypatch):
    (tmp_path / "a.c").write_text(SOURCE.replace("return n;", "return n + 0;"), encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir, immediate_verify=True)
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error",
        review_result={"hypothesis": "discarded error", "cwe": "CWE-252"})
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [])
    calls = []

    def produce(*args, **kwargs):
        calls.append(kwargs["source_snippet"])
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    counts = orch.OrchestratorResult()
    final = orch._verify_hypotheses_immediate(outcome, config, counts, source=SOURCE,
        synthesis_counter=orch.AtomicSynthesisCounter(cap=1))
    assert calls == []
    assert final.status == "suspicious"
    assert not final.review_result.get("immediate_verified")
    assert counts.ondemand_synthesized == 0
    checks = _checks(final, out_dir)
    rejection = next(c for c in checks if c["rule_id"] == "source-input-unbound")
    assert rejection["outcome"] == "inconclusive"
    assert rejection["scope"]["source_identity"] is None
    assert rejection["result"]["data"]["details"]["checker_execution"] == "not_run"


def _checks(outcome, out_dir):
    write_graded_findings(export_findings([outcome]), out_dir)
    return load_json(out_dir / "verification-checks.json")["checks"]


@pytest.mark.parametrize("route", ["fallback", "not_dominated"])
@pytest.mark.parametrize("change", ["none", "edit", "delete", "restore", "context_edit"])
def test_synthesis_binding_survives_until_claim_admission(tmp_path, monkeypatch, route, change):
    path = tmp_path / "a.c"
    path.write_text(SOURCE, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir, immediate_verify=True)
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error",
        review_result={"hypothesis": "discarded error", "cwe": "CWE-252"})
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: object() if route == "not_dominated" else None)
    monkeypatch.setattr(cwe_dispatch, "route_hypothesis_to_checkers", lambda *a, **kw:
                        cwe_dispatch.RoutingResult(False, "", "owned routing control"))
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw: [])
    calls = []

    def produce(candidate, cfg, **kwargs):
        calls.append(kwargs["source_snippet"])
        if change in {"edit", "restore"}:
            path.write_text(SOURCE + "\n// changed", encoding="utf-8")
        elif change == "delete":
            path.unlink()
        if change == "restore":
            path.write_text(SOURCE, encoding="utf-8")
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    def context_gate(*args, **kwargs):
        if change == "context_edit":
            path.write_text(SOURCE + "\n// changed during context validation", encoding="utf-8")
        return None

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    monkeypatch.setattr(orch, "_ihv_context_gate", context_gate)
    counts = orch.OrchestratorResult()
    counter = orch.AtomicSynthesisCounter(cap=1)
    final = orch._verify_hypotheses_immediate(outcome, config, counts, source=SOURCE,
                                             synthesis_counter=counter)
    assert calls == [SOURCE]
    assert counts.ondemand_synthesized == counter.count == 1
    assert counts.total_cost_usd == pytest.approx(0.01)
    assert final.review_result["ihv_tools"] == [RECEIPT]
    if change == "none":
        assert final.status == "finding"
        assert final.review_result["immediate_verified"]
        assert final.evidence_tool == RECEIPT
    else:
        assert final.status == "suspicious"
        assert not final.review_result.get("immediate_verified")
        assert final.review_result["ihv_gate_blocked"] == "source-version-drift"
        checks = _checks(final, out_dir)
        withdrawal = next(c for c in checks if c["rule_id"] == "source-version-drift")
        assert withdrawal["outcome"] == "inconclusive"
        assert withdrawal["scope"]["source_identity"] is not None
        assert withdrawal["result"]["data"]["details"]["prior_receipts"] == [RECEIPT]


@pytest.mark.parametrize("binary", [False, True])
def test_unavailable_synthesis_identity_is_not_certified(tmp_path, monkeypatch, binary):
    file = "binary:demo" if binary else "missing.c"
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    outcome = orch.ReviewOutcome(file=file, function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error", review_result={})
    calls = []

    def produce(candidate, cfg, **kwargs):
        calls.append(kwargs["source_snippet"])
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    verification = orch._try_bound_ihv_synthesis(outcome, config, orch.OrchestratorResult(),
        {"mechanism": outcome.hypothesis}, "CWE-252", SOURCE, orch.AtomicSynthesisCounter(cap=1))
    assert calls == [SOURCE]
    assert verification.receipts == (RECEIPT,)
    assert verification.binding.source_identity is None
    assert verification.binding.scope == (file, "f", 1, outcome.hypothesis)


def test_fallback_excerpt_rejection_does_not_reserve_or_spend(tmp_path, monkeypatch):
    path = tmp_path / "a.c"
    path.write_text(SOURCE + "\n// another revision", encoding="utf-8")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error",
        review_result={"source_snippet": SOURCE.replace("return n;", "return 0;")})
    counts = orch.OrchestratorResult()
    counter = orch.AtomicSynthesisCounter(cap=1)
    calls = []

    def produce(*args, **kwargs):
        calls.append(kwargs["source_snippet"])
        return checker_synthesis.OnDemandSynthesisResult(confirmed=True, stamp=RECEIPT, cost_usd=0.01)

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", produce)
    args = (outcome, config, counts, {"mechanism": outcome.hypothesis}, "CWE-252")
    assert orch._try_bound_ihv_synthesis(*args, None, counter) is None
    assert calls == [] and counter.count == counts.ondemand_synthesized == 0
    assert counts.total_cost_usd == 0
    # The same allowance remains available when the reviewed input is bound.
    admitted = orch._try_bound_ihv_synthesis(*args, SOURCE, counter)
    assert admitted is not None and admitted.binding.source_identity is not None
    assert calls == [SOURCE]
    assert counter.count == counts.ondemand_synthesized == 1


def test_recording_failure_cannot_admit_stale_synthesis_input(tmp_path, monkeypatch):
    from core.audit import check_trace

    (tmp_path / "a.c").write_text(SOURCE, encoding="utf-8")
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error", review_result={})
    calls = []

    def failed_record(*args, **kwargs):
        calls.append("record")
        raise OSError("owned reporting failure")

    def unexpected_producer(*args, **kwargs):
        calls.append("producer")
        raise AssertionError("stale source dispatched")

    monkeypatch.setattr(check_trace, "record_source_input_rejection", failed_record)
    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", unexpected_producer)
    result = orch._try_bound_ihv_synthesis(outcome, config, orch.OrchestratorResult(),
        {"mechanism": outcome.hypothesis}, "CWE-252", "stale text", orch.AtomicSynthesisCounter(cap=1))
    assert result is None
    assert calls == ["record"]


@pytest.mark.parametrize("invalid", [7, False, {}, []])
@pytest.mark.parametrize("origin", ["direct", "fallback"])
def test_invalid_synthesis_source_is_refused_before_reservation(tmp_path, monkeypatch, invalid, origin):
    (tmp_path / "a.c").write_text(SOURCE, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir)
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Owned fixture", hypothesis="discarded error",
        review_result={"source_snippet": invalid} if origin == "fallback" else {})
    calls = []

    def unexpected_producer(*args, **kwargs):
        calls.append("producer")
        raise AssertionError("invalid input dispatched")

    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", unexpected_producer)
    counts = orch.OrchestratorResult()
    counter = orch.AtomicSynthesisCounter(cap=1)
    result = orch._try_bound_ihv_synthesis(outcome, config, counts,
        {"mechanism": outcome.hypothesis}, "CWE-252", invalid if origin == "direct" else None, counter)
    assert result is None and calls == []
    assert counter.count == counts.ondemand_synthesized == 0
    checks = _checks(outcome, out_dir)
    rejection = next(c for c in checks if c["rule_id"] == "claim-scope-rejected")
    assert rejection["outcome"] == "inconclusive"
    assert rejection["reason"] == "invalid-source-input"
