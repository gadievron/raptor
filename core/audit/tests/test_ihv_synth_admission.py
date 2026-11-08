"""Immediate synthesis receipts obey the existing outcome-specific policy."""

import pytest

from core.audit import orchestrator as orch
from core.audit.claim_verification import ClaimVerification
from core.audit.refutation_source import capture_source_identity
from core.audit.verification_results import ToolChainResult, VerificationScope
from core.json import save_json


SELF = "semgrep:synth-a.c.f.CWE-252.0"
VARIANT = "semgrep:synth-a.c.other.CWE-252.0"
INDEPENDENT = "semgrep:explicit-error-discard"
WEAK = "smt:check-early-release"


def _subject(tmp_path, *, cwe="CWE-252", boundary=False, trusted=False):
    source = "int f(void) { return 0; }\nint other(void) { return 0; }\n"
    (tmp_path / "a.c").write_text(source, encoding="utf-8")
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    if boundary:
        save_json(out_dir / "context-map.json", {"entry_points": [{"file": "a.c", "name": "f"}]})
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=out_dir, immediate_verify=True)
    outcome = orch.ReviewOutcome(file="a.c", function="f", line=1, status="suspicious",
        body="Unresolved concern", hypothesis="discarded error", provenance_all_trusted=trusted,
        review_result={"hypothesis": "discarded error", "cwe": cwe})
    return config, outcome, source


def _record(config, outcome, receipts, *, mechanism="discarded error", cwe="CWE-252"):
    return ClaimVerification({"mechanism": mechanism, "cwe": cwe}, receipts,
        binding=VerificationScope(outcome.file, outcome.function, outcome.line, mechanism,
                                  capture_source_identity(config.target_path, outcome.file)))


@pytest.mark.parametrize("receipts,cwe,boundary,trusted,expected", [
    ((SELF,), "CWE-252", False, False, ""),
    ((SELF, INDEPENDENT), "CWE-252", False, False, INDEPENDENT),
    ((INDEPENDENT, SELF), "CWE-252", False, False, INDEPENDENT),
    ((SELF + "+" + INDEPENDENT,), "CWE-252", False, False, INDEPENDENT),
    ((INDEPENDENT + "+" + SELF,), "CWE-252", False, False, INDEPENDENT),
    ((SELF, WEAK), "CWE-252", False, False, ""),
    ((SELF + "+llm-claimed:text+" + INDEPENDENT,), "CWE-252", False, False, ""),
    ((VARIANT,), "CWE-252", False, False, VARIANT),
    ((VARIANT,), "CWE-697", False, False, ""),
    ((VARIANT,), "CWE-697", True, False, VARIANT),
    ((VARIANT,), "CWE-697", True, True, ""),
    ((INDEPENDENT,), "CWE-697", False, True, INDEPENDENT),
])
def test_immediate_receipt_admission_preserves_independent_proof(
        tmp_path, receipts, cwe, boundary, trusted, expected):
    config, outcome, _ = _subject(tmp_path, cwe=cwe, boundary=boundary, trusted=trusted)
    record = _record(config, outcome, receipts, cwe=cwe)
    counts = orch.OrchestratorResult()
    final = orch._aggregate_ihv_verdicts(outcome, counts, [record.hypothesis], [record], config)
    assert final.status == ("finding" if expected else "suspicious")
    assert (final.evidence_tool or "") == expected
    assert bool(final.review_result.get("immediate_verified")) is bool(expected)
    assert counts.immediate_verified == int(bool(expected))
    assert final.review_result["ihv_tools"] == list(receipts)
    assert record.receipts == receipts


def test_excluded_primary_receipt_does_not_hide_supported_secondary_claim(tmp_path):
    config, outcome, _ = _subject(tmp_path)
    records = [_record(config, outcome, (SELF,)),
               _record(config, outcome, (INDEPENDENT,), mechanism="independent concern")]
    final = orch._aggregate_ihv_verdicts(outcome, orch.OrchestratorResult(),
                                      [r.hypothesis for r in records], records, config)
    assert final.status == "finding"
    assert final.hypothesis == "independent concern"
    assert final.evidence_tool == INDEPENDENT
    assert final.review_result["ihv_tools"] == [SELF, INDEPENDENT]


@pytest.mark.parametrize("origin", ["chain", "synthesis"])
@pytest.mark.parametrize("receipt,admitted", [(SELF, False), (VARIANT, True)])
def test_real_immediate_ingress_applies_synthesis_policy(tmp_path, monkeypatch, origin, receipt, admitted):
    from core.audit import checker_synthesis

    config, outcome, source = _subject(tmp_path)
    monkeypatch.setattr(orch, "_correlated_mech_detector_tool", lambda *a: None)
    monkeypatch.setattr(orch, "_gather_library_candidates", lambda *a: [])
    monkeypatch.setattr(orch, "_get_llm_client", lambda *a: None)
    monkeypatch.setattr(orch, "_hypothesis_to_tool_chain", lambda *a, **kw:
                        [{"type": "semgrep", "config": {}}] if origin == "chain" else [])
    calls = []

    def chain(*args, **kwargs):
        calls.append("chain")
        return ToolChainResult([receipt], file=outcome.file, function=outcome.function,
            line_start=outcome.line, hypothesis=outcome.hypothesis,
            source_identity=capture_source_identity(tmp_path, outcome.file))

    def synthesize(*args, **kwargs):
        calls.append("synthesis")
        return checker_synthesis.OnDemandSynthesisResult(stamp=receipt, confirmed=True)

    monkeypatch.setattr(orch, "_run_tool_chain", chain)
    monkeypatch.setattr(checker_synthesis, "synthesize_verification_rule", synthesize)
    counts = orch.OrchestratorResult()
    final = orch._verify_hypotheses_immediate(outcome, config, counts, source=source,
        synthesis_counter=orch.AtomicSynthesisCounter(cap=1))
    assert calls == [origin]
    assert final.status == ("finding" if admitted else "suspicious")
    assert (final.evidence_tool or "") == (receipt if admitted else "")
    assert counts.immediate_verified == int(admitted)


def test_selected_claim_cwe_controls_synthesis_policy(tmp_path):
    config, outcome, _ = _subject(tmp_path, cwe="CWE-697")
    record = _record(config, outcome, (VARIANT,), cwe="CWE-252")
    final = orch._aggregate_ihv_verdicts(outcome, orch.OrchestratorResult(), [record.hypothesis], [record], config)
    assert final.status == "finding" and final.evidence_tool == VARIANT
    assert final.review_result["cwe_class"] == "CWE-252"


@pytest.mark.parametrize("producer_bound", [False, True])
def test_exclusion_reaches_normal_json_with_honest_producer_scope(tmp_path, producer_bound):
    from core.audit.findings_export import export_findings, write_graded_findings
    from core.json import load_json

    config, outcome, _ = _subject(tmp_path)
    record = _record(config, outcome, (SELF,)) if producer_bound else ClaimVerification(
        {"mechanism": "discarded error", "cwe": "CWE-252"}, (SELF,))
    final = orch._aggregate_ihv_verdicts(outcome, orch.OrchestratorResult(), [record.hypothesis], [record], config)
    write_graded_findings(export_findings([final]), config.out_dir)
    checks = load_json(config.out_dir / "verification-checks.json")["checks"]
    exclusion = next(c for c in checks if c["tool"] == "synthesis_admission")
    assert exclusion["outcome"] == "inconclusive"
    assert exclusion["rule_id"] == "synth-receipt-excluded"
    assert exclusion["scope"]["file"] == ("a.c" if producer_bound else "")
    assert bool(exclusion["scope"]["source_identity"]) is producer_bound
    details = exclusion["result"]["data"]["details"]
    assert details["producer_scope_recorded"] is producer_bound
    assert details["attempted_scope"]["file"] == "a.c"
    assert details["excluded_receipts"][0]["receipt"] == SELF
    assert "self-match" in details["excluded_receipts"][0]["reason"]
    assert final.status == "suspicious" and not final.evidence_tool
    assert final.review_result["ihv_tools"] == [SELF]
    assert not final.review_result.get("ihv_all_refuted")


def test_exclusion_recording_failure_cannot_restore_promotion(tmp_path, monkeypatch):
    from core.audit import check_trace

    config, outcome, _ = _subject(tmp_path)
    record = _record(config, outcome, (SELF,))
    reached = []

    def unavailable(*args, **kwargs):
        reached.append(kwargs)
        raise OSError("owned recording failure")

    monkeypatch.setattr(check_trace, "record_synthesis_exclusion", unavailable)
    counts = orch.OrchestratorResult()
    final = orch._aggregate_ihv_verdicts(outcome, counts, [record.hypothesis], [record], config)
    assert len(reached) == 1
    assert final.status == "suspicious" and not final.evidence_tool
    assert counts.immediate_verified == 0
    assert final.review_result["ihv_tools"] == [SELF]


@pytest.mark.parametrize("raw,expected", [
    (SELF + "+" + INDEPENDENT, (SELF, INDEPENDENT)),
    (INDEPENDENT + "+" + SELF, (INDEPENDENT, SELF)),
    (SELF + "+llm-claimed:text+" + INDEPENDENT, (SELF,)),
    ("llm-claimed:" + SELF + "+" + INDEPENDENT, ()),
    ("prefilter:lead+" + SELF + "+" + INDEPENDENT, ()),
    (SELF + "+" + WEAK, (SELF,)),
    (WEAK + "+" + SELF, (SELF,)),
    (INDEPENDENT + "+" + INDEPENDENT, (INDEPENDENT, INDEPENDENT)),
    ("invented:proof", ()),
])
def test_receipt_iteration_preserves_existing_provenance_boundary(raw, expected):
    from core.audit.evidence_grade import is_verification_evidence, iter_verification_receipts

    assert tuple(iter_verification_receipts(raw)) == expected
    assert is_verification_evidence(raw) is bool(expected)
