"""LLM predicate models cannot establish or refute a source finding."""

from copy import deepcopy

import pytest

from packages.hypothesis_validation import Hypothesis
from packages.hypothesis_validation.result import Evidence, ValidationResult
from packages.llm_analysis import dataflow_validation as module
from packages.llm_analysis.verification_tier import derive_verification_tier, mechanical_receipt


@pytest.fixture(autouse=True)
def native_solver():
    pytest.importorskip("z3")


def existing_result(verdict):
    return ValidationResult(verdict=verdict, iterations=3, reasoning="owned source verdict", evidence=[
        Evidence(tool="codeql", rule="owned source query", summary="existing source evidence"),
    ])


@pytest.mark.parametrize("verdict", ["inconclusive", "confirmed", "refuted"])
@pytest.mark.parametrize("profile,conditions", [
    ("uint8", ["Value == 0", "Value == 1"]),
    (None, ["Value == 0", "Value == 1"]),
    ("uint8", ["Value < 0"]),
    ("uint8", ["min(Value, 1) > 1"]),
])
def test_native_contradictions_preserve_source_verdict_and_evidence(verdict, profile, conditions):
    original = existing_result(verdict)
    snapshot = deepcopy(original)
    analysis = {"path_conditions": conditions, "path_profile": profile, "is_exploitable": True}
    result, status = module._tier4_smt_refine(original, {}, analysis)
    assert result is original and result == snapshot and status == "smt_no_change"
    diagnostic = analysis["smt_diagnostics"]
    assert diagnostic["oracle_scope"] == "llm-extracted-predicates"
    assert diagnostic["modeled_feasible"] is False and diagnostic["conflicts"]
    assert diagnostic["path_profile"] == profile
    assert "smt_witness" not in analysis
    if "min(" in conditions[0]:
        assert diagnostic["summary_axioms"]
    module._attach_result(analysis, result, tier="tier1-prebuilt")
    assert analysis["dataflow_validation"]["recommends_downgrade"] is (verdict == "refuted")


def test_native_sat_retains_the_existing_model_reader_without_proof_evidence():
    original = existing_result("confirmed")
    analysis = {"path_conditions": ["Value == 2"], "path_profile": "uint8"}
    result, status = module._tier4_smt_refine(original, {}, analysis)
    assert result is original and status == "smt_witness" and len(result.evidence) == 1
    assert analysis["smt_witness"]["model"] == {"Value": 2}
    assert analysis["smt_diagnostics"]["modeled_feasible"] is True
    module._attach_result(analysis, result, tier="template")
    assert derive_verification_tier({"analysis": analysis}) == "llm_only"
    assert mechanical_receipt({"analysis": analysis}, "exploitable") == "codeql-llm:dataflow"


@pytest.mark.parametrize("conditions", [
    ["Value == 0", "Value / 2 == 1"],
    ["Value == 0", "update(&Value) == 0", "Value == 1"],
])
def test_partial_native_results_retain_uncertainty_and_add_no_witness(conditions):
    original = existing_result("confirmed")
    analysis = {"path_conditions": conditions, "path_profile": "uint8"}
    result, status = module._tier4_smt_refine(original, {}, analysis)
    assert result is original and status == "smt_no_change"
    assert analysis["smt_diagnostics"]["modeled_feasible"] is None
    assert analysis["smt_diagnostics"]["unknown_reasons"]
    assert "smt_witness" not in analysis


def test_native_dual_timeout_reaches_diagnostics_and_rejection_metrics(monkeypatch):
    from core.smt_solver import path_feasibility as paths
    from core.smt_solver.session import query_budget

    original = paths.check_path_feasibility
    legs = []

    def observe(*args, **kwargs):
        if len(legs) >= expire_after:
            with query_budget(0):
                checked = original(*args, **kwargs)
        else:
            checked = original(*args, **kwargs)
        legs.append(checked)
        return checked

    monkeypatch.setattr(paths, 'check_path_feasibility', observe)
    for predicates, expire_after in [(['Value < 0'], 1), (['Value == 1', 'Value == 2'], 2)]:
        legs.clear()
        prior = existing_result('confirmed')
        snapshot = deepcopy(prior)
        analysis = {'path_conditions': [*predicates, 'unrecognized @ syntax'], 'path_profile': None}
        metrics = {}
        result, status = module._tier4_smt_refine(prior, {}, analysis, metrics=metrics)
        assert [leg.feasible for leg in legs] == [False] * expire_after + [None]
        assert result is prior and result == snapshot and status == 'smt_no_change'
        diagnostic = analysis['smt_diagnostics']
        assert diagnostic['modeled_feasible'] is None
        assert diagnostic['unknown'] == ['unrecognized @ syntax', *predicates]
        assert len(diagnostic['unknown_reasons']) == 1 + len(predicates)
        counts = metrics['n_smt_rejections_by_kind']
        assert counts['solver_timeout'] == len(predicates) and sum(counts.values()) == 1 + len(predicates)
        assert 'smt_witness' not in analysis


def test_saved_records_snapshot_the_solved_question_and_model():
    condition = {"text": "Value == 2", "negated": False}
    analysis = {"path_conditions": [condition], "path_profile": "uint8"}
    module._tier4_smt_refine(existing_result("confirmed"), {}, analysis)
    condition["text"] = "Value == 9"
    analysis["smt_witness"]["model"]["Value"] = 9
    assert analysis["smt_diagnostics"]["path_conditions"][0]["text"] == "Value == 2"
    assert analysis["smt_witness"]["path_conditions"][0]["text"] == "Value == 2"
    assert analysis["smt_diagnostics"]["model"] == {"Value": 2}


@pytest.mark.parametrize("case", ["no-check", "bad-profile", "unavailable", "exception", "partial-publication"])
def test_failed_or_skipped_rechecks_clear_old_owned_records(monkeypatch, case):
    from packages.exploit_feasibility import smt_path

    old = {"foreign": ["old query"]}
    analysis = {"smt_diagnostics": old, "smt_witness": old,
                "path_conditions": ["Value == 2"], "path_profile": "uint8"}
    original = existing_result("inconclusive")
    if case == "no-check":
        analysis["path_conditions"] = []
    elif case == "bad-profile":
        analysis["path_profile"] = "unsupported"
    elif case == "unavailable":
        monkeypatch.setattr(smt_path, "validate_path", lambda *a, **kw: {"smt_available": False})
    elif case == "exception":
        def fail(*args, **kwargs):
            raise ValueError("owned query failed")
        monkeypatch.setattr(smt_path, "validate_path", fail)
    else:
        def fail(result, finding, target, **kwargs):
            target["smt_diagnostics"] = {"partial": True}
            target["smt_witness"] = {"partial": True}
            raise RuntimeError("owned publication failed")
        monkeypatch.setattr(module, "_tier4_smt_refine_inner", fail)
    result, _ = module._tier4_smt_refine(original, {}, analysis)
    assert result is original
    assert "smt_diagnostics" not in analysis and "smt_witness" not in analysis
    assert old == {"foreign": ["old query"]}


def test_cached_source_result_and_reconciliation_remain_independent_of_predicate_unsat(tmp_path, monkeypatch):
    from core.config import RaptorConfig
    from packages.hypothesis_validation.adapters import CodeQLAdapter

    monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    monkeypatch.setattr(CodeQLAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(module, "discover_prebuilt_query", lambda *a, **kw: None)
    monkeypatch.setattr(module, "_build_hypothesis", lambda *a, **kw: Hypothesis(
        claim="owned source claim", target=tmp_path, target_function="Read", cwe="CWE-190",
    ))
    original = existing_result("inconclusive")
    calls = []

    def prior_tier(*args, **kwargs):
        calls.append(1)
        return original, "tier1-prebuilt"

    monkeypatch.setattr(module, "_validate_one_hypothesis", prior_tier)
    database = tmp_path / "database"
    database.mkdir()
    shared = {"dataflow_summary": "owned source claim", "is_exploitable": True,
              "confidence": "high", "path_conditions": ["Value == 0", "Value == 1"], "path_profile": "uint8"}
    analyses = {name: deepcopy(shared) for name in ("F1", "F2")}
    metrics = module.validate_dataflow_claims(
        findings=[{"finding_id": name, "tool": "semgrep", "file_path": "record.c", "cwe_id": "CWE-190"}
                  for name in analyses],
        results_by_id=analyses, codeql_db=database, repo_path=tmp_path, llm_client=None,
    )
    assert calls == [1] and metrics["n_cache_hits"] == 1
    assert metrics["n_tier4_smt_refuted"] == metrics["n_tier4_smt_disagree"] == 0
    assert metrics["n_recommended_downgrades"] == 0
    reconciled = module.reconcile_dataflow_validation(analyses)
    assert reconciled["n_hard_downgrades"] == reconciled["n_soft_downgrades"] == 0
    for analysis in analyses.values():
        assert analysis["dataflow_validation"]["verdict"] == "inconclusive"
        assert analysis["is_exploitable"] is True and analysis["confidence"] == "high"
        assert analysis["smt_diagnostics"]["modeled_feasible"] is False
    assert analyses["F1"]["smt_diagnostics"] is not analyses["F2"]["smt_diagnostics"]


@pytest.mark.parametrize("kind", ["structured", "old-marker"])
@pytest.mark.parametrize("nested", [True, False])
def test_saved_unbound_refutations_cannot_grade_receipt_or_downgrade(kind, nested):
    block = {"verdict": "refuted", "method": "codeql-iris", "tier": "tier1-prebuilt",
             "recommends_downgrade": True}
    if kind == "structured":
        block["evidence"] = [{"tool": "smt", "rule": "path-feasibility:refuted"}]
    else:
        block["reasoning"] = "prior source check\n[smt] inconclusive → refuted: unsat path conditions"
    analysis = {"dataflow_validation": block, "is_exploitable": True, "confidence": "high"}
    finding = {"analysis": analysis} if nested else analysis
    assert derive_verification_tier(finding) == "llm_only"
    assert mechanical_receipt(finding, "false_positive") == ""
    result = module.reconcile_dataflow_validation({"F": analysis})
    assert result["n_hard_downgrades"] == result["n_soft_downgrades"] == 0
    assert result["n_skipped"] == 1
    assert analysis["is_exploitable"] is True and analysis["confidence"] == "high"
    assert analysis["validation_downgrade_withheld"] == "unbound-smt-predicates"


def test_independent_source_receipts_still_qualify_with_diagnostic_models():
    finding = {"analysis": {"smt_witness": {"model": {"Value": 2}},
                            "dataflow_validation": {"verdict": "confirmed", "method": "codeql-iris"}}}
    assert derive_verification_tier(finding) == "tool_backed"
    assert mechanical_receipt(finding, "exploitable") == "codeql:dataflow"


def test_model_text_cannot_mimic_saved_smt_refutation_marker():
    from core.audit.evidence_grade import defang_model_fields
    from packages.llm_analysis.verification_tier import unbound_smt_refutation

    legacy = {"verdict": "refuted", "method": "codeql-iris",
              "reasoning": "source note\n[smt] inconclusive → refuted: unsat path conditions"}
    assert unbound_smt_refutation(legacy)
    assert mechanical_receipt({"analysis": {"dataflow_validation": legacy}}, "false_positive") == ""

    cleaned = defang_model_fields(legacy)
    assert "[llm-claimed:smt]" in cleaned["reasoning"]
    assert not unbound_smt_refutation(cleaned)
    assert defang_model_fields(cleaned) == cleaned
    finding = {"analysis": {"dataflow_validation": cleaned}}
    assert mechanical_receipt(finding, "false_positive") == "codeql:dataflow"

    source = {"verdict": "refuted", "method": "codeql-iris", "reasoning": "owned source query"}
    assert not unbound_smt_refutation(source)
    assert mechanical_receipt({"analysis": {"dataflow_validation": source}}, "false_positive") == "codeql:dataflow"


@pytest.mark.parametrize("record_kind", ["typed", "dictionary"])
def test_attached_smt_evidence_is_independent_of_cached_results(tmp_path, record_kind):
    from core.smt_solver import BV_C_UINT8
    from packages.hypothesis_validation.adapters.smt import SMTAdapter

    native = SMTAdapter(bv_profile=BV_C_UINT8).run("Value == 2", tmp_path)
    assert native.success and native.predicate_verdict == "sat"
    assert native.matches[0]["variable"] == "Value"
    assert native.matches[0]["value"] == 2
    item = Evidence(
        tool=native.tool, rule=native.rule, summary=native.summary,
        matches=native.matches, predicate_verdict=native.predicate_verdict,
    )
    original = ValidationResult(
        verdict="confirmed", evidence=[item.to_dict() if record_kind == "dictionary" else item],
        iterations=1, reasoning="supplied predicate is satisfiable",
    )
    first, second = {}, {}
    for analysis in (first, second):
        module._attach_result(analysis, original, method="codeql-iris-llm")
    first_record = first["dataflow_validation"]["evidence"][0]
    second_record = second["dataflow_validation"]["evidence"][0]
    first_record["matches"][0]["value"] = 9
    assert second_record["matches"][0]["value"] == 2
    assert native.matches[0]["value"] == 2
    assert second_record["predicate_verdict"] == "sat"
    native.matches[0]["value"] = 7
    assert second_record["matches"][0]["value"] == 2
    assert first_record["matches"][0]["value"] == 9
