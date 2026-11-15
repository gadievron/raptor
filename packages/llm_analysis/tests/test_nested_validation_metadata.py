"""Malformed saved metadata must not abort the dataflow validation pass."""

import pytest

from core.config import RaptorConfig
from packages.hypothesis_validation.adapters import CodeQLAdapter
from packages.hypothesis_validation.result import ValidationResult
from packages.llm_analysis import dataflow_validation as dv


@pytest.mark.parametrize("nested", ["saved", ["saved"], 7, True])
@pytest.mark.parametrize("present", [False, True])
def test_malformed_nested_auto_gate_retains_top_level_fallback(nested, present):
    analysis = {"dataflow_validation": nested}
    if present:
        analysis["path_conditions"] = ["x > 0"]
    assert dv._effective_deep_validate(
        analysis, deep_validate=False, deep_validate_disabled=False,
    ) == (present, present)
    assert analysis["dataflow_validation"] is nested


@pytest.mark.parametrize("disabled,expected", [(False, (True, False)), (True, (False, False))])
def test_explicit_flags_keep_precedence_with_malformed_metadata(disabled, expected):
    assert dv._effective_deep_validate(
        {"dataflow_validation": "saved"}, deep_validate=True,
        deep_validate_disabled=disabled,
    ) == expected


@pytest.mark.parametrize("nested,top,expected", [
    ({"path_conditions": ["nested"]}, [], True),
    ({"path_conditions": []}, ["top"], True),
    ({"path_conditions": []}, [], False),
])
def test_valid_nested_mapping_keeps_existing_gate(nested, top, expected):
    assert dv._effective_deep_validate(
        {"dataflow_validation": nested, "path_conditions": top},
        deep_validate=False, deep_validate_disabled=False,
    ) == (expected, expected)


@pytest.mark.parametrize("forced,disabled,expected_deep", [
    (False, False, [True, False]),
    (True, False, [True, True]),
    (True, True, [False, False]),
], ids=["auto", "forced", "disabled"])
def test_validation_pass_continues_after_malformed_metadata(
    tmp_path, monkeypatch, forced, disabled, expected_deep,
):
    db = tmp_path / "db"
    db.mkdir()
    monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    monkeypatch.setattr(CodeQLAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(dv, "_db_is_stale", lambda *args: False)
    monkeypatch.setattr(dv, "discover_prebuilt_query", lambda *args: None)
    monkeypatch.setattr(dv, "_build_strategy_block", lambda **kwargs: "")
    calls = []

    def validate(hypothesis, finding, adapter, client, *, deep_validate, tier1_batch):
        calls.append((finding["finding_id"], deep_validate))
        return ValidationResult(
            verdict="inconclusive", evidence=[], iterations=1, reasoning="owned",
        ), "prebuilt"

    monkeypatch.setattr(dv, "_validate_one_hypothesis", validate)
    monkeypatch.setattr(
        dv, "_tier4_smt_refine", lambda result, *args, **kwargs: (result, "no_check"),
    )
    findings = [
        {"finding_id": name, "file_path": name + ".py", "language": "python",
         "cwe_id": "CWE-79"}
        for name in ("first", "second")
    ]
    results = {
        "first": {"is_exploitable": True, "dataflow_summary": "first claim",
                  "dataflow_validation": "saved", "path_conditions": ["x > 0"]},
        "second": {"is_exploitable": True, "dataflow_summary": "second claim",
                   "dataflow_validation": {"path_conditions": []}},
    }
    metrics = dv.validate_dataflow_claims(
        findings, results, codeql_db=db, repo_path=tmp_path, llm_client=None,
        deep_validate=forced, deep_validate_disabled=disabled,
    )
    assert calls == list(zip(("first", "second"), expected_deep))
    assert metrics["n_validated"] == 2 and metrics["n_errors"] == 0
    assert metrics["n_path_conditions_populated"] == 1
    assert metrics["path_conditions_by_cwe"] == {"CWE-79": 1}
    for analysis in results.values():
        assert analysis["is_exploitable"] is True
        assert analysis["dataflow_validation"]["verdict"] == "inconclusive"
        assert analysis["dataflow_validation"]["recommends_downgrade"] is False
