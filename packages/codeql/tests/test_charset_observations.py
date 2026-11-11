"""Conditional charset observations survive normal review without claim authority."""
from copy import deepcopy
from hashlib import sha256
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.audit import check_trace
from core.audit.record import load_verified_audit_log
from core.dataflow import injection_prescreen as ip
from core.smt_solver.path_feasibility import PathSMTResult
from packages.codeql import dataflow_validator as module
from packages.codeql.tests.test_dataflow_validator import _validator, _FULL_RESPONSE
from packages.codeql.tests.test_injection_prescreen_hook import _dataflow
from packages.codeql.tests.test_reachability_prefilter import _analyzer, _finding


MODEL = {
    "path_index": 0, "validator_file": "app.py", "validator_line": 7,
    "kind": "charset", "pattern": "A-Za-z0-9", "sink_classes": ["pathtrav"],
    "reasoning": "owned conditional language exclusion",
    "source_input_sha256": sha256(b"owned model input").hexdigest(),
}


@pytest.fixture
def validator(monkeypatch):
    instance = _validator()
    monkeypatch.setattr(ip, "prescreen_finding", lambda **kw: ip.PrescreenVerdict(
        refuted=False, paths_checked=1, evidence=[deepcopy(MODEL)], reason="model only",
    ))
    monkeypatch.setattr(module, "check_path_feasibility_dual", lambda *a, **k: PathSMTResult(
        feasible=None, reasoning="owned diagnostic", satisfied=[], unknown=[],
        unsatisfied=[], smt_available=False, model={},
    ))
    monkeypatch.setattr("core.llm.scorecard.prefilter_decision",
                        lambda *a, **k: SimpleNamespace(short_circuit=False))
    monkeypatch.setattr("core.llm.scorecard.record_prefilter_outcome", lambda *a, **k: None)
    monkeypatch.setattr(module, "load_methodology", lambda *a, **k: "")
    return instance


def test_signed_charset_observation_roundtrip_preserves_review(validator, tmp_path):
    result = validator.validate_dataflow_path(_dataflow(), tmp_path, observation_out_dir=tmp_path)
    assert result.error is None
    assert result.is_exploitable is _FULL_RESPONSE["is_exploitable"]
    assert result.reasoning == _FULL_RESPONSE["reasoning"]
    validator.llm.generate_structured.assert_called_once()
    event, = [row for row in load_verified_audit_log(tmp_path)
              if row.get("rule_id") == "smt:conditional-charset-model"]
    assert event["outcome"] == "inconclusive"
    assert event["scope"] == {"file": "app.py", "function": "", "line_start": 7,
                              "hypothesis": "", "source_identity": None}
    assert "claim_reference" not in event
    snapshot = event["result"]
    assert snapshot["complete"] is True  # Serialization only.
    assert snapshot["data"]["raw_output"] == MODEL
    assert snapshot["data"]["request"]["source_input_sha256"] == MODEL["source_input_sha256"]
    details = snapshot["data"]["details"]
    assert details["source_bound"] is False
    assert "sink_interpretation" in details["unverified_source_premises"]
    assert details["assumptions"]["accepted_charset_model"]["pattern"] == MODEL["pattern"]
    export = {"findings": [], "clean_reviews": []}
    check_trace.write_check_results(export, tmp_path)
    sidecar = json.loads((tmp_path / "verification-checks.json").read_text())
    assert sidecar["checks"][0]["result"]["data"]["raw_output"] == MODEL
    assert sidecar["checks"][0]["outcome"] == "inconclusive"


@pytest.mark.parametrize("failure_seam", ["record_check_observation", "append_audit_log"])
def test_optional_recording_failure_preserves_review(validator, tmp_path, monkeypatch, failure_seam):
    def unavailable(*a, **kw):
        raise OSError("owned observation failure")
    monkeypatch.setattr(check_trace, failure_seam, unavailable)
    result = validator.validate_dataflow_path(_dataflow(), tmp_path, observation_out_dir=tmp_path)
    assert result.error is None
    assert result.reasoning == _FULL_RESPONSE["reasoning"]
    assert result.is_exploitable is _FULL_RESPONSE["is_exploitable"]
    validator.llm.generate_structured.assert_called_once()


def test_missing_output_directory_skips_optional_recording(validator, tmp_path, monkeypatch):
    observer = MagicMock(side_effect=AssertionError("no output owner"))
    monkeypatch.setattr(check_trace, "record_check_observation", observer)
    result = validator.validate_dataflow_path(_dataflow(), tmp_path)
    assert result.error is None
    observer.assert_not_called()
    validator.llm.generate_structured.assert_called_once()


def test_model_observations_keep_their_actual_path_sink(validator, tmp_path, monkeypatch):
    primary = _dataflow()
    alternative = _dataflow()
    alternative.sink.file_path = "other.py"
    alternative.sink.line = 42
    primary.alternatives = [alternative]
    other_model = {**MODEL, "path_index": 1, "validator_file": "other.py", "validator_line": 8}
    monkeypatch.setattr(ip, "prescreen_finding", lambda **kw: ip.PrescreenVerdict(
        refuted=False, paths_checked=2, evidence=[deepcopy(MODEL), other_model],
    ))
    assert validator._injection_prescreen(primary, tmp_path, observation_out_dir=tmp_path) is None
    events = [row for row in load_verified_audit_log(tmp_path)
              if row.get("rule_id") == "smt:conditional-charset-model"]
    requests = {row["result"]["data"]["request"]["path_index"]:
                row["result"]["data"]["request"] for row in events}
    assert requests[0]["sink"] == {"file": "app.py", "line": 10}
    assert requests[1]["sink"] == {"file": "other.py", "line": 42}


@pytest.mark.parametrize("with_output", [False, True])
def test_validate_finding_forwards_owned_directory_only_when_present(validator, tmp_path, with_output):
    path = _dataflow()
    validator.extract_dataflow_from_sarif = MagicMock(return_value=path)
    expected = module.DataflowValidation(**_FULL_RESPONSE)
    validator.validate_dataflow_path = MagicMock(return_value=expected)
    if with_output:
        result = validator.validate_finding({}, tmp_path, observation_out_dir=tmp_path)
        validator.validate_dataflow_path.assert_called_once_with(path, tmp_path, observation_out_dir=tmp_path)
    else:
        result = validator.validate_finding({}, tmp_path)
        validator.validate_dataflow_path.assert_called_once_with(path, tmp_path)
    assert result is expected


def test_autonomous_caller_routes_run_directory_before_later_stages(tmp_path, monkeypatch):
    analyzer = _analyzer()
    finding = _finding("app.py")
    finding.has_dataflow = True
    monkeypatch.setattr(analyzer, "parse_sarif_finding", lambda *a: finding)
    monkeypatch.setattr(analyzer, "_check_reachability", lambda *a: None)
    monkeypatch.setattr(analyzer, "read_vulnerable_code", lambda *a: "")

    class ReachedValidation(Exception):
        pass

    # Stop at the actual dispatch, before any later review/generation stage.
    analyzer.dataflow_validator = MagicMock()
    analyzer.dataflow_validator.validate_finding.side_effect = ReachedValidation
    repo = tmp_path / "repo"
    output = tmp_path / "run"
    sarif = {"ruleId": "py/path-injection"}
    with pytest.raises(ReachedValidation):
        analyzer.analyze_finding_autonomous(sarif, {}, repo, output)
    analyzer.dataflow_validator.validate_finding.assert_called_once_with(
        sarif, repo, observation_out_dir=output,
    )
