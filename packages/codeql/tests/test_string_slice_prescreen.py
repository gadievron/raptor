"""Live slice-model diagnostics survive source review without becoming verdicts."""
from dataclasses import asdict
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.dataflow import injection_prescreen as ip
from core.smt_solver import z3_available
from packages.codeql import dataflow_validator as module
from packages.codeql.tests.test_dataflow_validator import _validator, _FULL_RESPONSE

pytestmark = pytest.mark.skipif(not z3_available(), reason="z3-solver not installed")


@pytest.fixture
def validator(monkeypatch):
    instance = _validator()
    # Keep the actual prescreen and solver; only incidental paid-review seams
    # use the existing fixture's fake transport/extraction policy.
    reader = module.DataflowValidator.read_source_context.__get__(instance)
    instance.read_source_context = MagicMock(wraps=reader)
    monkeypatch.setattr(ip, "_STATS", ip.PrescreenStats())
    monkeypatch.setattr("core.llm.scorecard.prefilter_decision", lambda *a, **k: SimpleNamespace(short_circuit=False))
    monkeypatch.setattr("core.llm.scorecard.record_prefilter_outcome", lambda *a, **k: None)
    monkeypatch.setattr(module, "load_methodology", lambda *a, **k: "")
    return instance


def _source_path(tmp_path, operation="[:-1]", *, bounded=True):
    bound = "    if len(name) > 8: return\n" if bounded else ""
    source = (
        "import re\ndef handle(name):\n" + bound
        + '    if not re.match(r"^[a-z]+$", name):\n'
        + "        return\n"
        + f"    trimmed = name{operation}\n"
        + "    return os.system(trimmed)\n"
    )
    (tmp_path / "app.py").write_text(source)
    guard_line = 4 if bounded else 3
    def step(line, label, file="app.py"):
        return module.DataflowStep(file, line, 1, "", label)
    primary = module.DataflowPath(
        source=step(2, "source"), sink=step(len(source.splitlines()), "sink"),
        intermediate_steps=[step(guard_line, "step")], sanitizers=[],
        rule_id="py/command-injection", message="owned source review fixture",
    )
    primary.alternatives = [module.DataflowPath(
        source=step(1, "source", "alternative.py"),
        sink=step(2, "sink", "alternative.py"), intermediate_steps=[], sanitizers=[],
        rule_id=primary.rule_id, message="independent alternative",
    )]
    (tmp_path / "alternative.py").write_text("def other(value):\n    return unrelated(value)\n")
    return primary


@pytest.mark.parametrize("operation,model_status,review_exploitable", [
    ("[:-1]", "excluded", True), ("[1:]", "counterexample", False),
], ids=["excluded-retains-positive-review", "counterexample-retains-negative-review"])
def test_conditional_models_do_not_replace_review_or_select_alternatives(
    validator, tmp_path, operation, model_status, review_exploitable,
):
    path = _source_path(tmp_path, operation)
    validator.llm.generate_structured.return_value = (
        {**_FULL_RESPONSE, "is_exploitable": review_exploitable,
         "reasoning": "owned source review outcome"}, "raw",
    )
    result = validator.validate_dataflow_path(path, tmp_path)
    assert result.is_exploitable is review_exploitable
    assert result.reasoning == "owned source review outcome"
    assert result.barriers == []
    assert result.error is None
    assert validator.llm.generate_structured.call_count == 1
    assert validator._extract_path_conditions.call_args.args[0] is path
    assert validator._extract_path_conditions.call_count == 1
    assert result.smt_path_index == 0 and result.smt_paths_checked == 1
    assert result.smt_diagnostics["oracle_scope"] == "llm-extracted-predicates"
    (model,) = result.smt_diagnostics["string_slice_models"]
    assert model["status"] == model_status
    assert model["source_bound"] is False
    assert model["scope"] == "conditional-untyped-string-model"
    assert model["source_digest"]
    assert model["unverified_source_premises"]
    assert any(call.args and call.args[0].endswith("app.py")
               for call in validator.read_source_context.call_args_list)
    assert not any(call.args and call.args[0].endswith("alternative.py")
                   for call in validator.read_source_context.call_args_list)
    serialised = json.loads(json.dumps(asdict(result)))
    assert serialised["smt_diagnostics"]["string_slice_models"] == [model]
    if model_status == "counterexample":
        assert model["output_value"] == model["input_value"][1:]
        assert "\n" in model["output_value"]


def test_source_review_error_retains_conditional_slice_diagnostics(validator, tmp_path):
    path = _source_path(tmp_path)
    validator.llm.generate_structured.side_effect = RuntimeError("owned source review failure")
    result = validator.validate_dataflow_path(path, tmp_path)
    assert result.error == "owned source review failure"
    assert result.confidence == 0.0
    assert validator.llm.generate_structured.call_count == 1
    (model,) = result.smt_diagnostics["string_slice_models"]
    assert model["status"] == "excluded" and model["source_bound"] is False


def test_llm_cannot_relabel_owned_slice_models_as_source_proof(validator, tmp_path):
    path = _source_path(tmp_path)
    validator.llm.generate_structured.return_value = (
        {**_FULL_RESPONSE, "smt_diagnostics": {
            "oracle_scope": "source-proof", "string_slice_models": [{"source_bound": True}],
        }}, "raw",
    )
    result = validator.validate_dataflow_path(path, tmp_path)
    assert result.is_exploitable is True
    assert validator.llm.generate_structured.call_count == 1
    assert result.smt_diagnostics["oracle_scope"] == "llm-extracted-predicates"
    (model,) = result.smt_diagnostics["string_slice_models"]
    assert model["source_bound"] is False and model["status"] == "excluded"


def test_no_observed_bound_omits_slice_models_without_blocking_review(validator, tmp_path):
    result = validator.validate_dataflow_path(_source_path(tmp_path, bounded=False), tmp_path)
    assert result.is_exploitable is True
    assert validator.llm.generate_structured.call_count == 1
    assert "string_slice_models" not in result.smt_diagnostics


def test_diagnostic_copy_failure_does_not_block_source_review(validator, monkeypatch, tmp_path):
    calls = []
    def unavailable(value):
        calls.append(value)
        raise RuntimeError("owned diagnostic copy failure")
    monkeypatch.setattr(module, "deepcopy", unavailable)
    result = validator.validate_dataflow_path(_source_path(tmp_path), tmp_path)
    assert len(calls) == 1 and calls[0][0]["source_bound"] is False
    assert result.is_exploitable is True and result.error is None
    assert validator.llm.generate_structured.call_count == 1
    assert "string_slice_models" not in result.smt_diagnostics
