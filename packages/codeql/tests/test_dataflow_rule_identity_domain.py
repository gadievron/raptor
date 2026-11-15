"""Malformed rule identities cannot enter logging or prefilter authority."""

import json
import logging
from types import SimpleNamespace

from packages.codeql import dataflow_validator as module


def _result(**identity):
    locations = [{"location": {"physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": line},
    }}} for line in (1, 2)]
    return {**identity, "codeFlows": [{"threadFlows": [{"locations": locations}]}]}


def test_malformed_rule_identity_returns_error_before_prefilter(tmp_path, monkeypatch):
    (tmp_path / "owned.c").write_text("owned_source_marker\nowned_sink_marker\n")
    calls = []

    def generated(**kwargs):
        assert "owned_source_marker" in kwargs["prompt"]
        calls.append(kwargs)
        return {"is_exploitable": True, "confidence": 0.5,
                "sanitizers_effective": False, "bypass_possible": True,
                "bypass_strategy": None, "attack_complexity": "low", "reasoning": "owned",
                "barriers": [], "prerequisites": []}, "owned"

    validator = module.DataflowValidator(SimpleNamespace(scorecard=None, generate_structured=generated))
    validator.logger = logging.getLogger("owned-rule-identity")
    monkeypatch.setattr(validator, "_injection_prescreen", lambda *a, **kw: None)
    monkeypatch.setattr(validator, "_cheap_dataflow_fp_check", lambda *a: None)
    monkeypatch.setattr(validator, "_fast_tier_model_name", lambda: "owned-fast")

    def no_diagnostics(*args):
        raise ValueError("owned optional diagnostics unavailable")

    monkeypatch.setattr(validator, "_extract_path_conditions", no_diagnostics)
    for identity in ({}, {"ruleId": ""}, {"ruleId": "cpp/owned"}):
        validation = validator.validate_finding(_result(**identity), tmp_path)
        assert validation is not None
        assert validation.error is None
        assert validation.is_exploitable is True
    assert len(calls) == 3

    def forbidden(*args, **kwargs):
        raise AssertionError("malformed identity entered review or prefilter work")

    for name in ("_injection_prescreen", "_extract_path_conditions", "_cheap_dataflow_fp_check",
                 "_fast_tier_model_name", "read_source_context"):
        monkeypatch.setattr(validator, name, forbidden)
    monkeypatch.setattr(validator.llm, "generate_structured", forbidden)
    for value in (True, False, 1, 0, 1.0, None, [], {}, ["owned"], {"id": "cpp/owned"}):
        result = _result(ruleId=value)
        before = json.dumps(result, sort_keys=True)
        validation = validator.validate_finding(result, tmp_path)
        assert validation is not None
        assert validation.error is not None
        assert "rule identity" in validation.error
        assert validation.is_exploitable is False
        assert validation.smt_paths_checked == 0
        assert validation.smt_diagnostics is None
        assert json.dumps(result, sort_keys=True) == before
    assert len(calls) == 3
