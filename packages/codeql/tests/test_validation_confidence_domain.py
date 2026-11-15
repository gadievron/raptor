"""Malformed confidence cannot become a successful dataflow result."""

from types import SimpleNamespace

from packages.codeql import dataflow_validator as module


def test_public_validation_rejects_invalid_confidence(tmp_path, monkeypatch):
    (tmp_path / "owned.c").write_text("source_marker\nsink_marker\n")
    source = module.DataflowStep("owned.c", 1, 1, "source_marker", "source")
    sink = module.DataflowStep("owned.c", 2, 1, "sink_marker", "sink")
    path = module.DataflowPath(source, sink, [], [], "cpp/owned-rule", "owned")
    response = {
        "is_exploitable": True, "confidence": 0.5,
        "sanitizers_effective": False, "bypass_possible": True,
        "bypass_strategy": None, "attack_complexity": "low",
        "reasoning": "owned response", "barriers": [], "prerequisites": [],
    }
    calls = []

    def generated(**kwargs):
        assert "source_marker" in kwargs["prompt"]
        assert "sink_marker" in kwargs["prompt"]
        calls.append(dict(response))
        return dict(response), "owned"

    validator = module.DataflowValidator(SimpleNamespace(scorecard=None, generate_structured=generated))
    monkeypatch.setattr(validator, "_injection_prescreen", lambda *a, **kw: None)
    monkeypatch.setattr(validator, "_cheap_dataflow_fp_check", lambda *a: None)
    monkeypatch.setattr(validator, "_fast_tier_model_name", lambda: "owned-fast")

    def no_diagnostics(*args):
        raise ValueError("owned unavailable optional diagnostics")

    monkeypatch.setattr(validator, "_extract_path_conditions", no_diagnostics)
    for value in (0, 0.5, 1, 0.0, 1.0):
        response["confidence"] = value
        result = validator.validate_dataflow_path(path, tmp_path)
        assert result.error is None
        assert result.is_exploitable is True
        assert result.confidence == value
        assert f"{result.confidence:.2f}" in ("0.00", "0.50", "1.00")
    for value in (float("nan"), float("inf"), -float("inf"), -0.1, 1.1,
                  True, False, "0.5", None, [], {}, 10 ** 1000):
        response["confidence"] = value
        result = validator.validate_dataflow_path(path, tmp_path)
        assert result.error is not None
        assert "confidence" in result.error
        assert result.is_exploitable is False
        assert result.confidence == 0.0
        assert result.smt_diagnostics["oracle_scope"] == "llm-extracted-predicates"
    assert len(calls) == 17
