"""Malformed optional result-message text cannot abort dataflow review."""

import json
import logging
from types import SimpleNamespace

from packages.codeql import dataflow_validator as module


def _location(label, line):
    return {"location": {"message": {"text": label}, "physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": line},
    }}}


def test_result_message_normalisation_preserves_review(tmp_path, monkeypatch, caplog):
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
    validator.logger = logging.getLogger("owned-result-message")
    monkeypatch.setattr(validator, "_injection_prescreen", lambda *a, **kw: None)
    monkeypatch.setattr(validator, "_cheap_dataflow_fp_check", lambda *a: None)
    monkeypatch.setattr(validator, "_fast_tier_model_name", lambda: "owned-fast")

    def no_diagnostics(*args):
        raise ValueError("owned optional diagnostics unavailable")

    monkeypatch.setattr(validator, "_extract_path_conditions", no_diagnostics)
    controls = [(None, "", False), ({}, "", False),
                ({"text": ""}, "", False), ({"text": "owned message"}, "owned message", False)]
    malformed = [{"text": ["owned array"]}, {"text": {}}, {"text": True}, {"text": 1},
                 {"text": None}, ["owned array"], "owned message", 1]
    for message, expected, warned in controls + [(value, "", True) for value in malformed]:
        result = {"ruleId": "cpp/owned", "message": message, "codeFlows": [
            {"threadFlows": [{"locations": [_location("primary", 1), _location("sink", 2)]}]},
            {"threadFlows": [{"locations": [_location("sibling", 1), _location("sink", 2)]}]},
        ]}
        before = json.dumps(result, sort_keys=True)
        caplog.clear()
        path = validator.extract_dataflow_from_sarif(result)
        assert path is not None
        assert path.source.label == "primary"
        assert [p.source.label for p in path.alternatives] == ["sibling"]
        validation = validator.validate_dataflow_path(path, tmp_path)
        assert validation.error is None
        assert validation.is_exploitable is True
        assert path.message == expected
        assert any("SARIF result message" in record.message for record in caplog.records) is warned
        assert json.dumps(result, sort_keys=True) == before
    assert len(calls) == 12
