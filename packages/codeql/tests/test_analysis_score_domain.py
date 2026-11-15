"""Deep-analysis score errors retain valid JSON artifact values."""

import json
import logging
from types import SimpleNamespace

from packages.codeql import autonomous_analyzer as module


def test_public_analysis_refuses_invalid_scores(tmp_path, monkeypatch):
    source = tmp_path / "owned.c"
    source.write_text("owned_source_marker\n")
    finding = module.CodeQLFinding("cpp/owned-rule", "owned", "owned", "warning",
                                  "owned.c", 1, 1, "owned_source_marker")
    response = {
        "is_true_positive": True, "is_exploitable": True,
        "exploitability_score": 0.5, "severity_assessment": "medium",
        "reasoning": "owned response", "attack_scenario": "owned",
        "prerequisites": [], "impact": "owned", "cvss_estimate": 5.0,
        "mitigation": "owned",
    }
    calls = []

    def generated(**kwargs):
        assert "owned_source_marker" in kwargs["prompt"]
        calls.append(dict(response))
        return dict(response), "owned"

    analyzer = module.AutonomousCodeQLAnalyzer.__new__(module.AutonomousCodeQLAnalyzer)
    analyzer.llm = SimpleNamespace(scorecard=None, generate_structured=generated)
    analyzer.logger = logging.getLogger("owned-analysis-score")
    monkeypatch.setattr(analyzer, "_cheap_fp_check", lambda *a: None)
    monkeypatch.setattr(analyzer, "_fast_tier_model_name", lambda: "owned-fast")
    for field, upper in (("exploitability_score", 1), ("cvss_estimate", 10)):
        for value in (0, 0.0, upper / 2, upper, float(upper)):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            assert result.error is None
            assert getattr(result, field) == value
        for value in (float("nan"), float("inf"), -float("inf"), -0.1, upper + 0.1,
                      True, False, "0.5", None, [], {}, 10 ** 1000):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            assert result.error is not None
            assert field in result.error
            assert result.is_exploitable is False
            payload = module._analysis_artifact_payload(
                finding=finding, analysis=result, dataflow_validation=None,
                refinement_count=0, elapsed_seconds=0.0)
            json.dumps(payload, allow_nan=False)
            assert payload["analysis"][field] == 0.0
        response[field] = upper / 2
    assert len(calls) == 34
