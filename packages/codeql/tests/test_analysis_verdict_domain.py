"""Deep-analysis verdicts admit booleans and explicit null abstention."""

import logging
from types import SimpleNamespace

from packages.codeql import autonomous_analyzer as module


def test_public_analysis_refuses_nonboolean_verdicts(tmp_path, monkeypatch):
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
    analyzer.logger = logging.getLogger("owned-analysis-verdict")
    monkeypatch.setattr(analyzer, "_cheap_fp_check", lambda *a: None)
    monkeypatch.setattr(analyzer, "_fast_tier_model_name", lambda: "owned-fast")
    for field in ("is_true_positive", "is_exploitable"):
        for value in (True, False, None):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            assert result.error is None
            assert getattr(result, field) is value
        for value in (0, 1, 0.0, 1.0, "false", "", [], {}):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            assert result.error is not None
            assert field in result.error
            assert result.is_true_positive is False
            assert result.is_exploitable is False
        response[field] = True
    assert len(calls) == 22
