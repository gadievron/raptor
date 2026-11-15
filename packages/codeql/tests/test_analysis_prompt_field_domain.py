"""Malformed prior-analysis prompt fields become explicit analysis errors."""

import logging
from types import SimpleNamespace

from packages.codeql import autonomous_analyzer as module


def test_analysis_prompt_fields_are_refused_before_prompt_construction(tmp_path, monkeypatch):
    source = tmp_path / "owned.c"
    source.write_text("owned_source_marker\n")
    finding = module.CodeQLFinding("cpp/owned-rule", "owned", "owned", "warning",
                                  "owned.c", 1, 1, "owned_source_marker")
    response = {
        "is_true_positive": True, "is_exploitable": True,
        "exploitability_score": 0.5, "severity_assessment": "medium",
        "reasoning": "owned reasoning", "attack_scenario": "owned scenario",
        "prerequisites": [], "impact": "owned", "cvss_estimate": 5.0,
        "mitigation": "owned",
    }
    analysis_calls = []
    prompt_calls = []

    def structured(**kwargs):
        assert "owned_source_marker" in kwargs["prompt"]
        analysis_calls.append(dict(response))
        return dict(response), "owned"

    def generated(**kwargs):
        assert "owned_source_marker" in kwargs["prompt"]
        prompt_calls.append(kwargs)
        return "owned generated text"

    analyzer = module.AutonomousCodeQLAnalyzer.__new__(module.AutonomousCodeQLAnalyzer)
    analyzer.llm = SimpleNamespace(scorecard=None, generate_structured=structured, generate=generated)
    analyzer.logger = logging.getLogger("owned-analysis-prompt-fields")
    monkeypatch.setattr(analyzer, "_cheap_fp_check", lambda *a: None)
    monkeypatch.setattr(analyzer, "_fast_tier_model_name", lambda: "owned-fast")
    for field in ("reasoning", "attack_scenario"):
        for value in ("", "owned text", "owned\nmultiline"):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            assert result.error is None
            assert getattr(result, field) == value
            assert analyzer.generate_exploit(finding, result, source.read_text()) == "owned generated text"
        for value in (["owned array"], {"owned": "object"}, 1, True, None):
            response[field] = value
            result = analyzer.analyze_vulnerability(finding, source.read_text())
            failure = None
            if result.error is None:
                try:
                    analyzer.generate_exploit(finding, result, source.read_text())
                except (TypeError, AttributeError) as exc:
                    failure = type(exc).__name__
            assert result.error is not None, (field, failure)
            assert field in result.error
            assert result.is_exploitable is False
        response[field] = "owned text"
    assert len(analysis_calls) == 16
    assert len(prompt_calls) == 6
