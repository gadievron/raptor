"""Tests that migrated CodeQL callsites use the defense envelope correctly.

Verifies envelope quarantine for autonomous_analyzer and dataflow_validator.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
    VulnerabilityAnalysis,
)
from packages.codeql.dataflow_validator import DataflowPath, DataflowStep, DataflowValidator


def _finding(**overrides):
    defaults = dict(
        rule_id="cwe-79/xss",
        rule_name="Cross-site Scripting",
        message="SCANNER_MSG_MARKER_xyz",
        level="error",
        file_path="src/handler.java",
        start_line=42,
        end_line=42,
        snippet="resp.write(input)",
        cwe="CWE-79",
    )
    defaults.update(overrides)
    return CodeQLFinding(**defaults)


def _analysis():
    return VulnerabilityAnalysis(
        is_true_positive=True,
        is_exploitable=True,
        exploitability_score=0.9,
        severity_assessment="high",
        reasoning="PRIOR_LLM_REASONING_MARKER",
        attack_scenario="PRIOR_LLM_SCENARIO_MARKER",
        prerequisites=["auth bypass"],
        impact="RCE",
        cvss_estimate=9.0,
        mitigation="sanitise input",
    )


class TestAutonomousAnalyzerEnvelope:

    def _make_analyzer(self):
        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {
                "is_true_positive": True,
                "is_exploitable": True,
                "exploitability_score": 0.8,
                "severity_assessment": "high",
                "reasoning": "looks real",
                "attack_scenario": "send payload",
                "prerequisites": [],
                "impact": "XSS",
                "cvss_estimate": 7.5,
                "mitigation": "escape output",
            },
            "raw response",
        )
        mock_llm.generate.return_value = "```python\nprint('exploit')\n```"
        return AutonomousCodeQLAnalyzer(
            llm_client=mock_llm,
            exploit_validator=None,
        ), mock_llm

    def test_analyze_passes_system_prompt(self):
        analyzer, mock_llm = self._make_analyzer()
        code = "VULN_CODE_MARKER_999"
        analyzer.analyze_vulnerability(_finding(), code)

        call_kwargs = mock_llm.generate_structured.call_args.kwargs
        assert "system_prompt" in call_kwargs
        assert call_kwargs["system_prompt"] is not None

    def test_analyze_quarantines_code_in_user_message(self):
        analyzer, mock_llm = self._make_analyzer()
        code = "VULN_CODE_MARKER_999"
        analyzer.analyze_vulnerability(_finding(), code)

        call_kwargs = mock_llm.generate_structured.call_args.kwargs
        assert code in call_kwargs["prompt"]
        assert code not in call_kwargs["system_prompt"]

    def test_analyze_quarantines_scanner_message(self):
        analyzer, mock_llm = self._make_analyzer()
        analyzer.analyze_vulnerability(_finding(), "some code")

        prompt = mock_llm.generate_structured.call_args.kwargs["prompt"]
        assert "SCANNER_MSG_MARKER_xyz" in prompt
        assert "<untrusted-" in prompt

    def test_generate_exploit_quarantines_prior_llm_output(self):
        analyzer, mock_llm = self._make_analyzer()
        analyzer.generate_exploit(_finding(), _analysis(), "some code")

        call_kwargs = mock_llm.generate.call_args.kwargs
        assert "PRIOR_LLM_REASONING_MARKER" in call_kwargs["prompt"]
        assert "PRIOR_LLM_REASONING_MARKER" not in call_kwargs["system_prompt"]

    def test_generate_exploit_passes_system_prompt(self):
        analyzer, mock_llm = self._make_analyzer()
        analyzer.generate_exploit(_finding(), _analysis(), "some code")

        call_kwargs = mock_llm.generate.call_args.kwargs
        assert call_kwargs["system_prompt"] is not None
        assert "untrusted" in call_kwargs["system_prompt"].lower()


class TestDataflowValidatorEnvelope:

    def _make_validator(self):
        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = (
            {
                "is_exploitable": True,
                "confidence": 0.8,
                "sanitizers_effective": False,
                "bypass_possible": True,
                "bypass_strategy": "encoding",
                "attack_complexity": "low",
                "reasoning": "reachable",
                "barriers": [],
                "prerequisites": [],
                "path_width": 64,
                "path_signed": False,
                "path_conditions": [],
                "unparseable": [],
            },
            "raw",
        )
        return DataflowValidator(mock_llm), mock_llm

    def _make_dataflow(self):
        return DataflowPath(
            source=DataflowStep(
                file_path="src/input.java",
                line=10, column=1,
                snippet="getParameter()",
                label="SOURCE_LABEL_MARKER",
            ),
            sink=DataflowStep(
                file_path="src/output.java",
                line=50, column=1,
                snippet="executeQuery()",
                label="SINK_LABEL_MARKER",
            ),
            intermediate_steps=[],
            sanitizers=[],
            rule_id="cwe-89/sqli",
            message="DATAFLOW_MSG_MARKER_456",
        )

    def test_validate_passes_system_prompt(self):
        validator, mock_llm = self._make_validator()
        validator.validate_dataflow_path(self._make_dataflow(), repo_path=MagicMock())

        # Second call is validate_dataflow_path (first is _extract_path_conditions)
        for call in mock_llm.generate_structured.call_args_list:
            assert "system_prompt" in call.kwargs
            assert call.kwargs["system_prompt"] is not None

    def test_validate_quarantines_message(self):
        validator, mock_llm = self._make_validator()
        validator.validate_dataflow_path(self._make_dataflow(), repo_path=MagicMock())

        last_call = mock_llm.generate_structured.call_args_list[-1]
        prompt = last_call.kwargs["prompt"]
        system = last_call.kwargs["system_prompt"]
        assert "DATAFLOW_MSG_MARKER_456" in prompt
        assert "DATAFLOW_MSG_MARKER_456" not in system

    def test_validate_slots_contain_labels(self):
        validator, mock_llm = self._make_validator()
        validator.validate_dataflow_path(self._make_dataflow(), repo_path=MagicMock())

        last_call = mock_llm.generate_structured.call_args_list[-1]
        prompt = last_call.kwargs["prompt"]
        assert "SOURCE_LABEL_MARKER" in prompt
        assert "SINK_LABEL_MARKER" in prompt
