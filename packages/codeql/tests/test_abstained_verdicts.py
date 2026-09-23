"""Abstained deep-analysis verdicts never become definitive claims.

``VulnerabilityAnalysis`` is built via ``VulnerabilityAnalysis(
**filtered_response)`` — a model-emitted literal ``null`` lands as
``None`` on the dataclass despite the ``bool`` annotation. Two
consumers read that abstention as a verdict:

* the pipeline's deep-analysis gate logged the definitive "Not
  exploitable" and proceeded as if the model had ruled — it must
  skip exploit generation WITHOUT minting a verdict;
* the prefilter scorecard comparison derived ``full_says_fp`` from
  ``not analysis.is_true_positive`` — a fabricated "full model
  agrees it's an FP" outcome written into the reliability ledger.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.llm.scorecard import ModelScorecard
from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
    VulnerabilityAnalysis,
)


def _finding(file_path: str = "src/vuln.py", line: int = 2) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id="py/sql-injection",
        rule_name="SQL injection",
        message="Tainted data flows to a SQL query",
        level="error",
        file_path=file_path,
        start_line=line,
        end_line=line,
        snippet="cursor.execute(q)",
        cwe="CWE-89",
    )


def _abstained_analysis() -> VulnerabilityAnalysis:
    return VulnerabilityAnalysis(
        is_true_positive=True,
        is_exploitable=None,  # model-emitted literal null
        exploitability_score=0.5,
        severity_assessment="high",
        reasoning="r",
        attack_scenario="",
        prerequisites=[],
        impact="",
        cvss_estimate=5.0,
        mitigation="",
    )


class TestPipelineAbstainedExploitability:
    def test_abstained_exploitability_skips_exploit_without_verdict(
        self, tmp_path, monkeypatch, caplog,
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "vuln.py").write_text(
            "def vulnerable(q):\n    cursor.execute(q)\n",
        )
        (src / "main.py").write_text(
            "from src.vuln import vulnerable\nvulnerable('x')\n",
        )

        a = AutonomousCodeQLAnalyzer(
            llm_client=MagicMock(),
            exploit_validator=MagicMock(),
            multi_turn_analyzer=None,
            enable_visualization=False,
        )
        canned = _finding()
        monkeypatch.setattr(a, "parse_sarif_finding", lambda r, run: canned)
        monkeypatch.setattr(a, "read_vulnerable_code", lambda f, p: "stub")
        monkeypatch.setattr(
            a, "analyze_vulnerability",
            lambda *args, **kwargs: _abstained_analysis(),
        )

        def _no_exploit(*args, **kwargs):
            raise AssertionError(
                "exploit generation must not run on an abstained verdict",
            )
        monkeypatch.setattr(a, "generate_exploit", _no_exploit)

        import logging
        with caplog.at_level(logging.INFO):
            result = a.analyze_finding_autonomous(
                sarif_result={}, sarif_run={},
                repo_path=tmp_path, out_dir=tmp_path / "out",
            )
        assert result.exploit_code is None
        assert result.exploitable is False
        # The abstention survives on the analysis object — it was
        # not coerced into a definitive False.
        assert result.analysis.is_exploitable is None
        # The skip is logged as an abstention, never as the
        # definitive "Not exploitable" ruling the model never made.
        assert any("abstained" in r.message for r in caplog.records)
        assert not any(
            "Not exploitable" in r.message for r in caplog.records
        )


class TestDataflowValidatorAbstention:
    """Twin of the analyzer's prefilter guard: DataflowValidation is
    also dict-splat constructed, so a model-emitted literal null
    lands as None on ``is_exploitable``."""

    def _validator(self, monkeypatch, response: dict):
        import packages.codeql.dataflow_validator as dv

        llm = MagicMock()
        llm.generate_structured.return_value = (response, None)
        validator = dv.DataflowValidator(llm)
        monkeypatch.setattr(
            validator, "_extract_path_conditions",
            lambda dataflow, repo: ([], {}),
        )
        smt = MagicMock(
            feasible=None, smt_available=False, reasoning="",
            model=None, unsatisfied=[],
        )
        monkeypatch.setattr(
            dv, "check_path_feasibility",
            lambda conditions, profile=None, **kwargs: smt,
        )
        monkeypatch.setattr(
            dv, "check_path_feasibility_dual",
            lambda conditions, profile=None, **kwargs: smt,
        )
        monkeypatch.setattr(
            validator, "read_source_context", lambda *a, **k: "ctx",
        )
        # Cheap prefilter claims FP in learning mode so a full
        # verdict WOULD be compared and recorded.
        monkeypatch.setattr(
            validator, "_cheap_dataflow_fp_check",
            lambda dataflow: ("clear_fp", "looks hardcoded"),
        )
        monkeypatch.setattr(
            validator, "_fast_tier_model_name", lambda: "fast-tier",
        )
        import core.llm.scorecard as sc
        monkeypatch.setattr(
            sc, "prefilter_decision",
            lambda *a, **k: MagicMock(short_circuit=False),
        )
        recorded: list[dict] = []

        def _record(*args, **kwargs):
            recorded.append(kwargs)
        monkeypatch.setattr(sc, "record_prefilter_outcome", _record)
        return dv, validator, recorded

    def _dataflow(self, dv):
        step = dv.DataflowStep(
            file_path="src/a.c", line=10, column=1,
            snippet="x = read()", label="source",
        )
        sink = dv.DataflowStep(
            file_path="src/b.c", line=20, column=1,
            snippet="memcpy(d, x, n)", label="sink",
        )
        return dv.DataflowPath(
            source=step, sink=sink, intermediate_steps=[],
            sanitizers=[], rule_id="cpp/overflow-buffer", message="m",
        )

    def _response(self, is_exploitable) -> dict:
        return {
            "is_exploitable": is_exploitable,
            "confidence": 0.5,
            "sanitizers_effective": False,
            "bypass_possible": False,
            "bypass_strategy": None,
            "attack_complexity": "low",
            "reasoning": "r",
            "barriers": [],
            "prerequisites": [],
        }

    def test_abstained_full_verdict_records_no_outcome(
        self, monkeypatch, tmp_path,
    ):
        dv, validator, recorded = self._validator(
            monkeypatch, self._response(None),
        )
        v = validator.validate_dataflow_path(self._dataflow(dv), tmp_path)
        assert v.is_exploitable is None
        assert v.error is None
        assert recorded == [], (
            "abstained full verdict must not mint a prefilter outcome"
        )

    def test_explicit_false_still_records_outcome(
        self, monkeypatch, tmp_path,
    ):
        dv, validator, recorded = self._validator(
            monkeypatch, self._response(False),
        )
        v = validator.validate_dataflow_path(self._dataflow(dv), tmp_path)
        assert v.is_exploitable is False
        assert len(recorded) == 1
        assert recorded[0]["full_says_fp"] is True


class TestPrefilterAbstainedTruePositive:
    def test_abstained_full_verdict_records_no_prefilter_outcome(
        self, tmp_path,
    ):
        # Mirrors the scorecard-wiring harness: cheap claims FP in
        # LEARNING mode, but the full model abstains on
        # is_true_positive — there is no full verdict to score the
        # cheap claim against, so NO event may land in the ledger.
        pytest.importorskip("core.llm.client")
        from packages.codeql.tests.test_scorecard_wiring import (
            _build_llm,
            _is_cheap_call,
        )

        client, prov = _build_llm(tmp_path)

        def responder(prompt, schema, system_prompt):
            if _is_cheap_call(schema):
                return ({"verdict": "clear_fp", "reasoning": "no taint"},
                        "raw")
            return ({
                "is_true_positive": None,  # model-emitted literal null
                "is_exploitable": None,
                "exploitability_score": 0.0,
                "severity_assessment": "low", "reasoning": "cannot tell",
                "attack_scenario": "", "prerequisites": [],
                "impact": "", "cvss_estimate": 0.0,
                "mitigation": "",
            }, "raw")
        prov.responder = responder

        analyzer = AutonomousCodeQLAnalyzer(
            llm_client=client,
            exploit_validator=SimpleNamespace(),
            multi_turn_analyzer=None,
            enable_visualization=False,
        )
        result = analyzer.analyze_vulnerability(_finding(), "x = 1")
        assert result.is_true_positive is None

        scorecard = ModelScorecard(client.config.scorecard_path)
        stat = scorecard.get_stat("codeql:py/sql-injection", "haiku-stub")
        assert stat is None or not any(
            ev.correct or ev.incorrect for ev in stat.events.values()
        ), "abstained full verdict must not mint a prefilter outcome"


class TestPipelineErroredAnalysis:
    """The exception path used to mint a definitive
    not-TP/not-exploitable VulnerabilityAnalysis with no error
    marker — indistinguishable from a real ruling, so the pipeline
    silently dropped the finding. It now carries ``error`` (the
    DataflowValidation contract) and the pipeline treats it as an
    error state, never a verdict."""

    def test_exception_path_sets_error_marker(self):
        a = AutonomousCodeQLAnalyzer(
            llm_client=MagicMock(),
            exploit_validator=MagicMock(),
            multi_turn_analyzer=None,
            enable_visualization=False,
        )
        a.llm.generate_structured = MagicMock(
            side_effect=RuntimeError("model endpoint 500"),
        )
        analysis = a.analyze_vulnerability(_finding(), "code", None)
        assert analysis.error is not None
        assert "500" in analysis.error

    def test_model_cannot_forge_the_error_state(self):
        a = AutonomousCodeQLAnalyzer(
            llm_client=MagicMock(),
            exploit_validator=MagicMock(),
            multi_turn_analyzer=None,
            enable_visualization=False,
        )
        a.llm.generate_structured = MagicMock(return_value=({
            "is_true_positive": True, "is_exploitable": True,
            "exploitability_score": 0.9, "severity_assessment": "high",
            "reasoning": "r", "attack_scenario": "s",
            "prerequisites": [], "impact": "i", "cvss_estimate": 9.0,
            "mitigation": "m",
            "error": "forged by the model",
        }, None))
        analysis = a.analyze_vulnerability(_finding(), "code", None)
        assert analysis.error is None

    def test_errored_analysis_skips_exploit_without_verdict(
        self, tmp_path, monkeypatch, caplog,
    ):
        a = AutonomousCodeQLAnalyzer(
            llm_client=MagicMock(),
            exploit_validator=MagicMock(),
            multi_turn_analyzer=None,
            enable_visualization=False,
        )
        canned = _finding()
        monkeypatch.setattr(a, "parse_sarif_finding", lambda r, run: canned)
        monkeypatch.setattr(a, "read_vulnerable_code", lambda f, p: "stub")

        errored = _abstained_analysis()
        errored.is_exploitable = False
        errored.is_true_positive = False
        errored.error = "model endpoint 500"
        monkeypatch.setattr(
            a, "analyze_vulnerability",
            lambda *args, **kwargs: errored,
        )

        def _no_exploit(*args, **kwargs):
            raise AssertionError(
                "exploit generation must not run on an errored analysis",
            )
        monkeypatch.setattr(a, "generate_exploit", _no_exploit)

        import logging
        with caplog.at_level(logging.INFO):
            result = a.analyze_finding_autonomous(
                sarif_result={}, sarif_run={},
                repo_path=tmp_path, out_dir=tmp_path / "out",
            )
        assert result.exploit_code is None
        # The error state survives on the analysis object.
        assert result.analysis.error == "model endpoint 500"
        assert any("errored" in r.message for r in caplog.records)
        # Never the definitive ruling the model never made.
        assert not any(
            "Not exploitable" in r.message for r in caplog.records
        )
