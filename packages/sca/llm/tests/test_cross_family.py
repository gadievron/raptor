"""Tests for cross-family LLM verification (``packages.sca.llm.cross_family_check``)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from pydantic import BaseModel

from packages.sca.llm import StageResult, cross_family_check


class _MockVerdict(BaseModel):
    verdict: str
    confidence: str = "high"


def _stage_result(verdict: str, confidence: str = "high") -> StageResult:
    return StageResult(
        model=_MockVerdict(verdict=verdict, confidence=confidence),
        raw="{}",
        preflight_hit=False,
        confidence_haircut=1.0,
        cost=0.01,
    )


def _checker_kwargs():
    return dict(
        system="test system prompt",
        untrusted_blocks=(),
        slots={},
        schema_cls=_MockVerdict,
        verdict_field="verdict",
        high_severity_values=("malicious", "suspicious"),
        task_type="test_task",
    )


def test_benign_verdict_skips_cross_check():
    """Benign verdicts should not trigger the cross-family check."""
    primary = _stage_result("benign")
    client = MagicMock()
    result = cross_family_check(
        client=client, primary_result=primary, **_checker_kwargs(),
    )
    assert result is primary


def test_agreement_preserves_original_result():
    """When both models agree on a malicious verdict, original stays."""
    primary = _stage_result("malicious", "high")

    with patch("packages.sca.llm._select_checker", return_value="checker/model"), \
         patch("packages.sca.llm.run_stage", return_value=_stage_result("malicious")):
        result = cross_family_check(
            client=MagicMock(), primary_result=primary, **_checker_kwargs(),
        )
    assert result.model.verdict == "malicious"
    assert result.model.confidence == "high"


def test_disagreement_caps_confidence_to_medium():
    """When models disagree, conservative verdict wins but confidence is capped."""
    primary = _stage_result("malicious", "high")

    with patch("packages.sca.llm._select_checker", return_value="checker/model"), \
         patch("packages.sca.llm.run_stage", return_value=_stage_result("benign")):
        result = cross_family_check(
            client=MagicMock(), primary_result=primary, **_checker_kwargs(),
        )
    assert result.model.verdict == "malicious"
    assert result.model.confidence == "medium"


def test_no_checker_available_returns_primary():
    """When no cross-family model is available, primary result is returned as-is."""
    primary = _stage_result("suspicious")

    with patch("packages.sca.llm._select_checker", return_value=None):
        result = cross_family_check(
            client=MagicMock(), primary_result=primary, **_checker_kwargs(),
        )
    assert result is primary


def test_checker_failure_returns_primary():
    """When the checker call fails, fall back to primary."""
    primary = _stage_result("malicious")
    failed = StageResult(
        model=None, raw=None, preflight_hit=False,
        confidence_haircut=1.0, cost=0.0, error="boom",
    )

    with patch("packages.sca.llm._select_checker", return_value="checker/model"), \
         patch("packages.sca.llm.run_stage", return_value=failed):
        result = cross_family_check(
            client=MagicMock(), primary_result=primary, **_checker_kwargs(),
        )
    assert result is primary


def test_none_model_returns_primary():
    """StageResult with model=None (primary failed) returns immediately."""
    primary = StageResult(
        model=None, raw=None, preflight_hit=False,
        confidence_haircut=1.0, cost=0.0,
    )
    result = cross_family_check(
        client=MagicMock(), primary_result=primary, **_checker_kwargs(),
    )
    assert result is primary


def test_cost_aggregated_on_disagreement():
    """On disagreement, checker cost is added to primary cost."""
    primary = _stage_result("suspicious")
    primary.cost = 0.05
    checker_result = _stage_result("benign")
    checker_result.cost = 0.03

    with patch("packages.sca.llm._select_checker", return_value="checker/model"), \
         patch("packages.sca.llm.run_stage", return_value=checker_result):
        result = cross_family_check(
            client=MagicMock(), primary_result=primary, **_checker_kwargs(),
        )
    assert abs(result.cost - 0.08) < 0.001
