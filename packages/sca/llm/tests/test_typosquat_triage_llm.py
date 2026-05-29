"""Tests for the typosquat-triage LLM stage (Stage A). Patches ``run_stage`` —
no real LLM — mirroring the other llm-stage tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from packages.sca.llm.schemas import TyposquatTriageVerdict
from packages.sca.llm.typosquat_triage import assess_typosquat


def _call():
    return assess_typosquat(
        MagicMock(), "npm", "loadash", "lodash", 3851, 1, 1,
        "deprecated: yes\nrelease count: 2",
    )


@patch("packages.sca.llm.typosquat_triage.run_stage")
def test_returns_verdict(mock_rs):
    v = TyposquatTriageVerdict(verdict="typosquat", confidence="high",
                               rationale="deprecation-holder for lodash")
    mock_rs.return_value = MagicMock(error=None, model=v, preflight_hit=False)
    out = _call()
    assert out is not None and out.verdict == "typosquat"


@patch("packages.sca.llm.typosquat_triage.run_stage")
def test_error_returns_none(mock_rs):
    mock_rs.return_value = MagicMock(error="boom", model=None,
                                     preflight_hit=False)
    assert _call() is None


@patch("packages.sca.llm.typosquat_triage.run_stage")
def test_no_model_returns_none(mock_rs):
    mock_rs.return_value = MagicMock(error=None, model=None,
                                     preflight_hit=False)
    assert _call() is None


@patch("packages.sca.llm.typosquat_triage.run_stage")
def test_preflight_hit_caps_confidence(mock_rs):
    v = TyposquatTriageVerdict(verdict="legit", confidence="high", rationale="x")
    mock_rs.return_value = MagicMock(error=None, model=v, preflight_hit=True)
    out = _call()
    assert out.confidence == "medium"     # high haircut on injection indicators
