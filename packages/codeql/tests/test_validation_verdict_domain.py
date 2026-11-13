"""Admit explicit verdict booleans and the existing null abstention."""

import pytest

from packages.codeql.dataflow_validator import DataflowValidation


def _result(value):
    return DataflowValidation(
        is_exploitable=value,
        confidence=0.5,
        sanitizers_effective=False,
        bypass_possible=False,
        bypass_strategy=None,
        attack_complexity="high",
        reasoning="inert response fixture",
        barriers=[],
        prerequisites=[],
    )


@pytest.mark.parametrize("value", [0, 1, 0.0, 1.0, "", "false", [], {}])
def test_nonboolean_verdict_is_refused(value):
    with pytest.raises(ValueError, match="is_exploitable"):
        _result(value)


@pytest.mark.parametrize("value", [True, False, None])
def test_boolean_and_abstention_verdicts_are_preserved(value):
    result = _result(value)
    assert result.is_exploitable is value
    assert result.error is None


def test_error_state_preserves_explicit_false_default():
    result = _result(False)
    result.error = "inert parse failure"
    assert result.is_exploitable is False
    assert result.error == "inert parse failure"
