"""Tests for llm_response_schema."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from core.security.llm_response_schema import validate_response


class Verdict(BaseModel):
    exploitable: bool
    confidence: float
    reasoning: Optional[str] = None


def test_valid_json_parses_into_schema():
    raw = '{"exploitable": true, "confidence": 0.9, "reasoning": "see below"}'
    result = validate_response(raw, Verdict)
    assert result is not None
    assert result.exploitable is True
    assert result.confidence == 0.9


def test_valid_json_with_optional_field_omitted_parses():
    raw = '{"exploitable": false, "confidence": 0.1}'
    result = validate_response(raw, Verdict)
    assert result is not None
    assert result.reasoning is None


def test_malformed_json_returns_none_when_no_retry():
    raw = '{this is not json'
    assert validate_response(raw, Verdict) is None


def test_schema_violation_returns_none_when_no_retry():
    raw = '{"exploitable": "not a bool", "confidence": 0.5}'
    assert validate_response(raw, Verdict) is None


def test_missing_required_field_returns_none_when_no_retry():
    raw = '{"exploitable": true}'
    assert validate_response(raw, Verdict) is None


def test_retry_called_when_first_response_invalid():
    calls = []

    def llm_call() -> str:
        calls.append(1)
        return '{"exploitable": true, "confidence": 0.7}'

    result = validate_response('{bad', Verdict, llm_call=llm_call)
    assert result is not None
    assert result.exploitable is True
    assert len(calls) == 1


def test_retry_not_called_when_first_response_valid():
    calls = []

    def llm_call() -> str:
        calls.append(1)
        return '{"exploitable": true, "confidence": 0.7}'

    result = validate_response(
        '{"exploitable": false, "confidence": 0.1}', Verdict, llm_call=llm_call
    )
    assert result is not None
    assert result.exploitable is False
    assert len(calls) == 0


def test_retry_called_at_most_once():
    calls = []

    def llm_call() -> str:
        calls.append(1)
        return '{still invalid'

    result = validate_response('{bad', Verdict, llm_call=llm_call)
    assert result is None
    assert len(calls) == 1


def test_exception_in_retry_returns_none_not_raises():
    def llm_call() -> str:
        raise RuntimeError("provider down")

    result = validate_response('{bad', Verdict, llm_call=llm_call)
    assert result is None


def test_retry_returning_invalid_returns_none():
    def llm_call() -> str:
        return '{"exploitable": "still wrong"}'

    result = validate_response('{bad', Verdict, llm_call=llm_call)
    assert result is None


def test_does_not_raise_on_validation_error():
    raw = '{"exploitable": "wrong type"}'
    validate_response(raw, Verdict)


def test_extra_fields_in_response_are_rejected_by_default():
    class Strict(BaseModel):
        model_config = {"extra": "forbid"}
        x: int

    raw = '{"x": 1, "rogue": "extra"}'
    assert validate_response(raw, Strict) is None
