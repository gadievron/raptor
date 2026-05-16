"""Tests for ``core.dataflow.validator``."""

from __future__ import annotations

from core.dataflow import Finding, Step
from core.dataflow.validator import (
    TrivialValidator,
    Validator,
    ValidatorVerdict,
)


def _finding() -> Finding:
    s = Step(file_path="x.py", line=1, column=0, snippet="src", label="source")
    t = Step(file_path="x.py", line=2, column=0, snippet="snk", label="sink")
    return Finding(
        finding_id="f1",
        producer="codeql",
        rule_id="r",
        message="m",
        source=s,
        sink=t,
    )


def test_validator_verdict_string_enum_round_trips():
    assert ValidatorVerdict("exploitable") == ValidatorVerdict.EXPLOITABLE
    assert ValidatorVerdict.EXPLOITABLE.value == "exploitable"


def test_trivial_validator_always_says_exploitable():
    v = TrivialValidator()
    assert v.validate(_finding()) == ValidatorVerdict.EXPLOITABLE


def test_trivial_validator_satisfies_protocol():
    assert isinstance(TrivialValidator(), Validator)
