"""Worker failure must not invent feasibility for scalar integer constraints."""

import operator

import pytest

from core.audit.condition_extraction import GuardCondition
from core.audit.condition_smt import BoundsConstraint, _arithmetic_path_feasibility, check_path_feasibility


@pytest.mark.parametrize("terms,feasible", [
    pytest.param([("==", 5), ("==", 10)], False, id="incompatible-equalities"),
    pytest.param([("==", 5), ("!=", 5)], False, id="excluded-equality"),
    pytest.param([("==", 5), ("<", 5)], False, id="strict-upper-bound"),
    pytest.param([(">=", 0), ("<=", 1), ("!=", 0), ("!=", 1)], False, id="finite-domain-exhausted"),
    pytest.param([(">=", 0), ("<=", 2), ("!=", 0), ("!=", 1)], True, id="single-remaining-value"),
    pytest.param([("!=", 0), ("!=", 1)], True, id="unbounded-exclusions"),
    pytest.param([("<", -1), ("!=", -2)], True, id="upper-only-with-exclusion"),
    pytest.param([(">", 10**100), ("!=", 10**100 + 1)], True, id="large-unbounded-domain"),
    pytest.param([("unsupported", 1)], None, id="unsupported-operator"),
    pytest.param([("==", True)], None, id="boolean-bound-is-not-integer"),
])
def test_fallback_decides_the_complete_supported_integer_model(terms, feasible):
    constraints = [BoundsConstraint("Value", op, value, "owned constraint") for op, value in terms]
    result = _arithmetic_path_feasibility(constraints, 1)
    assert result.feasible is feasible
    if feasible:
        comparisons = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
                       "==": operator.eq, "!=": operator.ne}
        assert all(comparisons[op](result.witness["Value"], value) for op, value in terms)
    else:
        assert result.witness is None


def test_fallback_keeps_variables_independent():
    result = _arithmetic_path_feasibility([BoundsConstraint("Value", "==", 1, ""), BoundsConstraint("value", "==", 2, "")], 2)
    assert result.feasible is True and result.witness == {"Value": 1, "value": 2}


def test_equality_contradiction_is_decided_when_the_worker_is_unavailable(monkeypatch):
    monkeypatch.setattr("core.audit.condition_smt._try_z3_path_feasibility", lambda *a: None)
    guards = [GuardCondition(text=f"Value == {value}", category="bounds", polarity="required", line=1,
                             resolvable=True, concrete_values={}) for value in (5, 10)]
    result = check_path_feasibility(guards)
    assert result.feasible is False


def test_interval_fallback_matches_exhaustive_bounded_integer_enumeration():
    comparisons = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
                   "==": operator.eq, "!=": operator.ne}
    for left in comparisons:
        for right in comparisons:
            for a in range(-2, 3):
                for b in range(-2, 3):
                    constraints = [BoundsConstraint("Value", ">=", -3, ""), BoundsConstraint("Value", "<=", 3, ""),
                                   BoundsConstraint("Value", left, a, ""), BoundsConstraint("Value", right, b, "")]
                    expected = any(comparisons[left](value, a) and comparisons[right](value, b) for value in range(-3, 4))
                    result = _arithmetic_path_feasibility(constraints, 4)
                    assert result.feasible is expected, (left, right, a, b)
