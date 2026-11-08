"""Prose extraction must retain the identity and extent of a predicate."""

import pytest

from core.audit.path_feasibility import (
    check_path_feasibility,
    extract_conditions_from_annotation,
    extract_conditions_from_hypothesis,
)


@pytest.mark.parametrize("suffix", [
    " || Other", " && Other", " or Other", " and Other",
    " == 0", " != 0", " ? A : B", " + 1", "[0]", "(Other)",
])
@pytest.mark.parametrize("keyword", ["if", "when", "assuming"])
def test_closed_comparison_cannot_end_inside_another_expression(keyword, suffix):
    assert extract_conditions_from_hypothesis(f"{keyword} (Count > Limit){suffix}") == []


@pytest.mark.parametrize("name", [
    "State.Count", "State . Count", "State->Count", "State -> Count",
    "Scope::Count", "Scope :: Count", "*Count", "&Count", "Other + Count",
])
@pytest.mark.parametrize("phrase", ["is non-null", "is not null", "is positive", "is non-negative", "must be greater than zero"])
def test_prose_predicate_cannot_borrow_an_expression_suffix(name, phrase):
    assert extract_conditions_from_hypothesis(f"{name} {phrase}") == []


@pytest.mark.parametrize("phrase", ["Count is positive", "Count is non-negative", "Ptr is non-null"])
@pytest.mark.parametrize("suffix", [" || Other", " && Other", " or Other", " and Other", " == 0"])
def test_prose_predicate_cannot_end_inside_a_boolean_expression(phrase, suffix):
    assert extract_conditions_from_hypothesis(phrase + suffix) == []


@pytest.mark.parametrize("text", [
    "!(Count is positive)", "!(Ptr is non-null)",
    "!(if (Count > Limit))", "(Count is positive) || Other",
    "Count is positive or Other is positive",
    "Count is positive AND Other is positive",
    "Ptr is non-null || Other is non-null",
    "if (Count > Limit) || when (Other > Limit)",
    "not Count is positive", "NOT (Ptr is non-null)",
])
def test_wrappers_cannot_hide_a_negation_or_boolean_continuation(text):
    assert extract_conditions_from_hypothesis(text) == []


@pytest.mark.parametrize("text,expected", [
    ("if (Count > Limit) then continue", "Count > Limit"),
    ("when Count > 0.", "Count > 0"),
    ("Count is positive for this path", "Count > 0"),
    ("(Count is non-negative)", "Count >= 0"),
    ("assuming (Ptr is non-null), continue", "Ptr != NULL"),
])
def test_complete_atomic_predicates_remain_available(text, expected):
    assert [item.text for item in extract_conditions_from_hypothesis(text)] == [expected]


def test_punctuation_keeps_separate_atomic_predicates():
    conditions = extract_conditions_from_hypothesis("if (Count > Limit), when (Other == 0); Ptr is non-null.")
    assert [item.text for item in conditions] == ["Count > Limit", "Other == 0", "Ptr != NULL"]


@pytest.mark.parametrize("body", [
    "if (Count > 0) || Other", "State.Count is positive",
    "Count is positive or Other", "!(Count is positive)",
])
def test_rejected_body_cannot_refute_independent_annotation_metadata(monkeypatch, body):
    pytest.importorskip("z3")
    from core.audit import sweep
    from core.audit.sweep import SweepResult
    from core.smt_solver import BVProfile
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility as solve

    def supplied_predicates(*, file_path, function_name, verb, smt_args):
        assert verb == "validate-path"
        result = solve([PathCondition(text, index) for index, text in enumerate(smt_args["conditions"])],
                       profile=BVProfile(32, True), reduce_constraints=False)
        return SweepResult(tool="smt", file_path=file_path, function_name=function_name,
                           outcome="inconclusive", details={"oracle_scope": "supplied-predicates",
                                                            "feasible": result.feasible})

    monkeypatch.setattr(sweep, "run_smt_sweep", supplied_predicates)
    conditions = extract_conditions_from_annotation({"path_conditions": "Count == 0"}, body)
    result = check_path_feasibility(conditions)
    assert result.feasible is True and not result.error
