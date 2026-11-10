"""Source bitwise precedence must not acquire the legacy shorthand meaning."""
import pytest

from core.smt_solver import BVProfile
from core.smt_solver.availability import z3
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility

pytestmark = pytest.mark.skipif(z3 is None, reason="requires native Z3")
PROFILE = BVProfile(8, False)


@pytest.mark.parametrize("predicate", ["Value | 2 == 2", "Value & 2 == 2", "2 == Value | 2", "2 == Value & 2"],
                         ids=["or-left", "and-left", "or-right", "and-right"])
def test_ungrouped_bitwise_comparisons_remain_unknown(predicate):
    result = check_path_feasibility([PathCondition("Value == 1", 0), PathCondition(predicate, 1)], profile=PROFILE)
    assert result.feasible is None, result.reasoning
    assert predicate in result.unknown
    assert any("precedence" in reason.detail for reason in result.unknown_reasons)


@pytest.mark.parametrize("predicate,expected", [
    ("(Value | 2) == 2", False), ("(Value | 2) == 3", True),
    ("(Value & 2) == 2", False), ("(Value & 2) == 0", True),
    ("(Value | 2 & 1) == 1", True),
], ids=["or-refuted", "or-sat", "and-refuted", "and-sat", "and-before-or"])
def test_explicit_grouping_retains_the_bitvector_predicate(predicate, expected):
    result = check_path_feasibility([PathCondition("Value == 1", 0), PathCondition(predicate, 1)], profile=PROFILE)
    assert result.feasible is expected, result.reasoning
    assert not result.unknown
    if expected:
        assert result.model["Value"] == 1


def test_native_source_extractor_does_not_launder_ungrouped_c_conditions():
    from core.audit.condition_extraction import extract_sink_guards

    pytest.importorskip("tree_sitter_c")
    source = "void handle(unsigned Value) {\n if (Value == 1) {\n  if (Value | 2 == 2) {\n   consume(Value);\n  }\n }\n}\n"
    sinks = extract_sink_guards(source, "app.c", sink_lines=[4])
    assert len(sinks) == 1
    conditions = [PathCondition(guard.text, i) for i, guard in enumerate(sinks[0].guards)]
    assert {condition.text for condition in conditions} == {"Value == 1", "Value | 2 == 2"}
    result = check_path_feasibility(conditions, profile=PROFILE)
    assert result.feasible is None, result.reasoning
    assert "Value | 2 == 2" in result.unknown


def test_grouped_variable_masks_are_bound_by_the_same_profile():
    result = check_path_feasibility([
        PathCondition("Value == 3", 0), PathCondition("Mask == 2", 1),
        PathCondition("(Value & Mask) == 2", 2),
    ], profile=PROFILE)
    assert result.feasible is True, result.reasoning
    assert result.model["Value"] & result.model["Mask"] == 2


def test_unrelated_contradiction_can_refute_without_using_ambiguous_guard():
    result = check_path_feasibility([
        PathCondition("Value == 1", 0), PathCondition("Value == 2", 1),
        PathCondition("Other | 2 == 2", 2),
    ], profile=PROFILE)
    assert result.feasible is False, result.reasoning
    assert "Other | 2 == 2" in result.unknown
    assert "Other | 2 == 2" not in result.unsatisfied
