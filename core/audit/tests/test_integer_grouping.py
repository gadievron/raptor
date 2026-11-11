"""Alternative grouping is an observable truth difference, not an intent claim."""

import pytest

from core.audit import integer_grouping as grouping
from core.testing.module_views import module_function_view
from core.smt_solver import z3
from core.smt_solver.session import query_budget

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")
pytest.importorskip("z3")

SOURCE = "int Test(unsigned int Flags) { if(Flags & 4 == 4) return 1; return 0; }"
CLAIM = "Condition grouping changes truth in `Flags & 4 == 4`."


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("spelling,abi", [("unsigned int", "lp64"), ("signed char", "ilp32"), ("unsigned char", "i16"), ("long long", "llp64")])
def test_actual_and_grouped_truths_have_a_checked_entry_witness(language, spelling, abi):
    pytest.importorskip("tree_sitter_cpp" if language == "cpp" else "tree_sitter_c")
    source = SOURCE.replace("unsigned int", spelling)
    result = grouping.check_integer_grouping(source, CLAIM, language=language, integer_abi=abi)
    assert result["matches_claim"] is True, result
    value = result["entry_witness"]["Flags"]
    assert result["actual_truth"] is bool(value & 1)
    assert result["grouped_truth"] is ((value & 4) == 4)
    assert result["actual_truth"] != result["grouped_truth"]
    assert result["actual_expression"] == "Flags & 4 == 4"
    assert result["grouped_expression"] == "(Flags & 4) == 4"
    assert "constant_truth" not in result
    assert result["proof_scope"] == "function-entry-source-model"


def test_reaching_guards_can_make_the_groupings_equivalent():
    source = SOURCE.replace("if(Flags &", "if(Flags != 0) return 0; if(Flags &")
    result = grouping.check_integer_grouping(source, CLAIM, language="c", integer_abi="lp64")
    assert result["comparison_status"] == "checked" and result["matches_claim"] is False
    assert "entry_witness" not in result
    unreachable = SOURCE.replace("if(Flags &", "if(Flags > 0 && Flags < 0) { if(Flags &").replace("return 0; }", "} return 0; }")
    result = grouping.check_integer_grouping(unreachable, CLAIM, language="c", integer_abi="lp64")
    assert result["comparison_status"] == "checked" and result["matches_claim"] is None
    assert "entry_witness" not in result


@pytest.mark.parametrize("source,claim", [
    (SOURCE.replace("Flags & 4 == 4", "(Flags & 4) == 4"), CLAIM),
    (SOURCE.replace("unsigned int Flags", "int *Flags"), CLAIM),
    (SOURCE.replace("if(Flags &", "Flags = 4; if(Flags &"), CLAIM),
    (SOURCE.replace("if(Flags &", "unknown(); if(Flags &"), CLAIM),
    (SOURCE.replace("4 == 4", "4U == 4"), CLAIM),
    (SOURCE.replace("4 == 4", "4294967295 == 4"), CLAIM.replace("4 == 4", "4294967295 == 4")),
    (SOURCE.replace("Flags & 4 == 4", "Flags & Other == 4"), CLAIM),
    (SOURCE, "No " + CLAIM),
    (SOURCE, CLAIM.replace("4 == 4", "8 == 8")),
])
def test_unbound_effectful_or_qualified_objectives_have_no_positive_credit(source, claim):
    result = grouping.check_integer_grouping(source, claim, language="c", integer_abi="lp64")
    assert result["matches_claim"] is not True and "entry_witness" not in result


def test_unknown_expired_budget_and_bad_replay_cannot_confirm():
    for bindings in ({"check_solver": lambda *args: z3.unknown}, {"format_vars": lambda *args, **kwargs: {"Flags": 0}}):
        view = module_function_view(grouping, bindings=bindings)
        result = view.check_integer_grouping(SOURCE, CLAIM, language="c", integer_abi="lp64")
        assert result["matches_claim"] is not True and "entry_witness" not in result
    with query_budget(0):
        assert grouping.check_integer_grouping(SOURCE, CLAIM, language="c", integer_abi="lp64")["matches_claim"] is not True


def test_discovery_preserves_explicit_grouping_and_existing_false_cases():
    assert len(grouping.grouping_candidates(SOURCE, language="c", integer_abi="lp64")) == 1
    for expression in ("Flags & (4 == 4)", "Flags & 4 == 0", "Flags & 1 == 1", "(Flags & 4) == 4"):
        assert not grouping.grouping_candidates(SOURCE.replace("Flags & 4 == 4", expression), language="c", integer_abi="lp64")


@pytest.mark.parametrize("op,right", [("==", 4), ("!=", 0), ("<", 8), ("<=", 4), (">", 2), (">=", 4)])
def test_each_comparison_operator_is_replayed_under_both_groupings(op, right):
    import operator

    compare = {"==": operator.eq, "!=": operator.ne, "<": operator.lt,
               "<=": operator.le, ">": operator.gt, ">=": operator.ge}[op]
    expression = f"Flags & 4 {op} {right}"
    result = grouping.check_integer_grouping(SOURCE.replace("Flags & 4 == 4", expression),
                                             CLAIM.replace("Flags & 4 == 4", expression),
                                             language="c", integer_abi="lp64")
    assert result["matches_claim"] is True, result
    value = result["entry_witness"]["Flags"]
    assert result["actual_truth"] is bool(value & int(compare(4, right)))
    assert result["grouped_truth"] is compare(value & 4, right)
    assert result["actual_truth"] != result["grouped_truth"]


def test_duplicate_source_conditions_are_ambiguous():
    source = SOURCE.replace("return 0; }", "if(Flags & 4 == 4) return 2; return 0; }")
    result = grouping.check_integer_grouping(source, CLAIM, language="c", integer_abi="lp64")
    assert result["comparison_status"] == "unavailable" and result["matches_claim"] is None


@pytest.mark.parametrize("other", ["Flags & 4 == 4", "Flags & (4 == 4)"])
def test_ambiguous_shapes_do_not_consume_discovery_slots(other):
    source = SOURCE.replace("return 0; }", f"if({other}) return 2; return 0; }}")
    result = grouping.check_integer_grouping(source, CLAIM, language="c", integer_abi="lp64")
    assert result["comparison_status"] == "unavailable"
    assert grouping.grouping_candidates(source, language="c", integer_abi="lp64") == []


def test_ambiguous_shapes_preserve_distinct_discovery_candidates():
    source = SOURCE.replace("return 0; }", "if(Flags & 4 == 4) return 2; if(Flags & 8 == 8) return 3; return 0; }")
    candidates = grouping.grouping_candidates(source, language="c", integer_abi="lp64")
    assert [shape[1:] for shape in candidates] == [("Flags", "8", "==", "8")]
