"""Generated call symbols cannot consume real source identifier spellings."""

import pytest

from core.smt_solver import BV_C_UINT32
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_verb_feasibility, make_anon_call_var


@pytest.fixture(autouse=True)
def solver():
    pytest.importorskip("z3")


@pytest.mark.parametrize("conditions", [
    pytest.param(["read_value() == 1", "_anon_0 == 0"], id="source-name-later"),
    pytest.param(["_anon_0 == 0", "read_value() == 1"], id="source-name-first"),
    pytest.param(["read_value() == _anon_0", "_anon_0 == 1"], id="same-condition"),
    pytest.param(["read_value() != _anon_0"], id="not-a-tautology"),
    pytest.param(["read_value() == 1", "other_value() == 2", "_anon_0 == 0", "_anon_2 == 3"], id="reserved-gaps"),
])
def test_call_placeholders_are_disjoint_from_source_names(conditions):
    result = check_path_feasibility([PathCondition(text, i) for i, text in enumerate(conditions)], profile=BV_C_UINT32)
    assert result.feasible is True, result.reasoning
    assert not result.unknown
    source_names = {name for text in conditions for name in ("_anon_0", "_anon_2") if name in text}
    assert not source_names.intersection(result.anon_var_map)


def test_repeated_opaque_calls_remain_distinct_from_each_other_and_source_names():
    result = check_path_feasibility([PathCondition("read_value() == 1", 0), PathCondition("read_value() == 2", 1),
                                     PathCondition("_anon_0 == 0", 2)], profile=BV_C_UINT32)
    assert result.feasible is True
    assert len(result.anon_var_map) == 2
    assert "_anon_0" not in result.anon_var_map


def test_sparse_large_source_suffixes_do_not_inflate_generated_labels():
    name = "_anon_" + "9" * 1000
    result = check_path_feasibility([PathCondition(f"{name} == 0", 0), PathCondition("read_value() == 1", 1)], profile=BV_C_UINT32)
    assert result.feasible is True
    assert result.anon_var_map == {"_anon_0": "read_value()"}


def test_unused_reservations_do_not_create_objective_or_witness_values():
    # A source-looking name inside an opaque call argument is reserved but
    # is not a parsed independent variable or a valid optimization target.
    result = check_path_feasibility([PathCondition("read_value(_anon_0) == 1", 0)], profile=BV_C_UINT32,
                                    prefer_witness=("_anon_0", "max"))
    assert result.feasible is True
    assert "_anon_0" not in result.model
    assert "_anon_0" not in result.anon_var_map


def test_low_level_intrinsic_allocator_is_safe_before_future_guards_are_known():
    variables = {}
    pointer = make_anon_call_var(variables, profile=BV_C_UINT32)
    result = check_verb_feasibility([("call result is zero", pointer == 0)],
                                    [PathCondition("_anon_0 != 0", 0)], variables, profile=BV_C_UINT32)
    assert result.feasible is True
    assert result.model["_anon_0"] != 0
    assert "!" in str(pointer)


@pytest.mark.parametrize("verb", ["overflow", "bounds", "nullability", "overflow-to-oob", "negative-bypass"])
def test_named_verbs_do_not_borrow_real_anon_prefix_guards(verb):
    from packages.exploit_feasibility import smt_verbs as verbs
    if verb == "overflow":
        result = verbs.check_overflow(["read_value()", "_anon_0"], "+", guards=["_anon_0 == 1"])
    elif verb == "bounds":
        result = verbs.check_oob("Size", "read_value()", guards=["_anon_0 == 0", "Size == 1"])
    elif verb == "nullability":
        result = verbs.check_null_deref("read_value()", guards=["_anon_0 != 0"])
    elif verb == "overflow-to-oob":
        result = verbs.check_overflow_to_oob("read_value()", "16", "Index", guards=["_anon_0 == 0", "Index == 1"])
    else:
        result = verbs.check_negative_bypass("read_value()", "Limit", guards=["_anon_0 >= 0", "Limit == 10"])
    assert result["feasible"] is True, result["reasoning"]
    assert not result["unknown"]
    assert "_anon_0" in result["model"]


def test_guard_iterators_are_not_consumed_by_symbol_reservation():
    from packages.exploit_feasibility.smt_verbs import check_null_deref
    result = check_null_deref("Pointer", guards=iter(["Pointer != 0"]))
    assert result["feasible"] is False


def test_summary_arguments_remain_source_variables_instead_of_result_aliases():
    result = check_path_feasibility([PathCondition("min(_anon_0, 1) == 1", 0),
                                     PathCondition("_anon_0 == 2", 1)], profile=BV_C_UINT32)
    assert result.feasible is True
    assert result.model["_anon_0"] == 2
    assert result.summary_axioms
    assert "_anon_0" not in result.anon_var_map
