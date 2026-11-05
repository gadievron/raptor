"""Case distinguishes source identifiers in both parsed and intrinsic models."""

import pytest

from core.smt_solver import BV_C_INT32, BV_C_UINT32, BV_C_UINT64
from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility, check_path_feasibility_dual, make_var


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip("z3")


@pytest.mark.parametrize("profile", [BV_C_UINT32, BV_C_INT32, BV_C_UINT64], ids=["u32", "i32", "u64"])
def test_parser_keeps_case_distinct_variables(profile):
    result = check_path_feasibility([PathCondition("Value == 1", 0), PathCondition("value == 2", 1)], profile=profile)
    assert result.feasible is True
    assert result.model == {"Value": 1, "value": 2}
    contradiction = check_path_feasibility([
        PathCondition("Value == value", 0), PathCondition("Value == 1", 1), PathCondition("value == 2", 2),
    ], profile=profile)
    assert contradiction.feasible is False


def test_intrinsic_variables_share_only_exact_names():
    variables = {}
    upper = make_var("Value", variables, profile=BV_C_UINT32)
    lower = make_var("value", variables, profile=BV_C_UINT32)
    assert upper.eq(make_var("Value", variables, profile=BV_C_UINT32))
    assert not upper.eq(lower)
    assert set(variables) == {"Value", "value"}


@pytest.mark.parametrize("guard_name,feasible", [("Value", False), ("value", True)])
def test_verb_and_guard_symbols_agree_only_on_exact_names(guard_name, feasible):
    from packages.exploit_feasibility.smt_verbs import check_overflow

    result = check_overflow(["Value", "Step"], "+", profile="uint32", guards=[f"{guard_name} <= 10", "Step <= 10"])
    assert result["feasible"] is feasible
    if feasible:
        assert {"Value", "value", "Step"} <= result["model"].keys()


@pytest.mark.parametrize("verb", ["bounds", "nullability", "negative-bypass"])
def test_named_intrinsics_do_not_borrow_a_case_distinct_guard(verb):
    from packages.exploit_feasibility.smt_verbs import check_oob, check_null_deref, check_negative_bypass

    if verb == "bounds":
        result = check_oob("Size", "Index", guards=["index < Size"])
    elif verb == "nullability":
        result = check_null_deref("Ptr", guards=["ptr != 0"])
    else:
        result = check_negative_bypass("Value", "Limit", guards=["value >= 0"])
    assert result["feasible"] is True


def test_dual_profile_robustness_counts_case_distinct_identifiers():
    result = check_path_feasibility_dual([
        PathCondition("r == R", 0),
        PathCondition("R > 0x7FFFFFFFFFFFFFFF", 1),
        PathCondition("r <= 0x7FFFFFFFFFFFFFFF", 2),
    ])
    assert result.feasible is None
    assert "refusing the refutation" in result.reasoning
