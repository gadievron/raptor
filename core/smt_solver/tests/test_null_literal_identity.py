"""Literal spellings must not consume case-distinct source identifiers."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip("z3")


@pytest.mark.parametrize("name", ["Null", "null", "nUlL", "NULLValue", "_NULL"])
@pytest.mark.parametrize("reduce", [True, False])
def test_case_variants_are_real_variables(name, reduce):
    result = paths.check_path_feasibility([paths.PathCondition(f"{name} == 1", 0)],
                                          profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is True and result.model[name] == 1
    assert not paths.is_literal_identifier(name)


@pytest.mark.parametrize("profile", [BV_C_INT8, BV_C_UINT8], ids=["signed", "unsigned"])
def test_uppercase_null_is_zero_without_a_model_variable(profile):
    result = paths.check_path_feasibility([paths.PathCondition("NULL == 0", 0)],
                                          profile=profile, reduce_constraints=False)
    assert result.feasible is True and result.model == {}
    impossible = paths.check_path_feasibility([paths.PathCondition("NULL != 0", 0)], profile=profile)
    assert impossible.feasible is False
    assert paths.is_literal_identifier("NULL")


def test_case_variants_do_not_alias_each_other_or_null():
    result = paths.check_path_feasibility([paths.PathCondition(text, n) for n, text in enumerate(
        ["Null == 1", "null == 2", "nUlL == 3", "NULL == 0"])], profile=BV_C_UINT8)
    assert result.feasible is True
    assert result.model == {"Null": 1, "null": 2, "nUlL": 3}


@pytest.mark.parametrize("text", ["Pointer is null", "Pointer is NULL", "Pointer equals NULL"])
def test_english_aliases_keep_the_null_constant(text):
    result = paths.check_path_feasibility([paths.PathCondition(text, 0)], profile=BV_C_UINT8)
    assert result.feasible is True and result.model["Pointer"] == 0
    assert "null" not in result.model and "NULL" not in result.model


@pytest.mark.parametrize("reduce", [True, False])
def test_call_summary_arguments_keep_case_distinct_variables(reduce):
    result = paths.check_path_feasibility([paths.PathCondition("min(Null, 4) == 2", 0),
                                           paths.PathCondition("Null == 2", 1)],
                                          profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is True and result.model["Null"] == 2
    assert result.summary_axioms == ["summary: min(Null, 4)"]


def test_dual_profile_contradictions_still_count_case_variants_as_variables():
    result = paths.check_path_feasibility_dual([paths.PathCondition("null == 1", 0),
                                                paths.PathCondition("null == 2", 1)],
                                               profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is False and result.unsatisfied


def test_null_like_variable_cannot_hide_mixed_profile_ambiguity():
    # Uniform signed and unsigned frames both contradict this conjunction,
    # but neither represents mixed per-variable C conversions. Two real
    # identifiers must not become a single-identifier contradiction proof.
    result = paths.check_path_feasibility_dual([
        paths.PathCondition("null == Value", 0),
        paths.PathCondition("Value > 0x7f", 1),
        paths.PathCondition("null <= 0x7f", 2),
    ], profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None


def test_public_variable_builder_cannot_create_a_reserved_literal_symbol(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("reserved literal must be rejected before native allocation")
    monkeypatch.setattr(paths, "_mk_var", forbidden)
    variables = {}
    with pytest.raises(ValueError, match="reserved zero literal"):
        paths.make_var("NULL", variables, profile=BV_C_UINT8)
    assert variables == {}
