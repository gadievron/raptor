"""Text guards must denote the same formula in path and intrinsic queries."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths
from core.smt_solver.rejection import RejectionKind


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip("z3")


def conditions(texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


def verb_query(texts, profile, reduce):
    import z3
    return paths.check_verb_feasibility([("intrinsic true", z3.BoolVal(True))],
                                        conditions(texts), {}, profile=profile, reduce_constraints=reduce)


@pytest.mark.parametrize("reduce", [True, False])
@pytest.mark.parametrize("texts,expected", [
    (["probe(Data) == 1", "probe(Data) == 2"], True),
    (["probe(Data) == 1", "probe(Other) == 2"], True),
    (["probe(Data) == 1", "Probe(Data) == 2"], True),
    (["strlen(Data) < 0"], False),
    (["sizeof(Data) == 0"], False),
    (["min(Value, 4) > 4"], False),
    (["max(Value, 4) < 4"], False),
    (["abs(Value) == -1"], False),
    (["abs(Value) == -128", "Value == -128"], True),
    (["project_size(Data) < 0"], True),
], ids=["separate-occurrences", "different-args", "case-sensitive-call", "nonnegative", "sizeof", "min", "max",
        "abs-negative", "abs-minimum", "unknown-call"])
def test_path_and_intrinsic_guards_agree(texts, expected, reduce):
    path = paths.check_path_feasibility(conditions(texts), profile=BV_C_INT8, reduce_constraints=reduce)
    verb = verb_query(texts, BV_C_INT8, reduce)
    assert path.feasible is expected and verb.feasible is expected
    assert path.anon_var_map == verb.anon_var_map
    assert path.summary_axioms == verb.summary_axioms
    assert not path.unknown and not verb.unknown
    assert verb.wp_complete is reduce


@pytest.mark.parametrize("reduce", [True, False])
@pytest.mark.parametrize("barrier", ["Data = replacement", "Data += 1", "Data++"])
def test_mutation_barriers_preserve_distinct_call_values(barrier, reduce):
    texts = ["probe(Data) == 1", barrier, "probe(Data) == 2"]
    result = verb_query(texts, BV_C_INT8, reduce)
    assert result.feasible is None
    assert result.unknown == [barrier]
    assert result.unknown_reasons[0].kind is RejectionKind.ASSIGNMENT_SHAPED
    assert list(result.anon_var_map.values()) == ["probe(Data)", "probe(Data)"]
    values = [result.model[name] for name in result.anon_var_map]
    assert values == [1, 2]
    assert result.wp_complete is False


@pytest.mark.parametrize("reduce", [True, False])
def test_each_mutation_window_retains_its_own_axioms(reduce):
    texts = ["strlen(Data) == 1", "Data = replacement", "strlen(Data) == 2"]
    result = verb_query(texts, BV_C_INT8, reduce)
    assert result.feasible is None
    assert result.summary_axioms == ["summary: strlen(Data)"] * 2
    assert len(result.anon_var_map) == 2


@pytest.mark.parametrize("reduce", [True, False])
def test_all_source_identifiers_are_reserved_before_guard_allocation(reduce):
    import z3
    real = z3.BitVec("_anon_0", 8)
    variables = {"_anon_0": real}
    result = paths.check_verb_feasibility([("source value", real == 7)],
                                         conditions(["probe(Data) == 1", "_anon_1 == 3"]), variables,
                                         profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is True
    assert result.model["_anon_0"] == 7 and result.model["_anon_1"] == 3
    assert result.anon_var_map == {"_anon_2": "probe(Data)"}
    assert result.model["_anon_2"] == 1


def test_guard_frames_do_not_leak_between_queries():
    first = verb_query(["probe(Data) == 1"], BV_C_INT8, False)
    second = verb_query(["probe(Data) == 2"], BV_C_INT8, False)
    assert first.feasible is second.feasible is True
    assert first.model["_anon_0"] == 1 and second.model["_anon_0"] == 2


@pytest.mark.parametrize("reduce", [True, False])
def test_summary_that_is_vacuous_for_unsigned_profiles_is_not_reported(reduce):
    result = verb_query(["strlen(Data) == 2"], BV_C_UINT8, reduce)
    assert result.feasible is True and result.summary_axioms == []
    assert result.anon_var_map == {"_anon_0": "strlen(Data)"}


@pytest.mark.parametrize("reduce", [True, False])
def test_negated_guard_preserves_explicit_scalar_identity(reduce):
    import z3
    guards = [paths.PathCondition("Result == 1", 0),
              paths.PathCondition("Result == 1", 1, negated=True)]
    result = paths.check_verb_feasibility([("intrinsic true", z3.BoolVal(True))], guards, {},
                                         profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is False
    assert set(result.unsatisfied) == {"Result == 1", "NOT (Result == 1)"}


@pytest.mark.parametrize("profile,values", [(BV_C_INT8, [-5, 0, 7]), (BV_C_UINT8, [0, 7, 250])],
                         ids=["signed", "unsigned"])
@pytest.mark.parametrize("callee,operation", [("min", min), ("max", max)])
@pytest.mark.parametrize("reduce", [True, False])
def test_summary_witnesses_match_independent_integer_arithmetic(profile, values, callee, operation, reduce):
    import z3
    for value in values:
        variable = z3.BitVec("Value", 8)
        call = f"{callee}(Value, 4)"
        result = paths.check_verb_feasibility([("fixed operand", variable == value)],
                                             conditions([f"{call} >= {-128 if profile.signed else 0}"]), {"Value": variable},
                                             profile=profile, reduce_constraints=reduce)
        assert result.feasible is True
        assert result.summary_axioms == [f"summary: {call}"]
        placeholder, = result.anon_var_map
        assert result.model[placeholder] == operation(value, 4)
