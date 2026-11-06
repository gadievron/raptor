"""Independent operand occurrences retain their own bounded call theory."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths
from core.smt_solver.call_arguments import find_call_end


@pytest.mark.parametrize("text,valid", [
    ('strnlen("a)b", 4)', True), ('strnlen("a(b", 4)', True),
    ('probe(\')\')', True), ('probe(inner("["), Data[2])', True),
    ('probe("escaped\\\"(quote")', True), ('probe("unfinished)', False),
    ('probe(Data[))', False), ('probe(Data)', True),
    ('probe(Data) + 1', False), ('probe(Data', False),
], ids=["quoted-close", "quoted-open", "character-close", "nested", "escaped-quote",
        "unclosed-quote", "mismatched-bracket", "ordinary", "trailing-expression", "unclosed"])
def test_balanced_call_syntax_respects_literals(text, valid):
    assert paths.is_balanced_call(text) is valid


def test_call_boundary_stops_before_trailing_conditions():
    text = 'strnlen("a)b", 4) == 0'
    assert find_call_end(text, text.index("(")) == text.index(" ==")
    assert find_call_end(text, -1) is None
    assert find_call_end(text, len(text)) is None


@pytest.fixture
def native():
    return pytest.importorskip("z3")


@pytest.mark.parametrize("profile", [BV_C_INT8, BV_C_UINT8], ids=["signed", "unsigned"])
def test_operand_occurrences_have_distinct_identities_and_complete_labels(native, profile):
    model = paths.CallOperandModel()
    variables = {}
    first = paths.make_call_operand("probe(Data)", variables, profile=profile, model=model)
    second = paths.make_call_operand("probe(Data)", variables, profile=profile, model=model)
    assert not first.eq(second)
    assert len(model.anon_var_map) == 2 and model.axioms == []
    assert list(model.anon_var_map.values()) == ["probe(Data)"] * 2


@pytest.mark.parametrize("reduce", [True, False])
def test_operand_theory_is_solved_even_without_intrinsics_or_guards(native, reduce):
    model = paths.CallOperandModel()
    variables = {}
    value = paths.make_call_operand("strnlen(Data, 0)", variables, profile=BV_C_UINT8, model=model)
    result = paths.check_verb_feasibility([], [], variables, profile=BV_C_UINT8,
                                          operand_model=model, reduce_constraints=reduce)
    assert result.feasible is True and result.model[str(value)] == 0
    assert result.summary_axioms == ["summary: strnlen(Data, 0)"]
    assert result.anon_var_map == model.anon_var_map


def test_impossible_background_theory_cannot_be_skipped(native):
    model = paths.CallOperandModel(axioms=[("impossible theory", native.BoolVal(False))])
    result = paths.check_verb_feasibility([], [], {}, profile=BV_C_UINT8,
                                          operand_model=model, reduce_constraints=False)
    assert result.feasible is False and result.unsatisfied == ["impossible theory"]


@pytest.mark.parametrize("text", ['min(Value, 4) == min(Value, 4)', 'strnlen("a)b", 4) == strnlen("a)b", 4)'])
def test_repeated_call_guards_keep_each_reported_theory(native, text):
    result = paths.check_path_feasibility([paths.PathCondition(text, 0)], profile=BV_C_UINT8)
    assert result.feasible is True and result.satisfied == []
    assert len(result.anon_var_map) == len(result.summary_axioms) == 2
    assert result.model and result.wp_complete is True
    assert result.wp_conjuncts == ([] if text.startswith("min(") else [text])


def test_summary_supported_guard_keeps_witness_preference(native):
    result = paths.check_path_feasibility([paths.PathCondition("min(Value, 4) == min(Value, 4)", 0)],
                                          profile=BV_C_UINT8, prefer_witness=("Value", "max"))
    assert result.feasible is True and result.model["Value"] == 255


@pytest.mark.parametrize("operand", ["probe(Data", "probe(Data) + 1", "probe(" + "x" * 2049 + ")"])
def test_invalid_call_operand_is_rejected_before_allocation(monkeypatch, native, operand):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid input must stop before native symbol allocation")
    monkeypatch.setattr(paths, "make_anon_call_var", forbidden)
    model = paths.CallOperandModel()
    with pytest.raises(ValueError):
        paths.make_call_operand(operand, {}, profile=BV_C_UINT8, model=model)
    assert model.anon_var_map == {} and model.axioms == []


def test_operand_theory_does_not_acquire_mutation_segment_ownership(native):
    model = paths.CallOperandModel(axioms=[("unowned operand theory", native.BoolVal(False))])
    result = paths.check_verb_feasibility([], [paths.PathCondition("Value = 2", 0)], {},
                                          profile=BV_C_UINT8, operand_model=model, reduce_constraints=False)
    assert result.feasible is None and result.wp_complete is False


@pytest.mark.parametrize("literal", ['"A equals B"', '"A  B"', '"is null"', '"an escaped\\\" equals value"'])
def test_canonicalisation_preserves_literal_bytes(literal):
    from core.smt_solver.canonicalise import canonicalise

    text = f"probe({literal}) is greater than 0"
    result = canonicalise(text)
    assert result == f"probe({literal}) > 0"
    assert canonicalise(result) == result


@pytest.mark.parametrize("first,second", [("A equals B", "A == B"), ("A  B", "A B")])
@pytest.mark.parametrize("reduce", [True, False])
def test_quoted_arguments_cannot_be_canonicalised_into_false_identity(native, first, second, reduce):
    texts = [f'strlen("{first}") == {len(first)}', f'strlen("{second}") == {len(second)}']
    result = paths.check_path_feasibility([paths.PathCondition(text, n) for n, text in enumerate(texts)],
                                          profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is True
    assert list(result.anon_var_map.values()) == [f'strlen("{first}")', f'strlen("{second}")']
    assert list(result.model[name] for name in result.anon_var_map) == [len(first), len(second)]


def test_operand_model_cannot_bypass_the_complete_obligation_budget(monkeypatch, native):
    def forbidden(*args, **kwargs):
        pytest.fail("over-budget query must not create a solver")
    monkeypatch.setattr(paths, "_new_solver", forbidden)
    model = paths.CallOperandModel()
    variables = {}
    paths.make_call_operand("strnlen(Data, 4)", variables, profile=BV_C_UINT8, model=model)
    guards = [paths.PathCondition(f"Value == {n}", n) for n in range(64)]
    result = paths.check_verb_feasibility([("intrinsic", native.BoolVal(True))], guards, variables,
                                          profile=BV_C_UINT8, operand_model=model, reduce_constraints=False)
    assert result.feasible is None and result.summary_axioms == []
