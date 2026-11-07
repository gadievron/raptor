"""Opaque calls exposing addresses cannot freeze scalar state across guards."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths

pytestmark = pytest.mark.usefixtures("require_native")


@pytest.fixture
def require_native():
    pytest.importorskip("z3")


def conditions(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


def verb_query(guards, **kwargs):
    return paths.check_verb_feasibility([], guards, {}, **kwargs)


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query])
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("call", ["update(&Value) == 0", "update (&Value) == 0", "outer(inner(&Value)) == 0"])
def test_address_exposing_call_is_a_scalar_state_barrier(entry, reduce, call):
    result = entry(conditions("Value == 0", call, "Value == 1"),
                   profile=BVProfile(8, False), reduce_constraints=reduce)
    assert result.feasible is None
    assert result.model == {} and result.wp_complete is False
    assert result.unknown == [call]
    assert result.unknown_reasons[0].kind.value == "unmodeled_state_effect"
    assert "unmodeled scalar value flow" in result.reasoning


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query])
@pytest.mark.parametrize("texts,epoch", [
    (("Value == 0", "Value == 1", "update(&Other) == 0"), 0),
    (("update(&Other) == 0", "Value == 0", "Value == 1"), 1),
])
def test_independent_contradictions_keep_their_segment_proof(entry, texts, epoch):
    result = entry(conditions(*texts), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is False
    assert f"mutation-free segment {epoch}" in result.reasoning
    assert result.unknown and result.wp_complete is False


@pytest.mark.parametrize("text", [
    'probe("Value=1") == 0', 'probe("Value++") == 0',
    'probe("&Value") == 0', "probe('&') == 0",
    'probe("Value = 1 && &Other") == 0',
    r'probe("escaped\"&Value") == 0',
    "probe(A && B) == 0", "Flags & 1 == 0",
])
def test_literal_bytes_and_non_call_bitmasks_do_not_create_state_effects(text):
    result = paths.check_path_feasibility(conditions(text), profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is True and result.unknown == []


def test_real_effect_after_quoted_text_still_creates_a_barrier():
    call = 'update("& is quoted", &Value) == 0'
    result = paths.check_path_feasibility(conditions("Value == 0", call, "Value == 1"),
                                          profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is None and result.unknown == [call]


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query])
def test_state_effect_refusal_adds_no_solver_queries(monkeypatch, entry):
    original = paths._new_solver
    queries = []

    def factory(*args, **kwargs):
        solver = original(*args, **kwargs)
        check = solver.check

        def counted(*assumptions):
            queries.append(1)
            return check(*assumptions)

        monkeypatch.setattr(solver, "check", counted)
        return solver

    monkeypatch.setattr(paths, "_new_solver", factory)
    result = entry(conditions("Value == 0", "update(&Value) == 0", "Value == 1"),
                   profile=BVProfile(8, False), reduce_constraints=False)
    assert result.feasible is None and queries == [1]


@pytest.mark.parametrize("text", ["update(&Value)", "outer(inner(&Value))", "update(Value++)", "update(Value=1)"])
def test_effectful_operand_declines_before_symbol_or_theory_allocation(monkeypatch, text):
    def forbidden(*args, **kwargs):
        pytest.fail("effectful operand reached native allocation")

    monkeypatch.setattr(paths, "make_anon_call_var", forbidden)
    registry = {}
    model = paths.CallOperandModel()
    with pytest.raises(ValueError, match="state effects"):
        paths.make_call_operand(text, registry, profile=BVProfile(8, False), model=model)
    assert registry == {} and model.axioms == [] and model.anon_var_map == {}


@pytest.mark.parametrize("verb", ["overflow", "bounds", "null", "chain", "negative"])
def test_named_consumers_reject_effectful_call_operands(verb):
    from packages.exploit_feasibility import smt_verbs as verbs

    with pytest.raises(ValueError, match="state effects"):
        if verb == "overflow":
            verbs.check_overflow(["Value", "update(&Value)"], "*", guards=["Value == 0"])
        elif verb == "bounds":
            verbs.check_oob("Value", "update(&Value)")
        elif verb == "null":
            verbs.check_null_deref("update(&Value)")
        elif verb == "chain":
            verbs.check_overflow_to_oob("Value", "update(&Value)", "Index")
        else:
            verbs.check_negative_bypass("update(&Value)", "Limit")


def test_quoted_operand_data_does_not_create_a_state_effect():
    model = paths.CallOperandModel()
    value = paths.make_call_operand('probe("Value++ & Other=1")', {}, profile=BVProfile(8, False), model=model)
    assert model.anon_var_map[str(value)] == 'probe("Value++ & Other=1")'
