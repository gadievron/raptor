"""Uninspected oversized inputs cannot establish unchanged scalar state."""

import pytest

from core.smt_solver import BV_C_UINT8
from core.smt_solver import path_feasibility as paths
from core.smt_solver.rejection import RejectionKind

pytestmark = pytest.mark.usefixtures("native_solver")


@pytest.fixture
def native_solver():
    pytest.importorskip("z3")


def verb_query(conditions, **kwargs):
    return paths.check_verb_feasibility([], conditions, {}, **kwargs)


ENTRIES = [paths.check_path_feasibility, paths.check_path_feasibility_dual, verb_query]


def guards(texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


def oversized(tail):
    return " " * paths._MAX_CONDITION_CHARS + tail


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("reduce", [False, True])
@pytest.mark.parametrize("tail", ["Value = 1", "update(&Value) == 0", "Unknown == 0"], ids=["assignment", "address-exposure", "uninspected-predicate"])
def test_oversized_input_cannot_join_pre_and_post_values(entry, reduce, tail):
    text = oversized(tail)
    result = entry(guards(["Value == 0", text, "Value == 1"]),
                   profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is None, result
    assert result.model == {} and result.wp_complete is False
    assert result.unknown == [text]
    assert result.unknown_reasons[0].kind == RejectionKind.INPUT_TOO_LONG
    assert "unmodeled scalar value flow" in result.reasoning


@pytest.mark.parametrize("entry", ENTRIES)
@pytest.mark.parametrize("before", [True, False])
def test_independent_contradictions_survive_an_uninspected_input(entry, before):
    text = oversized("Value = 1")
    contradiction = ["Value == 0", "Value == 1"]
    texts = contradiction + [text] if before else [text] + contradiction
    result = entry(guards(texts), profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is False
    assert "mutation-free segment" in result.reasoning
    assert result.unknown == [text]


def test_oversized_refusal_does_not_inspect_or_canonicalise_the_body(monkeypatch):
    original = paths._canonicalise

    def bounded(text):
        assert len(text) <= paths._MAX_CONDITION_CHARS, "oversized input reached canonicalisation"
        return original(text)

    monkeypatch.setattr(paths, "_canonicalise", bounded)
    text = oversized("Value = 1")
    result = paths.check_path_feasibility(guards(["Value == 0", text, "Value == 1"]),
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None
    assert result.unknown_reasons[0].kind == RejectionKind.INPUT_TOO_LONG
