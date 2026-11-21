"""A refutation resting on an assumption-tier summary axiom is demoted.

``sizeof != 0`` is an assumption, not a contract: GNU C zero-size
objects (zero-length array members, empty structs) have ``sizeof`` 0,
so an unsat whose native core needs that axiom proves only that the
assumption conflicts with the path. Contract-tier axioms (strlen /
strnlen / abs / min-max semantics of the genuine callee) remain
refutation-grade.
"""

from unittest.mock import patch

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip("z3")


def conditions(*texts):
    return [paths.PathCondition(text, index) for index, text in enumerate(texts)]


@pytest.mark.parametrize("reduce", [True, False])
@pytest.mark.parametrize("entry", [paths.check_path_feasibility,
                                   paths.check_path_feasibility_dual])
@pytest.mark.parametrize("profile", [BV_C_UINT8, BV_C_INT8])
def test_sizeof_dependent_refutation_is_demoted(entry, profile, reduce):
    result = entry(conditions("sizeof(Buf) == 0"), profile=profile,
                   reduce_constraints=reduce)
    assert result.feasible is None
    assert result.summary_axioms == ["summary: sizeof(Buf)"]
    assert "background assumption" in result.reasoning
    assert "summary: sizeof(Buf)" in result.reasoning
    assert "refusing the refutation" in result.reasoning


@pytest.mark.parametrize("reduce", [True, False])
@pytest.mark.parametrize("texts,axiom", [
    (("strlen(Data) < 0",), "summary: strlen(Data)"),
    (("strnlen(Data, 4) > 4",), "summary: strnlen(Data, 4)"),
    (("abs(Value) == -1",), "summary: abs(Value)"),
    (("min(0, 4) > 4",), "summary: min(0, 4)"),
], ids=["strlen", "strnlen", "abs", "min"])
def test_contract_tier_axioms_still_refute(texts, axiom, reduce):
    result = paths.check_path_feasibility(conditions(*texts),
                                          profile=BV_C_INT8,
                                          reduce_constraints=reduce)
    assert result.feasible is False
    assert result.summary_axioms == [axiom]
    assert result.refutation_uses_call_terms is True


@pytest.mark.parametrize("entry", [paths.check_path_feasibility,
                                   paths.check_path_feasibility_dual])
def test_sizeof_sat_direction_is_unaffected(entry):
    result = entry(conditions("sizeof(Buf) == 8"), profile=BV_C_UINT8,
                   reduce_constraints=False)
    assert result.feasible is True
    assert result.model == {"_anon_0": 8}
    assert result.summary_axioms == ["summary: sizeof(Buf)"]


def test_plain_contradictions_keep_refuting():
    result = paths.check_path_feasibility(
        conditions("Value == 0", "Value == 1"),
        profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is False
    assert result.refutation_uses_call_terms is False


def test_unextractable_core_keeps_the_verdict_with_the_receipt():
    # Demotion requires KNOWN dependence. When the native core cannot
    # be extracted the verdict stands, and the nonempty
    # ``summary_axioms`` receipt tells consumers the dependence was
    # not ruled out (stage-e doctrine: confirm it is empty before
    # trusting a false verdict whose core mentions call terms).
    with patch.object(paths, "_core_names", return_value=[]):
        result = paths.check_path_feasibility(conditions("sizeof(Buf) == 0"),
                                              profile=BV_C_UINT8,
                                              reduce_constraints=False)
    assert result.feasible is False
    assert result.summary_axioms == ["summary: sizeof(Buf)"]
    assert result.unsatisfied == ["sizeof(Buf) == 0"]


def test_core_label_filter_requires_registered_axiom_labels():
    # A path condition whose TEXT merely resembles an axiom label must
    # not trigger demotion: only labels registered in summary_axioms
    # qualify.
    assert paths._assumption_tier_core_axioms(
        ["summary: sizeof(Buf)"], []) == []
    assert paths._assumption_tier_core_axioms(
        ["summary: strlen(Data)"], ["summary: strlen(Data)"]) == []
    assert paths._assumption_tier_core_axioms(
        ["summary: sizeof(Buf)", "sizeof(Buf) == 0"],
        ["summary: sizeof(Buf)"]) == ["summary: sizeof(Buf)"]
    assert paths._assumption_tier_core_axioms(
        None, ["summary: sizeof(Buf)"]) == []
