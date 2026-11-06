"""Audit verdicts do not depend on optional constraint summaries."""

import pytest

from core.audit import sweep
from core.audit.array_bounds import check_array_bounds
from core.smt_solver import path_feasibility as paths


@pytest.fixture(autouse=True)
def forbid_optional_passes(monkeypatch):
    pytest.importorskip("z3")
    pytest.importorskip("tree_sitter_c")
    original = paths._classify_text_condition

    def no_tautology(cond, vars_, solver, **kwargs):
        assert solver is None, "audit must not spend its deadline classifying tautologies"
        return original(cond, vars_, solver, **kwargs)

    def no_summary(*args, **kwargs):
        pytest.fail("audit must not spend its deadline reducing constraints")
    monkeypatch.setattr(paths, "_classify_text_condition", no_tautology)
    monkeypatch.setattr(paths, "_extract_wp", no_summary)


@pytest.mark.parametrize("guard,expected", [("Alpha==2 && Zulu>0", "confirmed"),
                                             ("Alpha>=0 && Alpha<=4 && Zulu>=0 && Zulu<=4", "refuted")])
def test_typed_overflow_and_premise_gate(guard, expected):
    source = f"int Read(int Alpha,int Zulu){{if({guard}) return Alpha * Zulu; return 0;}}"
    result = sweep._run_smt_verb_inner(file_path="unit.c", function_name="Read", verb="check-overflow",
                                     source=source, hypothesis="integer overflow in `Alpha * Zulu`", integer_abi="lp64")
    assert result.outcome == expected, result.details
    assert result.details["wp_predicate"] is None and result.details["wp_complete"] is False
    if expected == "confirmed":
        assert result.details["witness_validated"] is True


@pytest.mark.parametrize("maximum,violation", [(3, False), (4, True)])
def test_array_entry_and_violation_obligations(maximum, violation):
    source = f"int Read(int Index){{int Data[4]={{0}}; if(Index>=0 && Index<={maximum}) return Data[Index]; return 0;}}"
    result = check_array_bounds(source, "Data[Index] out-of-bounds read", language="c", integer_abi="lp64")
    assert result["violation"] is violation, result
    if violation:
        assert result["witness_index"] == 4


@pytest.mark.slow
@pytest.mark.parametrize("guard,outcome", [("Alpha==2 && Zulu>0", "confirmed"),
                                          ("Alpha>=0 && Alpha<=4 && Zulu>=0 && Zulu<=4", "refuted")])
def test_confined_worker_returns_verdict_without_summary(guard, outcome):
    source = f"int Read(int Alpha,int Zulu){{if({guard}) return Alpha * Zulu; return 0;}}"
    result = sweep.run_smt_verb_direct(file_path="unit.c", function_name="Read", verb="check-overflow",
                                      source=source, hypothesis="integer overflow in `Alpha * Zulu`", integer_abi="lp64")
    assert result.outcome == outcome, result.details
    assert result.details["wp_predicate"] is None and result.details["wp_conjuncts"] == []
    assert result.details["wp_complete"] is False
    assert result.details["source_scope"]


def test_auxiliary_overflow_disproof_skips_optional_passes():
    from core.audit.condition_smt import disprove_integer_overflow

    source = "int Read(int Alpha,int Zulu){if(Alpha>=0 && Alpha<=4 && Zulu>=0 && Zulu<=4) return Alpha * Zulu; return 0;}"
    result = disprove_integer_overflow("integer overflow in `Alpha * Zulu`", source,
                                      file_path="unit.c", function_name="Read", integer_abi="lp64")
    assert result.disproved is True
