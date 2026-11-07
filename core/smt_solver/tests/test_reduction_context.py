"""Constraint reduction keeps the primary query's native context and budget."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import BVProfile, new_solver  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402
from core.smt_solver.session import query_budget  # noqa: E402


def test_private_context_query_retains_complete_reduced_summary():
    context = z3.Context()
    value = z3.BitVec("Value", 8, ctx=context)
    strong, weak = z3.ULE(value, 3), z3.ULE(value, 7)
    lower = z3.UGE(value, 1)
    result = paths._solve_pending(
        [("strong", strong), ("weak", weak)], new_solver(ctx=context), [], [], [],
        profile=BVProfile(8, False), vars_={"Value": value}, axioms=[("lower", lower)],
    )
    assert result.feasible is True
    assert 1 <= result.model["Value"] <= 3
    assert result.wp_complete is True
    assert result.wp_conjuncts == ["strong"]
    reduced = z3.parse_smt2_string(f"(assert {result.wp_predicate})", decls={"Value": value}, ctx=context)
    verifier = z3.Solver(ctx=context)
    verifier.add(lower, z3.Xor(z3.And(strong, weak), z3.And(*reduced)))
    assert verifier.check() == z3.unsat


@pytest.mark.parametrize("where", ["predicate", "axiom"])
def test_boolean_constants_use_the_frame_context(where):
    context = z3.Context()
    value = z3.BitVec("Value", 8, ctx=context)
    if where == "predicate":
        pending, axioms = [("always", True)], [("value", value == 3)]
    else:
        pending, axioms = [("value", value == 3)], [("always", True)]
    predicate, conjuncts, complete = paths._extract_wp(pending, axioms=axioms)
    assert complete is True
    assert predicate is not None
    assert conjuncts == ([] if where == "predicate" else ["value"])
    if where == "predicate":
        assert pending[0][1] is True
    else:
        assert axioms[0][1] is True


@pytest.mark.parametrize("bad", ["context", "sort", "number"])
def test_invalid_reduction_frame_declines_before_solver_allocation(monkeypatch, bad):
    context = z3.Context()
    value = z3.BitVec("Value", 8, ctx=context)
    invalid = z3.Bool("Foreign") if bad == "context" else value if bad == "sort" else 1
    monkeypatch.setattr(paths, "_new_solver", lambda *a, **k: pytest.fail("invalid frame allocated a solver"))
    with pytest.raises(ValueError, match="Boolean.*context"):
        paths._extract_wp([("valid", value == 3)], axioms=[("invalid", invalid)])


def test_private_context_reduction_respects_expired_shared_budget(monkeypatch):
    context = z3.Context()
    value = z3.BitVec("Value", 8, ctx=context)
    monkeypatch.setattr(z3.Solver, "check", lambda *a: pytest.fail("expired reduction reached native check"))
    with query_budget(0):
        predicate, conjuncts, complete = paths._extract_wp([("value", value == 3)])
    assert predicate is not None
    assert conjuncts == ["value"]
    assert complete is False
