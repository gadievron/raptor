"""Native proof dependencies distinguish typed models from source refutations."""

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths
from core.smt_solver.assertion_frames import track_frames

z3 = pytest.importorskip("z3")


def conditions(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("width,literal", [(8, "0xff"), (32, "0xffffffff")])
def test_conditional_call_width_refutations_retain_their_dependency(entry, signed, width, literal):
    result = entry(conditions(f"fetch_width() > {literal}"), profile=BVProfile(width=width, signed=signed),
                   use_call_summaries=False, reduce_constraints=False)
    assert result.feasible is False  # Correct only in the selected bitvector model.
    assert result.refutation_uses_call_terms is True
    assert result.summary_axioms == []
    wider = paths.check_path_feasibility(conditions(f"fetch_width() > {literal}"),
                                         profile=BVProfile(width=64, signed=False),
                                         use_call_summaries=False, reduce_constraints=False)
    assert wider.feasible is True


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("call,admitted", [("fetch_width() >= 0", True), ("fetch_width() / 2 == 7", False)])
def test_calls_outside_native_scalar_core_do_not_taint_its_provenance(entry, call, admitted):
    result = entry(conditions(call, "Value == 0", "Value == 1"),
                   profile=BVProfile(width=32, signed=False), use_call_summaries=False)
    assert result.feasible is False
    assert bool(result.anon_var_map) is admitted
    assert result.unknown == ([] if admitted else [call])
    assert result.refutation_uses_call_terms is False
    assert set(result.unsatisfied) == {"Value == 0", "Value == 1"}


def test_dual_reports_the_exhibited_subset_instead_of_the_initial_call_core():
    result = paths.check_path_feasibility_dual(
        conditions("fetch_width() < 0", "Value == 0", "Value == 1"),
        profile=BVProfile(width=32, signed=False), use_call_summaries=False,
    )
    assert result.feasible is False
    assert result.refutation_uses_call_terms is False
    assert set(result.unsatisfied) == {"Value == 0", "Value == 1"}
    assert "signedness-robust" in result.reasoning


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_native_indices_distinguish_duplicate_text_in_custom_contexts(backend):
    ctx = z3.Context()
    solver = getattr(z3, backend)(ctx=ctx)
    value = z3.Bool("Value", ctx=ctx)
    frame = track_frames(solver, [([("same", value), ("same", z3.Not(value)), ("same", True)], [0, 0, 1])])
    assert frame.check() == z3.unsat
    assert set(frame.core_indices(solver)) == {0, 1}
    assert frame.single_core_origin(solver) == 0
    assert frame.core_indices(getattr(z3, backend)(ctx=ctx)) is None
    solver.add(z3.BoolVal(True, ctx=ctx))
    assert frame.core_indices(solver) is None


@pytest.mark.parametrize("failure", ["empty", "foreign", "exception"])
def test_unavailable_native_core_cannot_claim_call_independence(monkeypatch, failure):
    real = paths._new_solver

    def solver_factory(*args, **kwargs):
        solver = real(*args, **kwargs)

        def missing_core():
            if failure == "exception":
                raise z3.Z3Exception("no core")
            return [] if failure == "empty" else [z3.Bool("foreign", ctx=solver.ctx)]
        monkeypatch.setattr(solver, "unsat_core", missing_core)
        return solver
    monkeypatch.setattr(paths, "_new_solver", solver_factory)
    result = paths.check_path_feasibility(conditions("fetch_width() > 0xff"),
                                         profile=BVProfile(width=8, signed=False),
                                         use_call_summaries=False, reduce_constraints=False)
    assert result.feasible is False
    assert result.refutation_uses_call_terms is None


@pytest.mark.parametrize("flags", [[], [False, True], [0], ["false"]])
def test_invalid_call_metadata_is_rejected_before_assertions_or_objectives(flags):
    solver = z3.Optimize()
    value = z3.BitVec("Value", 8)
    with pytest.raises(ValueError, match="call dependenc"):
        paths._solve_pending([("guard", value == 0)], solver, [], [], [],
                             profile=BVProfile(width=8, signed=False),
                             pending_call_terms=flags, prefer_witness=("Value", "max"), vars_={"Value": value})
    assert len(solver.assertions()) == 0 and len(solver.objectives()) == 0


def test_provenance_does_not_add_solver_queries(monkeypatch):
    real = paths._new_solver
    checks = []

    def solver_factory(*args, **kwargs):
        solver = real(*args, **kwargs)
        check = solver.check

        def counted_check(*args, **kwargs):
            checks.append(1)
            return check(*args, **kwargs)
        monkeypatch.setattr(solver, "check", counted_check)
        return solver
    monkeypatch.setattr(paths, "_new_solver", solver_factory)
    result = paths.check_path_feasibility(conditions("fetch_width() > 0xff"),
                                         profile=BVProfile(width=8, signed=False),
                                         reduce_constraints=False, use_call_summaries=False)
    assert result.refutation_uses_call_terms is True and checks == [1]


def test_optimizer_without_contradiction_core_leaves_path_inconclusive(monkeypatch):
    solver = z3.Optimize()
    value = z3.BitVec("Value", 8)
    monkeypatch.setattr(solver, "unsat_core", lambda: [])
    result = paths._solve_pending(
        [("zero", value == 0), ("one", value == 1)], solver, [], [], [],
        profile=BVProfile(width=8, signed=False), vars_={"Value": value},
        reduce_constraints=False,
    )
    assert result.feasible is None
    assert result.model == {}
    assert set(result.unknown) == {"zero", "one"}
    assert result.wp_complete is False


def test_unclassified_intrinsics_do_not_claim_call_independence():
    result = paths.check_verb_feasibility(
        [("intrinsic", z3.BoolVal(False))], [], {}, profile=BVProfile(width=8, signed=False),
    )
    assert result.feasible is False and result.refutation_uses_call_terms is None


def test_summary_axiom_dependencies_are_calls_even_without_call_guards():
    result = paths._solve_pending([], z3.Solver(), [], [], [],
                                  profile=BVProfile(width=8, signed=False),
                                  axioms=[("conditional call axiom", z3.BoolVal(False))])
    assert result.feasible is False and result.refutation_uses_call_terms is True
