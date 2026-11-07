"""Assertion tracking must preserve formulas, namespaces, and Z3 contexts."""

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver import core_names, track  # noqa: E402


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
@pytest.mark.parametrize("location", ["incoming", "later-batch-entry", "existing"])
def test_tracking_labels_cannot_constrain_a_formula_variable(backend, location):
    ctx = z3.Context()
    solver = getattr(z3, backend)(ctx=ctx)
    source = z3.Bool("_raptor_track!0", ctx=ctx)
    if location == "existing":
        solver.add(z3.Not(source))
        batch = [("true", True)]
    elif location == "later-batch-entry":
        batch = [("true", True), ("source", z3.Not(source))]
    else:
        batch = [("source", z3.Not(source))]
    reverse = track(solver, batch)
    assert "_raptor_track!0" not in reverse
    assert solver.check() == z3.sat
    assert z3.is_false(solver.model().eval(source))


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_custom_context_unsat_cores_round_trip_across_batches(backend):
    ctx = z3.Context()
    solver = getattr(z3, backend)(ctx=ctx)
    source = z3.Bool("Input", ctx=ctx)
    reverse = track(solver, [("positive", source)])
    assert track(solver, [("negative", z3.Not(source))], reverse) is reverse
    assert len(reverse) == 2
    assert solver.check() == z3.unsat
    assert set(core_names(solver, reverse)) == {"positive", "negative"}


@pytest.mark.parametrize("invalid", ["sort", "context"])
def test_invalid_later_expression_declines_the_batch_before_solver_mutation(invalid):
    ctx = z3.Context()
    solver = z3.Solver(ctx=ctx)
    valid = z3.Bool("Valid", ctx=ctx)
    bad = z3.BitVec("NotBoolean", 8, ctx=ctx) if invalid == "sort" else z3.Bool("Foreign")
    reverse = {"old": "old receipt"}
    with pytest.raises(ValueError, match="Boolean.*context"):
        track(solver, [("first", valid), ("second", bad)], reverse)
    assert len(solver.assertions()) == 0
    assert reverse == {"old": "old receipt"}


def test_reverse_map_names_are_reserved_even_after_their_assertions_were_popped():
    ctx = z3.Context()
    solver = z3.Solver(ctx=ctx)
    reverse = {"_raptor_track!0": "old scope"}
    track(solver, [("new scope", True)], reverse)
    assert reverse["_raptor_track!0"] == "old scope"
    assert len(reverse) == 2
    assert solver.check() == z3.sat


def test_shared_formula_dags_and_quantified_bound_variables_remain_supported():
    ctx = z3.Context()
    solver = z3.Solver(ctx=ctx)
    source = z3.Bool("_raptor_track!0", ctx=ctx)
    bound = z3.Bool("Bound", ctx=ctx)
    clause = z3.Or(source, z3.Not(source))
    track(solver, [("shared", z3.And(clause, clause)), ("bound", z3.ForAll([bound], z3.Or(bound, z3.Not(bound))))])
    assert solver.check() == z3.sat


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
@pytest.mark.parametrize("carry_reverse", [False, True])
def test_later_batches_cannot_reuse_an_active_marker_as_a_source_variable(backend, carry_reverse):
    ctx = z3.Context()
    solver = getattr(z3, backend)(ctx=ctx)
    reverse = track(solver, [("first", True)])
    assert solver.check() == z3.sat
    marker = z3.Bool(next(iter(reverse)), ctx=ctx)
    count = len(solver.assertions())
    with pytest.raises(ValueError, match="active tracking label"):
        track(solver, [("later source", z3.Not(marker))], reverse if carry_reverse else None)
    assert len(solver.assertions()) == count
    assert solver.check() == z3.sat


@pytest.mark.parametrize("backend,cleanup", [("Solver", "pop"), ("Solver", "reset"), ("Optimize", "pop")])
def test_removed_markers_do_not_block_new_formulas_or_grow_the_registry(backend, cleanup):
    ctx = z3.Context()
    solver = getattr(z3, backend)(ctx=ctx)
    solver.push()
    reverse = track(solver, [("old", True)])
    old_name = next(iter(reverse))
    getattr(solver, cleanup)()
    source = z3.Bool(old_name, ctx=ctx)
    current = track(solver, [("new", z3.Not(source))])
    assert old_name not in current
    assert solver.check() == z3.sat
    assert len(solver._raptor_track_labels) == 1


@pytest.mark.parametrize("objective_kind", ["max", "min", "soft"])
def test_tracking_cannot_change_an_optimizer_objective_or_soft_preference(objective_kind):
    ctx = z3.Context()
    solver = z3.Optimize(ctx=ctx)
    source = z3.Bool("_raptor_track!0", ctx=ctx)
    if objective_kind == "max":
        solver.maximize(z3.If(source, 0, 1))
    elif objective_kind == "min":
        solver.minimize(z3.If(source, 1, 0))
    else:
        solver.add_soft(z3.Not(source))
    reverse = track(solver, [("tautology", True)])
    assert "_raptor_track!0" not in reverse
    assert solver.check() == z3.sat
    assert z3.is_false(solver.model().eval(source))


@pytest.mark.parametrize("soft", [False, True])
def test_later_objectives_cannot_reuse_an_active_tracking_label(soft):
    ctx = z3.Context()
    solver = z3.Optimize(ctx=ctx)
    reverse = track(solver, [("original", True)])
    marker = z3.Bool(next(iter(reverse)), ctx=ctx)
    if soft:
        solver.add_soft(z3.Not(marker))
    else:
        solver.maximize(z3.If(marker, 0, 1))
    before = tuple(solver.assertions())
    names = dict(reverse)
    with pytest.raises(ValueError, match="active tracking label"):
        track(solver, [("new", True)], reverse)
    assert dict(reverse) == names
    assert all(a.eq(b) for a, b in zip(before, solver.assertions(), strict=True))
