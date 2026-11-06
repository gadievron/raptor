"""Proof ownership belongs to an immutable frame and its own native query."""

from dataclasses import FrozenInstanceError, replace

import pytest

z3 = pytest.importorskip("z3")

from core.smt_solver.assertion_frames import track_frames  # noqa: E402


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_metadata_cannot_reorder_core_indices_or_rewrite_native_owners(backend):
    solver = getattr(z3, backend)()
    frame = track_frames(solver, [([("irrelevant", True), ("contradiction", False)], [0, 1])])
    assert frame.check() == z3.unsat
    assert frame.core_indices(solver) == (1,)
    assert frame.single_core_origin(solver) == 1
    first, second = frame.labels
    with pytest.raises(TypeError):
        del frame.labels[first]
    with pytest.raises(TypeError):
        frame.origins[second] = 0
    with pytest.raises(FrozenInstanceError):
        frame.labels = {second: "rewritten", first: "reordered"}
    with pytest.raises(FrozenInstanceError):
        frame.origins = {first: 0, second: 0}
    assert frame.core_indices(solver) == (1,)
    assert frame.single_core_origin(solver) == 1


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_stale_core_after_scope_rollback_cannot_refute_the_base_frame(backend):
    context = z3.Context()
    solver = getattr(z3, backend)(ctx=context)
    value = z3.Bool("Value", ctx=context)
    frame = track_frames(solver, [([("base", value)], [0])])
    solver.push()
    solver.add(z3.Not(value))
    assert solver.check() == z3.unsat
    solver.pop()
    # Z3 may retain the temporary query's core after pop. These assertions
    # now match the base frame, but its formula is satisfiable.
    assert frame.core_indices(solver) is None
    assert frame.single_core_origin(solver) is None
    assert frame.check() == z3.sat
    assert frame.core_indices(solver) is None


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_external_assumption_core_cannot_establish_frame_ownership(backend):
    solver = getattr(z3, backend)()
    value = z3.Bool("Value")
    frame = track_frames(solver, [([("base", value)], [0])])
    assert solver.check(z3.Not(value)) == z3.unsat
    assert frame.core_indices(solver) is None
    assert frame.check() == z3.sat
    assert frame.single_core_origin(solver) is None


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_unowned_queries_do_not_rewrite_a_captured_base_proof(backend):
    solver = getattr(z3, backend)()
    frame = track_frames(solver, [([("contradiction", False)], [3])])
    assert frame.check() == z3.unsat
    captured = frame.core_indices(solver)
    solver.push()
    solver.add(False)
    assert solver.check() == z3.unsat
    assert frame.core_indices(solver) is None  # temporary formula is not this frame
    solver.pop()
    assert frame.core_indices(solver) == captured == (0,)
    assert frame.single_core_origin(solver) == 3  # the original proof remains valid


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_changed_formula_is_declined_before_running_an_owned_query(monkeypatch, backend):
    solver = getattr(z3, backend)()
    frame = track_frames(solver, [([("base", True)], [0])])
    solver.add(False)
    monkeypatch.setattr(solver, "check", lambda: pytest.fail("changed formula reached solve"))
    with pytest.raises(ValueError, match="assertions changed"):
        frame.check()
    assert frame.core_indices(solver) is None


@pytest.mark.parametrize("failure", ["exception", "unknown", "sat", "unavailable-core"])
def test_failed_or_inconclusive_owned_query_clears_an_earlier_snapshot(monkeypatch, failure):
    solver = z3.Solver()
    frame = track_frames(solver, [([("contradiction", False)], [0])])
    assert frame.check() == z3.unsat
    assert frame.single_core_origin(solver) == 0
    if failure == "exception":
        def fail():
            raise z3.Z3Exception("owned query failed")
        monkeypatch.setattr(solver, "check", fail)
        with pytest.raises(z3.Z3Exception, match="owned query failed"):
            frame.check()
    elif failure == "unavailable-core":
        def fail_core():
            raise z3.Z3Exception("owned core unavailable")
        monkeypatch.setattr(solver, "unsat_core", fail_core)
        assert frame.check() == z3.unsat
    else:
        outcome = z3.unknown if failure == "unknown" else z3.sat
        monkeypatch.setattr(solver, "check", lambda: outcome)
        assert frame.check() == outcome
    assert frame.core_indices(solver) is None
    assert frame.single_core_origin(solver) is None


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_native_core_capture_checks_context_identity_not_printed_names(monkeypatch, backend):
    solver = getattr(z3, backend)()
    frame = track_frames(solver, [([("contradiction", False)], [0])])
    foreign = z3.Bool(next(iter(frame.labels)), ctx=z3.Context())
    monkeypatch.setattr(solver, "unsat_core", lambda: [foreign])
    assert frame.check() == z3.unsat
    assert frame.core_indices(solver) is None


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_core_reads_never_reconsult_native_state_or_add_queries(monkeypatch, backend):
    solver = getattr(z3, backend)()
    frame = track_frames(solver, [([("contradiction", False)], [7])])
    assert frame.check() == z3.unsat
    monkeypatch.setattr(solver, "check", lambda: pytest.fail("extra query"))
    monkeypatch.setattr(solver, "unsat_core", lambda: pytest.fail("re-read mutable native core"))
    assert frame.core_indices(solver) == (0,)
    assert frame.single_core_origin(solver) == 7


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_captured_proof_cannot_survive_replacement_with_a_satisfiable_formula(backend):
    solver = getattr(z3, backend)()
    solver.push()
    frame = track_frames(solver, [([("contradiction", False)], [0])])
    assert frame.check() == z3.unsat
    solver.pop()
    # Reuse the printed label and assertion count, but replace its formula.
    solver.assert_and_track(z3.BoolVal(True), z3.Bool(next(iter(frame.labels))))
    assert solver.check() == z3.sat
    assert frame.core_indices(solver) is None


@pytest.mark.parametrize("backend", ["Solver", "Optimize"])
def test_metadata_copies_do_not_alias_inputs_or_depend_on_display_order(backend):
    solver = getattr(z3, backend)()
    original = track_frames(solver, [([("irrelevant", True), ("contradiction", False)], [0, 1])])
    labels = dict(reversed(tuple(original.labels.items())))
    origins = dict(original.origins)
    frame = replace(original, labels=labels, origins=origins)
    labels.clear()
    origins.update({marker: 9 for marker in origins})
    assert frame.check() == z3.unsat
    assert len(frame.labels) == 2
    assert frame.core_indices(solver) == (1,)
    assert frame.single_core_origin(solver) == 1
