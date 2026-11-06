"""A rejected state update must not prove a false scalar contradiction."""

import pytest

from core.smt_solver import BV_C_INT8, BV_C_UINT8
from core.smt_solver import path_feasibility as paths
from core.smt_solver.rejection import RejectionKind


@pytest.fixture(autouse=True)
def require_z3():
    pytest.importorskip("z3")


def conditions(*texts):
    return [paths.PathCondition(text, n) for n, text in enumerate(texts)]


@pytest.mark.parametrize("mutation", ["Value = 2", "Value += 1", "Value++", "++Value"])
@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("profile", [BV_C_INT8, BV_C_UINT8], ids=["signed", "unsigned"])
@pytest.mark.parametrize("reduce", [True, False])
def test_mutation_cannot_be_removed_to_obtain_a_refutation(mutation, entry, profile, reduce):
    result = entry(conditions("Value == 1", mutation, "Value == 2"), profile=profile, reduce_constraints=reduce)
    assert result.feasible is None and result.model == {}
    assert result.unknown == [mutation]
    assert result.unknown_reasons[0].kind == RejectionKind.ASSIGNMENT_SHAPED
    assert result.unsatisfied and result.wp_complete is False
    assert "unmodeled scalar value flow" in result.reasoning


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("reduce", [True, False])
def test_mutation_free_scalar_contradictions_still_refute(entry, reduce):
    result = entry(conditions("Value == 1", "Value == 2"), profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is False and result.unsatisfied


@pytest.mark.parametrize("reduce", [True, False])
def test_non_mutating_parse_failure_does_not_prevent_a_contradiction_proof(reduce):
    result = paths.check_path_feasibility(conditions("Value == 1", "Value / 2 == 9", "Value == 2"),
                                          profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is False
    assert result.unknown == ["Value / 2 == 9"]


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_sat_candidates_keep_the_mutation_warning(entry):
    result = entry(conditions("Before == 1", "Value = 2", "After == 2"),
                   profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is True and result.unknown == ["Value = 2"]
    assert result.wp_complete is False


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
def test_verdict_only_mutation_refusal_needs_one_solver_check(monkeypatch, entry):
    original = paths._new_solver
    checks = []

    def counted_solver(*args, **kwargs):
        solver = original(*args, **kwargs)
        check = solver.check

        def counted_check(*args, **kwargs):
            checks.append(1)
            return check(*args, **kwargs)
        monkeypatch.setattr(solver, "check", counted_check)
        return solver
    monkeypatch.setattr(paths, "_new_solver", counted_solver)
    result = entry(conditions("Value == 1", "Value = 2", "Value == 2"),
                   profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None and len(checks) == 1


@pytest.mark.parametrize("reduce", [True, False])
def test_new_call_placeholders_do_not_make_mutated_summary_arguments_ssa(reduce):
    result = paths.check_path_feasibility(conditions("abs(Value) == 1", "Value = 2", "abs(Value) == 2"),
                                          profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is None and result.wp_complete is False
    assert list(result.anon_var_map.values()) == ["abs(Value)", "abs(Value)"]
    assert result.summary_axioms == ["summary: abs(Value)"] * 2


@pytest.mark.parametrize("entry", [paths.check_path_feasibility, paths.check_path_feasibility_dual])
@pytest.mark.parametrize("reduce", [True, False])
@pytest.mark.parametrize("texts,epoch", [
    (("Value == 1", "Value == 2", "Other = 3"), 0),
    (("Other = 3", "Value == 1", "Value == 2"), 1),
    (("Other = 3", "Other = 4", "Value == 1", "Value == 2"), 2),
], ids=["before-mutation", "after-mutation", "after-two-mutations"])
def test_native_core_inside_one_segment_keeps_a_valid_refutation(texts, epoch, reduce, entry):
    result = entry(conditions(*texts), profile=BV_C_UINT8, reduce_constraints=reduce)
    assert result.feasible is False and result.unsatisfied
    assert f"mutation-free segment {epoch}" in result.reasoning
    assert result.unknown and result.wp_complete is False


@pytest.mark.parametrize("reduce", [True, False])
def test_duplicate_summary_labels_use_native_marker_ownership(reduce):
    result = paths.check_path_feasibility(conditions(
        "abs(Value) == abs(Value)", "Value = 2", "abs(Value) == 2", "Value == 3",
    ), profile=BV_C_INT8, reduce_constraints=reduce)
    assert result.feasible is False
    assert "mutation-free segment 1" in result.reasoning
    assert result.summary_axioms == ["summary: abs(Value)"] * 3


@pytest.mark.parametrize("unknown_core", [False, True], ids=["empty-core", "unowned-marker"])
def test_missing_or_unowned_core_provenance_never_refutes(monkeypatch, unknown_core):
    import z3
    original = paths._new_solver

    def broken_core_solver(*args, **kwargs):
        solver = original(*args, **kwargs)
        monkeypatch.setattr(solver, "unsat_core", lambda: [z3.Bool("not_our_marker")] if unknown_core else [])
        return solver
    monkeypatch.setattr(paths, "_new_solver", broken_core_solver)
    result = paths.check_path_feasibility(conditions("Other = 3", "Value == 1", "Value == 2"),
                                          profile=BV_C_UINT8, reduce_constraints=False)
    assert result.feasible is None and result.model == {}


@pytest.mark.parametrize("invalid", [False, 0.0, "0", -1])
def test_invalid_origin_metadata_fails_before_any_assertion(invalid):
    import z3
    from core.smt_solver.assertion_frames import track_frames

    solver = z3.Solver()
    with pytest.raises(ValueError, match="origins"):
        track_frames(solver, [([("first", z3.BoolVal(True))], [0]),
                              ([("second", z3.BoolVal(False))], [invalid])])
    assert len(solver.assertions()) == 0


def test_mismatched_origin_metadata_fails_before_any_assertion():
    import z3
    from core.smt_solver.assertion_frames import track_frames

    solver = z3.Solver()
    with pytest.raises(ValueError, match="origin count"):
        track_frames(solver, [([("first", z3.BoolVal(True))], [0]),
                              ([("second", z3.BoolVal(False))], [])])
    assert len(solver.assertions()) == 0


@pytest.mark.parametrize("second_origin,expected", [(0, 0), (1, None)])
def test_iterator_frames_and_duplicate_text_preserve_actual_native_owners(second_origin, expected):
    import z3
    from core.smt_solver.assertion_frames import track_frames

    value = z3.BitVec("Value", 8)
    solver = z3.Solver()
    frames = iter([(iter([("same display", value == 1)]), iter([0])),
                   (iter([("same display", value == 2)]), iter([second_origin]))])
    tracked = track_frames(solver, frames)
    assert tracked.check() == z3.unsat
    assert len(tracked.labels) == 2
    assert tracked.single_core_origin(solver) == expected


@pytest.mark.parametrize("wrong_context", [False, True], ids=["non-boolean", "foreign-context"])
def test_invalid_later_frame_cannot_partially_assert_an_earlier_frame(wrong_context):
    import z3
    from core.smt_solver.assertion_frames import track_frames

    invalid = z3.BoolVal(True, ctx=z3.Context()) if wrong_context else z3.BitVecVal(1, 8)
    solver = z3.Solver()
    with pytest.raises(ValueError, match="Boolean formulas"):
        track_frames(solver, [([("first", z3.BoolVal(True))], [0]),
                              ([("later", invalid)], [1])])
    assert len(solver.assertions()) == 0


def test_native_labels_reserve_boolean_names_from_later_frames():
    import z3
    from core.smt_solver.assertion_frames import track_frames

    context = z3.Context()
    solver = z3.Solver(ctx=context)
    source = z3.Bool("_raptor_track!0", ctx=context)
    tracked = track_frames(solver, [([("earlier", z3.BoolVal(True, ctx=context))], [0]),
                                   ([("later positive", source), ("later negative", z3.Not(source))], [1, 1])])
    assert tracked.check() == z3.unsat
    assert "_raptor_track!0" not in tracked.labels
    assert tracked.single_core_origin(solver) == 1


def test_unowned_preexisting_assertions_cannot_hide_from_core_provenance():
    import z3
    from core.smt_solver.assertion_frames import track_frames

    solver = z3.Solver()
    value = z3.BitVec("Value", 8)
    solver.add(value == 1)
    with pytest.raises(ValueError, match="fresh solver"):
        track_frames(solver, [([("post-mutation", value == 2)], [1])])
    assert len(solver.assertions()) == 1


@pytest.mark.parametrize("reset", [False, True], ids=["added-assertion", "same-count-reset"])
def test_changing_assertions_invalidates_native_ownership(reset):
    import z3
    from core.smt_solver.assertion_frames import track_frames

    solver = z3.Solver()
    value = z3.BitVec("Value", 8)
    tracked = track_frames(solver, [([("one", value == 1), ("two", value == 2)], [0, 0])])
    assert tracked.check() == z3.unsat and tracked.single_core_origin(solver) == 0
    if reset:
        first, second = tracked.labels
        solver.reset()
        solver.assert_and_track(value == 3, z3.Bool(first))
        solver.assert_and_track(value == 4, z3.Bool(second))
    else:
        solver.add(z3.BoolVal(True))
    assert solver.check() == z3.unsat
    assert tracked.single_core_origin(solver) is None


@pytest.mark.parametrize("within_segment,expected", [(False, None), (True, False)])
def test_optimizer_uses_the_same_native_segment_ownership(within_segment, expected):
    texts = ("Other = 3", "Value == 1", "Value == 2") if within_segment else (
        "Value == 1", "Value = 2", "Value == 2")
    result = paths.check_path_feasibility(conditions(*texts), profile=BV_C_UINT8,
                                          prefer_witness=("Value", "max"), reduce_constraints=False)
    assert result.feasible is expected


def test_dual_subset_cannot_erase_a_mutation_between_conflicting_guards():
    result = paths._robust_contradiction_result(
        frozenset({"Value == 1", "Value == 2"}),
        conditions("Value == 1", "Value = 2", "Value == 2"),
        (BV_C_UINT8, BV_C_INT8), None,
        mutation_texts=frozenset({"Value = 2"}),
    )
    assert result is None
