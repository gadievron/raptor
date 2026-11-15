from core.smt_solver.canonicalise import canonicalise


def test_symbolic_condition_uses_stored_source_characters():
    class Condition(str):
        def __getitem__(self, index):
            if isinstance(index, slice):
                return 'Count == 0'
            return str.__getitem__(self, index)

    text = Condition('Count == 1')
    assert str.__str__(text) == 'Count == 1'
    assert canonicalise(text) == 'Count == 1'


def test_identical_stored_guards_remain_feasible():
    from core.smt_solver.config import BVProfile
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility

    class Condition(str):
        def __getitem__(self, index):
            if isinstance(index, slice):
                return 'Count == 0'
            return str.__getitem__(self, index)

    result = check_path_feasibility(
        [PathCondition(Condition('Count == 1'), 0), PathCondition('Count == 1', 1)],
        profile=BVProfile(8, False), timeout_ms=1000,
        reduce_constraints=False, use_call_summaries=False,
    )
    assert result.feasible is True


def test_canonical_size_limit_uses_stored_length(monkeypatch):
    import importlib
    import pytest
    module = importlib.import_module('core.smt_solver.canonicalise')

    class Condition(str):
        def __len__(self):
            return 0

    def forbidden(*args):
        raise AssertionError('oversized source reached scanning')

    monkeypatch.setattr(module, 'non_code_spans', forbidden)
    text = Condition('x' * (module.MAX_CANONICALISE_CHARS + 1))
    with pytest.raises(ValueError, match='canonicalisation limit'):
        module.canonicalise(text)


def test_condition_size_limit_uses_stored_length(monkeypatch):
    from core.smt_solver import path_feasibility as pf
    from core.smt_solver.config import BVProfile
    from core.smt_solver.rejection import Rejection, RejectionKind

    class Condition(str):
        def __len__(self):
            return 0

    def forbidden(*args):
        raise AssertionError('oversized guard reached canonicalisation')

    monkeypatch.setattr(pf, '_canonicalise', forbidden)
    text = Condition(' ' * pf._MAX_CONDITION_CHARS + 'Count == 1')
    result = pf._parse_condition_in_frame(text, {}, profile=BVProfile(8))
    assert isinstance(result, Rejection) and result.kind is RejectionKind.INPUT_TOO_LONG


def test_path_condition_preserves_stored_text_and_polarity():
    from core.smt_solver.path_feasibility import PathCondition

    class Condition(str):
        def __str__(self):
            raise AssertionError("custom conversion must not run")

    guard = PathCondition(Condition("Count == 1"), 7, negated=True)
    assert type(guard.text) is str
    assert guard.text == "Count == 1"
    assert guard.step_index == 7
    assert guard.negated is True


def test_stored_contradiction_remains_infeasible():
    from core.smt_solver.config import BVProfile
    from core.smt_solver.path_feasibility import PathCondition, check_path_feasibility

    result = check_path_feasibility(
        [PathCondition("Count == 1", 0), PathCondition("Count == 0", 1)],
        profile=BVProfile(8, False), timeout_ms=1000,
        reduce_constraints=False, use_call_summaries=False,
    )
    assert result.feasible is False
