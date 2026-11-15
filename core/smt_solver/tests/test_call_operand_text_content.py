import pytest
from core.smt_solver import path_feasibility as pf
from core.smt_solver.config import BVProfile


def test_stored_mutating_call_declines_before_registry(monkeypatch):
    class Operand(str):
        def strip(self, *args):
            return "strlen(value)"

    def forbidden(*args, **kwargs):
        raise AssertionError("mutating stored call reached registry validation")

    monkeypatch.setattr(pf, "_validate_var_registry", forbidden)
    with pytest.raises(ValueError, match="unmodeled scalar state effects"):
        pf.make_call_operand(Operand("mutate(value++)"), {},
                             profile=BVProfile(8), model=pf.CallOperandModel())


def test_stored_call_limit_precedes_registry(monkeypatch):
    class Operand(str):
        def __len__(self):
            return 0

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized call reached registry validation")

    monkeypatch.setattr(pf, "_validate_var_registry", forbidden)
    with pytest.raises(ValueError, match="character limit"):
        pf.make_call_operand(Operand(" " * pf._MAX_CONDITION_CHARS + "strlen(value)"), {},
                             profile=BVProfile(8), model=pf.CallOperandModel())
