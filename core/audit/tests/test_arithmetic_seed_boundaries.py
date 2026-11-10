"""QUALITY prep binds candidates without entering the native proof path."""

import builtins

import pytest

from core.audit import arithmetic_guards, arithmetic_seeds, array_bounds, sweep
from core.testing.module_views import module_function_view

SOURCE = "int Read(int Index){int Data[4]={0};if(Index+1<4)return Data[Index];return 0;}"
CLAIM = "Potential out-of-bounds read at `Data[Index]`."


def test_array_prep_never_enters_prefix_evaluation():
    def forbidden(*a, **kw):
        raise AssertionError("candidate discovery entered prefix evaluation")

    guards = module_function_view(arithmetic_guards, bindings={"PrefixIntegerModel": forbidden})
    binder = module_function_view(array_bounds, bindings={"guards_for_operation": guards.guards_for_operation})

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "array_bounds" and level == 1:
            return binder
        return builtins.__import__(name, globals, locals, fromlist, level)

    producer = module_function_view(arithmetic_seeds, import_hook=local_import)
    gap = {"file": "math.c", "name": "Read", "line_start": 1, "line_end": 1}
    assert producer.seed_arithmetic_hypotheses([gap], {"math.c": SOURCE}, mode="quality", integer_abi="lp64") == 1
    seed = gap["injected_hypotheses"][0]
    assert seed["arithmetic_site"]["binding_status"] == "candidate"
    assert seed["arithmetic_site"]["object_extent"] == 4
    assert "verdict" not in seed


def test_full_binding_still_requires_prefix_admission():
    calls = []

    def refuse(*a, **kw):
        calls.append(1)
        return arithmetic_guards.GuardPremises("unavailable")

    view = module_function_view(array_bounds, bindings={"guards_for_operation": refuse})
    candidate = view.array_access_candidate(SOURCE, CLAIM, language="c", integer_abi="lp64")
    assert candidate.status == "candidate" and candidate.premises == ()
    assert calls == []
    bound = view.bind_array_access(SOURCE, CLAIM, language="c", integer_abi="lp64")
    assert calls == [1]
    assert bound.status == "unavailable"
    result = view.check_array_bounds(SOURCE, CLAIM, language="c", integer_abi="lp64")
    assert calls == [1, 1]
    assert result["violation"] is None


@pytest.mark.slow
def test_real_worker_does_not_promote_an_unverified_array_candidate():
    result = sweep.run_smt_verb_direct(file_path="math.c", function_name="Read", verb="check-array-bounds",
                                      source=SOURCE, hypothesis=CLAIM, integer_abi="lp64")
    assert result.outcome == "inconclusive", result.errors
    assert result.matches == []
    assert result.details["array_bounds_status"] == "unavailable"
