"""Bounded evidence memory fixtures retire partially acquired tracing."""

from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_bounded_evidence_work as native
from core.testing.module_views import module_function_view

CASES = {
    "parity": "test_parity_does_not_materialize_linked_or_outside_read_lists",
    "alarm": "test_alarm_does_not_copy_unused_native_tier_items",
}


def case_view(case, **bindings):
    view = module_function_view(native, bindings=bindings)
    name = CASES[case]
    invoke = getattr(view, name)
    assert invoke.__code__ is getattr(native, name).__code__
    return invoke


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(case, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned bounded evidence trace startup fault")
    original = tracemalloc.start
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    invoke = case_view(case, tracemalloc=trace)
    try:
        with pytest.raises(error) as caught:
            invoke()
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_receipt_boundary_fault_retires_owned_trace(case, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned bounded evidence receipt fault")
    reached = []
    parity = native.detect_field_parity_deviations
    alarm = native.build_alarm_record

    if case == "parity":
        def fail(census, *, min_cluster):
            assert tracemalloc.is_tracing() and min_cluster == 3
            assert set(census.fields) == {"copied0", "copied1", "copied2", "missed"}
            reads = census.fields["missed"].reads
            assert len(reads) == 50000 and all(read is reads[0] for read in reads)
            assert (reads[0].file, reads[0].line, reads[0].function, reads[0].owner) == ("b.c", 20, "read", "old")
            reached.append(True)
            raise failure

        invoke = case_view(case, detect_field_parity_deviations=fail)
    else:
        def build(**kwargs):
            review = kwargs["review_result"]
            reached.append(tracemalloc.is_tracing())
            if len(reached) == 1:
                assert reached == [False]
                assert review == {native.G2_BYPASS_KEY: ["warm"]}
                result = alarm(**kwargs)
                assert result["bypass_claimed"] == ["warm"]
                return result
            assert reached == [False, True]
            assert review[native.G2_BYPASS_KEY] == ["inv"]
            tiers = review["g2_invariant_bypass_tiers"]
            assert len(tiers) == 50000 and tiers["0"] == tiers["49999"] == "xref_backed"
            raise failure

        invoke = case_view(case, build_alarm_record=build)
    try:
        with pytest.raises(error) as caught:
            invoke()
        assert caught.value is failure
        assert reached == ([True] if case == "parity" else [False, True])
        assert not tracemalloc.is_tracing()
        assert native.detect_field_parity_deviations is parity
        assert native.build_alarm_record is alarm
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
def test_borrowed_trace_skip_preserves_session(case):
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires ownership of allocation tracing"):
            getattr(native, CASES[case])()
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
