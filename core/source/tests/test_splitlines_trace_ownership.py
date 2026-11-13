"""The display-prefix memory fixture retires partially started tracing."""

from types import ModuleType
import tracemalloc

import pytest

from core.source.tests import test_splitlines_prefix as native
from core.testing.module_views import module_function_view


def case_view(**bindings):
    view = module_function_view(native, bindings=bindings)
    assert view.test_large_unused_tail_is_not_split_or_copied.__code__ is native.test_large_unused_tail_is_not_split_or_copied.__code__
    return view


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(after, error):
    assert not tracemalloc.is_tracing()
    original = tracemalloc.start
    failure = error("owned trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    view = case_view(tracemalloc=trace)
    try:
        with pytest.raises(error) as caught:
            view.test_large_unused_tail_is_not_split_or_copied()
        assert caught.value is failure
        assert reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original
        assert native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_splitter_boundary_fault_retires_owned_trace(error):
    assert not tracemalloc.is_tracing()
    failure = error("owned splitter boundary fault")
    entered = []
    original = native.splitlines_prefix

    def fail(text, limit):
        assert tracemalloc.is_tracing()
        assert len(text) > 1_000_000 and limit == 20
        entered.append(True)
        raise failure

    view = case_view(splitlines_prefix=fail)
    try:
        with pytest.raises(error) as caught:
            view.test_large_unused_tail_is_not_split_or_copied()
        assert caught.value is failure
        assert entered == [True]
        assert not tracemalloc.is_tracing()
        assert native.splitlines_prefix is original
    finally:
        tracemalloc.stop()


def test_existing_borrowed_trace_skip_preserves_caller_session():
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        assert provenance is not None
        peak = tracemalloc.get_traced_memory()[1]
        with pytest.raises(pytest.skip.Exception, match="requires ownership of allocation tracing"):
            native.test_large_unused_tail_is_not_split_or_copied()
        assert tracemalloc.is_tracing()
        assert tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
