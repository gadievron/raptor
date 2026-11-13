"""Include guard memory fixtures retire tracing when acquisition or collection fails."""
from types import ModuleType
import tracemalloc
import pytest
from core.audit.tests import test_return_domain_guard_prefix as native
from core.testing.module_views import module_function_view


def case_view(**bindings):
    view = module_function_view(native, bindings=bindings)
    function = view.test_unguarded_file_does_not_allocate_a_line_list
    assert function.__code__ is native.test_unguarded_file_does_not_allocate_a_line_list.__code__
    return function


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned guard trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []
    original = tracemalloc.start
    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure
    trace.start = start
    invoke = case_view(tracemalloc=trace)
    try:
        with pytest.raises(error) as caught:
            invoke()
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_collection_fault_retires_owned_trace(error):
    assert not tracemalloc.is_tracing()
    failure = error("owned guard collection fault")
    reached = []
    original = native.rd._strip_include_guard
    producer = ModuleType("return_domain")
    vars(producer).update(vars(native.rd))
    def fail(text):
        assert tracemalloc.is_tracing()
        assert text == "int ordinary;\n" * 100000
        reached.append(True)
        raise failure
    producer._strip_include_guard = fail
    invoke = case_view(rd=producer)
    try:
        with pytest.raises(error) as caught:
            invoke()
        assert caught.value is failure and reached == [True]
        assert not tracemalloc.is_tracing()
        assert native.rd._strip_include_guard is original
    finally:
        tracemalloc.stop()


def test_borrowed_trace_skip_preserves_session():
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
            native.test_unguarded_file_does_not_allocate_a_line_list()
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
