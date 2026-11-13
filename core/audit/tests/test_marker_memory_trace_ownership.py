"""Marker-free source memory fixtures retire tracing when acquisition or collection fails."""
from types import ModuleType
import tracemalloc
import pytest
from core.audit.tests import test_source_view_hash_skipping as native
from core.testing.module_views import module_function_view


def case_view(**bindings):
    view = module_function_view(native, bindings=bindings)
    function = view.test_marker_free_source_has_bounded_temporary_allocation
    assert function.__code__ is native.test_marker_free_source_has_bounded_temporary_allocation.__code__
    return function


@pytest.mark.parametrize("extension", ["py", "rb", "pl", "sh", "toml", "yaml"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(extension, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned marker trace startup fault")
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
            invoke(extension)
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("extension", ["py", "rb", "pl", "sh", "toml", "yaml"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_collection_fault_retires_owned_trace(extension, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned marker collection fault")
    reached = []
    original = native.sanitized_view_with_status
    def fail(text, filename):
        assert tracemalloc.is_tracing()
        assert text == "ordinary_call(argument);\n" * 50000
        assert filename == "a." + extension
        reached.append(True)
        raise failure
    invoke = case_view(sanitized_view_with_status=fail)
    try:
        with pytest.raises(error) as caught:
            invoke(extension)
        assert caught.value is failure and reached == [True]
        assert not tracemalloc.is_tracing()
        assert native.sanitized_view_with_status is original
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("extension", ["py", "rb", "pl", "sh", "toml", "yaml"])
def test_borrowed_trace_skip_preserves_session(extension):
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
            native.test_marker_free_source_has_bounded_temporary_allocation(extension)
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
