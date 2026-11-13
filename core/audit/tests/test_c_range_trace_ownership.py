"""C range memory fixtures retire their allocation tracer on failure."""

from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_source_view_c_ranges as native
from core.testing.module_views import module_function_view

CASES = {
    "sparse": ("test_large_views_do_not_expand_temporary_storage", (False,)),
    "newlines": ("test_large_views_do_not_expand_temporary_storage", (True,)),
    "tiny": ("test_dense_tiny_comments_retain_legacy_allocation_bound", ()),
    "ascii": ("test_large_ascii_comment_avoids_per_line_string_allocation", ()),
}


def case_view(case, **bindings):
    name, args = CASES[case]
    view = module_function_view(native, bindings=bindings)
    invoke = getattr(view, name)
    assert invoke.__code__ is getattr(native, name).__code__
    return invoke, args


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(case, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned C range trace startup fault")
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
    invoke, args = case_view(case, tracemalloc=trace)
    try:
        with pytest.raises(error) as caught:
            invoke(*args)
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_renderer_fault_retires_owned_trace(case, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned C range renderer fault")
    original = native.sanitized_view_with_status
    reached = []

    def fail(source, filename):
        assert tracemalloc.is_tracing() and filename == "a.c"
        if case == "sparse":
            assert source == "int live;\n" * 100000 + "/* hide */"
        elif case == "newlines":
            assert source == "/*" + "\n" * 20000 + "*/"
        elif case == "tiny":
            assert source == "/**/" * 20000
        else:
            assert source == "int live;\n/*" + ("a" * 80 + "\n") * 10000 + "*/\n"
        reached.append(True)
        raise failure

    invoke, args = case_view(case, sanitized_view_with_status=fail)
    try:
        with pytest.raises(error) as caught:
            invoke(*args)
        assert caught.value is failure and reached == [True]
        assert not tracemalloc.is_tracing()
        assert native.sanitized_view_with_status is original
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
def test_borrowed_trace_skip_preserves_session(case):
    assert not tracemalloc.is_tracing()
    name, args = CASES[case]
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
            getattr(native, name)(*args)
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
