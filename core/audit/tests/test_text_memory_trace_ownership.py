"""Native text memory fixtures retire partially acquired allocation tracing."""

from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_source_view_c_blanking as blank
from core.audit.tests import test_protocol_state_streaming as protocol
from core.testing.module_views import module_function_view

CASES = {
    "blank": (blank, "test_large_region_has_bounded_temporary_allocation"),
    "protocol": (protocol, "test_large_line_does_not_retain_all_match_objects"),
}


def case_view(case, **bindings):
    module, name = CASES[case]
    view = module_function_view(module, bindings=bindings)
    assert getattr(view, name).__code__ is getattr(module, name).__code__
    return getattr(view, name)


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_native_start_fault_retires_owned_trace(case, after, error):
    assert not tracemalloc.is_tracing()
    module, _name = CASES[case]
    original = tracemalloc.start
    failure = error("owned text tracing startup fault")
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
        assert caught.value is failure
        assert reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and module.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_native_body_fault_retires_owned_trace(case, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned text consumer boundary fault")
    calls = []
    blanking = blank._blank_c_region
    indexer = protocol.ps.build_state_field_index
    namespace = protocol.ps

    if case == "blank":
        def fail(chars, source, start, end):
            calls.append(tracemalloc.is_tracing())
            assert calls == [True]
            assert len(chars) == len(source) == 1024 * 1024
            assert start == 0 and end == len(source)
            raise failure

        invoke = case_view(case, _blank_c_region=fail)
    else:
        def scan(sources):
            calls.append(tracemalloc.is_tracing())
            if len(sources["a.c"]) < 1000:
                assert calls == [False]
                return indexer(sources)
            assert calls == [False, True]
            assert sources["a.c"].count("obj->field = 7;") == 20000
            raise failure

        private = ModuleType("core.audit.protocol_state")
        vars(private).update(vars(protocol.ps))
        private.build_state_field_index = scan
        invoke = case_view(case, ps=private)

    try:
        with pytest.raises(error) as caught:
            invoke()
        assert caught.value is failure
        assert calls == ([True] if case == "blank" else [False, True])
        assert not tracemalloc.is_tracing()
        assert blank._blank_c_region is blanking
        assert protocol.ps is namespace and protocol.ps.build_state_field_index is indexer
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("case", CASES)
def test_existing_borrowed_skip_preserves_caller_session(case):
    assert not tracemalloc.is_tracing()
    module, name = CASES[case]
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        assert provenance is not None
        peak = tracemalloc.get_traced_memory()[1]
        with pytest.raises(pytest.skip.Exception, match="requires isolated allocation tracing"):
            getattr(module, name)()
        assert tracemalloc.is_tracing()
        assert tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
