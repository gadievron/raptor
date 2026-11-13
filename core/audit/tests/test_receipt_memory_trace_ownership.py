"""Receipt memory fixtures retire tracing when acquisition or collection fails."""
from types import ModuleType
import tracemalloc
import pytest
from core.audit.tests import test_lifecycle_receipt_efficiency as native
from core.testing.module_views import module_function_view


def case_view(**bindings):
    view = module_function_view(native, bindings=bindings)
    function = view.test_receipt_collection_has_bounded_temporary_allocation
    assert function.__code__ is native.test_receipt_collection_has_bounded_temporary_allocation.__code__
    return function


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(local, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned receipt trace startup fault")
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
            invoke(local)
        assert caught.value is failure and reached == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("local", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_collection_fault_retires_owned_trace(local, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned receipt collection fault")
    reached = []
    producer = ModuleType("ptr_lifecycle")
    vars(producer).update(vars(native.lifecycle))
    name = "_local_post_event_reads" if local else "_post_event_reads"
    original = getattr(native.lifecycle, name)
    def fail(*args):
        assert tracemalloc.is_tracing()
        if local:
            edge, lines, span, event = args
            assert edge.kind == "local" and edge.name == "alias"
            assert len(lines) == 20000 and lines[0] == lines[-1] == "use(alias);"
            assert span.start == 1 and span.end == 20000 and event == 0
        else:
            census, edge, function, event = args
            assert edge.kind == "field" and edge.name == "alias"
            assert len(census.fields["alias"].reads) == 20000
            assert function == "event" and event == 1
        reached.append(True)
        raise failure
    setattr(producer, name, fail)
    invoke = case_view(lifecycle=producer)
    try:
        with pytest.raises(error) as caught:
            invoke(local)
        assert caught.value is failure and reached == [True]
        assert not tracemalloc.is_tracing()
        assert getattr(native.lifecycle, name) is original
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("local", [False, True])
def test_borrowed_trace_skip_preserves_session(local):
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.raises(pytest.skip.Exception, match="requires ownership of allocation tracing"):
            native.test_receipt_collection_has_bounded_temporary_allocation(local)
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
