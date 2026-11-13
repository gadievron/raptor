"""The bounded pair-enumeration memory proof owns tracing and child lifetimes."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.orchestration.tests import test_context_map_taint as native
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.slow


@contextmanager
def caller_trace(frames=25, prior_peak=True):
    assert not tracemalloc.is_tracing(), "companion requires its own caller trace"
    try:
        tracemalloc.start(frames)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        if prior_peak:
            previous = bytearray(64 * 1024 * 1024)
            del previous
        peak = tracemalloc.get_traced_memory()[1]
        yield
        assert tracemalloc.is_tracing()
        assert tracemalloc.get_traceback_limit() == frames
        assert provenance is not None
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("frames", [1, 25])
@pytest.mark.parametrize("prior_peak", [False, True])
def test_actual_pair_enumeration_preserves_borrowed_trace(frames, prior_peak):
    with caller_trace(frames, prior_peak):
        native.TestBoundedMaterialisation().test_cap_bounds_materialisation_memory()



@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error):
    failure = error("owned pair memory runner fault")
    original = native._run_memory_process
    completed = []

    def run(*args, **kwargs):
        if after:
            result = original(*args, **kwargs)
            assert result.returncode == 0, result.stderr
            completed.append(result)
        raise failure

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_run_memory_process", run)
        with caller_trace():
            with pytest.raises(error) as caught:
                native.TestBoundedMaterialisation().test_cap_bounds_materialisation_memory()
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


def case_view(trace=tracemalloc, **bindings):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.TestBoundedMaterialisation.test_cap_bounds_materialisation_memory
    view = module_function_view(
        native, bindings={"_owned_case": function, **bindings}, import_hook=importer,
    )
    assert view._owned_case.__code__ is function.__code__
    return view


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned pair trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start():
        if after:
            tracemalloc.start()
        raise failure

    trace.start = start
    view = case_view(trace)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestBoundedMaterialisation())
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_pair_boundary_fault_retires_owned_trace(error):
    assert not tracemalloc.is_tracing()
    failure = error("owned enumeration boundary fault")
    entered = []
    original = native.build_taint_pairs

    def fail(ctx, checklist, *, max_pairs):
        assert tracemalloc.is_tracing()
        assert len(ctx["entry_points"]) == len(ctx["sink_details"]) == 1000
        assert checklist is None and max_pairs == 500
        entered.append(True)
        raise failure

    view = case_view(build_taint_pairs=fail)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestBoundedMaterialisation())
        assert caught.value is failure
        assert len(entered) == 1
        assert not tracemalloc.is_tracing()
        assert native.build_taint_pairs is original
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_caller_trace_acquisition_failure_retires_trace(after, error):
    import sys

    assert not tracemalloc.is_tracing()
    failure = error("owned caller trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start(frames):
        if after:
            tracemalloc.start(frames)
        raise failure

    trace.start = start
    view = module_function_view(
        sys.modules[__name__],
        bindings={"tracemalloc": trace, "_owned_trace": caller_trace.__wrapped__},
    )
    try:
        with pytest.raises(error) as caught:
            with contextmanager(view._owned_trace)():
                pytest.fail("failed trace acquisition entered its body")
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()
