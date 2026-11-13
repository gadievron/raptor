"""Reader memory proofs leave caller-owned tracing sessions intact."""

from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.coverage.tests import test_reader_budgets as native
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.slow
CASES = sorted(native._MEMORY_CASES)


@contextmanager
def caller_trace(frames=25):
    assert not tracemalloc.is_tracing(), "companion requires its own caller trace"
    try:
        tracemalloc.start(frames)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        previous = bytearray(16 * 1024 * 1024)
        del previous
        prior_peak = tracemalloc.get_traced_memory()[1]
        yield
        assert tracemalloc.is_tracing()
        assert tracemalloc.get_traceback_limit() == frames
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert provenance is not None
        assert tracemalloc.get_traced_memory()[1] >= prior_peak
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("owner,method", CASES)
@pytest.mark.parametrize("frames", [1, 25])
def test_actual_memory_method_preserves_borrowed_trace(owner, method, frames, tmp_path):
    with caller_trace(frames):
        getattr(getattr(native, owner)(), method)(tmp_path)


@pytest.mark.parametrize("owner,method", CASES)
def test_child_failure_preserves_trace_and_native_refusal(owner, method, tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="NotADirectoryError"):
            getattr(getattr(native, owner)(), method)(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error, tmp_path):
    failure = error("owned memory runner fault")
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
                native.TestVerifiedOutcomesTrail().test_oversize_trail_loads_as_empty(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_trace_start_fault_is_retired(after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned tracing startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start():
        if after:
            tracemalloc.start()
        raise failure

    trace.start = start
    view = module_function_view(native, bindings={"tracemalloc": trace})
    try:
        with pytest.raises(error) as caught:
            view._peak(lambda: None)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_failure_retires_trace(error):
    assert not tracemalloc.is_tracing()
    failure = error("owned measured callback fault")

    def fail():
        assert tracemalloc.is_tracing()
        raise failure

    try:
        with pytest.raises(error) as caught:
            native._peak(fail)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


def test_direct_peak_rejects_borrowed_trace_without_consuming_it():
    with caller_trace():
        with pytest.raises(AssertionError, match="owned trace"):
            native._peak(lambda: None)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_caller_trace_acquisition_failure_retires_its_trace(after, error):
    import sys

    assert not tracemalloc.is_tracing()
    failure = error("owned caller tracing startup fault")
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
                pytest.fail("failed tracing acquisition entered its body")
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()
