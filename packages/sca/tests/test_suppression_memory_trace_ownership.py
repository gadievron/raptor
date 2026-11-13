"""The overlay refusal proof owns tracing and child lifetimes."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from packages.sca.tests import test_suppressions as native
from packages.sca import suppressions as producer
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
            previous = bytearray(32 * 1024 * 1024)
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
def test_actual_overlay_reader_preserves_borrowed_trace(frames, prior_peak, tmp_path):
    with caller_trace(frames, prior_peak):
        native.test_load_refuses_oversized_overlay_without_reading_it(tmp_path)


def test_refused_child_fixture_path_preserves_trace(tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="NotADirectoryError"):
            native.test_load_refuses_oversized_overlay_without_reading_it(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error, tmp_path):
    failure = error("owned suppression memory runner fault")
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
                native.test_load_refuses_oversized_overlay_without_reading_it(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


def case_view(trace=tracemalloc, reader=None):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.test_load_refuses_oversized_overlay_without_reading_it
    bindings = {"_owned_case": function}
    if reader is not None:
        bindings["load"] = reader
    return module_function_view(native, bindings=bindings, import_hook=importer)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned suppression trace startup fault")
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
            view._owned_case(tmp_path)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_reader_boundary_fault_retires_owned_trace(error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned reader boundary fault")
    entered = []

    def fail(path):
        assert tracemalloc.is_tracing()
        assert path.stat().st_size == 60 * 1024 * 1024
        entered.append(path)
        raise failure

    view = case_view(reader=fail)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(tmp_path)
        assert caught.value is failure
        assert len(entered) == 1
        assert not tracemalloc.is_tracing()
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


def test_native_overlay_refusal_reaches_actual_bounded_reader(tmp_path):
    assert not tracemalloc.is_tracing()
    assert producer._HAS_YAML and producer._yaml is not None
    borrowed_load, borrowed_read = native.load, producer.read_bounded
    calls = []

    def observe(path, **kwargs):
        result = borrowed_read(path, **kwargs)
        calls.append((path, kwargs, result, path.stat().st_size))
        return result

    load_view = module_function_view(producer, bindings={"read_bounded": observe})
    view = case_view(reader=load_view.load)
    view._owned_case(tmp_path)
    assert calls == [(tmp_path / ".raptor-sca-suppress.yml", {"follow_symlinks": False}, None, 60 * 1024 * 1024)]
    assert native.load is borrowed_load and producer.read_bounded is borrowed_read
    assert not tracemalloc.is_tracing()
