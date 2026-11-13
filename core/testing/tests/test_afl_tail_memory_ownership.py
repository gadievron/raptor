"""Exact tail-reader source owns tracing without importing campaign packages."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.testing.tests._afl_tail_memory import load_memory_module
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.slow


@pytest.fixture
def native():
    return load_memory_module()


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
def test_actual_tail_preserves_borrowed_trace(native, frames, prior_peak, tmp_path):
    with caller_trace(frames, prior_peak):
        native.TestBoundedTargetWritableReads().test_tail_file_does_not_materialise_whole_file(tmp_path)


def test_refused_child_fixture_path_preserves_trace(native, tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="NotADirectoryError"):
            native.TestBoundedTargetWritableReads().test_tail_file_does_not_materialise_whole_file(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(native, after, error, tmp_path):
    failure = error("owned tail memory runner fault")
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
                native.TestBoundedTargetWritableReads().test_tail_file_does_not_materialise_whole_file(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


def case_view(native, trace=tracemalloc, **bindings):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.TestBoundedTargetWritableReads.test_tail_file_does_not_materialise_whole_file
    view = module_function_view(
        native, bindings={"_owned_case": function, **bindings}, import_hook=importer,
    )
    assert view._owned_case.__code__ is function.__code__
    return view


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(native, after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned tail trace startup fault")
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))

    def start():
        if after:
            tracemalloc.start()
        raise failure

    trace.start = start
    view = case_view(native, trace)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestBoundedTargetWritableReads(), tmp_path)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_tail_boundary_fault_retires_owned_trace(native, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned tail boundary fault")
    entered = []
    from types import SimpleNamespace

    original = native.AFLRunner._tail_file

    def fail(log):
        assert tracemalloc.is_tracing() and log == tmp_path / "stderr.log"
        assert log.stat().st_size == 8 * 1024 * 1024 + len(b"TAIL-MARKER")
        entered.append(True)
        raise failure

    view = case_view(native, AFLRunner=SimpleNamespace(_tail_file=fail))
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestBoundedTargetWritableReads(), tmp_path)
        assert caught.value is failure and entered == [True]
        assert not tracemalloc.is_tracing()
        assert native.AFLRunner._tail_file is original
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


def test_actual_tail_without_borrowed_trace(native, tmp_path):
    assert not tracemalloc.is_tracing()
    native.TestBoundedTargetWritableReads().test_tail_file_does_not_materialise_whole_file(tmp_path)
    assert not tracemalloc.is_tracing()


def test_source_loader_preserves_package_and_logging_state():
    import logging
    import sys

    def packages():
        return {key: value for key, value in sys.modules.items()
                if key == "packages.fuzzing" or key.startswith("packages.fuzzing.")}

    modules = packages()
    root = logging.getLogger()
    raptor = logging.getLogger("raptor")
    root_handlers, raptor_handlers = root.handlers, raptor.handlers
    root_values, raptor_values = list(root_handlers), list(raptor_handlers)
    levels = root.level, raptor.level, raptor.propagate
    native = load_memory_module()
    assert packages() == modules
    assert root.handlers is root_handlers and raptor.handlers is raptor_handlers
    assert root.handlers == root_values and raptor.handlers == raptor_values
    assert (root.level, raptor.level, raptor.propagate) == levels
    assert native.AFLRunner._tail_file.__defaults__ == (4096,)
    assert native.AFLRunner._tail_file.__code__.co_filename.endswith("packages/fuzzing/afl_runner.py")
    assert native.strip_terminal_controls("A" + chr(27) + "B") == "AB"
