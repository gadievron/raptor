"""The source-backed compiler walk owns tracing and child lifetimes."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import _compiler_walk_memory as owner
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
def test_actual_walk_preserves_borrowed_trace(frames, prior_peak, tmp_path):
    with caller_trace(frames, prior_peak):
        owner.load_memory_module().TestChangePointOwners().test_layer2_walk_memory_is_not_per_line(tmp_path)


def test_refused_child_fixture_path_preserves_trace(tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="FileExistsError"):
            owner.load_memory_module().TestChangePointOwners().test_layer2_walk_memory_is_not_per_line(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error, tmp_path):
    failure = error("owned walk memory runner fault")
    original = owner._run_memory_process
    completed = []

    def run(*args, **kwargs):
        if after:
            result = original(*args, **kwargs)
            assert result.returncode == 0, result.stderr
            completed.append(result)
        raise failure

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(owner, "_run_memory_process", run)
        with caller_trace():
            with pytest.raises(error) as caught:
                owner.load_memory_module().TestChangePointOwners().test_layer2_walk_memory_is_not_per_line(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert owner._run_memory_process is original


def case_view(trace=tracemalloc, **bindings):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    native = owner.load_memory_module()
    function = native.TestChangePointOwners.test_layer2_walk_memory_is_not_per_line
    view = module_function_view(
        native, bindings={"_owned_case": function, **bindings}, import_hook=importer,
    )
    assert view._owned_case.__code__ is function.__code__
    return view


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned walk trace startup fault")
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
            view._owned_case(owner.load_memory_module().TestChangePointOwners(), tmp_path)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_walk_boundary_fault_retires_owned_trace(error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned walk boundary fault")
    entered = []
    native = owner.load_memory_module()
    original = native.compiler_sweep._l2_closure

    def fail(pp, target, tu):
        assert tracemalloc.is_tracing()
        assert tu == target / "t.c" and tu.read_text() == "int t;\n"
        assert pp == f'# 1 "{tu}"\n' + ";\n" * 300_000
        entered.append(True)
        raise failure

    producer = ModuleType("compiler_sweep")
    vars(producer).update(vars(native.compiler_sweep))
    producer._l2_closure = fail
    view = case_view(compiler_sweep=producer)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestChangePointOwners(), tmp_path)
        assert caught.value is failure
        assert len(entered) == 1
        assert not tracemalloc.is_tracing()
        assert native.compiler_sweep._l2_closure is original
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


def test_actual_walk_without_borrowed_trace(tmp_path):
    assert not tracemalloc.is_tracing()
    owner.load_memory_module().TestChangePointOwners().test_layer2_walk_memory_is_not_per_line(tmp_path)
    assert not tracemalloc.is_tracing()
