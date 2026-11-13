"""The synthetic ELF memory proof owns its tracing and child lifetimes."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.binary.tests import test_elf_hostile_dynstr as native
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
def test_actual_section_walk_preserves_borrowed_trace(frames, prior_peak, tmp_path):
    with caller_trace(frames, prior_peak):
        native.TestSectionNameWalkBounded().test_many_sections_no_nul_shstrtab_stays_small(tmp_path)


def test_refused_child_fixture_path_preserves_trace(tmp_path):
    refused = tmp_path / "owned"
    refused.write_text("not a directory")
    with caller_trace():
        with pytest.raises(AssertionError, match="NotADirectoryError"):
            native.TestSectionNameWalkBounded().test_many_sections_no_nul_shstrtab_stays_small(refused)


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_managed_runner_fault_preserves_primary_and_trace(after, error, tmp_path):
    failure = error("owned ELF memory runner fault")
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
                native.TestSectionNameWalkBounded().test_many_sections_no_nul_shstrtab_stays_small(tmp_path)
            assert caught.value is failure
            assert len(completed) == int(after)
    assert native._run_memory_process is original


def case_view(trace=tracemalloc, **bindings):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.TestSectionNameWalkBounded.test_many_sections_no_nul_shstrtab_stays_small
    return module_function_view(
        native, bindings={"_owned_case": function, **bindings}, import_hook=importer,
    )


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_owned_measurement_start_fault_retires_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned ELF trace startup fault")
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
            view._owned_case(native.TestSectionNameWalkBounded(), tmp_path)
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_parser_boundary_fault_retires_owned_trace(error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned parser boundary fault")
    entered = []

    def fail(path):
        assert tracemalloc.is_tracing()
        assert path.read_bytes()[:4] == b"\x7fELF"
        entered.append(path)
        raise failure

    view = case_view(parse_elf=fail)
    try:
        with pytest.raises(error) as caught:
            view._owned_case(native.TestSectionNameWalkBounded(), tmp_path)
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
