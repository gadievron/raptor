"""Native SARIF identity memory proofs own tracing and loader bindings."""

import builtins
from contextlib import contextmanager
from types import ModuleType
import tracemalloc

import pytest

from core.sarif import parser
from core.sarif.tests import test_rule_resolution as native
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.slow
PROFILES = ["location", "partial-fingerprint", "tool-fingerprint", "merge"]


def invoke(case, patch):
    if case == "merge":
        return native.test_merge_identity_does_not_copy_a_whole_rule_table(patch)
    return native.test_established_identity_does_not_copy_unused_result_payload(patch, case)


@contextmanager
def caller_trace(frames=25):
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(frames)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        previous = bytearray(8 * 1024 * 1024)
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


@pytest.mark.parametrize("case", PROFILES)
@pytest.mark.parametrize("frames", [1, 25])
def test_actual_native_profile_preserves_trace_and_loader(case, frames):
    borrowed = parser.load_sarif

    def inherited(*args, **kwargs):
        pytest.fail("borrowed parent loader must not be called by the child proof")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(parser, "load_sarif", inherited)
        with caller_trace(frames):
            invoke(case, patch)
        assert parser.load_sarif is inherited
    assert parser.load_sarif is borrowed


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_runner_fault_preserves_primary_trace_and_loader(after, error):
    failure = error("owned SARIF memory runner fault")
    original, loader = native._run_memory_process, parser.load_sarif
    completed = []

    def run(*args, **kwargs):
        if after:
            result = original(*args, **kwargs)
            assert result.returncode == 0, result.stderr
            assert result.stdout.strip() == "sarif-memory-proof-ok"
            completed.append(result)
        raise failure

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_run_memory_process", run)
        with caller_trace():
            with pytest.raises(error) as caught:
                invoke("merge", patch)
            assert caught.value is failure
            assert len(completed) == int(after)
        assert parser.load_sarif is loader
    assert native._run_memory_process is original
    assert parser.load_sarif is loader


def case_view(case, trace):
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tracemalloc":
            return trace
        return builtins.__import__(name, globals, locals, fromlist, level)

    function = native.test_merge_identity_does_not_copy_a_whole_rule_table if case == "merge" else native.test_established_identity_does_not_copy_unused_result_payload
    view = module_function_view(native, bindings={"_owned_case": function}, import_hook=importer)
    assert view._owned_case.__code__ is function.__code__
    return view


@pytest.mark.parametrize("case", ["location", "merge"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_native_partial_trace_start_retires_before_loader_restore(case, after, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned SARIF tracing startup fault")
    loader = parser.load_sarif
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        assert parser.load_sarif is not loader
        if after:
            tracemalloc.start()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    view = case_view(case, trace)
    with pytest.MonkeyPatch.context() as patch:
        try:
            with pytest.raises(error) as caught:
                if case == "merge":
                    view._owned_case(patch)
                else:
                    view._owned_case(patch, case)
            assert caught.value is failure
            assert reached == [after]
            assert not tracemalloc.is_tracing()
            assert parser.load_sarif is not loader
        finally:
            tracemalloc.stop()
    assert parser.load_sarif is loader


@pytest.mark.parametrize("case", ["location", "merge"])
@pytest.mark.parametrize("phase", ["warmup", "measurement"])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_native_consumer_fault_retires_trace_and_loader(case, phase, error):
    assert not tracemalloc.is_tracing()
    failure = error("owned SARIF consumer boundary fault")
    borrowed = (parser.load_sarif, parser.parse_sarif_findings, parser.merge_sarif)
    entry = "merge_sarif" if case == "merge" else "parse_sarif_findings"
    original = getattr(parser, entry)
    calls = []

    def consume(*args, **kwargs):
        calls.append(tracemalloc.is_tracing())
        if len(calls) == (1 if phase == "warmup" else 2):
            raise failure
        return original(*args, **kwargs)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(parser, entry, consume)
        try:
            with pytest.raises(error) as caught:
                invoke(case, patch)
            assert caught.value is failure
            assert calls == ([False] if phase == "warmup" else [False, True])
            assert not tracemalloc.is_tracing()
            assert parser.load_sarif is not borrowed[0]
        finally:
            tracemalloc.stop()
    assert (parser.load_sarif, parser.parse_sarif_findings, parser.merge_sarif) == borrowed


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_caller_trace_acquisition_fault_retires_its_trace(after, error):
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
                pytest.fail("failed acquisition entered the body")
        assert caught.value is failure
        assert not tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


def test_unknown_profile_refuses_before_launch():
    called = []

    def reject(*args, **kwargs):
        called.append(True)
        pytest.fail("unknown profile reached process launch")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_run_memory_process", reject)
        with caller_trace():
            with pytest.raises(AssertionError):
                native._run_sarif_memory_proof("unknown")
        assert not called
