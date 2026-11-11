"""Native reader memory proofs preserve a caller-owned tracing session."""

from contextlib import contextmanager
import tracemalloc

import pytest
from core.coverage.tests import test_reader_fd_discipline as native

pytestmark = pytest.mark.slow


@contextmanager
def _caller_trace(frames=25, prior_peak=False):
    inherited = tracemalloc.is_tracing()
    if not inherited:
        tracemalloc.start(frames)
    try:
        limit = tracemalloc.get_traceback_limit()
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        assert provenance is not None
        if prior_peak:
            previous = bytearray(6 * 1024 * 1024)
            del previous
        peak = tracemalloc.get_traced_memory()[1]

        def verify():
            assert tracemalloc.is_tracing()
            assert tracemalloc.get_traceback_limit() == limit
            assert tracemalloc.get_object_traceback(retained) == provenance
            assert tracemalloc.get_traced_memory()[1] >= peak

        yield verify
        verify()
    finally:
        if not inherited:
            tracemalloc.stop()


@pytest.mark.parametrize("frames", [1, 25])
@pytest.mark.parametrize("prior_peak", [False, True])
@pytest.mark.parametrize("refused_path", [False, True])
def test_native_child_preserves_trace_and_memory_refusals(
    frames, prior_peak, refused_path, tmp_path
):
    target = tmp_path / "owned"
    if refused_path:
        target.write_bytes(b"owned non-directory")
    else:
        target.mkdir()
    with _caller_trace(frames, prior_peak) as verify:
        with pytest.MonkeyPatch.context() as patch:
            if refused_path:
                with pytest.raises(AssertionError, match="NotADirectoryError"):
                    native.TestJournalReader().test_budget_holds_at_line_granularity(
                        target, patch
                    )
            else:
                native.TestJournalReader().test_budget_holds_at_line_granularity(
                    target, patch
                )
        verify()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_runner_fault_keeps_primary_and_caller_trace(after, error, tmp_path):
    failure = error("owned memory child boundary")
    original = native._run_memory_process
    completed = []

    def run(*args, **kwargs):
        if not after:
            raise failure
        result = original(*args, **kwargs)
        completed.append(result)
        assert result.returncode == 0, result.stderr
        raise failure

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(native, "_run_memory_process", run)
        with _caller_trace() as verify:
            with pytest.raises(error) as caught:
                native.TestJournalReader().test_budget_holds_at_line_granularity(
                    tmp_path, patch
                )
            assert caught.value is failure
            assert len(completed) == int(after)
            verify()
    assert native._run_memory_process is original


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_native_start_failure_retires_new_trace(after, error, tmp_path):
    from types import FunctionType, ModuleType

    assert not tracemalloc.is_tracing()
    original_start, original_stop = tracemalloc.start, tracemalloc.stop
    borrowed = (
        native._mock_consumer_os.Path,
        native._mock_consumer_os.os,
        native._mock_consumer_os._MAX_JOURNAL_BYTES,
    )
    private = ModuleType(tracemalloc.__name__)
    vars(private).update(vars(tracemalloc))
    failure = error("owned native tracing startup failure")
    entered = []

    def start(*args, **kwargs):
        if after:
            original_start(*args, **kwargs)
        entered.append(tracemalloc.is_tracing())
        raise failure

    private.start = start
    original = native.TestJournalReader.test_budget_holds_at_line_granularity
    invoke = FunctionType(
        original.__code__,
        dict(original.__globals__, tracemalloc=private),
        original.__name__,
        original.__defaults__,
        original.__closure__,
    )
    try:
        with pytest.MonkeyPatch.context() as scope:
            with pytest.raises(error) as caught:
                invoke(native.TestJournalReader(), tmp_path, scope)
            assert caught.value is failure
        assert entered == [after]
        assert not tracemalloc.is_tracing()
        assert tracemalloc.start is original_start
        assert tracemalloc.stop is original_stop
        assert native._mock_consumer_os.Path is borrowed[0]
        assert native._mock_consumer_os.os is borrowed[1]
        assert native._mock_consumer_os._MAX_JOURNAL_BYTES == borrowed[2]
    finally:
        original_stop()
