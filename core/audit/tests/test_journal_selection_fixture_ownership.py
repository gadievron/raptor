"""Journal-selection fixtures own loader imports and allocation tracing."""

from types import ModuleType
import tracemalloc

import pytest

from core.audit.tests import test_index_allocation_contracts as native
from core.testing.module_views import module_function_view

CASES = [
    "test_journal_selection_preserves_first_entry_at_equal_timestamps",
    "test_journal_selection_does_not_copy_eligible_history",
]
EXPECTED = {"smt": {"survived": 1, "disproven": 0, "unknown": 0}}


class RecordingPatch:
    def __init__(self, patch):
        self.patch = patch
        self.loaders = []

    def setattr(self, target, name, value, raising=True):
        assert target is not native.journal and name == "load_entries"
        self.loaders.append((target, target.load_entries))
        self.patch.setattr(target, name, value, raising=raising)

    def assert_restored(self):
        assert all(loader.load_entries is original for loader, original in self.loaders)


@pytest.mark.parametrize("name", CASES)
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
def test_native_fixture_preserves_borrowed_loader(name, error, tmp_path):
    assert not tracemalloc.is_tracing()
    original = native.journal.load_entries
    failure = error("owned journal fixture body fault") if error else None
    recorder = None

    def exercise():
        nonlocal recorder
        with pytest.MonkeyPatch.context() as patch:
            recorder = RecordingPatch(patch)
            getattr(native, name)(recorder, tmp_path)
            assert len(recorder.loaders) == 1
            assert native.journal.load_entries is original
            if failure:
                raise failure
    try:
        if error:
            with pytest.raises(error) as caught:
                exercise()
            assert caught.value is failure
        else:
            exercise()
    finally:
        assert recorder is not None
        recorder.assert_restored()
        assert native.journal.load_entries is original
        assert not tracemalloc.is_tracing()


def test_simultaneous_entry_sets_use_distinct_exact_imports(tmp_path):
    original = native.journal.load_entries
    left = [native._entry("1", ["smt:left"]), native._entry("2", [], correction=True)]
    right = [native._entry("1", ["semgrep:right"]), native._entry("2", [], correction=True)]
    with pytest.MonkeyPatch.context() as patch:
        recorder = RecordingPatch(patch)
        first = native._survival_with_entries(recorder, left)
        second = native._survival_with_entries(recorder, right)
        assert first.__code__ is second.__code__ is native.survival.aggregate_survival.__code__
        assert first.__globals__ is not second.__globals__
        assert all(type(entry) is native.ReviewJournalEntry for entry in left + right)
        assert first(tmp_path) == EXPECTED
        assert second(tmp_path) == {"semgrep": {"survived": 1, "disproven": 0, "unknown": 0}}
        assert first(tmp_path) == EXPECTED
        assert len(recorder.loaders) == 2
        assert recorder.loaders[0][0] is not recorder.loaders[1][0]
        assert native.journal.load_entries is original
    recorder.assert_restored()
    assert native.journal.load_entries is original


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_private_loader_publication_failure_restores_binding(after, error):
    original = native.journal.load_entries
    failure = error("owned journal loader publication fault")
    loaders = []
    try:
        with pytest.MonkeyPatch.context() as patch:
            class Publication:
                def setattr(self, target, name, value, raising=True):
                    assert target is not native.journal and name == "load_entries"
                    assert target.load_entries is original
                    loaders.append(target)
                    if after:
                        patch.setattr(target, name, value, raising=raising)
                    raise failure

            with pytest.raises(error) as caught:
                native._survival_with_entries(Publication(), [])
            assert caught.value is failure and len(loaders) == 1
            assert native.journal.load_entries is original
    finally:
        assert all(loader.load_entries is original for loader in loaders)
        assert native.journal.load_entries is original


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_start_fault_retires_owned_trace(after, error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned journal trace startup fault")
    original = tracemalloc.start
    trace = ModuleType("tracemalloc")
    vars(trace).update(vars(tracemalloc))
    reached = []

    def start():
        if after:
            original()
        reached.append(tracemalloc.is_tracing())
        raise failure

    trace.start = start
    view = module_function_view(native, bindings={"tracemalloc": trace})
    recorder = None
    try:
        with pytest.MonkeyPatch.context() as patch:
            recorder = RecordingPatch(patch)
            with pytest.raises(error) as caught:
                getattr(view, CASES[1])(recorder, tmp_path)
            assert caught.value is failure and reached == [after]
            assert not tracemalloc.is_tracing()
        recorder.assert_restored()
        assert tracemalloc.start is original and native.tracemalloc is tracemalloc
    finally:
        tracemalloc.stop()
        if recorder is not None:
            recorder.assert_restored()


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_failure_after_real_aggregation_retires_trace(error, tmp_path):
    assert not tracemalloc.is_tracing()
    failure = error("owned journal measured body fault")
    view = module_function_view(native)
    original = view._survival_with_entries
    reached = []

    def prepare(patch, entries):
        assert len(entries) == 50001 and all(entry is entries[0] for entry in entries[:50000])
        aggregate = original(patch, entries)
        assert aggregate.__code__ is native.survival.aggregate_survival.__code__

        def measured(root):
            assert tracemalloc.is_tracing() and root == tmp_path
            result = aggregate(root)
            assert result == EXPECTED
            reached.append(True)
            raise failure
        return measured

    view._survival_with_entries = prepare
    recorder = None
    try:
        with pytest.MonkeyPatch.context() as patch:
            recorder = RecordingPatch(patch)
            with pytest.raises(error) as caught:
                getattr(view, CASES[1])(recorder, tmp_path)
            assert caught.value is failure and reached == [True]
            assert not tracemalloc.is_tracing()
        recorder.assert_restored()
    finally:
        tracemalloc.stop()
        if recorder is not None:
            recorder.assert_restored()


def test_borrowed_trace_skip_preserves_session(tmp_path):
    assert not tracemalloc.is_tracing()
    try:
        tracemalloc.start(25)
        retained = bytearray(8192)
        provenance = tracemalloc.get_object_traceback(retained)
        peak = tracemalloc.get_traced_memory()[1]
        assert provenance is not None
        with pytest.MonkeyPatch.context() as patch:
            recorder = RecordingPatch(patch)
            with pytest.raises(pytest.skip.Exception, match="requires ownership of allocation tracing"):
                getattr(native, CASES[1])(recorder, tmp_path)
            assert recorder.loaders == []
        assert tracemalloc.is_tracing() and tracemalloc.get_traceback_limit() == 25
        assert tracemalloc.get_object_traceback(retained) == provenance
        assert tracemalloc.get_traced_memory()[1] >= peak
    finally:
        tracemalloc.stop()
