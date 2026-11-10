"""Journal memory-fixture size faults stay on its reader consumer."""

import os
from pathlib import Path
from types import FunctionType
import tracemalloc

import pytest
from core.coverage import journal
from core.coverage.tests import test_reader_fd_discipline as native


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize(
    "after,error",
    [(False, None)]
    + [
        (after, error)
        for after in (False, True)
        for error in (OSError, KeyboardInterrupt, SystemExit)
    ],
)
def test_native_memory_size_fault_preserves_unrelated_consumers(
    borrowed, after, error, tmp_path
):
    assert not tracemalloc.is_tracing()
    original_stat, original_fstat = Path.stat, os.fstat
    unrelated = tmp_path / "unrelated" / "review-journal.jsonl"
    unrelated.parent.mkdir()
    unrelated.write_bytes(b"owned other file")
    expected = original_stat(unrelated).st_size
    failure = error("owned journal fixture load failure") if error else None
    real_load = native.load_entries
    original = native.TestJournalReader.test_budget_holds_at_line_granularity
    observations = []
    source_consumer = (journal.Path, journal.os, journal._MAX_JOURNAL_BYTES)

    def borrowed_stat(self, **kwargs):
        return original_stat(self, **kwargs)

    def borrowed_fstat(fd):
        return original_fstat(fd)

    with pytest.MonkeyPatch.context() as caller:
        if borrowed:
            caller.setattr(Path, "stat", borrowed_stat)
            caller.setattr(os, "fstat", borrowed_fstat)
        inherited_stat, inherited_fstat = Path.stat, os.fstat

        def observe(directory):
            assert Path.stat is inherited_stat
            assert os.fstat is inherited_fstat
            assert journal.Path is not Path
            assert journal.os is not os
            target = directory / "review-journal.jsonl"
            assert target.stat().st_size > 30 * 1024 * 1024
            assert journal.Path(target).stat().st_size == 100
            with target.open("rb") as stream:
                assert os.fstat(stream.fileno()).st_size == target.stat().st_size
                assert journal.os.fstat(stream.fileno()).st_size == 100
            assert unrelated.stat().st_size == expected
            with unrelated.open("rb") as stream:
                assert os.fstat(stream.fileno()).st_size == expected
            observations.append(True)
            if failure and not after:
                raise failure
            result = real_load(directory)
            if failure:
                raise failure
            return result

        invoke = FunctionType(
            original.__code__,
            dict(original.__globals__, load_entries=observe),
            original.__name__,
            original.__defaults__,
            original.__closure__,
        )
        try:
            with pytest.MonkeyPatch.context() as scope:
                if error:
                    with pytest.raises(error) as caught:
                        invoke(native.TestJournalReader(), tmp_path, scope)
                    assert caught.value is failure
                else:
                    invoke(native.TestJournalReader(), tmp_path, scope)
            assert observations == [True]
            assert Path.stat is inherited_stat
            assert os.fstat is inherited_fstat
            assert journal.Path is source_consumer[0]
            assert journal.os is source_consumer[1]
            assert journal._MAX_JOURNAL_BYTES == source_consumer[2]
            assert unrelated.stat().st_size == expected
            assert not tracemalloc.is_tracing()
        finally:
            assert not tracemalloc.is_tracing()
    assert Path.stat is original_stat
    assert os.fstat is original_fstat
