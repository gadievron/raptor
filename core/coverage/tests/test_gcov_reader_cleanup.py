"""Coverage readers retain cancellation instead of reporting empty coverage."""
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.coverage.parsers import gcov


@pytest.fixture(params=["gcov", "lcov"])
def report(request, tmp_path, monkeypatch):
    path = tmp_path / ("owned.gcov" if request.param == "gcov" else "owned.info")
    payload = (b"-:0:Source:owned.c\n1:7:executed\n#####:8:uncovered\n"
               if request.param == "gcov" else
               b"SF:owned.c\nDA:7,1\nDA:8,0\nend_of_record\n")
    path.write_bytes(payload)
    state = SimpleNamespace(path=path, payload=payload, native=[], readers=[],
                            reads=[], closes=0, primary=None, cleanup=None)

    class Reader(io.BufferedReader):
        def read(self, size=-1):
            data = super().read(size)
            state.reads.append(size)
            if state.primary is not None:
                raise state.primary
            return data

        def close(self):
            if self.closed:
                return super().close()
            super().close()
            state.closes += 1
            if state.cleanup is not None:
                raise state.cleanup

    class OwnedPath(type(Path())):
        def open(self, mode="r", *args, **kwargs):
            assert mode == "rb" and not args and not kwargs
            native = super().open(mode)
            state.native.append(native)
            reader = Reader(native)
            state.readers.append(reader)
            return reader

    monkeypatch.setattr(gcov, "Path", OwnedPath)
    monkeypatch.setattr(gcov, "_MAX_REPORT_BYTES", 128)
    parser = gcov.parse_gcov if request.param == "gcov" else gcov.parse_lcov
    state.run = lambda: parser(path)
    try:
        yield state
    finally:
        for reader in state.readers:
            if not reader.closed:
                io.BufferedReader.close(reader)
        if path.exists():
            assert path.read_bytes() == payload


def assert_retired(state):
    assert state.closes == len(state.readers) == len(state.native) == 1
    assert all(reader.closed for reader in state.readers + state.native)


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup", [OSError, MemoryError])
def test_report_cancellation_survives_consumed_close(report, primary, cleanup):
    report.primary = primary("after native coverage read")
    report.cleanup = cleanup("after native coverage close")
    with pytest.raises(primary) as caught:
        report.run()
    assert caught.value is report.primary
    assert_retired(report)


def test_unreadable_report_keeps_empty_result_policy(report):
    report.primary = OSError("after native coverage read")
    report.cleanup = KeyboardInterrupt("secondary coverage close interruption")
    assert report.run() == {}
    assert_retired(report)


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_fresh_close_failure_keeps_existing_policy(report, cleanup):
    report.cleanup = cleanup("fresh coverage close failure")
    if cleanup is OSError:
        assert report.run() == {}
    else:
        with pytest.raises(cleanup) as caught:
            report.run()
        assert caught.value is report.cleanup
    assert_retired(report)


def test_healthy_report_keeps_lines_and_bounded_read(report):
    assert report.run() == {"owned.c": {7}}
    assert report.reads == [gcov._MAX_REPORT_BYTES + 1]
    assert_retired(report)


def test_oversize_report_keeps_cap_refusal(report, monkeypatch):
    monkeypatch.setattr(gcov, "_MAX_REPORT_BYTES", len(report.payload) - 1)
    assert report.run() == {}
    assert report.reads == [len(report.payload)]
    assert_retired(report)


def test_missing_report_keeps_empty_result_policy(report):
    report.path.unlink()
    assert report.run() == {}
    assert report.closes == 0 and not report.readers and not report.native
