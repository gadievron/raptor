"""Optional document reads retire source descriptors on setup failure."""

from __future__ import annotations

import errno
import io
import os

import pytest

from core.concepts import study
from core.source import contained, streams as source_streams
from core.testing.module_views import module_function_view, scoped_function_imports


@pytest.fixture
def doc_case(tmp_path, monkeypatch):
    path = tmp_path / "notes.md"
    path.write_text("Owned documentation.\n")
    original_open, original_close, original_stream_open = os.open, os.close, io.open
    descriptors, closes, streams = [], [], []

    def run(*, failure=None, close_failure=False, related=None):
        def allocate(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            info = os.fstat(fd)
            descriptors.append((fd, info.st_dev, info.st_ino))
            return fd

        def close(fd):
            original_close(fd)
            closes.append(fd)
            if close_failure:
                raise OSError("secondary close failed")

        def construct(*args, **kwargs):
            if failure is not None and len(descriptors) == 1:
                raise failure
            stream = original_stream_open(*args, **kwargs)
            native_close = stream.close
            descriptor = stream.fileno()
            retired = False

            def close_stream():
                nonlocal retired
                try:
                    return native_close()
                finally:
                    if stream.closed and not retired:
                        retired = True
                        closes.append(descriptor)

            # Successful adoption now retires through the native stream.
            # Observe that actual close without changing its descriptor owner.
            stream.close = close_stream
            streams.append(stream)
            return stream

        private_os = module_function_view(os, bindings={"open": allocate, "close": close})
        private_io = module_function_view(io, bindings={"open": construct})
        private_streams = module_function_view(source_streams, bindings={"io": private_io})
        private_contained = module_function_view(
            contained, bindings={"os": private_os, "adopt_fd": private_streams.adopt_fd},
        )
        entries = [{"file": path.name}] if related is None else related
        with scoped_function_imports(
            study, ["_load_doc_context"], {"core.source.contained": private_contained},
        ):
            return study._load_doc_context(entries, tmp_path)

    yield run, path, descriptors, closes, streams
    for stream in streams:
        stream.close()
    for fd, device, inode in descriptors:
        try:
            info = os.fstat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == (device, inode):
            original_close(fd)


def _assert_retired(descriptors):
    assert descriptors
    for fd, device, inode in descriptors:
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
            continue
        assert (info.st_dev, info.st_ino) != (device, inode), "document descriptor remained open"


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit], ids=["io", "runtime", "interrupt", "exit"])
def test_setup_failure_retires_document_descriptor(doc_case, error_type):
    run, _path, descriptors, closes, _streams = doc_case
    failure = error_type("document setup failed")
    if error_type is OSError:
        assert run(failure=failure) == ""
    else:
        with pytest.raises(error_type) as caught:
            run(failure=failure)
        assert caught.value is failure
    assert len(descriptors) == 1
    _assert_retired(descriptors)
    assert closes == [descriptors[0][0]]


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_cleanup_error_keeps_document_setup_primary(doc_case, error_type):
    run, _path, descriptors, closes, _streams = doc_case
    failure = error_type("primary setup failed")
    with pytest.raises(error_type) as caught:
        run(failure=failure, close_failure=True)
    assert caught.value is failure
    _assert_retired(descriptors)
    assert closes == [descriptors[0][0]]


def test_success_keeps_framing_and_closes_both_owners(doc_case):
    run, _path, descriptors, _closes, streams = doc_case
    assert run() == "## notes.md\n```\nOwned documentation.\n```\n"
    assert streams and all(stream.closed for stream in streams)
    _assert_retired(descriptors)


def test_document_byte_cap_remains_truncating(doc_case, monkeypatch):
    run, path, descriptors, _closes, streams = doc_case
    path.write_text("A" * 100)
    monkeypatch.setattr(study, "_DOC_MAX_BYTES", 8)
    assert run() == "## notes.md\n```\nAAAAAAAA\n```\n"
    assert streams and all(stream.closed for stream in streams)
    _assert_retired(descriptors)


def test_failed_document_does_not_drop_later_document(doc_case):
    run, path, descriptors, closes, streams = doc_case
    second = path.with_name("second.md")
    second.write_text("Later documentation.\n")
    result = run(failure=OSError("first setup failed"), related=[{"file": path.name}, {"file": second.name}])
    assert result == "## second.md\n```\nLater documentation.\n```\n"
    assert len(descriptors) == len(closes) == 2
    assert streams and all(stream.closed for stream in streams)
    _assert_retired(descriptors)
