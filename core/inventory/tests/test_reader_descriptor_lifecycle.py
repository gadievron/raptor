"""Inventory exclusions and cancellation retire unadopted source descriptors."""

from __future__ import annotations

import errno
import os

import pytest

from core.inventory import builder
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def reader_case(tmp_path, monkeypatch):
    source = tmp_path / "sample.py"
    source.write_text("def entry():\n    return 1\n")
    original_open, original_close, original_fdopen = os.open, os.close, os.fdopen
    descriptors, closes, streams = [], [], []

    def run(*, failure=None, close_failure=False, grow=False):
        def allocate(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            info = os.fstat(fd)
            descriptors.append((fd, info.st_dev, info.st_ino))
            if grow:
                source.write_text("x=" + "1" * 100 + "\n")
            return fd

        def close(fd):
            original_close(fd)
            closes.append(fd)
            if close_failure:
                raise OSError("secondary close failed")

        def construct(*args, **kwargs):
            if failure is not None:
                raise failure
            stream = original_fdopen(*args, **kwargs)
            streams.append(stream)
            return stream

        patch_module_attribute(monkeypatch, builder, "os", "open", allocate)
        patch_module_attribute(monkeypatch, builder, "os", "close", close)
        patch_module_attribute(monkeypatch, builder, "os", "fdopen", construct)
        return builder._process_single_file(source, tmp_path, [])

    yield run, source, descriptors, closes, streams
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
    assert len(descriptors) == 1
    fd, device, inode = descriptors[0]
    try:
        info = os.fstat(fd)
    except OSError as error:
        assert error.errno == errno.EBADF
        return
    assert (info.st_dev, info.st_ino) != (device, inode), "source descriptor remained open"


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit], ids=["io", "runtime", "interrupt", "exit"])
def test_setup_failure_retires_source_descriptor(reader_case, error_type):
    run, _source, descriptors, closes, _streams = reader_case
    failure = error_type("source setup failed")
    if issubclass(error_type, Exception):
        result = run(failure=failure)
        assert result["_excluded"] and result["_reason"] == "processing_error"
        assert result["_pattern"] == error_type.__name__
    else:
        with pytest.raises(error_type) as caught:
            run(failure=failure)
        assert caught.value is failure
    _assert_retired(descriptors)
    assert closes == [descriptors[0][0]]


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_secondary_close_failure_keeps_primary(reader_case, error_type):
    run, _source, descriptors, closes, _streams = reader_case
    failure = error_type("primary setup failure")
    if issubclass(error_type, Exception):
        result = run(failure=failure, close_failure=True)
        assert result["_reason"] == "processing_error" and result["_pattern"] == "RuntimeError"
    else:
        with pytest.raises(error_type) as caught:
            run(failure=failure, close_failure=True)
        assert caught.value is failure
    _assert_retired(descriptors)
    assert closes == [descriptors[0][0]]


def test_success_keeps_parse_and_retires_both_owners(reader_case):
    run, _source, descriptors, _closes, streams = reader_case
    result = run()
    assert result["path"] == "sample.py"
    assert any(item["name"] == "entry" for item in result["items"])
    assert streams and all(stream.closed for stream in streams)
    _assert_retired(descriptors)


def test_initial_size_refusal_does_not_allocate(reader_case, monkeypatch):
    run, _source, descriptors, _closes, _streams = reader_case
    monkeypatch.setattr(builder, "MAX_FILE_BYTES", 8)
    result = run()
    assert result["_excluded"] and result["_reason"] == "too_large"
    assert descriptors == []


def test_growth_refusal_still_retires_source(reader_case, monkeypatch):
    run, source, descriptors, _closes, streams = reader_case
    source.write_text("x=1\n")
    monkeypatch.setattr(builder, "MAX_FILE_BYTES", 8)
    result = run(grow=True)
    assert result["_excluded"] and result["_reason"] == "too_large_during_read"
    assert streams and all(stream.closed for stream in streams)
    _assert_retired(descriptors)
