"""A JSONL reader owns its descriptor before and after stream adoption."""
import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.json import jsonl
from core.testing.module_bindings import patch_module_attribute


def assert_closed(fd):
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF


@pytest.fixture
def reader(tmp_path, monkeypatch):
    path = tmp_path / "owned.jsonl"
    path.write_bytes(b"0\n1\n2\n")
    owners, adopted, closed, streams = [], [], [], []
    real_open, real_close, real_stat = os.open, os.close, os.fstat
    real_seek, real_fdopen = os.lseek, os.fdopen

    def install(phase=None, primary=None, cleanup=None, stream_cleanup=None):
        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            info = real_stat(fd)
            owners.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def checked(fd):
            if phase == "fstat":
                raise primary
            info = real_stat(fd)
            if phase == "nonregular":
                return os.stat_result((stat.S_IFIFO, *info[1:]))
            return info

        def seek(*args):
            if phase == "seek":
                raise primary
            return real_seek(*args)

        class Stream:
            def __init__(self, raw):
                self.raw = raw
                self.read_calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.raw.__exit__(*args)
                if stream_cleanup is not None:
                    raise stream_cleanup

            def readline(self, size=-1):
                if phase == "read" or (phase == "read-after-first" and self.read_calls):
                    raise primary
                self.read_calls += 1
                return self.raw.readline(size)

            def __iter__(self):
                return self

            def __next__(self):
                line = self.readline()
                if not line:
                    raise StopIteration
                return line

        def adopt(fd, *args, **kwargs):
            adopted.append(fd)
            if phase == "fdopen":
                raise primary
            stream = Stream(real_fdopen(fd, *args, **kwargs))
            streams.append(stream)
            return stream

        def close(fd):
            real_close(fd)
            closed.append(fd)
            if cleanup is not None:
                raise cleanup

        for name, value in (("open", opened), ("fstat", checked),
                            ("lseek", seek), ("fdopen", adopt), ("close", close)):
            patch_module_attribute(monkeypatch, jsonl, "os", name, value)

    yield SimpleNamespace(path=path, install=install, owners=owners,
                          adopted=adopted, closed=closed, streams=streams)
    for stream in streams:
        if not stream.raw.closed:
            stream.raw.close()
    for fd, identity in owners:
        try:
            info = real_stat(fd)
        except OSError:
            continue
        if (info.st_dev, info.st_ino) == identity:
            real_close(fd)


@pytest.mark.parametrize("phase", ["fstat", "seek", "fdopen"])
@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_setup_error_retires_descriptor(reader, phase, error_type):
    primary = error_type("owned setup failure")
    reader.install(phase, primary)
    kwargs = {"max_total_bytes": 4, "oversize_tail": True} if phase == "seek" else {}
    with pytest.raises(error_type) as caught:
        jsonl.load_jsonl(reader.path, **kwargs)
    assert caught.value is primary
    assert len(reader.owners) == 1
    fd = reader.owners[0][0]
    assert reader.closed == [fd]
    assert_closed(fd)
    assert reader.streams == []


@pytest.mark.parametrize("phase", ["fstat", "seek", "fdopen"])
@pytest.mark.parametrize("close_fails", [False, True])
def test_setup_io_failure_keeps_tolerant_contract(reader, phase, close_fails):
    reader.install(phase, OSError("unreadable"), OSError("close failed") if close_fails else None)
    kwargs = {"max_total_bytes": 4, "oversize_tail": True} if phase == "seek" else {}
    assert jsonl.load_jsonl(reader.path, **kwargs) == []
    fd = reader.owners[0][0]
    assert reader.closed == [fd]
    assert_closed(fd)


@pytest.mark.parametrize("phase", ["nonregular", "oversize"])
@pytest.mark.parametrize("close_fails", [False, True])
def test_initial_refusal_precedes_adoption(reader, phase, close_fails):
    reader.install(phase, cleanup=OSError("close failed") if close_fails else None)
    assert jsonl.load_jsonl(reader.path, max_total_bytes=1) == []
    assert reader.adopted == []
    fd = reader.owners[0][0]
    assert reader.closed == [fd]
    assert_closed(fd)


@pytest.mark.parametrize("error_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_read_error_precedes_both_cleanup_errors(reader, error_type):
    primary = error_type("read failed")
    reader.install("read", primary, RuntimeError("raw close failed"), OSError("stream close failed"))
    with pytest.raises(error_type) as caught:
        jsonl.load_jsonl(reader.path)
    assert caught.value is primary
    fd = reader.owners[0][0]
    assert reader.closed == [fd] and reader.streams[0].raw.closed
    assert_closed(fd)


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_success_still_reports_raw_close_failure(reader, error_type):
    cleanup = error_type("raw close failed")
    reader.install(cleanup=cleanup)
    with pytest.raises(error_type) as caught:
        jsonl.load_jsonl(reader.path)
    assert caught.value is cleanup
    fd = reader.owners[0][0]
    assert reader.closed == [fd] and reader.streams[0].raw.closed
    assert_closed(fd)


@pytest.mark.parametrize("bounded", [False, True])
def test_read_io_failure_keeps_preceding_rows(reader, bounded):
    reader.install("read-after-first", OSError("later read failed"))
    kwargs = {"max_total_bytes": 6} if bounded else {}
    assert jsonl.load_jsonl(reader.path, **kwargs) == [0]
    fd = reader.owners[0][0]
    assert reader.closed == [fd] and reader.streams[0].raw.closed
    assert_closed(fd)


def test_stream_close_failure_does_not_strand_raw_descriptor(reader):
    cleanup = OSError("stream close failed")
    reader.install(stream_cleanup=cleanup)
    with pytest.raises(OSError) as caught:
        jsonl.load_jsonl(reader.path)
    assert caught.value is cleanup
    fd = reader.owners[0][0]
    assert reader.closed == [fd] and reader.streams[0].raw.closed
    assert_closed(fd)


def test_failed_partial_adoption_keeps_other_descriptor_alive(tmp_path, monkeypatch):
    path, other = tmp_path / "trail.jsonl", tmp_path / "sentinel"
    path.write_bytes(b"0\n")
    other.write_bytes(b"owned sentinel")
    real_fdopen, real_open, real_close = os.fdopen, os.open, os.close
    sentinel = []

    def adopt(fd, *args, **kwargs):
        # Model a constructor that cleans up its partial wrapper, then fails.
        stream = real_fdopen(fd, *args, **kwargs)
        stream.close()
        replacement = real_open(other, os.O_RDONLY)
        info = os.fstat(replacement)
        sentinel.append((replacement, (info.st_dev, info.st_ino)))
        raise OSError("partial adoption failed")

    patch_module_attribute(monkeypatch, jsonl, "os", "fdopen", adopt)
    try:
        assert jsonl.load_jsonl(path) == []
        assert len(sentinel) == 1
        fd, identity = sentinel[0]
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) == identity
        assert os.read(fd, 64) == b"owned sentinel"
    finally:
        for fd, identity in sentinel:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                real_close(fd)
