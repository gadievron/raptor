"""Capped-read fallbacks must not hide cancellation or refusal metadata."""
import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.security import capped_read
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def reader(tmp_path, monkeypatch):
    path = tmp_path / "owned"
    path.write_bytes(b"owned")
    owners, streams, closed = [], [], []
    real_open, real_close, real_stat, real_fdopen = os.open, os.close, os.fstat, os.fdopen

    def install(primary=None, stream_cleanup=None, raw_cleanup=None, nonregular=False):
        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            info = real_stat(fd)
            owners.append((fd, (info.st_dev, info.st_ino)))
            return fd

        def checked(fd):
            info = real_stat(fd)
            return os.stat_result((stat.S_IFIFO, *info[1:])) if nonregular else info

        class Stream:
            def __init__(self, raw):
                self.raw = raw

            def __enter__(self):
                return self

            def read(self, size):
                if primary is not None:
                    raise primary
                return self.raw.read(size)

            def __exit__(self, *args):
                self.raw.__exit__(*args)
                if stream_cleanup is not None:
                    raise stream_cleanup

        def adopt(fd, *args, **kwargs):
            assert kwargs["closefd"] is False
            stream = Stream(real_fdopen(fd, *args, **kwargs))
            streams.append(stream)
            return stream

        def close(fd):
            real_close(fd)
            closed.append(fd)
            if raw_cleanup is not None:
                raise raw_cleanup

        for name, value in (("open", opened), ("fstat", checked),
                            ("fdopen", adopt), ("close", close)):
            patch_module_attribute(monkeypatch, capped_read, "os", name, value)

    def read(kind, strict=False, cap=16):
        if kind == "stat":
            assert not strict
            return capped_read.read_capped_with_stat(path, cap)
        function = capped_read.read_capped if kind == "bytes" else capped_read.read_capped_text
        return function(path, cap, raise_on_refusal=strict)

    yield SimpleNamespace(path=path, install=install, read=read,
                          owners=owners, streams=streams, closed=closed)
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


def assert_retired(reader):
    assert len(reader.owners) == 1
    fd = reader.owners[0][0]
    assert reader.closed == [fd]
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF
    assert all(stream.raw.closed for stream in reader.streams)


@pytest.mark.parametrize("kind", ["bytes", "text", "stat"])
@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_stage", ["stream", "raw"])
def test_default_readers_keep_cancellation(reader, kind, error_type, cleanup_stage):
    primary = error_type("owned read cancellation")
    reader.install(primary, OSError("stream close failed") if cleanup_stage == "stream" else None,
                   RuntimeError("raw close failed") if cleanup_stage == "raw" else None)
    with pytest.raises(error_type) as caught:
        reader.read(kind)
    assert caught.value is primary
    assert_retired(reader)


@pytest.mark.parametrize("kind", ["bytes", "text"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError])
@pytest.mark.parametrize("cleanup_stage", ["stream", "raw"])
def test_strict_readers_preserve_primary_error(reader, kind, error_type, cleanup_stage):
    primary = error_type("owned read failure")
    reader.install(primary, OSError("stream close failed") if cleanup_stage == "stream" else None,
                   RuntimeError("raw close failed") if cleanup_stage == "raw" else None)
    with pytest.raises(error_type) as caught:
        reader.read(kind, strict=True)
    assert caught.value is primary
    assert_retired(reader)


@pytest.mark.parametrize("kind", ["bytes", "text", "stat"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError])
def test_ordinary_errors_keep_default_fallback(reader, kind, error_type):
    reader.install(error_type("unreadable"), OSError("stream close failed"), RuntimeError("raw close failed"))
    assert reader.read(kind) == ((None, None) if kind == "stat" else None)
    assert_retired(reader)


@pytest.mark.parametrize("kind,strict", [("bytes", False), ("bytes", True),
                                         ("text", False), ("text", True), ("stat", False)])
def test_success_keeps_legacy_raw_close_io_tolerance(reader, kind, strict):
    reader.install(raw_cleanup=OSError("raw close failed"))
    result = reader.read(kind, strict=strict)
    if kind == "stat":
        data, info = result
        assert data == b"owned"
        assert (info.st_dev, info.st_ino) == reader.owners[0][1]
    else:
        assert result == (b"owned" if kind == "bytes" else "owned")
    assert_retired(reader)


@pytest.mark.parametrize("nonregular", [False, True])
def test_refusal_keeps_metadata_before_adoption(reader, nonregular):
    reader.install(raw_cleanup=RuntimeError("raw close failed"), nonregular=nonregular)
    with pytest.raises(capped_read.CappedReadRefused) as caught:
        reader.read("bytes", strict=True, cap=2)
    error = caught.value
    assert error.reason == ("not_regular" if nonregular else "over_cap")
    assert error.st_size == 5
    assert stat.S_ISFIFO(error.st_mode) if nonregular else stat.S_ISREG(error.st_mode)
    assert reader.streams == []
    assert_retired(reader)
