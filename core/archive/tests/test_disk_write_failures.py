"""Failed output is never a complete extraction suitable for caching."""

import os
import errno
import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from core import atomic_fs
from core.testing.module_bindings import patch_module_attribute
from core.archive import extract_to_dir
from core.archive import extract as archive_extract


def make_archive(path, fmt):
    if fmt == "zip":
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("source.c", b"data")
    elif fmt == "tar":
        with tarfile.open(path, "w") as tar:
            info = tarfile.TarInfo("source.c")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"data"))
    else:
        path.write_bytes(gzip.compress(b"data"))
    return path


@pytest.mark.parametrize("fmt", ["zip", "tar", "gz"])
@pytest.mark.parametrize("stage", ["open", "write", "close"])
@pytest.mark.parametrize("error", [errno.ENOSPC, errno.EDQUOT, errno.EIO])
def test_filesystem_failure_aborts_extraction(tmp_path, monkeypatch, fmt, stage, error):
    source = make_archive(tmp_path / ("source." + fmt), fmt)
    dest = tmp_path / "out"
    failure = OSError(error, "output failed")
    real_open, real_write, real_close = os.open, os.write, os.close
    outputs, reached = set(), []

    def output_open(path, flags, *args, **kwargs):
        if flags & os.O_CREAT:
            reached.append('open')
            if stage == 'open':
                raise failure
        fd = real_open(path, flags, *args, **kwargs)
        if flags & os.O_CREAT:
            outputs.add(fd)
        return fd

    def write(fd, data):
        if fd in outputs and stage == 'write':
            reached.append('write')
            real_write(fd, data[:1])
            raise failure
        return real_write(fd, data)

    def close(fd):
        real_close(fd)
        if fd in outputs:
            outputs.remove(fd)
            if stage == 'close':
                reached.append('close')
                raise failure

    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'open', output_open)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'write', write)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'close', close)
    with pytest.raises(OSError) as caught:
        extract_to_dir(source, dest)
    assert caught.value is failure
    assert stage in reached
    assert outputs == set()
    assert list(dest.rglob('*')) == []


@pytest.mark.parametrize("sink", [False, True])
@pytest.mark.parametrize("error", [errno.ENAMETOOLONG, errno.EINVAL, errno.EISDIR])
def test_invalid_member_paths_still_drop_and_allow_later_members(
    tmp_path, monkeypatch, sink, error
):
    real_write = archive_extract.write_bytes_atomically
    reached = []

    def invalid(path, *args, **kwargs):
        if Path(path).name == "invalid":
            reached.append(path)
            raise OSError(error, "invalid member path")
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(archive_extract, "write_bytes_atomically", invalid)
    if sink:
        writer = archive_extract._DiskSink(tmp_path, 1000, 100)
        writer("invalid", b"bad")
        writer("valid", b"good")
        stats = writer.stats()
    else:
        stats = archive_extract._write_members(
            {"invalid": b"bad", "valid": b"good"}, tmp_path, 1000, 100
        )
    assert len(reached) == 1
    assert stats["files"] == 1
    assert stats["dropped_reasons"] == {"unwritable": 1}
    assert (tmp_path / "valid").read_bytes() == b"good"
