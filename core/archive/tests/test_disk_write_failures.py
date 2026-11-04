"""Failed output is never a complete extraction suitable for caching."""

import builtins
import errno
import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

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
    real_open = builtins.open

    class BrokenOutput:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def write(self, data):
            if stage == "write":
                self.stream.write(data[:1])
                raise failure
            return self.stream.write(data)

        def __exit__(self, *args):
            self.stream.close()
            if stage == "close":
                raise failure

    def output_open(path, mode="r", *args, **kwargs):
        if mode == "wb" and Path(path).is_relative_to(dest):
            if stage == "open":
                raise failure
            return BrokenOutput(real_open(path, mode, *args, **kwargs))
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", output_open)
    with pytest.raises(OSError) as caught:
        extract_to_dir(source, dest)
    assert caught.value is failure


@pytest.mark.parametrize("sink", [False, True])
@pytest.mark.parametrize("error", [errno.ENAMETOOLONG, errno.EINVAL, errno.EISDIR])
def test_invalid_member_paths_still_drop_and_allow_later_members(
    tmp_path, monkeypatch, sink, error
):
    real_open = builtins.open

    def invalid(path, mode="r", *args, **kwargs):
        if mode == "wb" and Path(path).name == "invalid":
            raise OSError(error, "invalid member path")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", invalid)
    if sink:
        writer = archive_extract._DiskSink(tmp_path, 1000, 100)
        writer("invalid", b"bad")
        writer("valid", b"good")
        stats = writer.stats()
    else:
        stats = archive_extract._write_members(
            {"invalid": b"bad", "valid": b"good"}, tmp_path, 1000, 100
        )
    assert stats["files"] == 1
    assert stats["dropped_reasons"] == {"unwritable": 1}
    assert (tmp_path / "valid").read_bytes() == b"good"
