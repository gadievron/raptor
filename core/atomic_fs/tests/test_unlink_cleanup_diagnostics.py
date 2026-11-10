"""Temporary cleanup reporting preserves active write failures."""
from pathlib import Path
import errno
import os

import pytest

import core.atomic_fs as atomic
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("anchored", [
    pytest.param(False, id="ordinary"),
    pytest.param(True, id="anchored", marks=pytest.mark.skipif(
        os.open not in os.supports_dir_fd, reason="requires directory descriptor support",
    )),
])
@pytest.mark.parametrize("primary_type", [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("diagnostic_type", [RuntimeError, KeyboardInterrupt, SystemExit])
def test_write_error_survives_unlink_diagnostic_failure(tmp_path, monkeypatch, anchored, primary_type, diagnostic_type):
    root = tmp_path / "owned"
    root.mkdir()
    target = root / "state"
    target.write_bytes(b"previous bytes")
    primary = primary_type("write failed")
    reported, retired, refused = [], [], []
    native_close, native_unlink = os.close, os.unlink

    class OwnedPath(type(Path())):
        def unlink(self, *args, **kwargs):
            if self.name.startswith(".atomic-"):
                refused.append(self.name)
                raise OSError("temporary unlink refused")
            return super().unlink(*args, **kwargs)

    def unlink(path, **kwargs):
        refused.append(path)
        raise OSError("temporary unlink refused")

    def write(fd, data):
        raise primary

    def close(fd):
        info = os.fstat(fd)
        native_close(fd)
        retired.append((fd, info.st_dev, info.st_ino))

    class Diagnostics:
        def warning(self, *args, **kwargs):
            reported.append(True)
            raise diagnostic_type("diagnostic failed")

    monkeypatch.setattr(atomic, "Path", OwnedPath)
    patch_module_attribute(monkeypatch, atomic, "os", "write", write)
    patch_module_attribute(monkeypatch, atomic, "os", "close", close)
    patch_module_attribute(monkeypatch, atomic, "os", "unlink", unlink)
    patch_module_attribute(monkeypatch, atomic, "logging", "getLogger", lambda *args: Diagnostics())
    try:
        with pytest.raises(primary_type) as caught:
            atomic.write_bytes_atomically(target, b"replacement", root=root if anchored else None)
        assert caught.value is primary
        assert reported == [True] and len(refused) == 1
        assert target.read_bytes() == b"previous bytes"
        staging = [path for path in root.iterdir() if path != target]
        assert len(staging) == 1 and staging[0].name == refused[0]
        assert len(retired) == (2 if anchored else 1)
        for fd, device, inode in retired:
            try:
                info = os.fstat(fd)
            except OSError as error:
                assert error.errno == errno.EBADF
                continue
            assert (info.st_dev, info.st_ino) != (device, inode)
    finally:
        for path in root.iterdir():
            if path != target:
                native_unlink(path)
