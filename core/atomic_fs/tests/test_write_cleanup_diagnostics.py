"""Failed-write diagnostics cannot replace the operation or strand staging."""

import errno
import os

import pytest

import core.atomic_fs as atomic
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('anchored', [
    pytest.param(False, id='ordinary'),
    pytest.param(True, id='anchored', marks=pytest.mark.skipif(
        os.open not in os.supports_dir_fd, reason='requires directory descriptor support',
    )),
])
@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('diagnostic_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_write_error_survives_close_diagnostic_failure(
    tmp_path, monkeypatch, anchored, primary_type, diagnostic_type,
):
    root = tmp_path / 'owned'
    root.mkdir()
    target = root / 'state'
    target.write_bytes(b'previous bytes')
    primary = primary_type('write failed')
    diagnostic = diagnostic_type('diagnostic failed')
    native_open, native_close = os.open, os.close
    identities, closes, reported = [], [], []

    def opened(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        info = os.fstat(fd)
        identities.append((fd, info.st_dev, info.st_ino))
        return fd

    def write(fd, data):
        assert fd == identities[0][0]
        raise primary

    def close(fd):
        native_close(fd)
        if fd == identities[0][0]:
            closes.append(fd)
            raise OSError('secondary close failure')

    class Diagnostics:
        def warning(self, *args, **kwargs):
            reported.append(True)
            raise diagnostic

    patch_module_attribute(monkeypatch, atomic, 'os', 'open', opened)
    patch_module_attribute(monkeypatch, atomic, 'os', 'write', write)
    patch_module_attribute(monkeypatch, atomic, 'os', 'close', close)
    patch_module_attribute(monkeypatch, atomic, 'logging', 'getLogger', lambda *args: Diagnostics())
    try:
        with pytest.raises(primary_type) as caught:
            atomic.write_bytes_atomically(
                target, b'replacement bytes', root=root if anchored else None,
            )
        assert caught.value is primary
        assert reported == [True] and closes == [identities[0][0]]
        assert target.read_bytes() == b'previous bytes'
        assert list(root.iterdir()) == [target]
        fd, device, inode = identities[0]
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (info.st_dev, info.st_ino) != (device, inode)
    finally:
        for fd, device, inode in identities:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                native_close(fd)
