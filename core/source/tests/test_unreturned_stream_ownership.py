"""A parent-retirement failure cannot abandon an unreturned borrowed stream."""
import errno
import os

import pytest

from core.source import beneath
from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('closefd', [True, False])
@pytest.mark.parametrize('mode', ['r', 'rb'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_root_retirement_failure_reclaims_unreturned_stream(
    tmp_path, monkeypatch, closefd, mode, error_type,
):
    path = tmp_path / 'owned'
    path.write_bytes(b'owned')
    original_open, original_close = os.open, os.close
    owners = {}
    roots = []
    primary = error_type('root retirement failed')

    def opened(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        info = os.fstat(fd)
        owners[fd] = (info.st_dev, info.st_ino)
        if not roots:
            roots.append(fd)
        return fd

    def close(fd):
        original_close(fd)
        if fd == roots[0]:
            raise primary

    monkeypatch.setattr(beneath, '_OPENAT2_ARCH_OK', False)
    patch_module_attribute(monkeypatch, beneath, 'os', 'open', opened)
    patch_module_attribute(monkeypatch, beneath, 'os', 'close', close)
    try:
        with pytest.raises(error_type) as caught:
            beneath.open_regular_beneath(tmp_path, path.name, mode, closefd=closefd)
        assert caught.value is primary
        assert len(owners) >= 2
        for fd in owners:
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
    finally:
        for fd, identity in owners.items():
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                original_close(fd)


@pytest.mark.parametrize('phase', ['before', 'after'])
@pytest.mark.parametrize('error_type', [OSError, KeyboardInterrupt])
def test_borrowed_retirement_keeps_stream_error_and_still_closes_raw(
    tmp_path, phase, error_type,
):
    import io

    from core.source.streams import retire_unreturned_stream

    path = tmp_path / 'owned'
    path.write_bytes(b'owned')
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    primary = error_type('wrapper close failed')
    attempts = []

    class FailedClose(io.FileIO):
        def close(self):
            if phase == 'after':
                super().close()
            raise primary

    raw = FailedClose(fd, 'rb', closefd=False)

    def close(descriptor):
        os.close(descriptor)
        attempts.append(descriptor)
        raise RuntimeError('secondary raw close failed')

    try:
        with pytest.raises(error_type) as caught:
            retire_unreturned_stream(raw, close)
        assert caught.value is primary
        assert attempts == [fd]
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
    finally:
        io.FileIO.close(raw)  # Borrowed close never retries a consumed number.
        try:
            current = os.fstat(fd)
        except OSError:
            pass
        else:
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                os.close(fd)
