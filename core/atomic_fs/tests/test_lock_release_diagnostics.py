"""Lock cleanup diagnostics cannot strand native descriptors or replace errors."""

import errno
import os

import pytest

from core.atomic_fs import fs_lock as locks
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(not locks._HAS_FCNTL, reason='requires flock')


@pytest.mark.parametrize('active', [False, True], ids=['no-body-error', 'body-error'])
@pytest.mark.parametrize('diagnostic_type', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('unlock_type', [OSError, RuntimeError], ids=['io-cleanup', 'runtime-cleanup'])
def test_diagnostic_failure_cannot_prevent_lock_retirement(
    tmp_path, monkeypatch, active, diagnostic_type, unlock_type,
):
    path = tmp_path / 'owned.lock'
    native_open, native_close, native_flock = os.open, os.close, locks.fcntl.flock
    identities, events = [], []
    diagnostic = diagnostic_type('diagnostic failed')
    unlock_error = unlock_type('unlock failed')
    primary = (KeyboardInterrupt('body interrupted') if active
               else unlock_error if unlock_type is RuntimeError else diagnostic)

    def opened(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        info = os.fstat(fd)
        identities.append((fd, info.st_dev, info.st_ino))
        return fd

    def flock(fd, operation):
        if operation == locks.fcntl.LOCK_UN:
            events.append('unlock')
            raise unlock_error
        return native_flock(fd, operation)

    def close(fd):
        native_close(fd)
        events.append('close')

    class Diagnostics:
        def warning(self, *args, **kwargs):
            events.append('diagnostic')
            raise diagnostic

    patch_module_attribute(monkeypatch, locks, 'os', 'open', opened)
    patch_module_attribute(monkeypatch, locks, 'os', 'close', close)
    patch_module_attribute(monkeypatch, locks, 'fcntl', 'flock', flock)
    monkeypatch.setattr(locks, 'logger', Diagnostics())
    entered = []
    try:
        with pytest.raises(type(primary)) as caught:
            with locks.sidecar_flock(path, required=True):
                entered.append(True)
                # Distinct native opens must contend while the body owns it.
                probe = native_open(path, os.O_RDWR)
                try:
                    with pytest.raises(OSError) as busy:
                        native_flock(probe, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
                    assert busy.value.errno in (errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK)
                finally:
                    native_close(probe)
                if active:
                    raise primary
        assert caught.value is primary
        assert entered == [True] and len(identities) == 1
        fd, device, inode = identities[0]
        try:
            info = os.fstat(fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            assert (info.st_dev, info.st_ino) != (device, inode), 'lock descriptor remained open'
        assert events == ['unlock', 'close', 'diagnostic']
        probe = native_open(path, os.O_RDWR)
        try:
            native_flock(probe, locks.fcntl.LOCK_EX | locks.fcntl.LOCK_NB)
        finally:
            native_close(probe)
    finally:
        # A red control must not retain its native lock or close a recycled FD.
        for fd, device, inode in identities:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                native_close(fd)
