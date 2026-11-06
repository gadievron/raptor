"""Artifact descriptor cleanup preserves failures without leaking ownership."""
import os
from types import SimpleNamespace
import stat

import pytest

from core.testing.module_bindings import patch_module_attribute

from core import atomic_fs


class Cancelled(BaseException):
    pass


@pytest.mark.parametrize('close_fails', [False, True])
def test_cancelled_permission_setup_closes_fd(tmp_path, monkeypatch, close_fails):
    original_open, original_close = os.open, os.close
    opened, closed = [], []
    cancellation = Cancelled('cancel setup')

    def open_fd(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close_fd(fd):
        original_close(fd)
        closed.append(fd)
        if close_fails:
            raise OSError('close after release')

    def cancel(*args):
        raise cancellation

    patch_module_attribute(monkeypatch, atomic_fs, "os", 'open', open_fd)
    patch_module_attribute(monkeypatch, atomic_fs, "os", 'close', close_fd)
    patch_module_attribute(monkeypatch, atomic_fs, "os", 'fchmod', cancel)
    with pytest.raises(Cancelled) as raised:
        atomic_fs.open_exclusive_artifact(tmp_path / 'new', mode=0o600)
    assert raised.value is cancellation
    # Cleanup on the baseline too, so the regression itself cannot leak.
    leaked = [fd for fd in opened if fd not in closed]
    for fd in leaked:
        original_close(fd)
    assert closed == opened


@pytest.mark.parametrize('failure', [OSError, Cancelled])
def test_write_error_survives_close_error(tmp_path, monkeypatch, failure):
    original_close = os.close
    error = failure('original write failure')
    closed = []

    def write(*args):
        raise error

    def close(fd):
        original_close(fd)
        closed.append(fd)
        raise OSError('secondary close failure')

    patch_module_attribute(monkeypatch, atomic_fs, "os", 'write', write)
    patch_module_attribute(monkeypatch, atomic_fs, "os", 'close', close)
    with pytest.raises(failure) as raised:
        atomic_fs.write_new_bytes(tmp_path / 'new', b'data')
    assert raised.value is error
    assert len(closed) == 1


def test_successful_write_still_reports_close_failure(tmp_path, monkeypatch):
    original_close = os.close

    def close(fd):
        original_close(fd)
        raise OSError('close failure')

    patch_module_attribute(monkeypatch, atomic_fs, "os", 'close', close)
    with pytest.raises(OSError, match='close failure'):
        atomic_fs.write_new_bytes(tmp_path / 'new', b'data')


@pytest.mark.parametrize('opener', ['open_hardened_read', 'open_hardened_append'])
def test_refusal_error_survives_close_error(tmp_path, monkeypatch, opener):
    path = tmp_path / 'existing'
    path.write_bytes(b'data')
    original_close = os.close
    closed = []

    def close(fd):
        original_close(fd)
        closed.append(fd)
        raise OSError('secondary close failure')

    patch_module_attribute(monkeypatch, atomic_fs, "os", 'fstat', lambda fd: SimpleNamespace(st_mode=stat.S_IFIFO))
    patch_module_attribute(monkeypatch, atomic_fs, "os", 'close', close)
    with pytest.raises(OSError, match='not a regular file'):
        getattr(atomic_fs, opener)(path)
    assert len(closed) == 1
