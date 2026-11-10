"""Directory cleanup cannot suppress cancellation after atomic publication."""

import os
import stat

import pytest

from core import atomic_fs
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='requires native directory descriptors')


def _directory_faults(monkeypatch, failure, cleanup=None):
    directories, closed = [], []
    sync, close = os.fsync, os.close
    if cleanup is None:
        cleanup = OSError('directory close failed')

    def flush(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            directories.append((fd, info.st_dev, info.st_ino))
            if failure is not None:
                raise failure
        return sync(fd)

    def retire(fd):
        close(fd)
        if any(fd == item[0] for item in directories):
            closed.append(fd)
            raise cleanup

    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'fsync', flush)
    patch_module_attribute(monkeypatch, atomic_fs, 'os', 'close', retire)
    return directories, closed


def _assert_retired(directories, closed):
    assert len(directories) == 1 and closed == [directories[0][0]]
    fd, device, inode = directories[0]
    try:
        current = os.fstat(fd)
    except OSError:
        return
    # Logging may reuse the consumed number; never close that new owner.
    assert (current.st_dev, current.st_ino) != (device, inode)


@pytest.mark.parametrize('anchored', [False, True], ids=['ordinary', 'anchored'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_directory_flush_cancellation_keeps_precedence(tmp_path, monkeypatch, anchored, failure):
    target = tmp_path / 'value'
    target.write_bytes(b'old')
    primary = failure('cancelled')
    directories, closed = _directory_faults(monkeypatch, primary)
    try:
        with pytest.raises(failure) as caught:
            atomic_fs.write_bytes_atomically(target, b'new', root=tmp_path if anchored else None)
        assert caught.value is primary
    finally:
        _assert_retired(directories, closed)
        assert target.read_bytes() == b'new'
        assert not list(tmp_path.glob('.atomic-*'))


@pytest.mark.parametrize('failure', [None, OSError('directory sync unsupported')])
def test_ordinary_directory_io_errors_remain_best_effort(tmp_path, monkeypatch, failure):
    directories, closed = _directory_faults(monkeypatch, failure)
    target = tmp_path / 'value'
    atomic_fs.write_bytes_atomically(target, b'new')
    _assert_retired(directories, closed)
    assert target.read_bytes() == b'new'
    assert not list(tmp_path.glob('.atomic-*'))


def test_anchored_close_only_failure_keeps_strict_contract(tmp_path, monkeypatch):
    directories, closed = _directory_faults(monkeypatch, None)
    target = tmp_path / 'value'
    with pytest.raises(OSError, match='directory close failed'):
        atomic_fs.write_bytes_atomically(target, b'new', root=tmp_path)
    _assert_retired(directories, closed)
    assert target.read_bytes() == b'new'


@pytest.mark.parametrize('anchored', [False, True], ids=['ordinary', 'anchored'])
@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_close_cancellation_after_tolerated_flush_error(tmp_path, monkeypatch, anchored, failure):
    primary = failure('cancelled while closing')
    directories, closed = _directory_faults(
        monkeypatch, OSError('directory sync unsupported'), primary,
    )
    target = tmp_path / 'value'
    try:
        with pytest.raises(failure) as caught:
            atomic_fs.write_bytes_atomically(target, b'new', root=tmp_path if anchored else None)
        assert caught.value is primary
    finally:
        _assert_retired(directories, closed)
        assert target.read_bytes() == b'new'
        assert not list(tmp_path.glob('.atomic-*'))
