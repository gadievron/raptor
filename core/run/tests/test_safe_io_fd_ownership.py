"""Directory permission errors retain precedence over consumed-FD close faults."""

import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.run import safe_io


@pytest.fixture
def directory_io(tmp_path, monkeypatch):
    state = {'path': tmp_path / 'owned-output', 'live': set(), 'closes': 0,
             'chmods': 0, 'primary': None, 'cleanup': None, 'opens': []}

    def open_directory(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        state['opens'].append((args, kwargs))
        return fd

    def fchmod(fd, mode):
        os.fchmod(fd, mode)
        state['chmods'] += 1
        if state['primary'] is not None:
            raise state['primary']

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['cleanup'] is not None:
            raise state['cleanup']

    monkeypatch.setattr(safe_io, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_directory, 'fchmod': fchmod, 'close': close}))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt])
def test_permission_primary_survives_consumed_directory_close(
        directory_io, primary_type, cleanup_type):
    primary = primary_type('permission operation failed after native fchmod')
    directory_io['primary'] = primary
    directory_io['cleanup'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        safe_io.safe_run_mkdir(directory_io['path'])
    assert raised.value is primary
    assert directory_io['chmods'] == directory_io['closes'] == 1
    assert not directory_io['live']


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_directory_close_error_remains_visible(directory_io, cleanup_type):
    failure = cleanup_type('native close consumed')
    directory_io['cleanup'] = failure
    with pytest.raises(cleanup_type) as raised:
        safe_io.safe_run_mkdir(directory_io['path'])
    assert raised.value is failure
    assert stat.S_IMODE(directory_io['path'].stat().st_mode) == 0o700
    assert directory_io['chmods'] == directory_io['closes'] == 1
    assert not directory_io['live']


def test_native_directory_creation_retains_mode_and_no_follow_flags(directory_io):
    safe_io.safe_run_mkdir(directory_io['path'])
    assert stat.S_IMODE(directory_io['path'].stat().st_mode) == 0o700
    args, kwargs = directory_io['opens'][0]
    assert args == (directory_io['path'], os.O_RDONLY | os.O_DIRECTORY |
                    getattr(os, 'O_NOFOLLOW', 0))
    assert kwargs == {}
    assert directory_io['chmods'] == directory_io['closes'] == 1
    assert not directory_io['live']


def test_existing_directory_retains_no_chmod_or_descriptor_allocation(directory_io):
    directory_io['path'].mkdir(mode=0o700)
    safe_io.safe_run_mkdir(directory_io['path'])
    assert directory_io['opens'] == []
    assert directory_io['closes'] == directory_io['chmods'] == 0
