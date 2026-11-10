"""Annotation lock setup owns its native descriptor without changing lock policy."""

import errno
import os
from types import SimpleNamespace

import pytest

from core.annotations import storage


@pytest.fixture
def lock_io(tmp_path, monkeypatch):
    if not storage._HAS_FCNTL:
        pytest.skip('native annotation flock requires POSIX fcntl')
    path = tmp_path / 'owned.md'
    state = {'path': path, 'lock': path.with_suffix('.md.lock'), 'live': set(),
             'closes': 0, 'metadata_error': None, 'close_error': None, 'entered': False}

    def open_file(name, flags, mode=0o777):
        fd = os.open(name, flags, mode)
        state['fd'] = fd
        state['flags'] = flags
        state['mode'] = mode
        state['live'].add(fd)
        return fd

    def fstat(fd):
        result = os.fstat(fd)
        state['inode'] = result.st_ino
        if state['metadata_error'] is not None:
            raise state['metadata_error']
        return result

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['close_error'] is not None:
            raise state['close_error']

    monkeypatch.setattr(storage, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'fstat': fstat, 'close': close},
    ))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def assert_retired(state):
    # Inspect only handles still owned by the fixture. Never probe a
    # released/recycled descriptor after logging or later operations.
    remaining = [os.fstat(fd).st_ino for fd in state['live']]
    assert not remaining
    assert state['closes'] == 1


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('cleanup_type', [None, KeyboardInterrupt])
def test_lock_setup_metadata_error_retires_native_fd(lock_io, primary_type, cleanup_type):
    primary = primary_type('primary native metadata failure')
    lock_io['metadata_error'] = primary
    if cleanup_type is not None:
        lock_io['close_error'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        with storage._file_lock(lock_io['path']):
            lock_io['entered'] = True
    assert raised.value is primary
    assert not lock_io['entered']
    assert_retired(lock_io)


def test_lock_setup_primary_oserror_survives_close_oserror(lock_io):
    primary = OSError('primary native metadata failure')
    lock_io['metadata_error'] = primary
    lock_io['close_error'] = OSError('native close consumed')
    with pytest.raises(OSError) as raised:
        with storage._file_lock(lock_io['path']):
            pytest.fail('metadata failure must not enter lock body')
    assert raised.value is primary
    assert_retired(lock_io)


@pytest.mark.parametrize('primary_type', [RuntimeError, KeyboardInterrupt, SystemExit])
def test_native_lock_body_primary_survives_close(lock_io, primary_type):
    primary = primary_type('primary annotation operation failed')
    lock_io['close_error'] = OSError('native close consumed')
    with pytest.raises(primary_type) as raised:
        with storage._file_lock(lock_io['path']):
            raise primary
    assert raised.value is primary
    assert_retired(lock_io)


@pytest.mark.parametrize('cleanup_type', [None, OSError, KeyboardInterrupt])
def test_native_nonregular_rejection_consumes_fd_once(lock_io, cleanup_type):
    os.mkfifo(lock_io['lock'], 0o600)
    if cleanup_type is None:
        expected = storage.AnnotationFileError
    else:
        expected = cleanup_type
        lock_io['close_error'] = cleanup_type('native explicit close consumed')
    with pytest.raises(expected) as raised:
        with storage._file_lock(lock_io['path']):
            pytest.fail('FIFO must not enter lock body')
    if cleanup_type is not None:
        assert raised.value is lock_io['close_error']
    assert_retired(lock_io)


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_lock_close_error_still_propagates(lock_io, cleanup_type):
    failure = cleanup_type('fresh native close consumed')
    lock_io['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        with storage._file_lock(lock_io['path']):
            lock_io['entered'] = True
    assert raised.value is failure
    assert lock_io['entered']
    assert_retired(lock_io)


def test_native_readonly_flock_excludes_then_releases(lock_io):
    lock_io['lock'].write_bytes(b'')
    lock_io['lock'].chmod(0o400)
    flags = storage.fcntl
    with storage._file_lock(lock_io['path']):
        assert lock_io['flags'] & os.O_ACCMODE == os.O_RDONLY
        assert lock_io['mode'] == 0o666
        other = os.open(lock_io['lock'], os.O_RDONLY)
        try:
            with pytest.raises(OSError) as held:
                flags.flock(other, flags.LOCK_EX | flags.LOCK_NB)
            assert held.value.errno in (errno.EACCES, errno.EAGAIN)
        finally:
            os.close(other)
    assert_retired(lock_io)
    other = os.open(lock_io['lock'], os.O_RDONLY)
    try:
        flags.flock(other, flags.LOCK_EX | flags.LOCK_NB)
        flags.flock(other, flags.LOCK_UN)
    finally:
        os.close(other)
    assert lock_io['lock'].read_bytes() == b''
