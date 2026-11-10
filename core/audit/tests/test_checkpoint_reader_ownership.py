"""Checkpoint intake retires native descriptors before invalidation or authentication."""

import errno
import io
import os
from types import SimpleNamespace

import pytest

from core.audit import sweep_checkpoint as checkpoint


@pytest.fixture
def reader(tmp_path, monkeypatch):
    path = tmp_path / checkpoint.CHECKPOINT_FILENAME
    path.write_bytes(b'owned checkpoint bytes\n')
    # Exercise the intake envelope directly, never constructor key acquisition
    # or record authentication/adoption. The key is inspected after intake.
    owner = object.__new__(checkpoint.SweepCheckpoint)
    owner._path = path
    owner._max_total_bytes = 1024
    owner._max_record_bytes = 512
    owner._mac_key = None
    owner._loaded = {('owned', ()): {}}
    owner._persisted = {b'owned'}
    state = {'owner': owner, 'path': path, 'live': set(), 'closes': 0,
             'metadata_error': None, 'setup_error': None, 'read_error': None,
             'stream_close_error': None, 'raw_close_error': None,
             'wrappers': 0, 'reads': 0, 'reasons': [], 'invalidate_closes': []}
    native_invalidate = owner._invalidate

    def invalidate(reason):
        state['reasons'].append(reason)
        state['invalidate_closes'].append(state['closes'])
        native_invalidate(reason)

    def open_file(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        state['fd'] = fd
        state['open_args'] = args, kwargs
        return fd

    def fstat(fd):
        info = os.fstat(fd)
        state['identity'] = info.st_dev, info.st_ino
        if state['metadata_error'] is not None:
            raise state['metadata_error']
        return info

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['raw_close_error'] is not None:
            raise state['raw_close_error']

    def fdopen(fd, mode, **kwargs):
        state['wrappers'] += 1
        if state['setup_error'] is not None:
            stream = os.fdopen(fd, mode, **kwargs)
            owns = stream.raw.closefd
            stream.close()
            if owns:
                state['live'].remove(fd)
            raise state['setup_error']

        class Reader(io.BufferedReader):
            def read(self, *args, **kw):
                state['reads'] += 1
                data = super().read(*args, **kw)
                if state['read_error'] is not None:
                    raise state['read_error']
                return data

            def close(self):
                if self.closed:
                    return
                owns = self.raw.closefd
                super().close()
                if owns:
                    state['live'].remove(fd)
                if state['stream_close_error'] is not None:
                    raise state['stream_close_error']

        return Reader(io.FileIO(fd, mode, closefd=kwargs.get('closefd', True)))

    monkeypatch.setattr(owner, '_invalidate', invalidate)
    monkeypatch.setattr(checkpoint, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'fstat': fstat, 'close': close, 'fdopen': fdopen}))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def assert_retired(state):
    assert state['closes'] == 1 and not state['live']


def test_metadata_io_failure_retires_fd_before_invalidation(reader):
    reader['metadata_error'] = OSError('metadata unavailable after native fstat')
    reader['owner']._load()
    if reader['live']:
        info = os.fstat(reader['fd'])
        assert (info.st_dev, info.st_ino) == reader['identity']
    assert_retired(reader)
    assert reader['invalidate_closes'] == [1]
    assert reader['reasons'] == ['read failed: OSError']
    assert not reader['owner']._loaded and not reader['owner']._persisted
    assert reader['path'].with_name(reader['path'].name + '.corrupt').is_file()


@pytest.mark.parametrize('primary_type', [MemoryError, KeyboardInterrupt, SystemExit])
def test_metadata_cancellation_keeps_primary_after_close_fault(reader, primary_type):
    primary = primary_type('native metadata cancelled')
    reader['metadata_error'] = primary
    reader['raw_close_error'] = OSError('raw descriptor consumed')
    with pytest.raises(primary_type) as raised:
        reader['owner']._load()
    assert raised.value is primary
    assert not reader['reasons']
    assert_retired(reader)


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
def test_stream_setup_failure_still_retires_raw_descriptor(reader, primary_type):
    primary = primary_type('native wrapper setup failed')
    reader['setup_error'] = primary
    if primary_type is OSError:
        reader['owner']._load()
        assert reader['reasons'] == ['read failed: OSError']
    else:
        with pytest.raises(primary_type) as raised:
            reader['owner']._load()
        assert raised.value is primary
    assert_retired(reader)


@pytest.mark.parametrize('primary_type', [OSError, KeyboardInterrupt, SystemExit])
def test_read_error_survives_both_cleanup_faults(reader, primary_type):
    primary = primary_type('native read cancelled')
    reader['read_error'] = primary
    reader['stream_close_error'] = OSError('stream closed')
    reader['raw_close_error'] = SystemExit('raw descriptor consumed')
    if primary_type is OSError:
        reader['owner']._load()
        assert reader['reasons'] == ['read failed: OSError']
    else:
        with pytest.raises(primary_type) as raised:
            reader['owner']._load()
        assert raised.value is primary
    assert_retired(reader)


@pytest.mark.parametrize('phase', ['stream_close_error', 'raw_close_error'])
@pytest.mark.parametrize('failure_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_stops_before_authentication(reader, phase, failure_type):
    failure = failure_type('native cleanup failed')
    reader[phase] = failure
    if failure_type is OSError:
        reader['owner']._load()
        assert reader['reasons'] == ['read failed: OSError']
    else:
        with pytest.raises(failure_type) as raised:
            reader['owner']._load()
        assert raised.value is failure
    assert_retired(reader)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
@pytest.mark.parametrize('close_type', [None, OSError, KeyboardInterrupt])
def test_pre_adoption_refusal_keeps_explicit_close_policy(reader, kind, close_type):
    if kind == 'fifo':
        reader['path'].unlink()
        os.mkfifo(reader['path'], 0o600)
    else:
        reader['path'].write_bytes(b'x' * 1025)
    if close_type is not None:
        reader['raw_close_error'] = close_type('native descriptor consumed')
    if close_type is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt):
            reader['owner']._load()
        assert not reader['reasons']
    else:
        reader['owner']._load()
        assert reader['invalidate_closes'] == [1]
        assert reader['reasons'][0] == ('read failed: OSError' if close_type else
                                       'not a regular file' if kind == 'fifo' else
                                       '1025 bytes exceeds the 1024-byte load bound')
    assert reader['wrappers'] == 0
    assert_retired(reader)


def test_healthy_intake_closes_before_disabled_authentication(reader):
    reader['owner']._load()
    assert reader['reads'] == 1 and not reader['reasons']
    assert reader['owner']._loaded == {('owned', ()): {}}
    args, kwargs = reader['open_args']
    assert args == (str(reader['path']), os.O_RDONLY | os.O_NOFOLLOW |
                    getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
    assert kwargs == {}
    assert_retired(reader)


def test_missing_checkpoint_remains_absent(reader):
    reader['path'].unlink()
    reader['owner']._load()
    assert not reader['live'] and reader['closes'] == 0 and not reader['reasons']
