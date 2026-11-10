"""Direct capture-file ownership only; no witness, target or process execution."""

import errno
import os
from types import SimpleNamespace

import pytest

from core.audit.dark_verify import _execute as capture
from core.source import streams


@pytest.fixture
def owned(tmp_path, monkeypatch):
    path = tmp_path / 'owned-capture'
    path.write_bytes(b'owned capture text\n')
    state = {'path': path, 'live': set(), 'closes': 0, 'metadata_error': None,
             'close_error': None, 'foreign': None, 'closed_foreign': False}

    def open_file(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        state['fd'] = fd
        state['open_args'] = args, kwargs
        return fd

    def fstat(fd):
        result = os.fstat(fd)
        if state['metadata_error'] is not None:
            raise state['metadata_error']
        return result

    def keep_independent_descriptor(fd):
        independent = os.open(tmp_path / 'owned-independent',
                              os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        assert independent == fd
        state['foreign'] = independent
        info = os.fstat(independent)
        state['identity'] = info.st_dev, info.st_ino

    def close(fd):
        if fd == state['foreign']:
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) == state['identity']
            state['closed_foreign'] = True
            state['foreign'] = None
            os.close(fd)
            return
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        if state['close_error'] is not None:
            keep_independent_descriptor(fd)
            raise state['close_error']

    state['keep_independent'] = keep_independent_descriptor
    monkeypatch.setattr(capture, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'fstat': fstat, 'close': close}))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
        if state['foreign'] is not None:
            os.close(state['foreign'])


def test_nonregular_close_error_never_retries_consumed_descriptor(owned):
    owned['path'].unlink()
    os.mkfifo(owned['path'], 0o600)
    owned['close_error'] = OSError('native FIFO descriptor consumed')
    assert capture._open_untrusted_regular(owned['path']) is None
    assert owned['closes'] == 1 and not owned['live']
    assert not owned['closed_foreign']


@pytest.mark.parametrize('primary_type', [MemoryError, KeyboardInterrupt, SystemExit])
def test_metadata_primary_survives_independent_close(owned, primary_type):
    primary = primary_type('native metadata cancelled')
    owned['metadata_error'] = primary
    owned['close_error'] = OSError('native descriptor consumed')
    with pytest.raises(primary_type) as raised:
        capture._open_untrusted_regular(owned['path'])
    assert raised.value is primary
    assert owned['closes'] == 1 and not owned['live']
    assert not owned['closed_foreign']


@pytest.mark.parametrize('close_fails', [False, True])
def test_handled_metadata_io_error_keeps_fresh_close_policy(owned, close_fails):
    owned['metadata_error'] = OSError('native metadata failed')
    if close_fails:
        failure = OSError('native close consumed')
        owned['close_error'] = failure
        with pytest.raises(OSError) as raised:
            capture._open_untrusted_regular(owned['path'])
        assert raised.value is failure
    else:
        assert capture._open_untrusted_regular(owned['path']) is None
    assert owned['closes'] == 1 and not owned['live']
    assert not owned['closed_foreign']


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt])
def test_failed_adoption_contract_does_not_reclaim_transferred_fd(
        owned, primary_type, monkeypatch):
    primary = primary_type('transferred stream setup failed')

    def failed_adoption(fd, *args, **kwargs):
        # Model the existing adopt_fd consume-on-entry contract using a real
        # native close/reused FD, not a new claim about its constructor internals.
        os.close(fd)
        owned['live'].remove(fd)
        owned['keep_independent'](fd)
        raise primary

    monkeypatch.setattr(streams, 'adopt_fd', failed_adoption)
    if primary_type is OSError:
        assert capture._open_untrusted_regular(owned['path']) is None
    else:
        with pytest.raises(primary_type) as raised:
            capture._open_untrusted_regular(owned['path'])
        assert raised.value is primary
    assert not owned['live'] and not owned['closed_foreign']
    assert owned['closes'] == 0


@pytest.mark.parametrize('kind', ['missing', 'symlink', 'fifo'])
def test_native_refusal_keeps_no_follow_nonblocking_contract(owned, kind):
    owned['path'].unlink()
    if kind == 'symlink':
        owned['path'].symlink_to('owned-missing-target')
    elif kind == 'fifo':
        os.mkfifo(owned['path'], 0o600)
    assert capture._open_untrusted_regular(owned['path']) is None
    assert not owned['live']
    assert owned['closes'] == (1 if kind == 'fifo' else 0)


def test_native_success_transfers_reader_and_integer_name(owned):
    stream = capture._open_untrusted_regular(owned['path'])
    assert stream is not None
    fd = stream.fileno()
    try:
        assert stream.name == fd
        assert stream.read() == b'owned capture text\n'
        assert owned['closes'] == 0 and owned['live'] == {fd}
        args, kwargs = owned['open_args']
        assert args == (str(owned['path']), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        assert kwargs == {}
    finally:
        stream.close()
        owned['live'].remove(fd)
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF


def test_passive_capture_reader_keeps_text_and_closes_returned_stream(owned, monkeypatch):
    native_open = capture._open_untrusted_regular
    retired = []

    def traced_open(path):
        stream = native_open(path)
        assert stream is not None

        class ObservedReader:
            def __getattr__(self, name):
                return getattr(stream, name)

            def close(self):
                fd = stream.fileno()
                stream.close()
                owned['live'].remove(fd)
                with pytest.raises(OSError) as closed:
                    os.fstat(fd)
                assert closed.value.errno == errno.EBADF
                retired.append(fd)

        return ObservedReader()

    monkeypatch.setattr(capture, '_open_untrusted_regular', traced_open)
    assert capture._read_capped(owned['path'], keep_tail=True) == ('owned capture text\n', False)
    assert len(retired) == 1 and not owned['live']
