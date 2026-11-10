"""Binary hashing retains native ownership and memo publication order."""

import errno
import hashlib
import io
import os
from types import SimpleNamespace

import pytest

from core.witness import matching as matching_module


@pytest.fixture
def binary(tmp_path, monkeypatch):
    payload = b'owned binary hash bytes'
    path = tmp_path / 'owned-binary'
    path.write_bytes(payload)
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned binary guard')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'path': path, 'payload': payload, 'guard': guard,
             'live': {guard}, 'setup_error': None, 'read_error': None,
             'stream_close_error': None, 'raw_close_error': None, 'replacement': None,
             'replacement_closed': False, 'retired': [], 'closes': [], 'wrappers': 0, 'reads': [], 'memo': {}}

    def open_binary(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['fd'] = fd
        state['live'].add(fd)
        return fd

    def close(fd):
        state['closes'].append(fd)
        if fd == state['replacement']:
            actual, owned = os.fstat(fd), os.fstat(guard)
            assert (actual.st_dev, actual.st_ino) == (owned.st_dev, owned.st_ino)
            state['replacement_closed'] = True
        os.close(fd)
        state['live'].discard(fd)
        with pytest.raises(OSError) as retired:
            os.fstat(fd)
        assert retired.value.errno == errno.EBADF
        state['retired'].append(fd)
        if state['raw_close_error'] is not None:
            raise state['raw_close_error']

    def fdopen(fd, mode, **kwargs):
        state['wrappers'] += 1
        if state['setup_error'] is not None:
            stream = os.fdopen(fd, mode, **kwargs)
            owns_fd = stream.raw.closefd
            stream.close()
            if owns_fd:
                state['live'].discard(fd)
                os.dup2(guard, fd)
                state['live'].add(fd)
                state['replacement'] = fd
            raise state['setup_error']

        class Reader(io.BufferedReader):
            def read(self, size=-1):
                state['reads'].append(size)
                if state['read_error'] is not None:
                    raise state['read_error']
                return super().read(size)

            def close(self):
                if self.closed:
                    return
                owns_fd = self.raw.closefd
                super().close()
                if owns_fd:
                    state['live'].discard(fd)
                if state['stream_close_error'] is not None:
                    raise state['stream_close_error']

        return Reader(io.FileIO(fd, mode, closefd=kwargs.get('closefd', True)))

    monkeypatch.setattr(matching_module, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_binary, 'close': close, 'fdopen': fdopen},
    ))
    monkeypatch.setattr(matching_module, '_binary_hash_memo', state['memo'])
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def hash_binary(state):
    return matching_module._on_disk_binary_hash(str(state['path']))


def assert_retired(state):
    assert state['closes'].count(state['fd']) == 1
    assert state['retired'].count(state['fd']) == 1


def expect_primary(state, primary):
    if isinstance(primary, OSError):
        assert hash_binary(state) is None
    else:
        with pytest.raises(type(primary)) as raised:
            hash_binary(state)
        assert raised.value is primary


@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_hash_setup_never_retries_consumed_descriptor(binary, error_type):
    primary = error_type('binary setup failed')
    binary['setup_error'] = primary
    expect_primary(binary, primary)
    assert not binary['replacement_closed']
    assert not binary['memo']
    assert_retired(binary)


@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_hash_read_primary_survives_independent_cleanup(binary, error_type):
    primary = error_type('binary read failed')
    binary['read_error'] = primary
    binary['stream_close_error'] = OSError('stream close failed')
    binary['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(binary, primary)
    assert not binary['memo']
    assert_retired(binary)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_hash_fresh_close_error_prevents_memo_publication(binary, stage):
    binary[stage + '_close_error'] = OSError('close consumed')
    assert hash_binary(binary) is None
    assert not binary['memo']
    assert_retired(binary)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_hash_fresh_cancellation_prevents_memo_publication(binary, stage):
    failure = KeyboardInterrupt('close consumed')
    binary[stage + '_close_error'] = failure
    expect_primary(binary, failure)
    assert not binary['memo']
    assert_retired(binary)


@pytest.mark.parametrize('payload', [b'', b'owned bytes', b'x' * 2048])
def test_native_hash_and_memo_are_exact(binary, payload):
    binary['path'].write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()
    assert hash_binary(binary) == expected
    assert list(binary['memo'].values()) == [expected]
    assert_retired(binary)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
def test_native_hash_admission_retains_best_effort_close(binary, kind):
    binary['path'].unlink()
    if kind == 'fifo':
        os.mkfifo(binary['path'], 0o600)
    else:
        with binary['path'].open('wb') as stream:
            stream.truncate(matching_module._MAX_BINARY_HASH_BYTES + 1)
    binary['raw_close_error'] = OSError('close consumed')
    assert hash_binary(binary) is None
    assert binary['wrappers'] == 0 and not binary['reads'] and not binary['memo']
    assert_retired(binary)


def test_native_cached_hash_retains_best_effort_raw_close(binary):
    st = binary['path'].stat()
    key = (str(binary['path']), st.st_mtime, st.st_size)
    expected = hashlib.sha256(binary['payload']).hexdigest()
    binary['memo'][key] = expected
    binary['raw_close_error'] = OSError('close consumed')
    assert hash_binary(binary) == expected
    assert binary['wrappers'] == 0 and not binary['reads']
    assert binary['memo'] == {key: expected}
    assert_retired(binary)


def test_native_regular_symlink_hash_is_unchanged(binary, tmp_path):
    target = tmp_path / 'owned-target'
    target.write_bytes(binary['payload'])
    binary['path'].unlink()
    binary['path'].symlink_to(target)
    assert hash_binary(binary) == hashlib.sha256(binary['payload']).hexdigest()
    assert_retired(binary)
