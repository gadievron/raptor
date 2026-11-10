"""Verified blob reads retain native ownership without relaxing integrity."""

import errno
import hashlib
import io
import os
from types import SimpleNamespace

import pytest

from core.witness import store as store_module


@pytest.fixture
def blob(tmp_path, monkeypatch):
    payload = b'owned passive blob bytes'
    key = hashlib.sha256(payload).hexdigest()
    store = store_module.WitnessStore(tmp_path / 'store')
    store._blobs_dir.mkdir(parents=True)
    path = store._blobs_dir / (key + '.bin')
    path.write_bytes(payload)
    guard_path = tmp_path / 'owned-guard'
    guard_path.write_bytes(b'owned blob guard')
    guard = os.open(guard_path, os.O_RDONLY)
    state = {'store': store, 'path': path, 'key': key, 'payload': payload, 'guard': guard,
             'live': {guard}, 'setup_error': None, 'read_error': None,
             'stream_close_error': None, 'raw_close_error': None, 'replacement': None,
             'replacement_closed': False, 'retired': [], 'closes': [], 'wrappers': 0, 'hashes': 0}

    def open_blob(*args, **kwargs):
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

    def compute(data):
        state['hashes'] += 1
        return hashlib.sha256(data).hexdigest()

    monkeypatch.setattr(store_module, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_blob, 'close': close, 'fdopen': fdopen},
    ))
    monkeypatch.setattr(store_module, 'compute_bytes_hash', compute)
    try:
        yield state
    finally:
        for fd in list(state['live']):
            os.close(fd)
            state['live'].remove(fd)


def read_blob(state):
    return state['store'].get_bytes(state['key'])


def assert_retired(state):
    assert state['closes'].count(state['fd']) == 1
    assert state['retired'].count(state['fd']) == 1


def expect_primary(state, primary):
    expected = store_module.WitnessStoreError if isinstance(primary, OSError) else type(primary)
    with pytest.raises(expected) as raised:
        read_blob(state)
    assert (raised.value.__cause__ if isinstance(primary, OSError) else raised.value) is primary
    assert state['hashes'] == 0


@pytest.mark.parametrize('error_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('raw_fails', [False, True], ids=['raw-close-ok', 'raw-close-cancel'])
def test_blob_setup_never_retries_consumed_descriptor(blob, error_type, raw_fails):
    primary = error_type('blob setup failed')
    blob['setup_error'] = primary
    if raw_fails:
        blob['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(blob, primary)
    assert not blob['replacement_closed']
    assert os.pread(blob['guard'], 64, 0) == b'owned blob guard'
    assert_retired(blob)


@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_blob_read_primary_survives_cleanup_errors(blob, error_type):
    primary = error_type('blob read failed')
    blob['read_error'] = primary
    blob['stream_close_error'] = OSError('stream close failed')
    blob['raw_close_error'] = KeyboardInterrupt('raw close consumed')
    expect_primary(blob, primary)
    assert_retired(blob)


@pytest.mark.parametrize('kind', ['fifo', 'oversized'])
def test_blob_validation_retains_best_effort_cleanup(blob, kind):
    blob['path'].unlink()
    if kind == 'fifo':
        os.mkfifo(blob['path'], 0o600)
    else:
        with blob['path'].open('wb') as stream:
            stream.truncate(store_module._MAX_BLOB_BYTES + 1)
    blob['raw_close_error'] = OSError('raw close consumed')
    with pytest.raises(store_module.WitnessStoreError, match='not a regular file|blob budget'):
        read_blob(blob)
    assert blob['wrappers'] == 0 and blob['hashes'] == 0
    assert_retired(blob)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_blob_fresh_close_error_stays_typed_and_refuses_verification(blob, stage):
    failure = OSError('close consumed')
    blob[stage + '_close_error'] = failure
    with pytest.raises(store_module.WitnessStoreError, match='cannot read blob') as raised:
        read_blob(blob)
    assert raised.value.__cause__ is failure
    assert blob['hashes'] == 0
    assert_retired(blob)


@pytest.mark.parametrize('stage', ['stream', 'raw'])
def test_blob_fresh_cancellation_still_propagates(blob, stage):
    failure = KeyboardInterrupt('close consumed')
    blob[stage + '_close_error'] = failure
    expect_primary(blob, failure)
    assert_retired(blob)


def test_native_verified_blob_returns_exact_bytes(blob):
    assert read_blob(blob) == blob['payload']
    assert blob['hashes'] == 1
    assert_retired(blob)


def test_native_blob_hash_mismatch_stays_refused(blob):
    blob['path'].write_bytes(b'owned different bytes')
    with pytest.raises(store_module.WitnessStoreError, match='does not match its address'):
        read_blob(blob)
    assert blob['hashes'] == 1
    assert_retired(blob)


def test_native_regular_symlink_still_requires_matching_hash(blob, tmp_path):
    target = tmp_path / 'owned-target'
    target.write_bytes(blob['payload'])
    blob['path'].unlink()
    blob['path'].symlink_to(target)
    assert read_blob(blob) == blob['payload']
    assert blob['hashes'] == 1
    assert_retired(blob)
