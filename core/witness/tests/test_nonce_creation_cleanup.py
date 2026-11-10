"""Nonce creation retains primary write errors while consuming its native FD."""

import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.witness import provenance


@pytest.fixture
def creation(tmp_path, monkeypatch):
    nonce = 'a' * provenance._NONCE_HEX_LEN
    path = tmp_path / provenance._BINDING_FILE
    state = {'root': tmp_path, 'path': path, 'nonce': nonce, 'write_error': None,
             'close_error': None, 'writer_open': False, 'closes': 0, 'race': False}

    def open_file(name, flags, *args):
        if flags & os.O_CREAT and state['race']:
            path.write_text(nonce)
            raise FileExistsError('owned competing nonce creator')
        fd = os.open(name, flags, *args)
        if flags & os.O_CREAT:
            state['fd'] = fd
            state['writer_open'] = True
        return fd

    def write(fd, data):
        count = os.write(fd, data)
        assert count == len(data)
        if state['write_error'] is not None:
            raise state['write_error']
        return count

    def close(fd):
        writer = state['writer_open'] and fd == state.get('fd')
        os.close(fd)
        if writer:
            state['writer_open'] = False
            state['closes'] += 1
            with pytest.raises(OSError) as retired:
                os.fstat(fd)
            assert retired.value.errno == errno.EBADF
            if state['close_error'] is not None:
                raise state['close_error']

    monkeypatch.setattr(provenance, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'write': write, 'close': close},
    ))
    monkeypatch.setattr(provenance, 'secrets', SimpleNamespace(token_hex=lambda size: nonce))
    try:
        yield state
    finally:
        if state['writer_open']:
            os.close(state['fd'])
            state['writer_open'] = False


def create(state):
    return provenance._load_or_create_run_nonce(state['root'])


@pytest.mark.parametrize('primary_type,cleanup_type', [
    pytest.param(OSError, OSError, id='ordinary'),
    pytest.param(OSError, KeyboardInterrupt, id='cleanup-interrupt'),
    pytest.param(OSError, SystemExit, id='cleanup-exit'),
    pytest.param(ValueError, KeyboardInterrupt, id='primary-value'),
    pytest.param(MemoryError, KeyboardInterrupt, id='primary-memory'),
    pytest.param(KeyboardInterrupt, OSError, id='primary-interrupt'),
    pytest.param(SystemExit, KeyboardInterrupt, id='primary-exit'),
])
def test_nonce_write_primary_survives_consumed_close(creation, primary_type, cleanup_type):
    primary = primary_type('primary nonce write failure')
    creation['write_error'] = primary
    creation['close_error'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        create(creation)
    assert raised.value is primary
    assert creation['closes'] == 1 and not creation['writer_open']
    assert creation['path'].read_bytes() == creation['nonce'].encode()


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_nonce_close_failure_still_propagates(creation, cleanup_type):
    failure = cleanup_type('native close consumed')
    creation['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        create(creation)
    assert raised.value is failure
    assert creation['closes'] == 1 and not creation['writer_open']
    assert creation['path'].read_bytes() == creation['nonce'].encode()


def test_native_nonce_creation_and_reread_unchanged(creation):
    assert create(creation) == creation['nonce']
    assert creation['closes'] == 1 and not creation['writer_open']
    assert stat.S_IMODE(creation['path'].stat().st_mode) == 0o600
    assert create(creation) == creation['nonce']
    assert creation['closes'] == 1


def test_native_malformed_existing_nonce_is_never_overwritten(creation):
    creation['path'].write_bytes(b'owned malformed nonce')
    assert create(creation) is None
    assert creation['path'].read_bytes() == b'owned malformed nonce'
    assert creation['closes'] == 0


def test_native_competing_creation_rereads_without_overwrite(creation):
    creation['race'] = True
    assert create(creation) == creation['nonce']
    assert creation['path'].read_bytes() == creation['nonce'].encode()
    assert creation['closes'] == 0


def test_native_missing_run_directory_still_refuses(creation):
    creation['root'] = creation['root'] / 'absent'
    assert create(creation) is None
    assert creation['closes'] == 0
