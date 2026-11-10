"""Staged record writes own only successfully created native resources."""

import errno
import os
import stat
from types import SimpleNamespace

import pytest

from core.labeled_attempts import store


@pytest.fixture
def staged(tmp_path, monkeypatch):
    final = tmp_path / 'sample-fixed.json'
    tmp = final.with_name(f'.{final.name}.{os.getpid()}.aaaaaaaa.tmp')
    state = {'final': final, 'tmp': tmp, 'live': set(), 'closes': 0, 'unlinks': [],
             'links': 0, 'write_error': None, 'close_error': None, 'zero_write': False,
             'short_write': False}

    def open_file(path, flags, *args, **kwargs):
        assert path == tmp
        fd = os.open(path, flags, *args, **kwargs)
        state['live'].add(fd)
        state['inode'] = os.fstat(fd).st_ino
        return fd

    def write(fd, data):
        if state['zero_write']:
            return 0
        result = os.write(fd, data[:2] if state['short_write'] else data)
        if state['write_error'] is not None:
            raise state['write_error']
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

    def link(src, dst):
        state['links'] += 1
        return os.link(src, dst)

    def unlink(path):
        state['unlinks'].append(path)
        return os.unlink(path)

    monkeypatch.setattr(store, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'write': write, 'close': close,
           'link': link, 'unlink': unlink},
    ))
    monkeypatch.setattr(store, 'secrets', SimpleNamespace(token_hex=lambda size: 'a' * 8 if size == 4 else 'b' * 6))
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


@pytest.mark.parametrize('kind', ['file', 'symlink', 'fifo'])
def test_exclusive_stage_refusal_never_deletes_preexisting_object(staged, tmp_path, kind):
    if kind == 'file':
        staged['tmp'].write_bytes(b'owned earlier writer stage')
    elif kind == 'symlink':
        target = tmp_path / 'owned-target'
        target.write_bytes(b'owned symlink target')
        staged['tmp'].symlink_to(target)
    else:
        os.mkfifo(staged['tmp'], 0o600)
    before = staged['tmp'].lstat()
    with pytest.raises(FileExistsError) as refused:
        store._write_atomic(staged['final'], 'owned passive replacement')
    assert refused.value.errno == errno.EEXIST
    assert staged['tmp'].lstat().st_ino == before.st_ino
    assert not staged['unlinks'] and not staged['live']
    assert staged['closes'] == staged['links'] == 0
    assert not staged['final'].exists()
    if kind == 'file':
        assert staged['tmp'].read_bytes() == b'owned earlier writer stage'
    elif kind == 'symlink':
        assert target.read_bytes() == b'owned symlink target'


@pytest.mark.parametrize('primary_type,cleanup_type', [
    pytest.param(OSError, OSError, id='ordinary'),
    pytest.param(OSError, KeyboardInterrupt, id='cleanup-interrupt'),
    pytest.param(OSError, SystemExit, id='cleanup-exit'),
    pytest.param(ValueError, KeyboardInterrupt, id='primary-value'),
    pytest.param(MemoryError, KeyboardInterrupt, id='primary-memory'),
    pytest.param(KeyboardInterrupt, OSError, id='primary-interrupt'),
    pytest.param(SystemExit, KeyboardInterrupt, id='primary-exit'),
])
def test_record_write_primary_survives_consumed_close(staged, primary_type, cleanup_type):
    primary = primary_type('primary staged write failed')
    staged['write_error'] = primary
    staged['close_error'] = cleanup_type('native close consumed')
    with pytest.raises(primary_type) as raised:
        store._write_atomic(staged['final'], 'owned passive bytes')
    assert raised.value is primary
    assert staged['closes'] == 1 and not staged['live']
    assert staged['links'] == 0 and staged['unlinks'] == [staged['tmp']]
    assert not staged['tmp'].exists() and not staged['final'].exists()


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_record_close_failure_never_publishes(staged, cleanup_type):
    failure = cleanup_type('native close consumed')
    staged['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        store._write_atomic(staged['final'], 'owned passive bytes')
    assert raised.value is failure
    assert staged['closes'] == 1 and not staged['live'] and staged['links'] == 0
    assert not staged['tmp'].exists() and not staged['final'].exists()


def test_existing_zero_write_refusal_keeps_primary(staged):
    staged['zero_write'] = True
    staged['close_error'] = OSError('native close consumed')
    with pytest.raises(OSError, match='short write'):
        store._write_atomic(staged['final'], 'owned passive bytes')
    assert staged['closes'] == 1 and staged['links'] == 0
    assert not staged['tmp'].exists() and not staged['final'].exists()


@pytest.mark.parametrize('short', [False, True])
def test_native_complete_publication_and_modes_unchanged(staged, short):
    staged['short_write'] = short
    payload = 'owned passive café bytes'
    result = store._write_atomic(staged['final'], payload)
    assert result == staged['final'] and result.read_bytes() == payload.encode()
    assert result.stat().st_ino == staged['inode']
    assert stat.S_IMODE(result.stat().st_mode) == 0o600
    assert result.stat().st_nlink == 1
    assert staged['closes'] == 1 and staged['links'] == 1
    assert not staged['tmp'].exists() and not staged['live']


def test_native_final_collision_rerolls_without_clobber(staged):
    staged['final'].write_bytes(b'owned earlier final')
    result = store._write_atomic(staged['final'], 'owned new bytes')
    assert result.name == 'sample-bbbbbb.json'
    assert staged['final'].read_bytes() == b'owned earlier final'
    assert result.read_bytes() == b'owned new bytes'
    assert staged['closes'] == 1 and not staged['tmp'].exists()


def test_native_retry_limit_remains_refusal(staged):
    staged['final'].write_bytes(b'owned earlier final')
    with pytest.raises(OSError, match='could not create unique filename'):
        store._write_atomic(staged['final'], 'owned new bytes', max_retries=1)
    assert staged['final'].read_bytes() == b'owned earlier final'
    assert staged['links'] == 1 and staged['closes'] == 1
    assert not staged['tmp'].exists()
