"""Direct sidecar writer ownership, without journal compaction or publication."""

import os
from types import SimpleNamespace

import pytest

from core.coverage import journal_compact as compact


@pytest.fixture
def writer(tmp_path, monkeypatch):
    owner = compact._SidecarWriter(tmp_path)
    state = {'writer': owner, 'metadata_error': None, 'sync_error': None,
             'close_error': None, 'live': set(), 'closes': 0, 'foreign': None,
             'closed_foreign': False}

    def open_file(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['live'].add(fd)
        return fd

    def fstat(fd):
        info = os.fstat(fd)
        if state['metadata_error'] is not None:
            raise state['metadata_error']
        return info

    def fsync(fd):
        os.fsync(fd)
        if state['sync_error'] is not None:
            raise state['sync_error']

    def close(fd):
        if fd in state['live']:
            os.close(fd)
            state['live'].remove(fd)
            state['closes'] += 1
            foreign = os.open(tmp_path / 'owned-independent-file',
                              os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            assert foreign == fd
            state['foreign'] = foreign
            info = os.fstat(foreign)
            state['identity'] = info.st_dev, info.st_ino
            if state['close_error'] is not None:
                raise state['close_error']
        else:
            assert fd == state['foreign']
            info = os.fstat(fd)
            assert (info.st_dev, info.st_ino) == state['identity']
            state['closed_foreign'] = True
            state['foreign'] = None
            os.close(fd)

    monkeypatch.setattr(compact, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_file, 'fstat': fstat, 'fsync': fsync, 'close': close}))
    try:
        yield state
    finally:
        for fd in state['live']:
            os.close(fd)
        if state['foreign'] is not None:
            os.close(state['foreign'])


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_sync_primary_survives_consumed_close(writer, primary_type):
    owner = writer['writer']
    owner.open()
    primary = primary_type('native fsync fault')
    writer['sync_error'] = primary
    writer['close_error'] = OSError('consumed native close fault')
    with pytest.raises(primary_type) as raised:
        owner.close()
    assert raised.value is primary
    assert owner._fd is None and writer['closes'] == 1
    assert not writer['live']


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_error_retires_writer_before_retry(writer, cleanup_type):
    owner = writer['writer']
    owner.open()
    failure = cleanup_type('consumed native close fault')
    writer['close_error'] = failure
    with pytest.raises(cleanup_type) as raised:
        owner.close()
    assert raised.value is failure
    writer['close_error'] = None
    owner.close()
    assert owner._fd is None and writer['closes'] == 1
    assert not writer['closed_foreign']


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
def test_open_metadata_primary_survives_consumed_close(writer, primary_type):
    primary = primary_type('native metadata fault')
    writer['metadata_error'] = primary
    writer['close_error'] = SystemExit('secondary consumed close fault')
    with pytest.raises(primary_type) as raised:
        writer['writer'].open()
    assert raised.value is primary
    assert writer['writer']._fd is None and writer['closes'] == 1
    assert not writer['live']


def test_native_append_sync_and_close_retains_offsets(writer):
    owner = writer['writer']
    owner.open()
    first = owner.append({'owned': 1})
    second = owner.append({'owned': 2})
    owner.sync()
    owner.close()
    owner.close()
    assert first[0] == 0 and second[0] == first[1]
    assert owner._fd is None and writer['closes'] == 1
    assert not writer['closed_foreign']
    assert owner._path.read_bytes() == b'{"owned":1}\n{"owned":2}\n'
