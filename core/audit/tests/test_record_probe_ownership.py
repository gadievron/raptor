"""Audit size probes retire their descriptors before parsing or disclosure."""

import errno
import os
from types import SimpleNamespace

import pytest

from core.audit import record


@pytest.fixture
def probe(tmp_path, monkeypatch):
    path = tmp_path / record.AUDIT_LOG_FILENAME
    path.write_text('{"seq": 1}\n')
    state = {'root': tmp_path, 'path': path, 'primary': None, 'cleanup': None,
             'live': set(), 'closes': 0, 'parsed': 0, 'opens': []}
    from core import json as json_io
    real_load = json_io.load_jsonl

    def open_probe(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        state['opens'].append((args, kwargs))
        state['live'].add(fd)
        return fd

    def fstat(fd):
        metadata = os.fstat(fd)
        if state['primary'] is not None:
            raise state['primary']
        return metadata

    def close(fd):
        os.close(fd)
        state['live'].remove(fd)
        state['closes'] += 1
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
        if state['cleanup'] is not None:
            raise state['cleanup']

    def load(*args, **kwargs):
        assert not state['live'] and state['closes'] == 1
        state['parsed'] += 1
        return real_load(*args, **kwargs)

    monkeypatch.setattr(record, 'os', SimpleNamespace(
        **{**vars(os), 'open': open_probe, 'fstat': fstat, 'close': close}))
    monkeypatch.setattr(json_io, 'load_jsonl', load)
    try:
        yield state
    finally:
        for fd in tuple(state['live']):
            os.close(fd)
            state['live'].remove(fd)


@pytest.mark.parametrize('primary_type', [OSError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('close_fails', [False, True])
def test_probe_primary_survives_native_close(probe, primary_type, close_fails):
    primary = primary_type('probe metadata unavailable')
    probe['primary'] = primary
    if close_fails:
        probe['cleanup'] = OSError('consumed probe close failed')
    with pytest.raises(primary_type) as raised:
        record.load_audit_log_disclosed(probe['root'])
    assert raised.value is primary
    assert probe['closes'] == 1 and not probe['live']
    assert probe['parsed'] == 0


@pytest.mark.parametrize('cleanup_type', [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_close_failure_prevents_parsing(probe, cleanup_type):
    failure = cleanup_type('consumed probe close failed')
    probe['cleanup'] = failure
    with pytest.raises(cleanup_type) as raised:
        record.load_audit_log_disclosed(probe['root'])
    assert raised.value is failure
    assert probe['closes'] == 1 and not probe['live']
    assert probe['parsed'] == 0


def test_native_probe_counts_and_parses_after_close(probe):
    rows, disclosure = record.load_audit_log_disclosed(probe['root'])
    assert rows == [{'seq': 1}]
    assert disclosure.complete and disclosure.shards == 1
    assert disclosure.total_bytes == probe['path'].stat().st_size
    assert probe['parsed'] == probe['closes'] == 1 and not probe['live']
    args, kwargs = probe['opens'][0]
    assert args == (str(probe['path']), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    assert kwargs == {}
