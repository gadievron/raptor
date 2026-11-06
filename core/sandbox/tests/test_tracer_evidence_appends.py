"""Telemetry append success reflects bytes accepted and descriptor ownership."""
import errno
import json
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, tracer
from core.testing.state_isolation import pin_user_state_dirs


LINE = '{"detail":"snowman \u2603"}\n'
RECORD = {'type': 'audit_summary', 'dropped_by_category': {}, 'detail': 'snowman \u2603'}


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setattr(tracer, '_evidence_out_fd', None)
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def borrowed(tmp_path, monkeypatch):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(tracer, '_evidence_out_fd', handle.fd)
            yield handle
    finally:
        handle.close(verify=False)


def local_os(monkeypatch, **changes):
    private = ModuleType('tracer_append_os')
    vars(private).update(vars(os))
    vars(private).update(changes)
    monkeypatch.setattr(tracer, 'os', private)


def append(run, caller):
    if caller == 'record':
        return tracer._write_record_dict(run, RECORD, filename='events.jsonl')
    return tracer._append_jsonl_line(run, 'events.jsonl', LINE)


@pytest.mark.parametrize('caller', ['line', 'record'])
@pytest.mark.parametrize('written', [0, 3], ids=['zero', 'partial'])
def test_incomplete_borrowed_append_fails_once(borrowed, tmp_path, monkeypatch, caplog, caller, written):
    calls = []

    def partial(fd, data):
        assert fd == borrowed.fd
        calls.append(bytes(data))
        return os.write(fd, data[:written])

    local_os(monkeypatch, write=partial)
    assert append(tmp_path, caller) is False
    assert len(calls) == 1
    assert borrowed.path.read_bytes() == calls[0][:written]
    assert 'incomplete' in caplog.text
    os.fstat(borrowed.fd)  # the appender never owns this descriptor


@pytest.mark.parametrize('caller', ['line', 'record'])
def test_complete_borrowed_append_keeps_descriptor_usable(borrowed, tmp_path, caller):
    assert append(tmp_path, caller) is True
    expected = RECORD if caller == 'record' else {'detail': 'snowman \u2603'}
    assert json.loads(borrowed.path.read_text()) == expected
    os.fstat(borrowed.fd)


@pytest.mark.parametrize('caller', ['line', 'record'])
def test_io_failure_does_not_close_borrowed_descriptor(borrowed, tmp_path, monkeypatch, caller):
    def fail(*args):
        raise OSError(errno.ENOSPC, 'storage unavailable')

    local_os(monkeypatch, write=fail)
    assert append(tmp_path, caller) is False
    os.fstat(borrowed.fd)
    assert borrowed.path.read_bytes() == b''


def test_encoding_failure_returns_false_before_borrowed_write(borrowed, tmp_path):
    assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', 'bad' + chr(0xD800)) is False
    os.fstat(borrowed.fd)
    assert borrowed.path.read_bytes() == b''


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='requires FIFO support')
def test_fallback_refuses_fifo_with_live_reader(tmp_path):
    path = evidence.evidence_write_path(tmp_path, 'events.jsonl')
    path.parent.mkdir()
    os.mkfifo(path, 0o600)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', LINE) is False
        assert os.read(reader, 1024) == b''
    finally:
        os.close(reader)


def test_fallback_regular_file_keeps_complete_records(tmp_path):
    assert append(tmp_path, 'line') is True
    assert append(tmp_path, 'record') is True
    path = evidence.evidence_write_path(tmp_path, 'events.jsonl')
    assert [json.loads(line) for line in path.read_text().splitlines()] == [
        {'detail': 'snowman \u2603'}, RECORD]


@pytest.mark.parametrize('written', [0, 3], ids=['zero', 'partial'])
def test_fallback_partial_append_is_not_retried(tmp_path, monkeypatch, written):
    calls, closed = [], []

    def partial(fd, data):
        calls.append((fd, bytes(data)))
        return os.write(fd, data[:written])

    def close(fd):
        closed.append(fd)
        os.close(fd)

    local_os(monkeypatch, write=partial, close=close)
    assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', LINE) is False
    assert len(calls) == 1
    assert closed == [calls[0][0]]
    assert evidence.evidence_write_path(tmp_path, 'events.jsonl').read_bytes() == calls[0][1][:written]
    with pytest.raises(OSError) as released:
        os.fstat(closed[0])
    assert released.value.errno == errno.EBADF


def test_fallback_close_error_fails_complete_append(tmp_path, monkeypatch):
    closed = []

    def close(fd):
        closed.append(fd)
        os.close(fd)
        raise OSError(errno.EIO, 'close failed')

    local_os(monkeypatch, close=close)
    assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', LINE) is False
    assert len(closed) == 1
    assert evidence.evidence_write_path(tmp_path, 'events.jsonl').read_bytes() == LINE.encode()
    with pytest.raises(OSError) as released:
        os.fstat(closed[0])
    assert released.value.errno == errno.EBADF


@pytest.mark.parametrize('failure', ['io', 'error', 'cancel'])
def test_fallback_releases_fd_and_preserves_primary_failure(tmp_path, monkeypatch, failure):
    error = (OSError(errno.ENOSPC, 'write failed') if failure == 'io' else
             RuntimeError('write failed') if failure == 'error' else
             KeyboardInterrupt('write cancelled'))
    written, closed = [], []

    def fail(fd, data):
        written.append(fd)
        raise error

    def close(fd):
        closed.append(fd)
        os.close(fd)
        raise OSError(errno.EIO, 'secondary close failure')

    local_os(monkeypatch, write=fail, close=close)
    if failure == 'io':
        assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', LINE) is False
    else:
        with pytest.raises(type(error)) as raised:
            tracer._append_jsonl_line(tmp_path, 'events.jsonl', LINE)
        assert raised.value is error
    assert len(written) == 1
    assert closed == written
    with pytest.raises(OSError) as released:
        os.fstat(closed[0])
    assert released.value.errno == errno.EBADF


def test_fallback_encoding_failure_does_not_create_artifact(tmp_path):
    assert tracer._append_jsonl_line(tmp_path, 'events.jsonl', 'bad' + chr(0xD800)) is False
    assert not evidence.evidence_write_path(tmp_path, 'events.jsonl').exists()
