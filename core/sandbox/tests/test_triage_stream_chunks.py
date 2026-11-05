"""Chunk scanning preserves streaming recovery and cumulative bounds."""
import json
import os

import pytest

from core.sandbox import triage


pytestmark = pytest.mark.usefixtures('private_triage_readers')


@pytest.fixture
def stream(tmp_path, monkeypatch):
    path = tmp_path / 'events.jsonl'
    real_read = os.read

    def run(data, chunk_size):
        path.write_bytes(data)
        with monkeypatch.context() as scoped:
            scoped.setattr(triage.os, 'read',
                           lambda fd, count: real_read(fd, min(count, chunk_size)))
            return triage._load_jsonl_stream(path)

    return run


@pytest.mark.parametrize('chunk_size', [1, 2, 7, 16, 1024, 1 << 20])
def test_split_records_and_invalid_lines(stream, chunk_size):
    records = [{'seq': i, 'host': 'h\u2028ost'} for i in range(20)]
    lines = [json.dumps(record, ensure_ascii=False).encode() for record in records]
    data = b'\n'.join([lines[0], b'not json', b'', *lines[1:]])
    assert stream(data, chunk_size) == (records, False)


@pytest.mark.parametrize('chunk_size', [1, 7, 31, 1024])
def test_oversize_line_resynchronizes_at_newline(stream, monkeypatch, chunk_size):
    monkeypatch.setattr(triage, '_MAX_EVENT_LINE_BYTES', 16)
    data = b'{"seq":1}\n' + b'x' * 100 + b'\n{"seq":2}\n{"seq":3}'
    assert stream(data, chunk_size) == ([{'seq': 1}, {'seq': 2}, {'seq': 3}], False)


@pytest.mark.parametrize('chunk_size', [1, 7, 1024])
def test_record_cap_preserves_prefix_and_over_bound(stream, monkeypatch, chunk_size):
    monkeypatch.setattr(triage, '_MAX_EVENTS_PARSED', 2)
    data = b'{"seq":1}\n{"seq":2}\n{"seq":3}\n'
    assert stream(data, chunk_size) == ([{'seq': 1}, {'seq': 2}], True)


def test_byte_cap_preserves_completed_records(stream, monkeypatch):
    monkeypatch.setattr(triage, '_MAX_EVENTS_STREAM_BYTES', 20)
    assert stream(b'{"seq":1}\n{"seq":2}\n{"seq":3}\n', 10) == (
        [{'seq': 1}, {'seq': 2}], True)


def test_many_short_records_in_one_chunk(stream):
    records = [{'seq': i} for i in range(10000)]
    data = b''.join(json.dumps(record).encode() + b'\n' for record in records)
    assert stream(data, 1 << 20) == (records, False)
