"""A complete stream at a ceiling is not a truncated stream."""
import os

import pytest

from core.sandbox import triage


@pytest.fixture
def stream(tmp_path, monkeypatch):
    path = tmp_path / 'events.jsonl'
    real_read = os.read

    def load(data, chunk_size):
        path.write_bytes(data)
        with monkeypatch.context() as scoped:
            scoped.setattr(triage.os, 'read',
                           lambda fd, count: real_read(fd, min(count, chunk_size)))
            return triage._load_jsonl_stream(path)

    return load


@pytest.mark.parametrize('chunk_size', [1, 10, 4096])
@pytest.mark.parametrize('extra', [b'', b'{"seq":3}\n'])
def test_record_cap_flags_only_continued_input(stream, monkeypatch, chunk_size, extra):
    monkeypatch.setattr(triage, '_MAX_EVENTS_PARSED', 2)
    data = b'{"seq":1}\n{"seq":2}\n'
    assert stream(data + extra, chunk_size) == ([{'seq': 1}, {'seq': 2}], bool(extra))


@pytest.mark.parametrize('chunk_size', [1, 10, 4096])
@pytest.mark.parametrize('terminated', [False, True])
def test_exact_byte_cap_preserves_final_record(stream, monkeypatch, chunk_size, terminated):
    data = b'{"seq":1}\n{"seq":2}' + (b'\n' if terminated else b'')
    monkeypatch.setattr(triage, '_MAX_EVENTS_STREAM_BYTES', len(data))
    assert stream(data, chunk_size) == ([{'seq': 1}, {'seq': 2}], False)


@pytest.mark.parametrize('chunk_size', [1, 10])
def test_byte_cap_flags_actual_trailing_input(stream, monkeypatch, chunk_size):
    data = b'{"seq":1}\n'
    monkeypatch.setattr(triage, '_MAX_EVENTS_STREAM_BYTES', len(data))
    assert stream(data + b'{"seq":2}\n', chunk_size) == ([{'seq': 1}], True)


@pytest.mark.parametrize('cap', ['records', 'bytes'])
def test_failed_lookahead_keeps_conservative_bound_flag(tmp_path, monkeypatch, cap):
    data = b'{"seq":1}\n'
    path = tmp_path / 'events.jsonl'
    path.write_bytes(data)
    if cap == 'records':
        monkeypatch.setattr(triage, '_MAX_EVENTS_PARSED', 1)
    else:
        monkeypatch.setattr(triage, '_MAX_EVENTS_STREAM_BYTES', len(data))
    real_read = os.read

    def read(fd, count):
        if count == 1:
            raise OSError('lookahead unavailable')
        return real_read(fd, count)

    monkeypatch.setattr(triage.os, 'read', read)
    assert triage._load_jsonl_stream(path) == ([{'seq': 1}], True)
