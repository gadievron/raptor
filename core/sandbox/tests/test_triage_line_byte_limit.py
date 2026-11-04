"""Whitespace cannot make line limits depend on input chunk boundaries."""
import os

import pytest

from core.sandbox import triage


@pytest.mark.parametrize('chunk_size', [1, 7, 64, 4096])
@pytest.mark.parametrize('padding', ['before', 'after', 'both'])
def test_oversized_padded_record_is_skipped_and_next_survives(
        tmp_path, monkeypatch, chunk_size, padding):
    monkeypatch.setattr(triage, '_MAX_EVENT_LINE_BYTES', 32)
    line = b'{"seq":1}'
    if padding in ('before', 'both'):
        line = b' ' * 33 + line
    if padding in ('after', 'both'):
        line += b'\t' * 33
    path = tmp_path / 'events.jsonl'
    path.write_bytes(line + b'\n{"seq":2}\n')
    real_read = os.read
    monkeypatch.setattr(triage.os, 'read', lambda fd, count: real_read(fd, min(count, chunk_size)))
    assert triage._load_jsonl_stream(path) == ([{'seq': 2}], False)


@pytest.mark.parametrize('length', [31, 32, 33])
def test_raw_line_size_is_checked_before_whitespace_stripping(monkeypatch, length):
    monkeypatch.setattr(triage, '_MAX_EVENT_LINE_BYTES', 32)
    line = b'{}' + b' ' * (length - 2)
    out = []
    triage._parse_jsonl_line(line, out)
    assert out == ([{}] if length <= 32 else [])


@pytest.mark.parametrize('chunk_size', [1, 7, 4096])
def test_exact_limit_padded_record_is_accepted_at_eof(tmp_path, monkeypatch, chunk_size):
    monkeypatch.setattr(triage, '_MAX_EVENT_LINE_BYTES', 32)
    path = tmp_path / 'events.jsonl'
    path.write_bytes(b'{}' + b' ' * 30)
    real_read = os.read
    monkeypatch.setattr(triage.os, 'read', lambda fd, count: real_read(fd, min(count, chunk_size)))
    assert triage._load_jsonl_stream(path) == ([{}], False)
