"""The streaming ceiling limits admission independently of read chunk size."""
import os
from types import ModuleType

import pytest

from core.sandbox import triage


@pytest.mark.parametrize('chunk_size', [1, 10, 4096])
@pytest.mark.parametrize('cut', ['boundary', 'partial'])
def test_only_complete_records_inside_byte_ceiling_are_admitted(tmp_path, monkeypatch, chunk_size, cut):
    first, second = b'{"seq":1}\n', b'{"seq":2,"detail":"tail"}\n'
    path = tmp_path / 'events.jsonl'
    path.write_bytes(first + second)
    limit = len(first) + (5 if cut == 'partial' else 0)
    monkeypatch.setattr(triage, '_MAX_EVENTS_STREAM_BYTES', limit)
    private = ModuleType('byte_budget_os')
    vars(private).update(vars(os))
    private.read = lambda fd, size: os.read(fd, min(size, chunk_size))
    monkeypatch.setattr(triage, 'os', private)
    assert triage._load_jsonl_stream(path) == ([{'seq': 1}], True)


@pytest.mark.parametrize('ceiling', ['bytes', 'records'])
@pytest.mark.parametrize('data', [b'', b'{"seq":1}\n'])
def test_zero_ceiling_never_admits_a_record(tmp_path, monkeypatch, ceiling, data):
    path = tmp_path / 'events.jsonl'
    path.write_bytes(data)
    name = '_MAX_EVENTS_STREAM_BYTES' if ceiling == 'bytes' else '_MAX_EVENTS_PARSED'
    monkeypatch.setattr(triage, name, 0)
    assert triage._load_jsonl_stream(path) == ([], bool(data))
