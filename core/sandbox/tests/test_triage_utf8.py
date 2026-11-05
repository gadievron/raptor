"""Invalid UTF-8 must not be silently replaced in accepted JSON telemetry."""
import json
import os

import pytest

from core.sandbox import triage


@pytest.mark.parametrize('record', [
    b'{"host":"bad\xff.test","result":"allowed"}',
    b'{"host":"bad\xc3.test","result":"allowed"}',
    b'{"ho\xffst":"example.test","result":"allowed"}',
    b'{"reason":"bad\xed\xa0\x80"}',
])
def test_whole_json_rejects_invalid_utf8(tmp_path, record):
    path = tmp_path / 'input.json'
    path.write_bytes(record)
    assert triage._load_json(path) is None


@pytest.mark.parametrize('chunk_size', [1, 1024])
def test_stream_keeps_valid_peers_and_reports_utf8_loss(tmp_path, monkeypatch, chunk_size):
    good = {'host': 'example.test', 'result': 'allowed'}
    path = tmp_path / triage.PROXY_EVENTS_FILENAME
    path.write_bytes(b'{"host":"bad\xff.test","result":"allowed"}\n'
                     + json.dumps(good).encode() + b'\n')
    original = os.read
    monkeypatch.setattr(os, 'read', lambda fd, size: original(fd, min(size, chunk_size)))
    issues = set()
    assert triage._load_jsonl_stream(path, issues=issues) == ([good], False)
    assert issues == {'malformed_record'}
    report = triage.triage_run(tmp_path, allow_legacy=True)
    assert report['inputs']['total_proxy_events'] == 1
    assert report['inputs']['integrity']['proxy_events'] == triage._INTEGRITY_TAMPERED
    assert 'malformed_record' in json.dumps(report)


@pytest.mark.parametrize('text', ['snowman \u2603', 'literal replacement \ufffd', 'separator \u2028'])
def test_valid_utf8_and_explicit_replacement_characters_remain_valid(tmp_path, text):
    record = {'reason': text}
    path = tmp_path / 'input.json'
    path.write_text(json.dumps(record, ensure_ascii=False), encoding='utf-8')
    assert triage._load_json(path) == record
    issues, events = set(), []
    triage._parse_jsonl_line(path.read_bytes(), events, issues=issues)
    assert events == [record]
    assert not issues
