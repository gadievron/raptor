"""Encoding failures follow the evidence writer's best-effort contract."""
import json

import pytest

from core.sandbox import evidence


@pytest.mark.parametrize('text', ['\ud800', '\udfff', 'path-\udcff'])
def test_unencodable_line_returns_false_without_writing(tmp_path, caplog, text):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        assert handle.write_line(text + '\n') is False
        assert handle.path.read_bytes() == b''
        assert 'evidence append failed' in caplog.text
        # Rejected input must not poison the handle or its write lock.
        assert handle.write_line('{"valid":true}\n') is True
        assert handle.path.read_bytes() == b'{"valid":true}\n'
    finally:
        assert handle.close() is True


def test_valid_unicode_line_remains_utf8(tmp_path):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    text = '{"path":"/tmp/caf\u00e9/\U0001f995"}\n'
    try:
        assert handle.write_line(text) is True
        assert handle.path.read_bytes() == text.encode('utf-8')
    finally:
        handle.close()


def test_record_api_preserves_surrogates_with_json_escaping(tmp_path):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    record = {'path': '/tmp/name-\udcff'}
    try:
        assert handle.write_record(record) is True
        assert json.loads(handle.path.read_text()) == record
    finally:
        handle.close()


def test_closed_handle_still_refuses_without_encoding(tmp_path):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    assert handle.close() is True
    assert handle.write_line('\ud800') is False
