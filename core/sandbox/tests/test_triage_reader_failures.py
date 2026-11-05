"""Malformed JSON and cleanup failures cannot abort offline triage reads."""
import errno
import json
import os
import sys

import pytest

from core.sandbox import triage


pytestmark = pytest.mark.usefixtures('private_triage_readers')


@pytest.mark.parametrize('error_type', [ValueError, RecursionError])
def test_single_document_decode_failure_is_refused(tmp_path, monkeypatch, error_type):
    path = tmp_path / 'summary.json'
    path.write_bytes(b'{}')

    def fail(*args, **kwargs):
        raise error_type('malformed input')

    monkeypatch.setattr(triage.json, 'loads', fail)
    assert triage._load_json(path) is None


@pytest.mark.parametrize('error_type', [ValueError, RecursionError])
def test_stream_resumes_after_decoder_failure(tmp_path, monkeypatch, error_type):
    path = tmp_path / 'events.jsonl'
    path.write_bytes(b'{"seq":1}\nBAD\n{"seq":2}\n')
    real_loads = json.loads

    def decode(text, *args, **kwargs):
        if text == 'BAD':
            raise error_type('malformed input')
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(triage.json, 'loads', decode)
    assert triage._load_jsonl_stream(path) == ([{'seq': 1}, {'seq': 2}], False)


def test_real_oversized_integer_is_refused_and_stream_continues(tmp_path):
    if not hasattr(sys, 'get_int_max_str_digits') or not sys.get_int_max_str_digits():
        pytest.skip('decimal conversion limit unavailable or disabled')
    malformed = b'{"seq":' + b'9' * (sys.get_int_max_str_digits() + 1) + b'}'
    path = tmp_path / 'input'
    path.write_bytes(malformed)
    assert triage._load_json(path) is None
    path.write_bytes(b'{"seq":1}\n' + malformed + b'\n{"seq":2}\n')
    assert triage._load_jsonl_stream(path) == ([{'seq': 1}, {'seq': 2}], False)


def test_close_failure_preserves_stream_result(tmp_path, monkeypatch):
    path = tmp_path / 'events.jsonl'
    path.write_bytes(b'{"seq":1}\n')
    real_close = os.close
    closed = []

    def close_then_fail(fd):
        closed.append(fd)
        real_close(fd)
        raise OSError(errno.EIO, 'close failed')

    with monkeypatch.context() as scoped:
        scoped.setattr(triage.os, 'close', close_then_fail)
        assert triage._load_jsonl_stream(path) == ([{'seq': 1}], False)
    assert len(closed) == 1


@pytest.mark.parametrize('payload', [b'[]', b'null', b'not json'])
def test_non_object_documents_remain_refused(tmp_path, payload):
    path = tmp_path / 'summary.json'
    path.write_bytes(payload)
    assert triage._load_json(path) is None
