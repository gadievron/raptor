"""RPC directions have independent encoded-byte frame ceilings."""
import json
import struct

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import _daemon as daemon


@pytest.mark.parametrize('payload', [{'text': 'plain'}, {'text': '\u2603'}, {'text': '\n'}])
def test_exact_limit_is_writable_and_readable(payload, monkeypatch):
    body = json.dumps(payload).encode('utf-8')
    monkeypatch.setattr(daemon, '_MAX_FRAME_BYTES', len(body))
    monkeypatch.setattr(daemon, '_MAX_REPLY_FRAME_BYTES', len(body), raising=False)
    written = bytearray()

    def write(fd, data):
        # Keep the existing short-write contract under the new bound.
        chunk = bytes(data[:3])
        written.extend(chunk)
        return len(chunk)

    patch_module_attribute(monkeypatch, daemon, "os", 'write', write)
    daemon._write_frame(123, payload)
    assert written == struct.pack('!I', len(body)) + body

    def read(fd, size):
        chunk = bytes(written[:size])
        del written[:size]
        return chunk

    patch_module_attribute(monkeypatch, daemon, "os", 'read', read)
    assert daemon._read_frame(123) == payload


@pytest.mark.parametrize('payload', [{'text': 'plain'}, {'text': '\u2603'}, {'text': '\n'}])
def test_oversized_write_emits_nothing(payload, monkeypatch):
    body = json.dumps(payload).encode('utf-8')
    monkeypatch.setattr(daemon, '_MAX_REPLY_FRAME_BYTES', len(body) - 1, raising=False)
    writes = []
    patch_module_attribute(monkeypatch, daemon, "os", 'write', lambda fd, data: writes.append(bytes(data)) or len(data))
    with pytest.raises(ValueError, match='frame too large'):
        daemon._write_frame(123, payload)
    assert writes == []


def test_oversized_input_rejected_without_reading_body(monkeypatch):
    monkeypatch.setattr(daemon, '_MAX_FRAME_BYTES', 7)
    calls = []

    def read(fd, size):
        calls.append(size)
        assert len(calls) == 1
        return struct.pack('!I', 8)

    patch_module_attribute(monkeypatch, daemon, "os", 'read', read)
    with pytest.raises(ValueError, match='frame too large'):
        daemon._read_frame(123)
    assert calls == [4]


def test_reply_ceiling_matches_parent_and_covers_bounded_capture():
    from core.sandbox import host
    assert getattr(daemon, '_MAX_REPLY_FRAME_BYTES', None) == host._MAX_REPLY_FRAME_BYTES
    assert daemon._MAX_REPLY_FRAME_BYTES >= 4 * daemon._MAX_CAPTURE_BYTES
    assert daemon._MAX_REPLY_FRAME_BYTES > daemon._MAX_FRAME_BYTES
