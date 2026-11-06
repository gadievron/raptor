"""Recoverable marker history survives later host I/O failures."""
import errno
import json
import os

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import telemetry_mac as tmac


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / 'tamper.jsonl'
    path.write_bytes(b'')
    monkeypatch.setattr(tmac, 'tamper_marker_path', lambda: path)
    return path


@pytest.mark.parametrize('records', [[], [{'reason': 'first'}],
                                     [{'reason': 'first'}, {'reason': 'second'}]])
def test_read_failure_preserves_parsed_prefix(marker, monkeypatch, records):
    closed = []
    real_close = os.close

    class FailingStream:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def __iter__(self):
            for record in records:
                yield json.dumps(record).encode() + b'\n'
                yield b'not json\n'
            raise OSError(errno.EIO, 'marker read failed')

    def close(fd):
        closed.append(fd)
        real_close(fd)

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, tmac, 'os', 'fdopen', lambda *args, **kwargs: FailingStream())
        patch_module_attribute(scoped, tmac, 'os', 'close', close)
        assert tmac.tamper_events() == records
    assert len(closed) == 1


def test_descriptor_close_failure_preserves_parsed_records(marker, monkeypatch):
    records = [{'reason': 'key quarantined'}, {'reason': 'key replaced'}]
    marker.write_text(''.join(json.dumps(record) + '\n' for record in records))
    real_close = os.close
    closed = []

    def close_then_fail(fd):
        closed.append(fd)
        real_close(fd)
        raise OSError(errno.EIO, 'marker close failed')

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, tmac, 'os', 'close', close_then_fail)
        assert tmac.tamper_events() == records
    assert len(closed) == 1


@pytest.mark.parametrize('operation', ['open', 'fstat', 'fdopen'])
def test_failure_before_first_record_returns_empty(marker, monkeypatch, operation):
    def fail(*args, **kwargs):
        raise OSError(errno.EIO, 'marker setup failed')

    patch_module_attribute(monkeypatch, tmac, 'os', operation, fail)
    assert tmac.tamper_events() == []
