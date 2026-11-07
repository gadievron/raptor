"""Audit marker reads stay bounded and best-effort through cleanup."""
import errno
import os

import pytest

from core.testing.module_bindings import patch_module_attribute

from core.sandbox import summary


@pytest.mark.parametrize('data', [b'', b'123', b'1234', b'12345'])
def test_actual_bytes_enforce_bound_after_stat(tmp_path, monkeypatch, data):
    marker = tmp_path / 'marker'
    marker.write_bytes(data)
    monkeypatch.setattr(summary, '_MARKER_MAX_BYTES', 4)
    real_fstat = summary.os.fstat

    def stale_stat(fd):
        st = real_fstat(fd)
        sequence, fields = st.__reduce__()[1]
        sequence = list(sequence)
        sequence[6] = 0
        return os.stat_result(sequence, fields)

    patch_module_attribute(monkeypatch, summary, 'os', 'fstat', stale_stat)
    assert summary._read_marker_bytes(marker) == (data if len(data) <= 4 else None)


def test_short_reads_are_accumulated(tmp_path, monkeypatch):
    marker = tmp_path / 'marker'
    marker.write_bytes(b'1234')
    monkeypatch.setattr(summary, '_MARKER_MAX_BYTES', 4)
    real_read = summary.os.read
    patch_module_attribute(monkeypatch, summary, 'os', 'read', lambda fd, count: real_read(fd, min(count, 1)))
    assert summary._read_marker_bytes(marker) == b'1234'


@pytest.mark.parametrize('read_fails', [False, True])
def test_close_failure_does_not_escape_or_mask_read_result(tmp_path, monkeypatch, read_fails):
    marker = tmp_path / 'marker'
    marker.write_bytes(b'intact')
    real_close = summary.os.close
    closed = []

    def close_then_fail(fd):
        closed.append(fd)
        real_close(fd)
        raise OSError(errno.EIO, 'close failure')

    def failed_read(fd, count):
        raise OSError(errno.EIO, 'read failure')

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, summary, 'os', 'close', close_then_fail)
        if read_fails:
            patch_module_attribute(scoped, summary, 'os', 'read', failed_read)
        result = summary._read_marker_bytes(marker)
    assert result == (None if read_fails else b'intact')
    assert len(closed) == 1


def test_reassert_continues_after_failed_read_and_close(tmp_path, monkeypatch):
    marker = tmp_path / summary.AUDIT_DEGRADED_FILE
    marker.write_bytes(b'altered')
    payload = {'reason': 'test'}
    monkeypatch.setattr(summary, '_degraded_markers', {
        str(tmp_path.resolve()): {'payload': payload, 'restored': False}})
    real_close = summary.os.close

    def close_then_fail(fd):
        real_close(fd)
        raise OSError(errno.EIO, 'close failure')

    restored = []
    monkeypatch.setattr(summary, 'write_text_atomically',
                        lambda path, text, **kwargs: restored.append((path, text)))
    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, summary, 'os', 'close', close_then_fail)
        assert summary.reassert_audit_degraded(tmp_path) is True
    assert len(restored) == 1
    assert restored[0][0] == marker
    assert summary._degraded_markers[str(tmp_path.resolve())]['restored'] is True
