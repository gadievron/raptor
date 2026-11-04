"""Marker storage survives partial I/O without publishing incomplete consent."""

import errno
import json
import os
from unittest.mock import Mock

import pytest

from core.sandbox import host_consent as hc


@pytest.fixture
def marker(tmp_path, monkeypatch):
    path = tmp_path / "data" / "consent.json"
    monkeypatch.setattr(hc, "marker_path", lambda: path)
    monkeypatch.setattr(hc, "grant_preflight", Mock(return_value={
        "kernel_identity": "test-kernel",
        "kernel_family": "test-family",
        "machine_id": "test-machine",
        "landlock_available": False,
        "is_wsl": True,
    }))
    return path


def test_partial_writes_publish_complete_json(marker, monkeypatch):
    real_write = os.write
    calls = []

    def partial(fd, data):
        calls.append(len(data))
        return real_write(fd, data[:7])

    monkeypatch.setattr(hc.os, "write", partial)
    assert hc.write_marker() == marker
    assert len(calls) > 1
    record, reason = hc._read_marker_record(marker)
    assert reason is None
    assert record["machine_id"] == "test-machine"
    assert record["schema"] == 1
    assert list(marker.parent.iterdir()) == [marker]


@pytest.mark.parametrize("stage", ["write", "fsync", "replace"])
@pytest.mark.parametrize("failure_type", [OSError, KeyboardInterrupt])
def test_failed_publish_preserves_previous_marker_and_cleans_up(
    marker, monkeypatch, stage, failure_type,
):
    marker.parent.mkdir()
    original = b"previous marker bytes"
    marker.write_bytes(original)
    failure = failure_type("operation failed")
    real_close = os.close
    closes = []

    def close(fd):
        closes.append(fd)
        # Intercept duplicate closes so a regression cannot close an
        # unrelated descriptor that reused this number.
        if closes.count(fd) > 1:
            raise OSError(errno.EBADF, "duplicate close")
        real_close(fd)

    monkeypatch.setattr(hc.os, "close", close)
    monkeypatch.setattr(hc.os, stage, Mock(side_effect=failure))
    with pytest.raises(failure_type) as raised:
        hc.write_marker()
    assert raised.value is failure
    assert len(closes) == 1
    with pytest.raises(OSError) as exc:
        os.fstat(closes[0])
    assert exc.value.errno == errno.EBADF
    assert marker.read_bytes() == original
    assert list(marker.parent.iterdir()) == [marker]


def test_zero_progress_write_does_not_publish(marker, monkeypatch):
    marker.parent.mkdir()
    marker.write_bytes(b"previous")
    real_write = os.write
    calls = []

    def stalled(fd, data):
        calls.append(fd)
        return real_write(fd, data[:5]) if len(calls) == 1 else 0

    monkeypatch.setattr(hc.os, "write", stalled)
    with pytest.raises(OSError) as exc:
        hc.write_marker()
    assert exc.value.errno == errno.EIO
    assert len(calls) == 2
    assert marker.read_bytes() == b"previous"
    assert list(marker.parent.iterdir()) == [marker]


def test_chunked_reads_load_the_complete_record(marker, monkeypatch):
    hc.write_marker()
    expected = json.loads(marker.read_bytes())
    real_read = os.read
    monkeypatch.setattr(hc.os, "read", lambda fd, size: real_read(fd, min(size, 3)))
    assert hc._read_marker_record(marker) == (expected, None)


def test_actual_read_size_is_checked_after_stat(marker, monkeypatch):
    hc.write_marker()
    requests = []

    def growing_read(fd, size):
        requests.append(size)
        return b"x" * size

    monkeypatch.setattr(hc.os, "read", growing_read)
    assert hc._read_marker_record(marker) == (None, "too-large")
    assert requests == [hc._MAX_MARKER_BYTES + 1]


def test_excessive_json_nesting_is_invalid_not_an_exception(marker):
    marker.parent.mkdir()
    marker.write_bytes(b"[" * 2000 + b"]" * 2000)
    marker.chmod(0o600)
    record, reason = hc._read_marker_record(marker)
    assert record is None
    # Newer Python decoders can accept this nesting; it is still
    # rejected as a non-object rather than becoming consent.
    assert reason in {"invalid-json", "wrong-schema"}


def test_decoder_recursion_error_is_invalid_json(marker, monkeypatch):
    marker.parent.mkdir()
    marker.write_bytes(b"{}")
    marker.chmod(0o600)
    monkeypatch.setattr(hc.json, "loads", Mock(side_effect=RecursionError("too deep")))
    assert hc._read_marker_record(marker) == (None, "invalid-json")
