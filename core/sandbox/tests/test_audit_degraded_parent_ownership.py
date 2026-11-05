"""Parent state, rather than mutable path existence, owns marker creation."""
import json
import threading
from unittest.mock import Mock

import pytest

from core.sandbox import summary
from core.sandbox import telemetry_mac


@pytest.fixture(autouse=True)
def state(monkeypatch):
    monkeypatch.setattr(summary, '_degraded_markers', {})
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
    monkeypatch.setattr(summary, '_log_security_event', Mock())


def test_preexisting_marker_cannot_suppress_parent_record(tmp_path):
    marker = tmp_path / summary.AUDIT_DEGRADED_FILE
    marker.write_text('{"reason":"preexisting"}')
    summary.record_audit_degraded(tmp_path, reason='actual degradation')
    assert json.loads(marker.read_text())['reason'] == 'actual degradation'
    assert str(tmp_path.resolve()) in summary._degraded_markers
    marker.unlink()
    assert summary.reassert_audit_degraded(tmp_path) is True


def test_repeated_call_does_not_erase_deletion_evidence(tmp_path):
    summary.record_audit_degraded(tmp_path, reason='first')
    marker = tmp_path / summary.AUDIT_DEGRADED_FILE
    original = marker.read_bytes()
    marker.unlink()
    summary.record_audit_degraded(tmp_path, reason='second')
    assert not marker.exists()
    assert summary.reassert_audit_degraded(tmp_path) is True
    assert marker.read_bytes() == original


def test_concurrent_caller_shares_pending_parent_record(tmp_path, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    write = summary.write_text_atomically
    calls, errors = [], []

    def blocked_write(*args, **kwargs):
        calls.append(args)
        entered.set()
        assert release.wait(timeout=5)
        return write(*args, **kwargs)

    def first():
        try:
            summary.record_audit_degraded(tmp_path, reason='first')
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(summary, 'write_text_atomically', blocked_write)
    worker = threading.Thread(target=first)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        summary.record_audit_degraded(tmp_path, reason='second')
        assert len(calls) == 1
    finally:
        release.set()
        worker.join(timeout=5)
    assert not worker.is_alive()
    assert not errors
    assert json.loads((tmp_path / summary.AUDIT_DEGRADED_FILE).read_text())['reason'] == 'first'


@pytest.mark.parametrize('error_type', [ValueError, TypeError, RecursionError])
def test_unserializable_payload_does_not_claim_slot(tmp_path, monkeypatch, error_type):
    def fail(*args, **kwargs):
        raise error_type('invalid payload')

    monkeypatch.setattr(summary, 'dumps_artifact', fail)
    summary.record_audit_degraded(tmp_path, reason='unavailable')
    assert summary._degraded_markers == {}
    assert not (tmp_path / summary.AUDIT_DEGRADED_FILE).exists()
