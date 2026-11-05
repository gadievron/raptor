"""Transient marker write failures remain recoverable without false tamper claims."""
import errno
import json
from unittest.mock import Mock

import pytest

from core.sandbox import summary
from core.sandbox import telemetry_mac


@pytest.fixture
def state(monkeypatch):
    monkeypatch.setattr(summary, '_degraded_markers', {})
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
    event = Mock()
    monkeypatch.setattr(summary, '_log_security_event', event)
    return event


def fail_once(monkeypatch):
    write = summary.write_text_atomically
    calls = []

    def flaky(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise OSError(errno.ENOSPC, 'temporary storage failure')
        return write(*args, **kwargs)

    monkeypatch.setattr(summary, 'write_text_atomically', flaky)
    return calls


def test_initial_failure_is_retried_without_tamper_claim(tmp_path, monkeypatch, state):
    calls = fail_once(monkeypatch)
    summary.record_audit_degraded(tmp_path, reason='audit unavailable')
    marker = tmp_path / summary.AUDIT_DEGRADED_FILE
    assert not marker.exists()
    assert summary.reassert_audit_degraded(tmp_path) is False
    assert json.loads(marker.read_text())['reason'] == 'audit unavailable'
    assert len(calls) == 2
    state.assert_not_called()
    assert summary._degraded_markers[str(tmp_path.resolve())]['persisted'] is True


def test_finalization_retries_pending_marker(tmp_path, monkeypatch, state):
    fail_once(monkeypatch)
    summary.record_audit_degraded(tmp_path, reason='audit unavailable')
    assert summary.summarize_and_write(tmp_path) is None
    assert (tmp_path / summary.AUDIT_DEGRADED_FILE).exists()
    state.assert_not_called()


def test_deletion_after_successful_retry_remains_tampering(tmp_path, monkeypatch, state):
    fail_once(monkeypatch)
    summary.record_audit_degraded(tmp_path, reason='audit unavailable')
    assert summary.reassert_audit_degraded(tmp_path) is False
    (tmp_path / summary.AUDIT_DEGRADED_FILE).unlink()
    assert summary.reassert_audit_degraded(tmp_path) is True
    assert summary.reassert_audit_degraded(tmp_path) is True
    state.assert_called_once()


def test_repeated_write_failures_keep_retry_state(tmp_path, monkeypatch, state):
    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, 'still unavailable')

    monkeypatch.setattr(summary, 'write_text_atomically', fail)
    summary.record_audit_degraded(tmp_path, reason='audit unavailable')
    assert summary.reassert_audit_degraded(tmp_path) is False
    assert summary.reassert_audit_degraded(tmp_path) is False
    assert summary._degraded_markers[str(tmp_path.resolve())]['persisted'] is False
    state.assert_not_called()


def test_successful_initial_marker_still_detects_deletion(tmp_path, state):
    summary.record_audit_degraded(tmp_path, reason='audit unavailable')
    (tmp_path / summary.AUDIT_DEGRADED_FILE).unlink()
    assert summary.reassert_audit_degraded(tmp_path) is True
    state.assert_called_once()
