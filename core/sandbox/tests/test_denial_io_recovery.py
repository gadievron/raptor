"""Transient denial I/O can recover without hiding prior evidence loss."""
import errno
import json
import os
from unittest.mock import Mock

import pytest

from core.sandbox import evidence, summary, telemetry_mac, triage


import core.sandbox.evidence as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(autouse=True)
def isolated_run(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'keys'))
    summary.set_active_run_dir(None)
    monkeypatch.setattr(summary, '_evidence_write_failures', {}, raising=False)
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', {})
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    monkeypatch.setattr(summary, '_floor_refusals', {})
    monkeypatch.setattr(summary, '_cli_disables', {})
    monkeypatch.setattr(summary, '_log_security_event', Mock())
    yield
    summary.set_active_run_dir(None)


def deny(cmd='test command'):
    summary.record_denial(cmd, 1, 'network', host='example.test')


def fail_open(*args, **kwargs):
    raise OSError(errno.ENOSPC, 'evidence storage unavailable')


def test_open_retry_obeys_backoff_and_keeps_loss_flag(tmp_path, monkeypatch):
    clock, attempts = [0.0], []
    original = evidence.EvidenceFile.open

    def open_once_failed(*args, **kwargs):
        attempts.append(clock[0])
        if len(attempts) == 1:
            return fail_open()
        return original(*args, **kwargs)

    monkeypatch.setattr(summary, '_monotonic', lambda: clock[0], raising=False)
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(open_once_failed))
    summary.set_active_run_dir(tmp_path)
    deny('lost first')
    clock[0] = 0.5
    deny('backing off')
    assert attempts == [0.0]
    clock[0] = 1.1
    deny('recovered')
    assert attempts == [0.0, 1.1]
    result = summary.summarize_and_write(tmp_path)
    assert result['total_denials'] == 1
    assert result['denials'][0]['cmd'] == 'recovered'
    assert result['evidence_write_failure'] is True
    assert summary.get_evidence_write_failure(tmp_path)
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    deny('later batch')
    assert summary.summarize_and_write(tmp_path)['evidence_write_failure'] is True


def test_new_run_resets_open_retry_deadline(tmp_path, monkeypatch):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir()
    second.mkdir()
    original = evidence.EvidenceFile.open

    def refuse_first(path, filename):
        return fail_open() if path == first else original(path, filename)

    monkeypatch.setattr(summary, '_monotonic', lambda: 0.0, raising=False)
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(refuse_first))
    summary.set_active_run_dir(first)
    deny()
    summary.set_active_run_dir(second)
    deny()
    result = summary.summarize_and_write(second)
    assert result['total_denials'] == 1
    assert 'evidence_write_failure' not in result
    assert summary.get_evidence_write_failure(first)
    assert not summary.get_evidence_write_failure(second)


def test_open_failure_without_disk_artifacts_still_reports(tmp_path, monkeypatch):
    summary.set_active_run_dir(tmp_path)
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(fail_open))
    deny()
    assert not (tmp_path / summary.SUMMARY_FILE).exists()
    report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report is not None
    assert 'parent observed a denial evidence write failure' in json.dumps(report)


def test_empty_failure_summary_retries_and_is_idempotent(tmp_path, monkeypatch):
    summary.set_active_run_dir(tmp_path)
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(fail_open))
    deny()

    def fail_summary(*args, **kwargs):
        raise OSError(errno.ENOSPC, 'summary unavailable')

    with monkeypatch.context() as scoped:
        scoped.setattr(summary, 'write_text_atomically', fail_summary)
        assert summary.summarize_and_write(tmp_path) is None
    result = summary.summarize_and_write(tmp_path)
    assert result['evidence_write_failure'] is True
    output = tmp_path / summary.SUMMARY_FILE
    before = output.read_bytes()
    assert summary.summarize_and_write(tmp_path) is None
    assert output.read_bytes() == before


def test_append_failure_keeps_surviving_record_and_mac_binding(tmp_path, monkeypatch):
    summary.set_active_run_dir(tmp_path)
    deny('surviving')
    fd = summary._evidence_handle.fd
    original = os.write

    def fail_append(current, data):
        return fail_open() if current == fd else original(current, data)

    with monkeypatch.context() as scoped:
        patch_module_attribute(scoped, _os_fault_consumer, "os", 'write', fail_append)
        deny('lost append')
    result = summary.summarize_and_write(tmp_path)
    assert result['total_denials'] == 1
    assert result['denials'][0]['cmd'] == 'surviving'
    assert result['evidence_write_failure'] is True
    fields = telemetry_mac.summary_fields(
        1, triage._denials_sha256(result['denials']), telemetry_mac.run_binding(tmp_path),
        evidence_write_failure=True)
    assert telemetry_mac.verify(fields, result['mac'])
    fields.pop('evidence_write_failure')
    assert not telemetry_mac.verify(fields, result['mac'])
    with monkeypatch.context() as scoped:
        scoped.setattr(summary, '_evidence_write_failures', {})
        report = triage.triage_run(tmp_path, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.parametrize('flag', [1, None, [], {}, 'yes'])
def test_malformed_failure_flags_are_rejected(flag, monkeypatch):
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: True)
    record = {'total_denials': 0, 'denials': [], 'mac': 'valid', 'evidence_write_failure': flag}
    assert triage._verify_summary(record, 'run') == (None, triage._INTEGRITY_TAMPERED)


def test_persistent_outage_limits_attempts_and_open_warnings(tmp_path, monkeypatch):
    clock, attempts = [0.0], []
    warning = Mock()

    def unavailable(*args, **kwargs):
        attempts.append(clock[0])
        return fail_open()

    monkeypatch.setattr(summary, '_monotonic', lambda: clock[0], raising=False)
    monkeypatch.setattr(summary.logger, 'warning', warning)
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(unavailable))
    summary.set_active_run_dir(tmp_path)
    for now in [0.0, 0.5, 1.5, 2.6]:
        clock[0] = now
        deny()
    assert attempts == [0.0, 1.5, 2.6]
    opens = [call for call in warning.call_args_list if 'cannot open evidence' in str(call.args[0])]
    assert len(opens) == 1


def test_failure_state_path_error_is_nonfatal(tmp_path, monkeypatch):
    class Unresolvable(type(tmp_path)):
        def resolve(self, *args, **kwargs):
            raise OSError('cannot resolve failed output path')

    summary.set_active_run_dir(tmp_path)
    monkeypatch.setattr(summary, '_active_run_dir', Unresolvable(tmp_path))
    monkeypatch.setattr(evidence.EvidenceFile, 'open', staticmethod(fail_open))
    deny()  # the original I/O failure and its accounting remain best-effort
