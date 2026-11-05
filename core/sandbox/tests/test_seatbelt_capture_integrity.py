"""Final evidence failures remain authoritative in the current parent."""
import errno
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, observe_profile as observe, seatbelt_audit as audit, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(summary, '_evidence_write_failures', dict(summary._evidence_write_failures))
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', dict(summary._evidence_inode_mismatches))


@pytest.mark.parametrize('failure', ['truncate', 'replace', 'close'])
def test_final_evidence_failure_reaches_parent_readers(tmp_path, monkeypatch, failure):
    run = tmp_path / 'run'
    owner = audit.LogStreamer(run, observe_mode=True, observe_nonce='trusted')
    try:
        owner._append_record({'type': 'write', 'syscall': 'stat', 'path': '/tmp/first',
                              'observe': True, 'nonce': 'trusted'})
        held = owner._evidence
        if failure == 'truncate':
            held.path.write_bytes(b'')
        elif failure == 'replace':
            original = held.path.read_bytes()
            held.path.unlink()
            held.path.write_bytes(original)
        else:
            private = ModuleType('streamer_close_os')
            vars(private).update(vars(os))

            def fail(fd):
                os.close(fd)
                raise OSError(errno.EIO, 'final evidence close failed')

            private.close = fail
            monkeypatch.setattr(evidence, 'os', private)
        owner.stop()
        assert owner._reader_failed is True
        assert summary.get_evidence_write_failure(run) is True
        profile = observe.parse_observe_log(run, expected_nonce='trusted', current_run=True)
        assert profile.capture_incomplete is True
        report = triage.triage_run(run, allow_legacy=False)
        assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    finally:
        owner.stop()


def test_parent_failure_floor_is_current_run_only(tmp_path):
    run = tmp_path / 'run'
    owner = audit.LogStreamer(run, observe_mode=True, observe_nonce='trusted')
    owner.stop()
    summary._record_evidence_write_failure(run)
    assert observe.parse_observe_log(run, expected_nonce='trusted', current_run=True).capture_incomplete is True
    assert observe.parse_observe_log(run, expected_nonce='trusted').capture_incomplete is False


def test_clean_finalization_stays_complete(tmp_path):
    run = tmp_path / 'run'
    owner = audit.LogStreamer(run, observe_mode=True, observe_nonce='trusted')
    owner.stop()
    assert summary.get_evidence_write_failure(run) is False
    assert observe.parse_observe_log(run, expected_nonce='trusted', current_run=True).capture_incomplete is False


@pytest.mark.slow
def test_known_reader_crash_reaches_signed_summary_and_triage(owned_audit_source):
    import json
    entry = {'senderImagePath': audit.SANDBOX_KEXT_SENDER,
             'eventMessage': 'Sandbox: tool(123) deny file-read-data /tmp/valid'}
    data = (json.dumps(entry) + '\n' + json.dumps(entry) + '\n').encode()
    owner, _ = owned_audit_source(data, decode_failure=True, observe_mode=False)
    assert owner._reader_failed is True
    assert summary.get_evidence_write_failure(owner._run_dir) is True
    result = summary.summarize_and_write(owner._run_dir)
    assert result['evidence_write_failure'] is True
    report = triage.triage_run(owner._run_dir, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
