"""Evidence finalization cannot attest success after descriptor-close failure."""
import errno
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, state, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def handle(tmp_path):
    owned = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        assert owned.write_record({'detail': 'preserved'})
        yield owned
    finally:
        owned.close(verify=False)


def close_fault(monkeypatch, handle, error):
    private = ModuleType('evidence_close_os')
    vars(private).update(vars(os))
    closed = []

    def close(fd):
        assert fd == handle.fd
        closed.append(fd)
        os.close(fd)
        # Inspect immediately, before a warning handler can reuse the number.
        with pytest.raises(OSError) as released:
            os.fstat(fd)
        assert released.value.errno == errno.EBADF
        raise error

    private.close = close
    monkeypatch.setattr(evidence, 'os', private)
    return closed, private


def forbid_inspection(private):
    def forbidden(*args, **kwargs):
        pytest.fail('finalized evidence descriptor was inspected or closed again')
    for name in ('stat', 'fstat', 'lseek', 'close'):
        setattr(private, name, forbidden)


@pytest.mark.parametrize('verify', [False, True], ids=['skip-verification', 'verify'])
@pytest.mark.parametrize('error_number', [errno.EIO, errno.ENOSPC], ids=['io', 'storage'])
def test_close_error_returns_and_caches_failure(handle, monkeypatch, caplog, verify, error_number):
    before = handle.path.read_bytes()
    closed, private = close_fault(monkeypatch, handle, OSError(error_number, 'close failed'))
    assert handle.close(verify=verify) is False
    assert 'evidence close failed' in caplog.text
    assert closed == [handle.fd]
    assert handle.path.read_bytes() == before
    forbid_inspection(private)
    assert handle.verify() is False
    assert handle.close() is False
    assert handle.write_record({'after': 'close'}) is False


@pytest.mark.parametrize('verify', [False, True], ids=['skip-verification', 'verify'])
@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt])
def test_interrupted_close_keeps_failed_verdict(handle, monkeypatch, verify, failure):
    error = failure('close interrupted')
    closed, private = close_fault(monkeypatch, handle, error)
    with pytest.raises(failure) as raised:
        handle.close(verify=verify)
    assert raised.value is error
    assert closed == [handle.fd]
    forbid_inspection(private)
    assert handle.verify() is False
    assert handle.close() is False


@pytest.mark.parametrize('failure', [RuntimeError, KeyboardInterrupt])
def test_verification_error_survives_secondary_close_error(handle, monkeypatch, failure):
    error = failure('verification interrupted')
    closed, private = close_fault(monkeypatch, handle, OSError(errno.EIO, 'secondary close failure'))

    def fail():
        raise error

    monkeypatch.setattr(handle, '_verify_locked', fail)
    with pytest.raises(failure) as raised:
        handle.close()
    assert raised.value is error
    assert closed == [handle.fd]
    forbid_inspection(private)
    assert handle.verify() is False
    assert handle.close() is False


def test_failed_verification_remains_failed_after_close_error(handle, monkeypatch):
    handle.path.write_bytes(b'')
    closed, private = close_fault(monkeypatch, handle, OSError(errno.EIO, 'close failed'))
    assert handle.close() is False
    assert closed == [handle.fd]
    forbid_inspection(private)
    assert handle.verify() is False


@pytest.mark.parametrize('verify', [False, True])
def test_clean_close_still_caches_success(handle, verify):
    assert handle.close(verify=verify) is True
    assert handle.verify() is True
    assert handle.close() is True


@pytest.mark.parametrize('deactivate', [False, True], ids=['finalize-active', 'finalize-inactive'])
def test_close_failure_reaches_authenticated_parent_summary(tmp_path, monkeypatch, deactivate):
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    run = tmp_path / 'run'
    run.mkdir()
    # Preserve inherited lifecycle bindings and maps, including any held fd.
    for name in ('_active_run_dir', '_active_run_generation', '_denial_count',
                 '_evidence_handle', '_evidence_open_failed', '_evidence_next_open_attempt'):
        monkeypatch.setattr(summary, name, getattr(summary, name))
    monkeypatch.setattr(summary, '_active_run_dir', None)
    monkeypatch.setattr(summary, '_evidence_handle', None)
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', dict(summary._evidence_inode_mismatches))
    monkeypatch.setattr(summary, '_evidence_write_failures', dict(summary._evidence_write_failures))
    summary.set_active_run_dir(run)
    try:
        summary.record_denial('owned test record', 1, 'write', path='/tmp/owned')
        owned = summary._evidence_handle
        assert owned is not None
        with monkeypatch.context() as scoped:
            closed, _ = close_fault(scoped, owned, OSError(errno.EIO, 'evidence writeback failed'))
            if deactivate:
                summary.set_active_run_dir(None)
            result = summary.summarize_and_write(run)
        assert closed == [owned.fd]
        assert result is not None
        assert result['total_denials'] == 1
        assert result['inode_mismatch'] is True
        assert result.get('mac')
        assert summary.get_evidence_inode_mismatch(run) is True
        report = triage.triage_run(run, allow_legacy=False)
        assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    finally:
        summary.set_active_run_dir(None)
