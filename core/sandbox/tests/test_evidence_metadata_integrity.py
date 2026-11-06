"""Evidence safety metadata is checked at acquisition and finalization."""
import errno
import json
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, observe_profile as observe, seatbelt_audit as audit
from core.sandbox import state, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.fixture
def handle(tmp_path, request):
    owner = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    request.addfinalizer(lambda: owner.close(verify=False))
    assert owner.write_record({'type': 'write', 'path': '/tmp/owned'})
    return owner


@pytest.fixture
def private_os(monkeypatch, request):
    private = ModuleType('owned_evidence_metadata_os')
    vars(private).update(vars(evidence.os))
    original_open, original_close = private.open, private.close
    acquired, closed = set(), []

    def cleanup():
        for fd in list(acquired):
            original_close(fd)
            acquired.remove(fd)
    request.addfinalizer(cleanup)

    def open_fd(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        acquired.add(fd)
        return fd

    def close_fd(fd):
        original_close(fd)
        acquired.discard(fd)
        closed.append(fd)

    private.open, private.close = open_fd, close_fd
    monkeypatch.setattr(evidence, 'os', private)
    return private, acquired, closed


@pytest.mark.parametrize('mode', [0o770, 0o777, 0o702, 0o706],
                         ids=['group-write', 'public-write', 'other-write', 'other-rw'])
def test_unsafe_existing_directory_is_refused_and_released(tmp_path, private_os, mode):
    directory = evidence.audit_dir_path(tmp_path)
    directory.mkdir(mode=0o700)
    directory.chmod(mode)
    private, acquired, closed = private_os
    fd = None
    try:
        with pytest.raises(OSError, match='refusing'):
            fd = evidence.ensure_audit_dirfd(tmp_path)
    finally:
        if fd is not None:
            private.close(fd)
    assert not acquired
    assert len(closed) == 1
    assert directory.stat().st_mode & 0o777 == mode


def test_foreign_directory_owner_is_refused_without_chown(tmp_path, private_os, monkeypatch):
    private, acquired, closed = private_os
    original_fstat = private.fstat

    def foreign_owner(fd):
        values = list(original_fstat(fd))
        values[4] = os.getuid() + 1
        return os.stat_result(values)
    monkeypatch.setattr(private, 'fstat', foreign_owner)
    fd = None
    try:
        with pytest.raises(OSError, match='refusing'):
            fd = evidence.ensure_audit_dirfd(tmp_path)
    finally:
        if fd is not None:
            private.close(fd)
    assert not acquired
    assert len(closed) == 1


@pytest.mark.parametrize('mode', [0o700, 0o750, 0o755], ids=['private', 'group-read', 'public-read'])
def test_safe_existing_directory_is_preserved(tmp_path, private_os, mode):
    directory = evidence.audit_dir_path(tmp_path)
    directory.mkdir(mode=0o700)
    directory.chmod(mode)
    before = directory.stat()
    private, acquired, closed = private_os
    fd = evidence.ensure_audit_dirfd(tmp_path)
    try:
        assert os.fstat(fd).st_ino == before.st_ino
        assert directory.stat().st_mode & 0o777 == mode
    finally:
        private.close(fd)
    assert not acquired
    assert len(closed) == 1


@pytest.mark.parametrize('mode', [0o660, 0o620, 0o602, 0o606, 0o666],
                         ids=['group-rw', 'group-write', 'other-write', 'other-rw', 'public-rw'])
def test_widened_file_permissions_fail_final_verification(handle, mode):
    before = handle.path.read_bytes()
    handle.path.chmod(mode)
    assert handle.verify() is False
    assert handle.close() is False
    assert handle.verify() is False
    assert handle.path.read_bytes() == before
    with pytest.raises(OSError) as released:
        os.fstat(handle.fd)
    assert released.value.errno == errno.EBADF


def test_new_hard_link_fails_final_verification(tmp_path, handle):
    alias = tmp_path / 'owned-alias'
    os.link(handle.path, alias)
    assert handle.verify() is False
    assert handle.close() is False
    assert alias.read_bytes() == handle.path.read_bytes()


def test_metadata_change_after_path_stat_is_detected(handle, private_os, monkeypatch):
    private, _acquired, _closed = private_os
    original_fstat = private.fstat

    def widen_before_descriptor_snapshot(fd):
        if fd == handle.fd:
            handle.path.chmod(0o660)
        return original_fstat(fd)
    monkeypatch.setattr(private, 'fstat', widen_before_descriptor_snapshot)
    assert handle.verify() is False
    assert handle.close() is False


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o644, 0o700],
                         ids=['private', 'group-read', 'public-read', 'owner-exec'])
def test_safe_file_metadata_retains_current_contract(handle, mode):
    handle.path.chmod(mode)
    assert handle.verify() is True
    assert handle.close() is True
    assert handle.verify() is True


@pytest.fixture
def active_run(tmp_path, monkeypatch, request):
    monkeypatch.setattr(state, '_cli_sandbox_disabled', False)
    for name in ('_active_run_dir', '_active_run_generation', '_denial_count',
                 '_evidence_handle', '_evidence_open_failed', '_evidence_next_open_attempt'):
        monkeypatch.setattr(summary, name, getattr(summary, name))
    monkeypatch.setattr(summary, '_active_run_dir', None)
    monkeypatch.setattr(summary, '_evidence_handle', None)
    run = tmp_path / 'run'
    run.mkdir()
    request.addfinalizer(lambda: summary.set_active_run_dir(None))
    summary.set_active_run_dir(run)
    return run


@pytest.mark.parametrize('mutation', ['mode', 'link'])
def test_metadata_failure_reaches_signed_summary(active_run, mutation):
    summary.record_denial('owned record', 1, 'write', path='/tmp/owned')
    owner = summary._evidence_handle
    assert owner is not None
    if mutation == 'mode':
        owner.path.chmod(0o660)
    else:
        os.link(owner.path, active_run / 'owned-alias')
    result = summary.summarize_and_write(active_run)
    assert result['total_denials'] == 1
    assert result['inode_mismatch'] is True
    assert result['mac']
    report = triage.triage_run(active_run, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


def test_unsafe_directory_refusal_reaches_signed_summary(active_run):
    directory = evidence.audit_dir_path(active_run)
    directory.mkdir(mode=0o700)
    directory.chmod(0o770)
    summary.record_denial('owned record', 1, 'write', path='/tmp/owned')
    assert summary._evidence_handle is None
    result = summary.summarize_and_write(active_run)
    assert result['evidence_write_failure'] is True
    assert result['mac']
    assert directory.stat().st_mode & 0o777 == 0o770
    assert triage.triage_run(active_run, allow_legacy=False)['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED


@pytest.mark.slow
@pytest.mark.parametrize('mutation', ['mode', 'link'])
def test_metadata_failure_reaches_current_observation(tmp_path, monkeypatch, owned_audit_source, mutation):
    original_close = evidence.EvidenceFile.close

    def mutate_then_close(owner, **kwargs):
        if owner.path.name == observe.OBSERVE_FILENAME and not owner._closed:
            if mutation == 'mode':
                owner.path.chmod(0o660)
            else:
                os.link(owner.path, tmp_path / 'owned-observation-alias')
        return original_close(owner, **kwargs)
    monkeypatch.setattr(evidence.EvidenceFile, 'close', mutate_then_close)
    line = (json.dumps({'senderImagePath': audit.SANDBOX_KEXT_SENDER,
                        'eventMessage': 'Sandbox: tool(123) deny(1) file-read-data /tmp/retained'}) + '\n').encode()
    owner, profile = owned_audit_source(line)
    assert profile.paths_read == ['/tmp/retained']
    assert owner._reader_failed is True
    assert profile.capture_incomplete is True
