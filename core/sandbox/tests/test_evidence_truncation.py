"""A held append offset detects truncation even when inode identity survives."""
import errno
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


FIRST = b'{"type":"network","cmd":"first"}\n'
SECOND = b'{"type":"network","cmd":"second"}\n'


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


def append(handle, writer):
    if writer == 'parent':
        assert handle.write_line((FIRST + SECOND).decode())
    elif writer == 'duplicate':
        # dup shares the open file description, just like an inherited fd.
        fd = os.dup(handle.fd)
        try:
            assert os.write(fd, FIRST + SECOND) == len(FIRST + SECOND)
        finally:
            os.close(fd)
    else:
        with handle.path.open('ab') as stream:
            stream.write(FIRST + SECOND)


@pytest.mark.parametrize('writer', ['parent', 'duplicate'])
@pytest.mark.parametrize('remaining', ['empty', 'first-record'])
def test_same_inode_truncation_fails_verification(tmp_path, writer, remaining, caplog):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        append(handle, writer)
        before = handle.path.stat()
        with handle.path.open('r+b') as stream:
            stream.truncate(0 if remaining == 'empty' else len(FIRST))
        after = handle.path.stat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        assert handle.close() is False
        assert handle.close() is False
        assert 'truncated' in caplog.text
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('writer', ['parent', 'duplicate', 'independent', 'reopened'])
def test_complete_appends_remain_verified(tmp_path, writer):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        append(handle, writer)
        if writer == 'reopened':
            assert handle.close() is True
            handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
        assert handle.close() is True
        assert handle.path.read_bytes() == FIRST + SECOND
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('remaining', ['empty', 'first-record'])
def test_truncated_denials_produce_flagged_summary(tmp_path, monkeypatch, remaining):
    run = tmp_path / 'run'
    run.mkdir()
    handle = evidence.EvidenceFile.open(run, summary.DENIALS_FILE)
    try:
        append(handle, 'duplicate')
        with handle.path.open('r+b') as stream:
            stream.truncate(0 if remaining == 'empty' else len(FIRST))
        # Borrow the summary binding without closing any inherited handle.
        monkeypatch.setattr(summary, '_evidence_handle', handle)
        monkeypatch.setattr(summary, '_evidence_inode_mismatches',
                            dict(summary._evidence_inode_mismatches))
        result = summary.summarize_and_write(run)
        assert result is not None
        assert result['inode_mismatch'] is True
        assert result['total_denials'] == (0 if remaining == 'empty' else 1)
        report = triage.triage_run(run, allow_legacy=False)
        assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('operation', ['lseek', 'fstat'])
def test_descriptor_inspection_failure_refuses_and_closes(tmp_path, monkeypatch, operation):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    local_os = ModuleType('evidence_verify_os')
    vars(local_os).update(vars(os))

    def fail(*args, **kwargs):
        raise OSError(errno.EIO, 'descriptor metadata unavailable')

    setattr(local_os, operation, fail)
    monkeypatch.setattr(evidence, 'os', local_os)
    try:
        assert handle.close() is False
        assert handle.close() is False
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
    finally:
        handle.close(verify=False)


@pytest.mark.parametrize('remaining', ['empty', 'first-record'])
@pytest.mark.parametrize('after', ['append', 'reopen'])
def test_size_floor_survives_offset_reset(tmp_path, remaining, after):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    try:
        append(handle, 'parent')
        if after == 'reopen':
            assert handle.close() is True
            handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
        with handle.path.open('r+b') as stream:
            stream.truncate(0 if remaining == 'empty' else len(FIRST))
        if after == 'append':
            assert handle.write_line(SECOND.decode())
        assert handle.close() is False
    finally:
        handle.close(verify=False)
