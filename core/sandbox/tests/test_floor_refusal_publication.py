"""Successful publication consumes its snapshot, preserving later refusals."""
from datetime import datetime
import errno

import pytest

from core.sandbox import summary
from core.testing.state_isolation import pin_user_state_dirs


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 5, tzinfo=tz)


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
    monkeypatch.setattr(summary, 'datetime', FrozenDatetime)
    monkeypatch.setattr(summary, '_active_run_dir', None)
    monkeypatch.setattr(summary, '_evidence_handle', None)
    monkeypatch.setattr(summary, '_floor_refusals', {
        key: list(records) for key, records in summary._floor_refusals.items()})
    monkeypatch.setattr(summary, '_evidence_inode_mismatches', dict(summary._evidence_inode_mismatches))
    monkeypatch.setattr(summary, '_evidence_write_failures', dict(summary._evidence_write_failures))


def refuse(run, reason):
    summary.record_floor_refusal(
        run, floor='mount-ns', achievable='landlock', reason=reason,
        remedies='use a capable host')


@pytest.mark.parametrize('interleaving', ['append', 'replace-queue'])
@pytest.mark.parametrize('same_payload', [False, True], ids=['distinct', 'identical'])
def test_publication_preserves_new_parent_records(tmp_path, monkeypatch, interleaving, same_payload):
    run = tmp_path / 'run'
    run.mkdir()
    key = str(run.resolve())
    refuse(run, 'first')
    first_record = summary._floor_refusals[key][0]
    late_reason = 'first' if same_payload else 'late'
    original_write = summary.write_text_atomically
    injected = False
    late_records = []

    def interleaved_write(path, text, **kwargs):
        nonlocal injected
        if path == run / summary.SUMMARY_FILE and not injected:
            injected = True
            if interleaving == 'replace-queue':
                # Another finalizer consumes the original snapshot before a
                # new producer creates a fresh queue for the same run.
                nested = summary.summarize_and_write(run)
                assert nested['total_floor_refusals'] == 1
                assert key not in summary._floor_refusals
            refuse(run, late_reason)
            late_records.append(summary._floor_refusals[key][-1])
        return original_write(path, text, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(summary, 'write_text_atomically', interleaved_write)
        first = summary.summarize_and_write(run)
    assert first['total_floor_refusals'] == 1
    pending = summary._floor_refusals.get(key, [])
    assert len(pending) == 1
    assert pending[0] is late_records[0]
    assert pending[0] is not first_record
    if same_payload:
        assert pending[0] == first_record
    second = summary.summarize_and_write(run)
    assert second['total_floor_refusals'] == 1
    assert second['floor_refusals'][0]['reason'] == late_reason
    assert second.get('floor_refusal_records_unverified', 0) == 0
    assert not second.get('unverified_floor_refusals')
    assert key not in summary._floor_refusals
    output = run / summary.SUMMARY_FILE
    before = output.read_bytes()
    assert summary.summarize_and_write(run) is None
    assert output.read_bytes() == before


def test_failed_publication_preserves_snapshot_and_new_refusal(tmp_path, monkeypatch):
    run = tmp_path / 'run'
    run.mkdir()
    key = str(run.resolve())
    refuse(run, 'first')

    def failed_write(*args, **kwargs):
        refuse(run, 'late')
        raise OSError(errno.ENOSPC, 'summary storage unavailable')

    with monkeypatch.context() as scoped:
        scoped.setattr(summary, 'write_text_atomically', failed_write)
        assert summary.summarize_and_write(run) is None
    assert [r['reason'] for r in summary._floor_refusals[key]] == ['first', 'late']
    result = summary.summarize_and_write(run)
    assert result['total_floor_refusals'] == 2
    assert [r['reason'] for r in result['floor_refusals']] == ['first', 'late']
    assert key not in summary._floor_refusals
