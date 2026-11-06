"""Fresh evidence must pass the same metadata floor as reopened evidence."""
import os
from types import ModuleType

import pytest

from core.sandbox import evidence, state, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path):
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_user_state_dirs(monkeypatch, tmp_path / 'state')
        monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
        yield


@pytest.fixture
def monkeypatch(owned_state):
    """Undo body patches before restoring the file-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.fixture
def acquisition(tmp_path, monkeypatch, request):
    private = ModuleType('evidence_creation_os')
    vars(private).update(vars(os))
    held = set()
    created = []
    mutation = [None]

    def cleanup():
        for fd in list(held):
            os.close(fd)
            held.remove(fd)
    request.addfinalizer(cleanup)

    def open_fd(*args, **kwargs):
        fd = os.open(*args, **kwargs)
        held.add(fd)
        if args[1] & os.O_EXCL:
            created.append(fd)
            change = mutation[0]
            if change == 'link':
                # Only link an owned, newly created regular file.
                name = args[0]
                os.link(name, 'owned-alias', src_dir_fd=kwargs['dir_fd'],
                        dst_dir_fd=kwargs['dir_fd'])
            elif change is not None:
                os.fchmod(fd, change)
        return fd

    def close_fd(fd):
        os.close(fd)
        held.remove(fd)

    private.open, private.close = open_fd, close_fd
    monkeypatch.setattr(evidence, 'os', private)
    return mutation, held, created


@pytest.mark.parametrize('change', [0o620, 0o602, 0o660, 0o606, 0o666, 'link'],
                         ids=['group-write', 'other-write', 'group-rw', 'other-rw', 'public-rw', 'hardlink'])
def test_unsafe_fresh_file_is_refused_before_writing(tmp_path, request, acquisition, change):
    mutation, held, created = acquisition
    mutation[0] = change
    with pytest.raises(OSError, match='refusing'):
        owner = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
        request.addfinalizer(lambda: owner.close(verify=False))
    assert len(created) == 1
    assert not held
    path = evidence.evidence_write_path(tmp_path, 'events.jsonl')
    assert path.read_bytes() == b''
    if change == 'link':
        assert path.stat().st_nlink == 2
        assert path.with_name('owned-alias').read_bytes() == b''
    else:
        assert path.stat().st_mode & 0o777 == change


@pytest.mark.parametrize('mode', [0o600, 0o640, 0o644, 0o700],
                         ids=['private', 'group-read', 'public-read', 'owner-exec'])
def test_safe_fresh_metadata_is_preserved(tmp_path, request, acquisition, mode):
    mutation, held, _created = acquisition
    mutation[0] = mode
    owner = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    request.addfinalizer(lambda: owner.close(verify=False))
    assert owner.write_record({'type': 'owned-event'})
    assert owner.path.stat().st_mode & 0o777 == mode
    assert owner.close() is True
    assert not held
    reopened = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    request.addfinalizer(lambda: reopened.close(verify=False))
    assert reopened.write_record({'type': 'next-event'})
    assert reopened.close() is True
    assert not held
    assert len(owner.path.read_text().splitlines()) == 2


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


@pytest.mark.parametrize('change', [0o620, 0o602, 'link'],
                         ids=['group-write', 'other-write', 'hardlink'])
def test_creation_refusal_reaches_parent_failure_report(acquisition, active_run, change):
    # Set up the active owner last so it closes before the fd fallback cleanup,
    # including when an assertion fails while production still holds a handle.
    mutation, held, _created = acquisition
    mutation[0] = change
    summary.record_denial('owned event', 1, 'write', path='/tmp/owned')
    assert summary._evidence_handle is None
    assert not held
    assert summary.get_evidence_write_failure(active_run) is True
    result = summary.summarize_and_write(active_run)
    assert result['evidence_write_failure'] is True
    assert result['total_denials'] == 0
    assert result['mac']
    report = triage.triage_run(active_run, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == 'tampered'
