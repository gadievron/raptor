"""Owned scratch deletion, crash retry, and context-free maintenance behavior."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from core.security import launch_scratch, scratch_lifecycle as lifecycle

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def owned(tmp_path, monkeypatch):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'registry'))
    family = tmp_path / 'operator-tmp' / f'raptor-{os.geteuid()}'
    family.mkdir(parents=True, mode=0o700)
    root = family / f'session-{os.getpid()}-123'
    root.mkdir(mode=0o700)
    metadata = launch_scratch.create(root)
    session_id = lifecycle.register(metadata, os.getpid())
    return root, metadata, session_id


def test_unsupervised_root_is_retained_without_pid_or_age_guesses(owned, monkeypatch):
    root, metadata, session_id = owned
    def no_probe(*args):
        pytest.fail('cleanup must not infer closure from a missing PID')
    monkeypatch.setattr(lifecycle.scratch(), '_birth', no_probe)
    assert lifecycle.cleanup(session_id) == 'retained'
    assert metadata.exists()
    assert lifecycle.session_for(metadata) == session_id


def test_verified_closure_cleans_only_owned_root_and_is_idempotent(owned):
    root, _, session_id = owned
    sibling = root.parent / 'unrelated'
    sibling.mkdir()
    (sibling / 'keep').write_text('operator data')
    lifecycle.record_closed(session_id, 'never-released')
    assert lifecycle.cleanup(session_id) == 'removed'
    assert lifecycle.cleanup(session_id) == 'removed'
    assert not root.exists()
    assert (sibling / 'keep').read_text() == 'operator data'
    assert root.parent.parent.exists(), 'the operator temporary base must survive'


def test_only_original_supervisor_can_record_closure(owned, monkeypatch):
    root, _, session_id = owned
    monkeypatch.setattr(lifecycle.scratch(), '_birth', lambda pid: {})
    with pytest.raises(PermissionError):
        lifecycle.record_closed(session_id, 'pid-namespace')
    assert lifecycle.cleanup(session_id) == 'retained'
    assert root.exists()


def test_symlink_and_hardlink_targets_are_unchanged(owned, tmp_path):
    root, _, session_id = owned
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'keep').write_text('original')
    (root / 'tmp/link').symlink_to(outside, target_is_directory=True)
    os.link(outside / 'keep', root / 'tmp/hardlink')
    lifecycle.record_closed(session_id, 'never-released')
    assert lifecycle.cleanup(session_id) == 'removed'
    assert (outside / 'keep').read_text() == 'original'
    assert (outside / 'keep').stat().st_nlink == 1


def test_replaced_root_is_not_deleted_even_with_force(owned):
    root, _, session_id = owned
    moved = root.with_name('original')
    root.rename(moved)
    root.mkdir(mode=0o700)
    (root / 'keep').write_text('not the registered directory')
    with pytest.raises(PermissionError):
        lifecycle.cleanup(session_id, force=True)
    assert (root / 'keep').read_text() == 'not the registered directory'
    assert moved.exists()


def test_symlink_root_is_not_followed_even_with_force(owned, tmp_path):
    root, _, session_id = owned
    original = root.with_name('original')
    root.rename(original)
    target = tmp_path / 'target'
    target.mkdir()
    (target / 'keep').write_text('safe')
    root.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError):
        lifecycle.cleanup(session_id, force=True)
    assert (target / 'keep').read_text() == 'safe'


def test_mount_detection_failure_retains_scratch(owned, monkeypatch):
    root, _, session_id = owned
    monkeypatch.setattr(lifecycle, '_mounts_below', lambda path: True)
    with pytest.raises(PermissionError):
        lifecycle.cleanup(session_id, force=True)
    assert root.exists()


def test_cleanup_interruption_is_retryable_without_metadata_files(owned, monkeypatch):
    root, _, session_id = owned
    lifecycle.record_closed(session_id, 'never-released')
    real_erase = lifecycle._erase
    def interrupted(node, device, deadline, **kwargs):
        # Simulate a partial cleanup that removed metadata before interruption.
        shutil.rmtree(root.parent / ('.cleanup-' + session_id) / 'metadata')
        raise TimeoutError('interrupted cleanup')
    with monkeypatch.context() as context:
        context.setattr(lifecycle, '_erase', interrupted)
        with pytest.raises(TimeoutError):
            lifecycle.cleanup(session_id)
    assert not root.exists()
    quarantine = root.parent / ('.cleanup-' + session_id)
    assert quarantine.exists()
    assert lifecycle._erase is real_erase
    assert lifecycle.cleanup(session_id) == 'removed'
    assert not quarantine.exists()


def test_force_requires_individual_selection(owned):
    root, _, _ = owned
    with pytest.raises(SystemExit) as error:
        lifecycle.main(['--force'])
    assert error.value.code == 2
    assert root.exists()


def test_readonly_listing_creates_no_lock_or_scratch(owned, capsys):
    _, _, session_id = owned
    before = sorted(lifecycle.registry().iterdir())
    assert lifecycle.main(['--list', '--session', session_id]) == 0
    assert 'retained' in capsys.readouterr().out
    assert sorted(lifecycle.registry().iterdir()) == before


def test_control_record_cannot_redirect_cleanup_to_operator_base(owned):
    root, _, session_id = owned
    node = lifecycle._open_registry()
    try:
        record = json.loads(lifecycle._read_file(node, session_id + '.json'))
        record['root'] = str(root.parent.parent)
        lifecycle._write(node, session_id + '.json', record)
    finally:
        os.close(node)
    with pytest.raises(ValueError):
        lifecycle.cleanup(session_id, force=True)
    assert root.exists()


@pytest.mark.parametrize('args', [['--list'], ['--dry-run'], ['--help']])
def test_launcher_maintenance_needs_neither_tempdir_nor_frontend(tmp_path, args):
    env = {'PATH': os.defpath, 'HOME': str(tmp_path), 'TMPDIR': '/nonexistent/temporary-base',
           'RAPTOR_WORK_DIR': '/another/nonexistent/base',
           'RAPTOR_REGISTRY_HOME': str(tmp_path / 'registry')}
    result = subprocess.run(['/bin/bash', str(ROOT / 'bin/raptor'), 'cleanup', *args],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not (tmp_path / 'registry').exists()
    assert not list(tmp_path.glob('raptor-*'))


def test_completed_unlink_with_missing_final_receipt_is_retryable(owned, monkeypatch):
    root, _, session_id = owned
    lifecycle.record_closed(session_id, 'never-released')
    original = lifecycle._write
    def fail_final_receipt(node, name, value):
        if value['state'] == 'removed':
            raise OSError('simulated final journal write failure')
        return original(node, name, value)
    with monkeypatch.context() as context:
        context.setattr(lifecycle, '_write', fail_final_receipt)
        with pytest.raises(OSError):
            lifecycle.cleanup(session_id)
    assert not root.exists()
    assert lifecycle.cleanup(session_id) == 'removed'


def test_registration_rejects_metadata_file_symlinks(owned, tmp_path):
    _, metadata, _ = owned
    alias = metadata.with_name('actual.json')
    metadata.rename(alias)
    metadata.symlink_to(alias)
    with pytest.raises(OSError):
        lifecycle.register(metadata, os.getpid())


def test_locked_cleanup_does_not_compete_with_another_cleaner(owned):
    root, _, session_id = owned
    with lifecycle.locked(session_id):
        with pytest.raises(BlockingIOError):
            lifecycle.cleanup(session_id, force=True)
    assert root.exists()


def test_closed_session_removes_only_its_own_credential_group(owned):
    root, metadata, session_id = owned
    family = lifecycle.authority_family()
    first = launch_scratch.issue(family, metadata, os.getpid())
    first_entry = Path(json.loads(first)['entry'])
    assert first_entry.parent.parent.name == 'session-' + session_id
    second_metadata = launch_scratch.allocate(root.parent.parent, os.getpid())
    second_id = lifecycle.register(second_metadata, os.getpid())
    second = launch_scratch.issue(family, second_metadata, os.getpid())
    second_entry = Path(json.loads(second)['entry'])
    lifecycle.record_closed(session_id, 'never-released')
    assert lifecycle.cleanup(session_id) == 'removed'
    assert not first_entry.parent.parent.exists()
    assert second_entry.is_file()
    assert second_entry.parent.parent.name == 'session-' + second_id
    assert launch_scratch._restore_authorized(second)[0] == second_metadata
    assert family.exists()


def test_uncertain_session_preserves_its_credential_group(owned):
    _, metadata, session_id = owned
    token = launch_scratch.issue(lifecycle.authority_family(), metadata, os.getpid())
    assert lifecycle.cleanup(session_id) == 'retained'
    assert launch_scratch._restore_authorized(token)[0] == metadata


def test_refreshed_delegations_stay_in_the_physical_session_group(owned, monkeypatch):
    _, metadata, session_id = owned
    family = lifecycle.authority_family()
    token = launch_scratch.issue(family, metadata, os.getpid())
    monkeypatch.setattr(launch_scratch, '_metadata_path', metadata)
    monkeypatch.setenv('_RAPTOR_SCRATCH_AUTH', token)
    launch_scratch._refresh_delegation(Path(json.loads(token)['entry']))
    refreshed = Path(json.loads(os.environ['_RAPTOR_SCRATCH_AUTH'])['entry'])
    assert refreshed.parent.parent == family / ('session-' + session_id)
    assert launch_scratch._restore_authorized(os.environ['_RAPTOR_SCRATCH_AUTH'])[0] == metadata


def test_authority_symlink_substitution_retains_outside_data_and_allows_retry(owned, tmp_path):
    root, _, session_id = owned
    group = lifecycle.authority_family() / ('session-' + session_id)
    saved = group.with_name('saved-authorities')
    group.rename(saved)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'keep').write_text('operator data')
    group.symlink_to(outside, target_is_directory=True)
    lifecycle.record_closed(session_id, 'never-released')
    with pytest.raises(OSError):
        lifecycle.cleanup(session_id)
    assert not root.exists()
    assert (outside / 'keep').read_text() == 'operator data'
    group.unlink()
    saved.rename(group)
    assert lifecycle.cleanup(session_id) == 'removed'


def test_duplicate_registration_does_not_create_another_record_or_authority_group(owned):
    _, metadata, _ = owned
    before = sorted(lifecycle.registry().iterdir())
    groups = sorted(lifecycle.authority_family().iterdir())
    with pytest.raises(FileExistsError):
        lifecycle.register(metadata, os.getpid())
    assert sorted(lifecycle.registry().iterdir()) == before
    assert sorted(lifecycle.authority_family().iterdir()) == groups


@pytest.mark.parametrize('args', [[], ['--list'], ['--dry-run']])
def test_empty_cleanup_explains_scope_without_creating_state(tmp_path, monkeypatch, capsys, args):
    registry = tmp_path / 'empty-registry'
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(registry))
    assert lifecycle.main(args) == 0
    text = capsys.readouterr().out
    assert 'no registered launcher-session scratch' in text
    assert 'not scanned' in text
    assert not registry.exists()


@pytest.mark.parametrize('closure', ['never-released', 'pid-namespace', 'cgroup-v2'])
def test_dry_run_reports_eligibility_without_mutating_owned_tree(owned, capsys, closure):
    root, _, session_id = owned
    lifecycle.record_closed(session_id, closure)
    before = {p.name: p.read_bytes() for p in lifecycle.registry().iterdir()}
    assert lifecycle.main(['--dry-run', '--session', session_id]) == 0
    text = capsys.readouterr().out
    assert 'would-remove' in text
    assert 'filesystem checks' in text
    assert root.exists()
    assert before == {p.name: p.read_bytes() for p in lifecycle.registry().iterdir()}


def test_retained_cleanup_explains_individual_override(owned, capsys):
    root, _, session_id = owned
    assert lifecycle.main([]) == 0
    text = capsys.readouterr().out
    assert '1 retained' in text
    assert 'no recorded process-tree closure' in text
    assert f'--session {session_id} --force' in text
    assert root.exists()


def test_cleanup_summary_distinguishes_new_removal_from_receipts(owned, capsys):
    root, _, session_id = owned
    lifecycle.record_closed(session_id, 'never-released')
    assert lifecycle.main([]) == 0
    assert '1 removed.' in capsys.readouterr().out
    assert not root.exists()
    assert lifecycle.main([]) == 0
    assert '1 already-removed.' in capsys.readouterr().out
    assert lifecycle.main(['--dry-run']) == 0
    assert '1 already-removed.' in capsys.readouterr().out


def test_cleanup_error_reports_sanitized_reason_and_fails(owned, monkeypatch, capsys):
    root, _, _ = owned
    def unavailable(*args, **kwargs):
        raise PermissionError('fixture denied\x1b[31m\nnext line')
    monkeypatch.setattr(lifecycle, 'cleanup', unavailable)
    assert lifecycle.main([]) == 1
    text = capsys.readouterr().out
    assert 'PermissionError' in text
    assert 'fixture denied' in text
    assert '\x1b' not in text
    assert '1 cleanup-error' in text
    assert root.exists()


@pytest.mark.parametrize('args', [[], ['--list'], ['--dry-run']])
def test_invalid_record_is_visible_and_returns_failure(owned, capsys, args):
    root, _, session_id = owned
    (lifecycle.registry() / (session_id + '.json')).write_text('{}')
    assert lifecycle.main(args) == 1
    text = capsys.readouterr().out
    assert 'invalid control record' in text
    assert '1 invalid' in text
    assert root.exists()


def test_cleanup_warns_when_limit_leaves_records_uninspected(owned, capsys):
    root, metadata, _ = owned
    other = root.with_name('session-' + 'a' * 32)
    other.mkdir(mode=0o700)
    lifecycle.register(launch_scratch.create(other), os.getpid())
    assert lifecycle.main(['--dry-run', '--limit', '1']) == 0
    text = capsys.readouterr().out
    assert 'more records remain' in text
    assert '1 inspected' in text
    assert root.exists() and other.exists() and metadata.exists()


def test_exact_limit_does_not_warn_about_nonexistent_records(owned, capsys):
    assert lifecycle.main(['--dry-run', '--limit', '1']) == 0
    assert 'more records remain' not in capsys.readouterr().out


def test_dry_run_recognizes_prior_removal_authorization(owned, capsys):
    root, _, session_id = owned
    with lifecycle.locked(session_id) as (node, value):
        value.update(removal_authorized=True, state='cleanup-error')
        lifecycle._write(node, session_id + '.json', value)
    assert lifecycle.main(['--dry-run']) == 0
    assert '1 would-remove' in capsys.readouterr().out
    assert root.exists()


def test_missing_selected_session_reports_reason(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv('RAPTOR_REGISTRY_HOME', str(tmp_path / 'absent'))
    assert lifecycle.main(['--session', 'b' * 32]) == 1
    assert 'FileNotFoundError' in capsys.readouterr().err


def test_individual_failure_does_not_stop_remaining_cleanup(owned, monkeypatch, capsys):
    root, _, session_id = owned
    other = root.with_name('session-' + 'c' * 32)
    other.mkdir(mode=0o700)
    second = lifecycle.register(launch_scratch.create(other), os.getpid())
    lifecycle.record_closed(second, 'never-released')
    original = lifecycle.cleanup
    def fail_one(identifier, **kwargs):
        if identifier == session_id:
            raise OSError('first session unavailable')
        return original(identifier, **kwargs)
    monkeypatch.setattr(lifecycle, 'cleanup', fail_one)
    assert lifecycle.main([]) == 1
    text = capsys.readouterr().out
    assert '1 cleanup-error, 1 removed' in text
    assert root.exists() and not other.exists()
