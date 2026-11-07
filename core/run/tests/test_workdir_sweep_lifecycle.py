"""Legacy workspace reclamation shares conservative liveness and ownership gates."""
import os

import pytest
from core.run import tmp_reaper, workdir
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def roots(tmp_path, monkeypatch):
    paths = []
    for pid in (1000000001, 1000000002):
        path = tmp_path / f'session-{pid}-123'
        path.mkdir()
        (path / 'keep').write_text('owned')
        paths.append(path)
    monkeypatch.setattr(workdir, '_pid_alive', lambda pid: False)
    monkeypatch.setattr(workdir, '_live_cwds', lambda: set())
    return tmp_path, paths


@pytest.mark.parametrize('marker', ['file', 'directory', 'dangling-link'])
@pytest.mark.parametrize('when', ['initial', 'during-probe'])
def test_lifecycle_markers_are_reserved_even_during_publication(roots, monkeypatch, marker, when):
    root, (target, other) = roots
    def publish():
        path = target / 'metadata'
        if marker == 'file':
            path.write_text('incomplete')
        elif marker == 'directory':
            path.mkdir()
        else:
            path.symlink_to('missing')
    if when == 'initial':
        publish()
    else:
        def dead(pid):
            if pid == 1000000001:
                publish()
            return False
        monkeypatch.setattr(workdir, '_pid_alive', dead)
    workdir._sweep_dead_sessions(root)
    assert (target / 'keep').read_text() == 'owned'
    assert not other.exists()


@pytest.mark.parametrize('change', ['directory', 'symlink', 'file', 'refresh'])
def test_replaced_or_refreshed_workspace_is_not_deleted(roots, monkeypatch, change):
    root, (target, other) = roots
    saved = root / 'preserved'
    def changed(path, cwds):
        if path == target:
            if change == 'refresh':
                os.utime(target, (1, 1))
            else:
                target.rename(saved)
                if change == 'directory':
                    target.mkdir()
                    (target / 'keep').write_text('replacement')
                elif change == 'file':
                    target.write_text('replacement')
                else:
                    target.symlink_to(saved, target_is_directory=True)
        return False
    monkeypatch.setattr(workdir, '_dir_in_use', changed)
    workdir._sweep_dead_sessions(root)
    assert target.exists() and not other.exists()
    if change in ('directory', 'symlink', 'file'):
        assert (saved / 'keep').read_text() == 'owned'


@pytest.mark.parametrize('probe', ['unknown', 'cwd', 'socket'])
def test_in_use_or_unknown_liveness_preserves_workspace(roots, monkeypatch, probe):
    root, (target, other) = roots
    if probe == 'unknown':
        monkeypatch.setattr(workdir, '_live_cwds', lambda: None)
    elif probe == 'cwd':
        monkeypatch.setattr(workdir, '_live_cwds', lambda: {str(target / 'child')})
    else:
        monkeypatch.setattr(workdir, '_dir_in_use', lambda path, cwds: path == target)
    workdir._sweep_dead_sessions(root)
    assert target.exists()
    assert other.exists() == (probe == 'unknown')


def test_reused_pid_after_initial_probe_is_kept(roots, monkeypatch):
    root, (target, other) = roots
    calls = []
    def reused(pid):
        if pid == 1000000001:
            calls.append(pid)
            return len(calls) > 1
        return False
    monkeypatch.setattr(workdir, '_pid_alive', reused)
    workdir._sweep_dead_sessions(root)
    assert target.exists() and not other.exists() and len(calls) == 2


@pytest.mark.parametrize('stage', ['metadata', 'in-use', 'remove'])
def test_one_filesystem_failure_does_not_stop_other_reclamation(roots, monkeypatch, stage):
    root, (target, other) = roots
    if stage == 'metadata':
        original = workdir.os.lstat
        def unavailable(path, *args, **kwargs):
            if os.fspath(path) == str(target / 'metadata'):
                raise PermissionError('cannot inspect marker')
            return original(path, *args, **kwargs)
        patch_module_attribute(monkeypatch, workdir, 'os', 'lstat', unavailable)
    elif stage == 'in-use':
        def unavailable(path, cwds):
            if path == target:
                raise PermissionError('cannot inspect liveness')
            return False
        monkeypatch.setattr(workdir, '_dir_in_use', unavailable)
    else:
        original = workdir.rmtree_hardened
        def unavailable(path):
            if path == target:
                raise PermissionError('cannot remove tree')
            return original(path)
        monkeypatch.setattr(workdir, 'rmtree_hardened', unavailable)
    workdir._sweep_dead_sessions(root)
    assert target.exists() and not other.exists()


@pytest.mark.parametrize('verdict', ['nested', 'init', 'overflow', 'permission', 'dead'])
def test_shared_pid_guard_refuses_unverifiable_owners(tmp_path, monkeypatch, verdict):
    pid = 1 if verdict == 'init' else 1000000001
    target = tmp_path / f'session-{pid}-123'
    target.mkdir()
    monkeypatch.setattr(tmp_reaper, '_in_child_pid_ns', lambda: verdict == 'nested')
    monkeypatch.setattr(workdir, '_live_cwds', lambda: set())
    calls = []
    def probe(owner, signal):
        calls.append(owner)
        assert owner == 1000000001 and signal == 0
        raise {'overflow': OverflowError, 'permission': PermissionError,
               'dead': ProcessLookupError}[verdict]()
    patch_module_attribute(monkeypatch, tmp_reaper, 'os', 'kill', probe)
    workdir._sweep_dead_sessions(tmp_path)
    assert target.exists() == (verdict != 'dead')
    assert len(calls) == (2 if verdict == 'dead' else 1 if verdict in ('overflow', 'permission') else 0)


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_sweep_does_not_swallow_cancellation(roots, monkeypatch, failure):
    root, _ = roots
    def cancelled(*args):
        raise failure('stop sweep')
    monkeypatch.setattr(workdir, '_dir_in_use', cancelled)
    with pytest.raises(failure, match='stop sweep'):
        workdir._sweep_dead_sessions(root)
