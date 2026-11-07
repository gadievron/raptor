"""Reaping decisions are snapshots, not permission to delete later replacements."""

import json
import os
import time
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from core.run import tmp_reaper as reaper
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(params=['temp-file', 'pid-file', 'log-file', 'temp-dir', 'pid-dir', 'run-dir'])
def family(request, tmp_path, monkeypatch):
    kind = request.param
    root = tmp_path / 'artifacts'
    root.mkdir()
    old = time.time() - 60 * 86400
    now = time.time()
    monkeypatch.setattr(reaper, '_sweep_roots', lambda: [(root, False)])
    monkeypatch.setattr(reaper, '_live_cwds', lambda: set())
    monkeypatch.setattr(reaper, '_in_child_pid_ns', lambda: False)
    def dead(pid, signal):
        assert pid in (1000000001, 1000000002) and signal == 0
        raise ProcessLookupError
    patch_module_attribute(monkeypatch, reaper, 'os', 'kill', dead)
    monkeypatch.setenv('RAPTOR_TMP_REAP_MAX_AGE_H', '24')
    monkeypatch.setenv('RAPTOR_RUN_REAP_MAX_AGE_D', '30')
    monkeypatch.setenv('RAPTOR_LOG_REAP_MAX_AGE_D', '14')
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, 'LOG_DIR', root)
    paths = []
    for number in (1, 2):
        if kind == 'temp-file':
            path = root / f'audit_sweep_{number}.yaml'
        elif kind == 'pid-file':
            path = root / f'raptor-pytest-scorecard-{1000000000 + number}.json'
        elif kind == 'log-file':
            path = root / f'raptor_{number}.jsonl'
        elif kind == 'temp-dir':
            path = root / f'raptor-toolprobe-{number}'
        elif kind == 'pid-dir':
            path = root / f'owned-{1000000000 + number}'
        else:
            path = root / f'scan-{number}'
        if kind.endswith('-dir'):
            path.mkdir()
            payload = path / 'payload'
            payload.write_text('disposable')
            os.utime(payload, (old, old))
            if kind == 'run-dir':
                metadata = path / '.raptor-run.json'
                metadata.write_text(json.dumps({
                    'status': 'failed',
                    'timestamp': datetime.fromtimestamp(old, timezone.utc).isoformat(),
                }))
                os.utime(metadata, (old, old))
        else:
            path.write_text('disposable')
        os.utime(path, (old, old))
        paths.append(path)
    if kind == 'log-file':
        sweep = lambda: reaper.reap_stale_logs(now)
    elif kind == 'run-dir':
        sweep = lambda: reaper.reap_stale_runs(root, now)
    elif kind == 'pid-dir':
        sweep = lambda: reaper.reap_dead_pid_dirs(root, 'owned-')
    else:
        sweep = lambda: reaper.reap_stale_tmp(now)
    return SimpleNamespace(kind=kind, root=root, target=paths[0], other=paths[1],
                           old=old, now=now, sweep=sweep)


def test_unchanged_candidates_are_removed(family):
    assert set(family.sweep()) == {family.target, family.other}
    assert not family.target.exists() and not family.other.exists()


@pytest.mark.parametrize('change', ['refresh', 'replace', 'symlink'])
def test_changed_candidate_survives_and_other_removal_is_reported(family, monkeypatch, change):
    original = reaper._unchanged_artifact
    touched = []
    preserved = family.root.parent / 'preserved'
    def changed(path, info):
        if path == family.target and not touched:
            touched.append(path)
            if change == 'refresh':
                os.utime(path, (family.now, family.now))
            else:
                path.rename(preserved)
                if change == 'symlink':
                    path.symlink_to(preserved, target_is_directory=family.kind.endswith('-dir'))
                elif family.kind.endswith('-dir'):
                    path.mkdir()
                    (path / 'keep').write_text('replacement')
                else:
                    path.write_text('replacement')
                if change == 'replace':
                    os.utime(path, (family.old, family.old))
        return original(path, info)
    monkeypatch.setattr(reaper, '_unchanged_artifact', changed)
    assert family.sweep() == [family.other]
    assert touched and family.target.exists()
    if change == 'symlink':
        assert family.target.is_symlink() and preserved.exists()
    elif change == 'replace' and family.kind.endswith('-dir'):
        assert (family.target / 'keep').read_text() == 'replacement'
    elif change == 'replace':
        assert family.target.read_text() == 'replacement'


def test_candidate_probe_error_keeps_other_receipts(family, monkeypatch):
    original = reaper._unchanged_artifact
    def unavailable(path, info):
        if path == family.target:
            raise PermissionError('fixture inspection failure')
        return original(path, info)
    monkeypatch.setattr(reaper, '_unchanged_artifact', unavailable)
    assert family.sweep() == [family.other]
    assert family.target.exists()


def test_post_removal_replacement_is_not_reported_as_gone(family, monkeypatch):
    original = reaper._confirmed_absent
    def replaced(path):
        if path == family.target:
            path.symlink_to('missing-replacement')
        return original(path)
    monkeypatch.setattr(reaper, '_confirmed_absent', replaced)
    assert family.sweep() == [family.other]
    assert family.target.is_symlink()


@pytest.mark.parametrize('family', ['temp-dir', 'pid-dir', 'run-dir'], indirect=True)
@pytest.mark.parametrize('failure', ['false', 'oserror'])
def test_directory_removal_failure_does_not_abort_sweep(family, monkeypatch, failure):
    original = reaper.rmtree_hardened
    def refuse(path):
        if path == family.target:
            if failure == 'oserror':
                raise PermissionError('fixture removal failure')
            return False
        return original(path)
    monkeypatch.setattr(reaper, 'rmtree_hardened', refuse)
    assert family.sweep() == [family.other]
    assert family.target.exists()


@pytest.mark.parametrize('status', ['running', 'completed', 'failed', 'malformed', 'missing'])
def test_run_metadata_is_rechecked_after_liveness_probe(tmp_path, monkeypatch, status):
    root = tmp_path / 'runs'
    root.mkdir()
    run = root / 'scan-old'
    run.mkdir()
    marker = run / '.raptor-run.json'
    old = time.time() - 60 * 86400
    marker.write_text('{"status":"failed"}')
    os.utime(run, (old, old))
    monkeypatch.setenv('RAPTOR_RUN_REAP_MAX_AGE_D', '30')
    monkeypatch.setattr(reaper, '_live_cwds', lambda: set())
    def resumed(path, cwds):
        assert path == run
        if status == 'missing':
            marker.unlink()
        elif status == 'malformed':
            marker.write_text('{')
        else:
            marker.write_text(json.dumps({'status': status, 'extra': 'new activity'}))
        os.utime(run, (old, old))
        return False
    monkeypatch.setattr(reaper, '_dir_in_use', resumed)
    assert reaper.reap_stale_runs(root) == []
    assert run.is_dir()


def test_new_descendant_activity_after_liveness_probe_keeps_temp_dir(tmp_path, monkeypatch):
    tree = tmp_path / 'raptor-toolprobe-old'
    tree.mkdir()
    payload = tree / 'data'
    payload.write_text('old')
    old = time.time() - 60 * 86400
    os.utime(payload, (old, old))
    os.utime(tree, (old, old))
    monkeypatch.setenv('RAPTOR_TMP_REAP_MAX_AGE_H', '24')
    monkeypatch.setattr(reaper, '_sweep_roots', lambda: [(tmp_path, False)])
    monkeypatch.setattr(reaper, '_live_cwds', lambda: set())
    def active(path, cwds):
        payload.write_text('active')
        return False
    monkeypatch.setattr(reaper, '_dir_in_use', active)
    assert reaper.reap_stale_tmp() == []
    assert payload.read_text() == 'active'


@pytest.mark.parametrize('digits', ['²', '１２', '١٢'],
                         ids=['superscript', 'fullwidth', 'arabic'])
def test_non_ascii_pid_sidecar_does_not_abort_other_cleanup(tmp_path, monkeypatch, digits):
    poison = tmp_path / f'raptor-pytest-scorecard-{digits}.json'
    poison.write_text('keep')
    stale = tmp_path / 'audit_sweep_stale.yaml'
    stale.write_text('disposable')
    old = time.time() - 60 * 86400
    os.utime(stale, (old, old))
    monkeypatch.setenv('RAPTOR_TMP_REAP_MAX_AGE_H', '24')
    monkeypatch.setattr(reaper, '_sweep_roots', lambda: [(tmp_path, False)])
    monkeypatch.setattr(reaper, '_pid_alive', lambda pid: pytest.fail('non-ASCII PID probed'))
    assert reaper.reap_stale_tmp() == [stale]
    assert poison.read_text() == 'keep'


@pytest.mark.parametrize('family', ['temp-file', 'pid-file', 'log-file'], indirect=True)
def test_unlink_failure_does_not_abort_other_removals(family, monkeypatch):
    original = reaper._unlink_candidate_file
    class RefusingPath(type(family.target)):
        def unlink(self, *args, **kwargs):
            if self == family.target:
                raise PermissionError('fixture unlink failure')
            return super().unlink(*args, **kwargs)
    monkeypatch.setattr(reaper, '_unlink_candidate_file',
                        lambda path, info: original(RefusingPath(path), info))
    assert family.sweep() == [family.other]
    assert family.target.exists()


@pytest.mark.parametrize('failure', [KeyboardInterrupt, SystemExit])
def test_new_cancellation_propagates(family, monkeypatch, failure):
    def interrupted(path, info):
        raise failure('stop cleanup')
    monkeypatch.setattr(reaper, '_unchanged_artifact', interrupted)
    with pytest.raises(failure, match='stop cleanup'):
        family.sweep()


@pytest.mark.parametrize('family', ['temp-dir', 'pid-dir', 'run-dir'], indirect=True)
def test_false_removal_result_is_never_counted(family, monkeypatch):
    original = reaper.rmtree_hardened
    def uncertain(path):
        result = original(path)
        return False if path == family.target else result
    monkeypatch.setattr(reaper, 'rmtree_hardened', uncertain)
    assert family.sweep() == [family.other]
    assert not family.target.exists()
