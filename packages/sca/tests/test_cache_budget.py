"""Disk budgets must reclaim space without changing scan inputs or state."""
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from packages.sca import cache_budget as budget
from packages.sca.clean_cache import main


from core.testing.module_bindings import patch_module_attribute


def entry(root, name, size=100, age=1):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'x' * size)
    stamp = time.time() - age * 86400
    os.utime(path, (stamp, stamp))
    return path


def test_size_pruning_keeps_recently_used_entry(tmp_path):
    old = entry(tmp_path, 'q/old.json', age=3)
    hot = entry(tmp_path, 'q/hot.json', age=5)
    fresh = entry(tmp_path, 'q/new.json')
    os.utime(hot, (time.time(), hot.stat().st_mtime))
    result = budget.prune_cache(tmp_path, max_bytes=250)
    assert not old.exists()
    assert hot.exists() and fresh.exists()
    assert result.bytes_remaining == 200
    assert result.bytes_freed == 100


@pytest.mark.parametrize("no_noatime", [False, True], ids=["host-flags", "without-noatime"])
def test_expired_entry_precedes_older_valid_entry(tmp_path, monkeypatch, no_noatime):
    if no_noatime:
        monkeypatch.delattr(patch_module_attribute(monkeypatch, budget, 'os', "__name__", budget.os.__name__), "O_NOATIME", raising=False)
    from core.json.cache import JsonCache, TTL_FOREVER
    cache = JsonCache(tmp_path)
    cache.put('q/valid', 'x' * 100, ttl_seconds=TTL_FOREVER)
    cache.put('q/expired', 'x' * 100, ttl_seconds=0)
    old = time.time() - 86400
    os.utime(tmp_path / 'q/valid.json', (old, old))
    size = (tmp_path / 'q/valid.json').stat().st_size
    budget.prune_cache(tmp_path, max_bytes=int(size / .8) + 1,
                       now=time.time() + 1)
    assert (tmp_path / 'q/valid.json').exists()
    assert not (tmp_path / 'q/expired.json').exists()


def test_dry_run_matches_real_selection_without_deleting(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    before = path.read_bytes()
    dry = budget.prune_cache(tmp_path, dry_run=True)
    assert path.read_bytes() == before
    real = budget.prune_cache(tmp_path)
    assert dry.files_removed == real.files_removed == 1
    assert dry.bytes_remaining == real.bytes_remaining == 0
    assert dry.bytes_freed == real.bytes_freed


def test_stress_projects_removed_whole_and_separate_budget(tmp_path):
    first = entry(tmp_path, 'stress/clones/old/src/Cargo.lock', age=4)
    entry(tmp_path, 'stress/clones/old/out/findings.json', age=4)
    second = entry(tmp_path, 'stress/clones/new/src/Cargo.lock')
    # Project directory freshness participates in age retention, but budget
    # ordering reflects the newest file/creation time for each project.
    old = first.parents[1]
    os.utime(old, (time.time() - 4 * 86400,) * 2)
    query = entry(tmp_path, 'q/retained.json')
    result = budget.prune_cache(tmp_path, max_bytes=1000, stress_max_bytes=150)
    assert not old.exists()
    assert second.exists() and query.exists()
    assert result.files_removed == 2
    assert result.bytes_remaining == 200


def test_stress_age_does_not_remove_individual_old_files(tmp_path):
    path = entry(tmp_path, 'stress/clones/active/src/old-file', age=365)
    assert budget.prune_cache(tmp_path, max_age_days=1).files_removed == 0
    assert path.exists()  # checkout was created recently


def test_fingerprints_databases_and_symlink_targets_survive(tmp_path):
    root = tmp_path / 'sca'
    state = entry(root, 'fingerprints/base.json', age=365)
    db = entry(root, 'osv.sqlite', age=365)
    wal = entry(root, 'osv.sqlite-wal', age=365)
    outside = entry(tmp_path, 'outside/target.json', age=365)
    (root / 'link').symlink_to(outside.parent, target_is_directory=True)
    (root / 'linked.json').symlink_to(outside)
    clone = root / 'stress/clones/project'
    clone.mkdir(parents=True)
    (clone / 'link').symlink_to(outside.parent, target_is_directory=True)
    budget.prune_cache(root, max_bytes=0, stress_max_bytes=0)
    assert all(p.exists() for p in (state, db, wal, outside))
    assert not clone.exists()


def test_busy_scan_pins_files_and_maintenance_skips(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    with budget.cache_session(tmp_path, maintain=False):
        result = budget.prune_cache(tmp_path, max_bytes=0)
        assert result.busy and path.exists()
        # Nested sessions and independent shared leases must not deadlock.
        with budget.cache_session(tmp_path, maintain=False):
            assert budget.prune_cache(tmp_path).busy
    assert budget.prune_cache(tmp_path).files_removed == 1


def test_lock_fds_do_not_leak_under_contention(tmp_path):
    if not Path('/proc/self/fd').exists():
        pytest.skip('Linux fd census')
    with budget.cache_session(tmp_path, maintain=False):
        before = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(20):
            assert budget.prune_cache(tmp_path).busy
        assert len(list(Path('/proc/self/fd').iterdir())) == before


def test_symlink_lock_refuses_cleanup(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    target = entry(tmp_path, 'target')
    (tmp_path / budget._LOCK).symlink_to(target)
    assert budget.prune_cache(tmp_path).busy
    assert path.exists()


def test_delete_failure_reports_unmet_budget(tmp_path, monkeypatch):
    path = entry(tmp_path, 'q/old.json')
    original = Path.unlink
    def refuse(self, *args, **kwargs):
        if self == path:
            raise PermissionError('busy')
        return original(self, *args, **kwargs)
    monkeypatch.setattr(Path, 'unlink', refuse)
    result = budget.prune_cache(tmp_path, max_bytes=0)
    assert result.errors == 1 and result.budget_exceeded
    assert result.bytes_remaining == 100


def test_automatic_maintenance_and_disable(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    tuning = SimpleNamespace(sca_cache_max_mb=0, sca_stress_cache_max_mb=0)
    with patch('core.tuning.load_tuning', return_value=tuning):
        budget.maintain_cache(tmp_path)
        assert path.exists()
        tuning.sca_cache_max_mb = 1
        budget.maintain_cache(tmp_path)
        assert not path.exists()
        # Throttle repeated walks; this newly added stale file survives.
        another = entry(tmp_path, 'q/another.json', age=60)
        budget.maintain_cache(tmp_path)
        assert another.exists()


def test_offline_session_does_not_maintain(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    with budget.cache_session(tmp_path, maintain=False):
        pass
    assert path.exists()


def test_cli_dry_run_and_invalid_sizes(tmp_path, capsys):
    path = entry(tmp_path, 'q/old.json', age=60)
    assert main(['--cache-root', str(tmp_path), '--dry-run']) == 0
    assert 'would clean 1/1' in capsys.readouterr().out
    assert path.exists()
    assert main(['--cache-root', str(tmp_path), '--max-size-mb', '-1']) == 2
    with budget.cache_session(tmp_path, maintain=False):
        assert main(['--cache-root', str(tmp_path)]) == 1


def test_new_tuning_keys_are_validated(tmp_path):
    from core.tuning import load_tuning
    config = tmp_path / 'tuning.json'
    config.write_text(json.dumps({'sca_cache_max_mb': 100,
                                 'sca_stress_cache_max_mb': 0}))
    tuning = load_tuning(config)
    assert tuning.sca_cache_max_mb == 100
    assert tuning.sca_stress_cache_max_mb == 0
    config.write_text(json.dumps({'sca_cache_max_mb': -1}))
    assert load_tuning(config).sca_cache_max_mb == 2048


def test_inventory_shards_are_evicted_as_one_unit(tmp_path):
    manifest = entry(tmp_path, 'inventory/target/checklist.json', age=60)
    shard = entry(tmp_path, 'inventory/target/files/one.json', age=60)
    os.utime(manifest.parents[0], (time.time() - 60 * 86400,) * 2)
    result = budget.prune_cache(tmp_path)
    assert not manifest.parent.exists()
    assert not shard.exists()
    assert result.files_removed == 2


def test_cross_process_scan_lease(tmp_path):
    from core.testing.processes import reap_on_exit
    import subprocess
    import sys
    path = entry(tmp_path, 'q/old.json', age=60)
    script = '''
import sys
from pathlib import Path
from packages.sca.cache_budget import cache_session
with cache_session(Path(sys.argv[1]), maintain=False):
    print('ready', flush=True)
    sys.stdin.readline()
'''
    child = subprocess.Popen([sys.executable, '-c', script, str(tmp_path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True)
    with reap_on_exit(child):
        import select
        assert select.select([child.stdout], [], [], 10)[0]
        assert child.stdout.readline().strip() == 'ready'
        assert budget.prune_cache(tmp_path).busy
        assert path.exists()
        child.communicate('\n', timeout=10)
        assert child.returncode == 0
        assert budget.prune_cache(tmp_path).files_removed == 1

def test_scan_entry_point_pins_custom_root_and_preserves_offline_data(tmp_path):
    from packages.sca.pipeline import RunOptions, run_sca
    root = tmp_path / 'cache'
    path = entry(root, 'q/old.json', age=60)
    sentinel = object()
    def scan(*args, **kwargs):
        assert budget.prune_cache(root).busy
        return sentinel
    with patch('packages.sca.pipeline._run_sca', side_effect=scan):
        assert run_sca(tmp_path, tmp_path / 'out',
                       RunOptions(cache_root=root, offline=True)) is sentinel
    assert path.exists()


def test_stress_worker_pins_checkout_until_worker_actually_finishes(tmp_path, monkeypatch):
    import threading
    from packages.sca.calibration import stress
    import packages.sca
    monkeypatch.setattr(packages.sca, 'SCA_CACHE_ROOT', tmp_path)
    ready, release = threading.Event(), threading.Event()
    def scan(*args, **kwargs):
        ready.set()
        assert release.wait(10)
    sample = SimpleNamespace(ecosystem='Cargo', name='sample')
    with patch.object(stress, '_scan_one_inner', side_effect=scan):
        worker = threading.Thread(target=stress._scan_one,
                                  args=(sample, tmp_path / 'stress/clones'),
                                  kwargs={'git_clone_timeout': 1})
        worker.start()
        try:
            assert ready.wait(10)
            assert budget.prune_cache(tmp_path).busy
        finally:
            release.set()
            worker.join(timeout=10)
        assert not worker.is_alive()


def test_failed_scan_releases_lease_and_still_maintains(tmp_path):
    path = entry(tmp_path, 'q/old.json', age=60)
    with pytest.raises(RuntimeError, match='scan failed'):
        with budget.cache_session(tmp_path):
            raise RuntimeError('scan failed')
    assert not path.exists()
    assert not budget.prune_cache(tmp_path).busy


def test_custom_root_scan_also_pins_global_inventory(tmp_path):
    from packages.sca import sca_cache_root
    from packages.sca.pipeline import RunOptions, run_sca
    def scan(*args, **kwargs):
        assert budget.prune_cache(sca_cache_root()).busy
    with patch('packages.sca.pipeline._run_sca', side_effect=scan):
        run_sca(tmp_path, tmp_path / 'out',
                RunOptions(cache_root=tmp_path / 'custom', offline=True))
