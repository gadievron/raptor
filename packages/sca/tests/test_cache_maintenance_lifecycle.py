"""Whole-cache maintenance refuses stale decisions and preserves scan failures."""
import contextlib
import os
import time
from types import SimpleNamespace

import pytest
from packages.sca import cache_budget as budget
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture(params=['file', 'inventory', 'stress'])
def layout(request, tmp_path):
    root = tmp_path / 'cache'
    root.mkdir()
    kind = request.param
    if kind == 'file':
        target = root / 'target.json'
        payload = target
    else:
        target = root / ('inventory/target' if kind == 'inventory' else 'stress/clones/target')
        payload = target / 'src/data.json'
        payload.parent.mkdir(parents=True)
    payload.write_bytes(b'cached')
    old = time.time() - 60 * 86400
    os.utime(payload, (old, old))
    if kind != 'file':
        os.utime(payload.parent, (old, old))
        os.utime(target, (old, old))
    other = root / 'other.json'
    other.write_bytes(b'cached')
    os.utime(other, (old, old))
    return SimpleNamespace(root=root, target=target, payload=payload, other=other, kind=kind)


def prune(layout, policy, dry_run):
    return budget.prune_cache(
        layout.root, max_age_days=30 if policy == 'age' else 36500,
        stress_max_age_days=7 if policy == 'age' else 36500,
        max_bytes=0 if policy == 'size' else None,
        stress_max_bytes=0 if policy == 'size' else None,
        dry_run=dry_run,
    )


@pytest.mark.parametrize('policy', ['age', 'size'])
@pytest.mark.parametrize('dry_run', [False, True], ids=['delete', 'preview'])
@pytest.mark.parametrize('change', ['refresh', 'rewrite', 'replace', 'symlink'])
def test_changed_units_are_retained_and_other_units_continue(layout, monkeypatch, policy, dry_run, change):
    original = budget._units
    saved = layout.root.parent / 'saved'
    before = layout.payload.stat()
    def changed(root, result):
        units = original(root, result)
        if change == 'refresh':
            os.utime(layout.payload, None)
        elif change == 'rewrite':
            layout.payload.write_bytes(b'latest')
            os.utime(layout.payload, ns=(before.st_atime_ns, before.st_mtime_ns))
        else:
            layout.target.rename(saved)
            if change == 'symlink':
                layout.target.symlink_to(saved, target_is_directory=layout.kind != 'file')
            elif layout.kind == 'file':
                layout.target.write_bytes(b'latest')
            else:
                layout.target.mkdir()
                (layout.target / 'keep').write_bytes(b'latest')
        return units
    monkeypatch.setattr(budget, '_units', changed)
    result = prune(layout, policy, dry_run)
    assert result.errors >= 1
    assert result.files_removed == 1 and result.bytes_freed == 6
    assert layout.other.exists() == dry_run
    assert layout.target.exists()
    if change == 'rewrite':
        assert layout.payload.read_bytes() == b'latest'
    elif change == 'symlink':
        assert layout.target.is_symlink() and saved.exists()


@pytest.mark.parametrize('layout', ['inventory', 'stress'], indirect=True)
@pytest.mark.parametrize('policy', ['age', 'size'])
@pytest.mark.parametrize('dry_run', [False, True], ids=['delete', 'preview'])
def test_incomplete_whole_directory_scan_never_authorizes_removal(layout, monkeypatch, policy, dry_run):
    original = budget._walk
    def incomplete(path, result):
        yield from original(path, result)
        if path == layout.target:
            result.errors += 1
    monkeypatch.setattr(budget, '_walk', incomplete)
    result = prune(layout, policy, dry_run)
    assert result.errors >= 1 and result.files_removed == 1
    assert layout.payload.read_bytes() == b'cached'
    assert layout.other.exists() == dry_run


@pytest.mark.parametrize('layout', ['inventory', 'stress'], indirect=True)
@pytest.mark.parametrize('change', ['rename', 'replace-same-bytes'])
def test_whole_directory_generation_digest_detects_preserved_aggregate_usage(layout, monkeypatch, change):
    original = budget._units
    before = layout.payload.stat()
    def changed(root, result):
        units = original(root, result)
        if change == 'rename':
            layout.payload.rename(layout.payload.with_name('renamed.json'))
        else:
            staged = layout.payload.with_name('staged')
            staged.write_bytes(b'cached')
            os.utime(staged, ns=(before.st_atime_ns, before.st_mtime_ns))
            staged.replace(layout.payload)
        return units
    monkeypatch.setattr(budget, '_units', changed)
    result = prune(layout, 'size', False)
    assert result.errors >= 1 and layout.target.exists()
    assert not layout.other.exists()


@pytest.mark.parametrize('layout', ['inventory', 'stress'], indirect=True)
def test_post_removal_dangling_replacement_is_not_reported_as_freed(layout, monkeypatch):
    original = budget.rmtree_hardened
    def replace(path):
        result = original(path)
        if path == layout.target:
            path.symlink_to('missing-replacement')
        return result
    monkeypatch.setattr(budget, 'rmtree_hardened', replace)
    result = prune(layout, 'size', False)
    assert layout.target.is_symlink()
    assert result.errors >= 1 and result.files_removed == 1
    assert result.bytes_remaining == 6


@pytest.fixture
def tuned(monkeypatch):
    import core.tuning
    monkeypatch.setattr(core.tuning, 'load_tuning', lambda: SimpleNamespace(
        sca_cache_max_mb=1, sca_stress_cache_max_mb=1))


@pytest.mark.parametrize('kind', ['fresh', 'old', 'future', 'symlink', 'dangling', 'fifo', 'directory', 'hardlink'])
def test_maintenance_marker_is_only_a_throttle_when_regular_private_and_recent(tmp_path, tuned, kind):
    data = tmp_path / 'old.json'
    data.write_bytes(b'cached')
    old = time.time() - 60 * 86400
    os.utime(data, (old, old))
    marker = tmp_path / budget._STAMP
    target = tmp_path / '.borrowed'
    target.write_bytes(b'borrowed')
    target_time = target.stat().st_mtime_ns
    if kind == 'symlink':
        marker.symlink_to(target)
    elif kind == 'dangling':
        marker.symlink_to('missing')
    elif kind == 'fifo':
        os.mkfifo(marker)
    elif kind == 'directory':
        marker.mkdir()
    elif kind == 'hardlink':
        os.link(target, marker)
    else:
        marker.write_text('throttle')
        if kind == 'old':
            os.utime(marker, (old, old))
        elif kind == 'future':
            future = time.time() + 365 * 86400
            os.utime(marker, (future, future))
    identity = marker.lstat().st_ino
    budget.maintain_cache(tmp_path)
    assert data.exists() == (kind == 'fresh')
    assert target.read_bytes() == b'borrowed'
    assert target.stat().st_mtime_ns == target_time
    if kind not in ('fresh', 'old', 'future'):
        assert marker.lstat().st_ino == identity


@pytest.mark.parametrize('existing_marker', [False, True])
def test_failed_maintenance_is_retried_instead_of_throttled(tmp_path, monkeypatch, tuned, existing_marker):
    marker = tmp_path / budget._STAMP
    if existing_marker:
        marker.write_text('old receipt')
        os.utime(marker, (1, 1))
    calls = []
    def failed(*args):
        calls.append(True)
        return budget.EvictionResult(errors=1)
    monkeypatch.setattr(budget, '_prune_locked', failed)
    budget.maintain_cache(tmp_path)
    budget.maintain_cache(tmp_path)
    assert len(calls) == 2
    if existing_marker:
        assert marker.read_text() == 'old receipt' and marker.stat().st_mtime == 1
    else:
        assert not marker.exists()


@pytest.mark.parametrize('clock', [float('nan'), float('inf'), -float('inf')], ids=['nan', 'infinite', 'negative-infinite'])
def test_nonfinite_maintenance_clock_cannot_delete_or_stamp(tmp_path, monkeypatch, tuned, clock):
    data = tmp_path / 'old.json'
    data.write_bytes(b'cached')
    os.utime(data, (1, 1))
    patch_module_attribute(monkeypatch, budget, 'time', 'time', lambda: clock)
    budget.maintain_cache(tmp_path)
    assert data.exists() and not (tmp_path / budget._STAMP).exists()


@pytest.mark.parametrize('scan_error', [RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize('maintenance_error', [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_scan_failure_keeps_precedence_over_maintenance(tmp_path, monkeypatch, scan_error, maintenance_error):
    @contextlib.contextmanager
    def lease(*args, **kwargs):
        yield True
    def failed(*args):
        raise maintenance_error('maintenance failed')
    monkeypatch.setattr(budget, '_lock', lease)
    monkeypatch.setattr(budget, 'maintain_cache', failed)
    with pytest.raises(scan_error, match='scan failed'):
        with budget.cache_session(tmp_path):
            raise scan_error('scan failed')


@pytest.mark.parametrize('maintenance_error', [OSError, ValueError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_new_maintenance_failure_after_success_still_propagates(tmp_path, monkeypatch, maintenance_error):
    @contextlib.contextmanager
    def lease(*args, **kwargs):
        yield True
    def failed(*args):
        raise maintenance_error('maintenance failed')
    monkeypatch.setattr(budget, '_lock', lease)
    monkeypatch.setattr(budget, 'maintain_cache', failed)
    with pytest.raises(maintenance_error, match='maintenance failed'):
        with budget.cache_session(tmp_path):
            pass
