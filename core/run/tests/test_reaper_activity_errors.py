"""Unobservable activity retains scratch; old readable siblings still reap."""
from contextlib import contextmanager
import errno
import os
import time

import pytest

from core.run import tmp_ownership, tmp_reaper
from core.testing.module_bindings import patch_module_attribute


def aged_tree(root, now):
    hidden = root / 'nested'
    hidden.mkdir(parents=True)
    leaf = hidden / 'output'
    leaf.write_bytes(b'owned output')
    old = now - 7200
    for path in (leaf, hidden, root):
        os.utime(path, (old, old))
    return hidden, leaf


def activity_fault(monkeypatch, phase, failure, root, leaf, reached):
    original = os.scandir
    class Entry:
        def __init__(self, entry):
            self.entry = entry
        def __getattr__(self, name):
            return getattr(self.entry, name)
        def stat(self, *, follow_symlinks=True):
            assert not follow_symlinks
            if self.entry.path == str(leaf):
                reached.append(phase)
                raise failure
            return self.entry.stat(follow_symlinks=follow_symlinks)
    @contextmanager
    def scan(path):
        if phase == 'walk':
            assert path == root
            reached.append(phase)
            raise failure
        with original(path) as entries:
            yield (Entry(entry) for entry in entries)
    patch_module_attribute(monkeypatch, tmp_reaper, 'os', 'scandir', scan)


@pytest.mark.parametrize('phase', ['walk', 'metadata'])
@pytest.mark.parametrize('error', [errno.EACCES, errno.EIO, errno.ENOENT])
def test_activity_errors_retain_an_unjudgeable_tree(tmp_path, monkeypatch, phase, error):
    now = time.time()
    root = tmp_path / 'candidate'
    _, leaf = aged_tree(root, now)
    reached = []
    failure = OSError(error, 'owned activity probe failure')
    activity_fault(monkeypatch, phase, failure, root, leaf, reached)
    assert tmp_reaper._recent_activity(root, now, 3600)
    assert reached == [phase]
    assert leaf.read_bytes() == b'owned output'


@pytest.mark.parametrize('phase', ['walk', 'metadata'])
@pytest.mark.parametrize('failure_type', [KeyboardInterrupt, SystemExit])
def test_activity_probe_does_not_swallow_cancellation(tmp_path, monkeypatch, phase, failure_type):
    now = time.time()
    root = tmp_path / 'candidate'
    _, leaf = aged_tree(root, now)
    failure = failure_type('cancelled activity probe')
    reached = []
    activity_fault(monkeypatch, phase, failure, root, leaf, reached)
    with pytest.raises(failure_type) as caught:
        tmp_reaper._recent_activity(root, now, 3600)
    assert caught.value is failure
    assert reached == [phase]


def test_readable_activity_and_processed_entry_budget_remain_meaningful(tmp_path, monkeypatch):
    now = time.time()
    root = tmp_path / 'candidate'
    _, leaf = aged_tree(root, now)
    assert not tmp_reaper._recent_activity(root, now, 3600)
    os.utime(leaf, (now, now))
    assert tmp_reaper._recent_activity(root, now, 3600)
    os.utime(leaf, (now - 7200, now - 7200))
    monkeypatch.setattr(tmp_reaper, '_DEEP_SCAN_MAX_ENTRIES', 1)
    assert tmp_reaper._recent_activity(root, now, 3600)


@pytest.mark.parametrize('sweep', ['age', 'legacy-owner'])
def test_unreadable_subtree_is_retained_while_old_readable_sibling_reaps(tmp_path, monkeypatch, sweep):
    now = time.time()
    blocked, stale = tmp_path / 'raptor-llm-blocked', tmp_path / 'raptor-llm-stale'
    hidden, fresh = aged_tree(blocked, now)
    aged_tree(stale, now)
    os.utime(fresh, (now, now))
    removals = []
    original = tmp_reaper.rmtree_hardened
    def remove(path):
        removals.append(path)
        return original(path)
    monkeypatch.setenv('RAPTOR_TMP_REAP_MAX_AGE_H', '1')
    patch_module_attribute(monkeypatch, tmp_reaper, 'tempfile', 'gettempdir', lambda: str(tmp_path))
    patch_module_attribute(monkeypatch, tmp_ownership, 'tempfile', 'gettempdir', lambda: str(tmp_path))
    monkeypatch.setattr(tmp_reaper, '_SYSTEM_TMP_ROOTS', ())
    monkeypatch.setattr(tmp_reaper, '_lane_fallback_bases', lambda: ())
    monkeypatch.setattr(tmp_reaper, '_in_child_pid_ns', lambda: False)
    monkeypatch.setattr(tmp_reaper, '_live_cwds', lambda: set())
    monkeypatch.setattr(tmp_ownership, '_live_cwds', lambda: set())
    monkeypatch.setattr(tmp_reaper, 'rmtree_hardened', remove)
    monkeypatch.setattr(tmp_ownership, 'rmtree_hardened', remove)
    try:
        hidden.chmod(0)
        try:
            list(hidden.iterdir())
        except PermissionError:
            pass
        else:
            pytest.skip('filesystem/identity bypasses directory permissions')
        if sweep == 'age':
            removed = tmp_reaper.reap_stale_tmp(now=now)
        else:
            removed = tmp_ownership.sweep_dead_owner_dirs('raptor-llm-', legacy_max_age_s=3600)
        assert removed == [stale]
        assert removals == [stale]
        assert blocked.is_dir() and not stale.exists()
    finally:
        if hidden.exists():
            hidden.chmod(0o700)
    assert fresh.read_bytes() == b'owned output'
