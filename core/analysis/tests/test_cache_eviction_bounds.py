"""Count quotas apply to cache files and continue after per-file failures."""

import errno
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from core.analysis import _reach_cache
from core.llm import client as response_cache


@pytest.fixture(params=["response", "reachability"])
def cache(request, tmp_path, monkeypatch):
    root = tmp_path / "cache"
    root.mkdir()
    cap = 2
    if request.param == "response":
        owner = SimpleNamespace(
            config=SimpleNamespace(cache_dir=root, cache_max_entries=cap)
        )
        evict = lambda: response_cache.LLMClient._maybe_evict_cache(owner)
    else:
        monkeypatch.setattr(_reach_cache, "_cache_dir", lambda: root)
        monkeypatch.setattr(_reach_cache, "_MAX_CACHE_ENTRIES", cap)
        evict = _reach_cache._evict_oldest
    return root, evict


def entries(root, count=4):
    result = []
    for i in range(count):
        path = root / f"{i}.json"
        path.write_text("cached")
        os.utime(path, (1000 + i,) * 2)
        result.append(path)
    return result


@pytest.mark.parametrize("kind", ["directory", "fifo"])
def test_non_cache_entries_do_not_consume_quota(cache, kind):
    root, evict = cache
    values = entries(root, 3)
    blocker = root / "newest.json"
    if kind == "directory":
        blocker.mkdir()
        (blocker / "keep").write_text("unrelated")
    else:
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO not supported")
        os.mkfifo(blocker)
    os.utime(blocker, (9000,) * 2)
    evict()
    assert blocker.exists()
    assert [p.exists() for p in values] == [False, True, True]


def test_dangling_links_do_not_cause_negative_eviction_slice(cache):
    root, evict = cache
    values = entries(root, 2)
    for i in range(4):
        link = root / f"dangling-{i}.json"
        link.symlink_to(root / "absent")
        os.utime(link, (100 + i,) * 2, follow_symlinks=False)
    evict()
    assert all(path.exists() for path in values)
    assert len(list(root.glob("*.json"))) == 2


@pytest.mark.parametrize(
    "error", [PermissionError("busy"), OSError(errno.EBUSY, "busy")]
)
def test_failed_oldest_delete_does_not_stop_quota_enforcement(
    cache, monkeypatch, error
):
    root, evict = cache
    values = entries(root)
    unlink = Path.unlink

    def refuse(path, *args, **kwargs):
        if path == values[0]:
            raise error
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    evict()
    assert [path.exists() for path in values] == [True, False, False, True]
    evict()
    assert [path.exists() for path in values] == [True, False, False, True]


def test_concurrent_unlink_counts_as_already_gone(cache, monkeypatch):
    root, evict = cache
    values = entries(root)
    unlink = Path.unlink

    def race(path, *args, **kwargs):
        result = unlink(path, *args, **kwargs)
        if path == values[0]:
            raise FileNotFoundError(path)
        return result

    monkeypatch.setattr(Path, "unlink", race)
    evict()
    assert [path.exists() for path in values] == [False, False, True, True]


def test_equal_timestamps_use_deterministic_path_order(cache):
    root, evict = cache
    paths = []
    for name in ("d", "c", "b", "a"):
        path = root / f"{name}.json"
        path.write_text("cached")
        os.utime(path, (1000,) * 2)
        paths.append(path)
    evict()
    assert sorted(path.name for path in paths if path.exists()) == ["c.json", "d.json"]


def test_symlink_target_is_never_deleted_or_counted_by_target_mtime(cache, tmp_path):
    root, evict = cache
    values = entries(root, 2)
    outside = tmp_path / "outside"
    outside.write_text("operator data")
    os.utime(outside, (99999,) * 2)
    link = root / "link.json"
    link.symlink_to(outside)
    os.utime(link, (100,) * 2, follow_symlinks=False)
    evict()
    assert all(p.exists() for p in values)
    assert not link.is_symlink()
    assert outside.read_text() == "operator data"


def test_reachability_clear_ignores_directories_and_preserves_link_targets(
    tmp_path, monkeypatch
):
    root = tmp_path / "cache"
    root.mkdir()
    monkeypatch.setattr(_reach_cache, "_cache_dir", lambda: root)
    (root / "directory.json").mkdir()
    (root / "entry.pickle").write_bytes(b"legacy")
    target = tmp_path / "outside"
    target.write_text("operator data")
    (root / "link.json").symlink_to(target)
    assert _reach_cache.clear_cache() == 2
    assert (root / "directory.json").exists()
    assert target.read_text() == "operator data"


@pytest.mark.parametrize('change', ['refresh', 'replace', 'symlink', 'directory', 'unlink-error', 'post-replace'])
def test_each_cache_routes_eviction_through_generation_checks(cache, monkeypatch, change):
    from core.atomic_fs import cache_eviction
    root, evict = cache
    values = entries(root)
    target = values[0]
    before = target.stat()
    preserved = root.parent / 'preserved'
    class ChangingPath(type(target)):
        calls = 0
        def lstat(self):
            type(self).calls += 1
            if self.calls == 2:
                if change == 'refresh':
                    os.utime(target, (9000, 9000))
                elif change in ('replace', 'symlink', 'directory'):
                    target.rename(preserved)
                    if change == 'replace':
                        target.write_text('latest')
                        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
                    elif change == 'directory':
                        target.mkdir()
                    else:
                        target.symlink_to(preserved)
            return super().lstat()
        def unlink(self):
            if change == 'unlink-error':
                raise PermissionError('fixture refused')
            result = super().unlink()
            if change == 'post-replace':
                target.write_text('latest')
            return result
    original = cache_eviction.evict_oldest_files
    called = []
    def owned_paths(paths, cap):
        called.append(True)
        return original([ChangingPath(p) if p == target else p for p in paths], cap)
    monkeypatch.setattr(cache_eviction, 'evict_oldest_files', owned_paths)
    evict()
    assert called == [True]
    assert target.exists()
    assert sum(path.exists() for path in values[1:]) == (2 if change == 'directory' else 1)
    if change in ('replace', 'post-replace'):
        assert target.read_text() == 'latest'
