"""Cache cleanup and memo validation against real filesystem generations."""

import json
import os
import time

import pytest

import core.json.cache as cache_module

JsonCache = cache_module.JsonCache


def aged(path, content=b"orphan"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    old = time.time() - 7200
    os.utime(path, (old, old))
    return path


@pytest.mark.parametrize("replacement", [False, True], ids=["rewrite", "atomic-replace"])
@pytest.mark.parametrize("value", ["new", "longer replacement"], ids=["same-size", "different-size"])
def test_memo_revalidates_preserved_mtime(tmp_path, replacement, value):
    cache = JsonCache(tmp_path)
    cache.put("key", "old", ttl_seconds=3600)
    assert cache.get("key", ttl_seconds=3600) == "old"
    path = tmp_path / "key.json"
    before = path.stat()
    document = json.loads(path.read_text())
    document["value"] = value
    if replacement:
        staged = tmp_path / "replacement"
        staged.write_text(json.dumps(document))
        os.utime(staged, ns=(before.st_atime_ns, before.st_mtime_ns))
        staged.replace(path)
    else:
        path.write_text(json.dumps(document))
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert cache.get("key", ttl_seconds=3600) == value
    assert cache.get("key", ttl_seconds=3600) == value


@pytest.mark.parametrize("name", [
    "key.tmp.123", "key.tmp.123.456",
    ".atomic-key.json.123.456.deadbeef.tmp",
    ".atomic-key.with.dots.json.123.456.0123abcd.tmp",
    ".atomic-key.json.123.456.0123456789abcdef.tmp",
])
def test_recognized_orphans_reclaimed(tmp_path, name):
    path = aged(tmp_path / name)
    JsonCache(tmp_path)
    assert not path.exists()


@pytest.mark.parametrize("name", [
    ".atomic-notes.tmp", ".atomic-key.json.pid.456.deadbeef.tmp",
    ".atomic-key.json.123.tid.deadbeef.tmp", ".atomic-key.json.123.456.short.tmp",
    ".atomic-key.json.123.456.not_hex!.tmp", "key.tmp.123.456.extra",
    "key.tmp.notes", ".tmp.123", "key.tmp.１２３",
], ids=["notes", "pid", "tid", "short-random", "nonhex", "extra", "text", "empty-name", "unicode-pid"])
def test_similar_caller_files_survive(tmp_path, name):
    path = aged(tmp_path / name, b"borrowed")
    before = path.lstat()
    JsonCache(tmp_path)
    assert path.read_bytes() == b"borrowed"
    assert path.lstat().st_ino == before.st_ino


@pytest.mark.parametrize("kind", ["symlink", "dangling", "fifo", "directory"])
def test_orphan_shape_does_not_claim_nonregular_nodes(tmp_path, kind):
    root = tmp_path / "cache"
    root.mkdir()
    path = root / "key.tmp.123.456"
    target = aged(tmp_path / "borrowed", b"retain")
    target_mtime = target.stat().st_mtime_ns
    if kind == "symlink":
        path.symlink_to(target)
    elif kind == "dangling":
        path.symlink_to(tmp_path / "missing")
    elif kind == "fifo":
        os.mkfifo(path)
    else:
        path.mkdir()
    old = time.time() - 7200
    os.utime(path, (old, old), follow_symlinks=False)
    identity = path.lstat().st_ino
    JsonCache(root)
    assert path.lstat().st_ino == identity
    assert target.read_bytes() == b"retain"
    assert target.stat().st_mtime_ns == target_mtime


@pytest.mark.parametrize("kind", ["symlink-old", "symlink-fresh", "dangling", "fifo", "directory", "hardlink"])
def test_unexpected_rate_marker_does_not_block_cleanup_or_modify_target(tmp_path, kind):
    root = tmp_path / "cache"
    root.mkdir()
    orphan = aged(root / "key.tmp.123")
    marker = root / cache_module._REAP_SENTINEL_NAME
    target = aged(tmp_path / "borrowed", b"retain")
    if kind == "symlink-fresh":
        os.utime(target, None)
    target_time = target.stat().st_mtime_ns
    if kind.startswith("symlink"):
        marker.symlink_to(target)
    elif kind == "dangling":
        marker.symlink_to(tmp_path / "missing")
    elif kind == "fifo":
        os.mkfifo(marker)
    elif kind == "directory":
        marker.mkdir()
    else:
        os.link(target, marker)
    identity = marker.lstat().st_ino
    JsonCache(root)
    assert not orphan.exists()
    assert marker.lstat().st_ino == identity
    assert target.read_bytes() == b"retain"
    assert target.stat().st_mtime_ns == target_time


def test_future_rate_marker_does_not_pin_orphans(tmp_path):
    orphan = aged(tmp_path / "key.tmp.123")
    marker = tmp_path / cache_module._REAP_SENTINEL_NAME
    marker.write_bytes(b"")
    future = time.time() + 7 * 86400
    os.utime(marker, (future, future))
    JsonCache(tmp_path)
    assert not orphan.exists()
    assert marker.stat().st_mtime < future


def test_rate_marker_race_cannot_touch_symlink_target(tmp_path, monkeypatch):
    root = tmp_path / "cache"
    root.mkdir()
    marker = root / cache_module._REAP_SENTINEL_NAME
    target = aged(tmp_path / "borrowed", b"retain")
    before = target.stat().st_mtime_ns
    original = cache_module.write_text_atomically
    def write(path, *a, **kw):
        if path == marker:
            marker.symlink_to(target)
        return original(path, *a, **kw)
    monkeypatch.setattr(cache_module, "write_text_atomically", write)
    JsonCache(root)
    assert marker.is_file() and not marker.is_symlink()
    assert target.read_bytes() == b"retain"
    assert target.stat().st_mtime_ns == before


def test_orphans_are_reclaimed_as_iterator_advances(tmp_path, monkeypatch):
    first = aged(tmp_path / "first.tmp.123")
    second = aged(tmp_path / "second.tmp.456")
    def candidates(*a, **kw):
        yield first
        assert not first.exists(), "cleanup buffered the entire candidate list"
        yield second
    monkeypatch.setattr(cache_module, "_iter_tempfile_candidates", candidates)
    JsonCache(tmp_path)
    assert not first.exists() and not second.exists()


def test_interrupted_walk_keeps_completed_cleanup_and_allows_retry(tmp_path):
    first = aged(tmp_path / "first.tmp.123")
    second = aged(tmp_path / "second.tmp.456")
    def candidates(*a, **kw):
        yield first
        raise OSError("directory disappeared")
    with pytest.MonkeyPatch.context() as scope:
        scope.setattr(cache_module, "_iter_tempfile_candidates", candidates)
        JsonCache(tmp_path)
    assert not first.exists() and second.exists()
    assert not (tmp_path / cache_module._REAP_SENTINEL_NAME).exists()
    JsonCache(tmp_path)
    assert not second.exists()


@pytest.mark.parametrize("change", ["replace", "refresh"])
def test_candidate_changed_since_inspection_survives(tmp_path, monkeypatch, change):
    path = aged(tmp_path / "key.tmp.123")
    retained = tmp_path / "old-generation"
    calls = []
    class Candidate(type(path)):
        def lstat(self):
            calls.append(None)
            if len(calls) == 2:
                if change == "replace":
                    path.rename(retained)
                    path.write_bytes(b"replacement")
                else:
                    os.utime(path, None)
            return super().lstat()
    monkeypatch.setattr(cache_module, "_iter_tempfile_candidates", lambda *a, **kw: [Candidate(path)])
    JsonCache(tmp_path)
    assert path.exists()
    assert path.read_bytes() == (b"replacement" if change == "replace" else b"orphan")


def test_marker_write_failure_does_not_disable_cache(tmp_path, monkeypatch):
    original = cache_module.write_text_atomically
    def write(path, *a, **kw):
        if path.name == cache_module._REAP_SENTINEL_NAME:
            raise OSError("disk full")
        return original(path, *a, **kw)
    monkeypatch.setattr(cache_module, "write_text_atomically", write)
    cache = JsonCache(tmp_path)
    cache.put("key", "value", ttl_seconds=3600)
    assert cache.get("key", ttl_seconds=3600) == "value"


def test_one_unremovable_orphan_does_not_block_others(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root bypasses directory permissions")
    held = aged(tmp_path / "restricted" / "held.tmp.123")
    removable = aged(tmp_path / "free.tmp.456")
    held.parent.chmod(0o500)
    try:
        JsonCache(tmp_path)
        assert held.exists() and not removable.exists()
    finally:
        held.parent.chmod(0o700)
