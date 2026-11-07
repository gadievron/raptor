"""Checklist replacement preserves the last committed form and bounds residue."""

import os
import shutil
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.inventory as inv
from core.testing.restricted_tree import restricted_tree


import core.inventory as _os_fault_consumer
from core.testing.module_bindings import patch_module_attribute

import core.atomic_fs as _storage_fault_consumer


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "_MAX_CHECKLIST_BYTES", 1024)
    monkeypatch.setattr(inv, "_CHECKLIST_SHARD_TARGET_BYTES", 1024)
    from core.atomic_fs import rmtree_hardened as cleanup

    yield tmp_path
    # Retain recovery evidence until assertions finish, then reclaim this
    # test's owned residue even when a regression causes an assertion failure.
    for path in tmp_path.glob(".checklist-*"):
        if path.is_symlink() or not path.is_dir():
            path.unlink(missing_ok=True)
        else:
            cleanup(path)


def document(revision, big=True):
    return {
        "revision": revision,
        "files": [
            {
                "path": f"src/file{i}.c",
                "sloc": 10,
                "items": [
                    {
                        "name": "f" * 64,
                        "kind": "function",
                        "line_start": 1,
                        "line_end": 2,
                    }
                ],
            }
            for i in range(20)
        ]
        if big
        else [],
    }


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_publication_restores_old_sharded_checklist(
    cache, monkeypatch, big, error
):
    inv.save_checklist(cache, document("old"))
    before = inv.read_checklist(cache)
    final = cache / ("checklist" if big else "checklist.json")
    rename, replace = inv.rename_without_replace, os.replace

    def fault(operation):
        def move(src, dst, *args, **kwargs):
            source = Path(src)
            staged = source.name.startswith(
                (".checklist-tmp-", ".~savejson-")
            ) or source.parent.name.startswith(".checklist-tmp-")
            if Path(dst) == final and staged:
                raise error("publish failed")
            return operation(src, dst, *args, **kwargs)

        return move

    monkeypatch.setattr(inv, "rename_without_replace", fault(rename))
    patch_module_attribute(monkeypatch, _os_fault_consumer, "os", "replace", fault(replace))
    with pytest.raises(error):
        inv.save_checklist(cache, document("new", big))
    assert inv.read_checklist(cache) == before
    assert list(cache.glob(".checklist-tmp-*")) == []


@pytest.mark.parametrize("big", [False, True])
def test_failed_retirement_is_not_reported_as_success(cache, monkeypatch, big):
    inv.save_checklist(cache, document("old"))
    before = inv.read_checklist(cache)
    active = cache / "checklist"
    rename = inv.rename_without_replace
    rmtree = shutil.rmtree

    def fail(src, dst, *args, **kwargs):
        if Path(src) == active:
            raise PermissionError("slot is busy")
        return rename(src, dst, *args, **kwargs)

    def blocked(path, *args, **kwargs):
        if Path(path) != active:
            return rmtree(path, *args, **kwargs)

    monkeypatch.setattr(inv, "rename_without_replace", fail)
    patch_module_attribute(monkeypatch, _storage_fault_consumer, 'shutil', 'rmtree', blocked)
    with pytest.raises(OSError):
        inv.save_checklist(cache, document("new", big))
    assert inv.read_checklist(cache) == before
    assert list(cache.glob(".checklist-tmp-*")) == []


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("big", [False, True])
def test_successful_swap_reclaims_restricted_retired_tree(cache, mode, big):
    inv.save_checklist(cache, document("old"))
    with restricted_tree(cache / "checklist" / "locked", mode):
        inv.save_checklist(cache, document("new", big))
        assert inv.read_checklist(cache)["revision"] == "new"
        assert list(cache.glob(".checklist-stale-*")) == []


def ages(monkeypatch, values):
    stat, lstat = Path.stat, Path.lstat

    def altered(original):
        def read(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path in values:
                return SimpleNamespace(st_mode=info.st_mode, st_ctime=values[path])
            return info

        return read

    monkeypatch.setattr(Path, "stat", altered(stat))
    monkeypatch.setattr(Path, "lstat", altered(lstat))


def test_fresh_entries_do_not_starve_old_retired_trees(cache, monkeypatch):
    fresh = [cache / f".checklist-tmp-fresh-{i}" for i in range(16)]
    old = cache / ".checklist-stale-old"
    for path in fresh + [old]:
        path.mkdir()
    now = time.time()
    ages(monkeypatch, {**{path: now for path in fresh}, old: now - 7200})
    iterdir = Path.iterdir
    monkeypatch.setattr(
        Path,
        "iterdir",
        lambda path: iter(fresh + [old]) if path == cache else iterdir(path),
    )
    inv._sweep_retired_dirs(cache)
    assert not old.exists()
    assert all(path.exists() for path in fresh)


@pytest.mark.parametrize("kind", ["directory", "file", "symlink", "dangling"])
def test_sweep_reclaims_old_owned_entries_without_following_links(
    cache, tmp_path, monkeypatch, kind
):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_text("keep")
    orphan = cache / ".checklist-stale-orphan"
    if kind == "directory":
        orphan.mkdir()
    elif kind == "file":
        orphan.write_text("retired")
    else:
        orphan.symlink_to(
            outside if kind == "symlink" else cache / "absent", target_is_directory=True
        )
    ages(monkeypatch, {orphan: time.time() - 7200})
    inv._sweep_retired_dirs(cache)
    assert not os.path.lexists(orphan)
    assert (outside / "payload").read_text() == "keep"


def test_failed_reclaims_do_not_consume_successful_removal_quota(cache, monkeypatch):
    from core import atomic_fs

    entries = [cache / f".checklist-tmp-{i:02d}" for i in range(19)]
    for path in entries:
        path.mkdir()
    ages(monkeypatch, {path: time.time() - 7200 for path in entries})
    remove = atomic_fs.rmtree_hardened
    monkeypatch.setattr(
        atomic_fs,
        "rmtree_hardened",
        lambda path: False if path in entries[:3] else remove(path),
    )
    inv._sweep_retired_dirs(cache)
    assert all(path.exists() for path in entries[:3])
    assert all(not path.exists() for path in entries[3:])


@pytest.mark.parametrize("now", [float("nan"), float("inf"), -float("inf")])
def test_invalid_sweep_clock_preserves_every_entry(cache, monkeypatch, now):
    old = cache / ".checklist-stale-old"
    old.mkdir()
    monkeypatch.setattr(time, "time", lambda: now)
    inv._sweep_retired_dirs(cache)
    assert old.exists()


def test_shard_to_single_preserves_existing_single_file_permissions(cache):
    dormant = cache / "checklist.json"
    dormant.write_text("old dormant form")
    dormant.chmod(0o600)
    inv.save_checklist(cache, document("old"))
    dormant.write_text("old dormant form")
    dormant.chmod(0o600)
    inv.save_checklist(cache, document("new", False))
    assert dormant.stat().st_mode & 0o777 == 0o600
    assert inv.read_checklist(cache)["revision"] == "new"


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_index_write_reclaims_restricted_staging(
    cache, monkeypatch, mode, error
):
    from core import atomic_fs

    inv.save_checklist(cache, document("old"))
    before = inv.read_checklist(cache)
    write = atomic_fs.write_text_atomically

    def fail(path, *args, **kwargs):
        if Path(path).name == inv.CHECKLIST_INDEX_NAME:
            locked = Path(path).parent / "locked"
            locked.mkdir()
            (locked / "payload").write_text("partial")
            locked.chmod(mode)
            raise error("index write failed")
        return write(path, *args, **kwargs)

    monkeypatch.setattr(atomic_fs, "write_text_atomically", fail)
    with pytest.raises(error):
        inv.save_checklist(cache, document("new"))
    assert inv.read_checklist(cache) == before
    assert list(cache.glob(".checklist-tmp-*")) == []


@pytest.mark.parametrize("kind", ["symlink", "file"])
@pytest.mark.parametrize("big", [False, True])
def test_swap_reclaims_retired_non_directory_entries_without_following_links(
    cache, kind, big
):
    outside = cache / "operator-data"
    outside.mkdir()
    (outside / "payload").write_text("keep")
    active = cache / "checklist"
    if kind == "symlink":
        active.symlink_to(outside, target_is_directory=True)
    else:
        active.write_text("old node")
    inv.save_checklist(cache, document("new", big))
    assert inv.read_checklist(cache)["revision"] == "new"
    assert (outside / "payload").read_text() == "keep"
    assert list(cache.glob(".checklist-stale-*")) == []


def test_failed_rollback_retains_recovery_copy_and_original_error(cache, monkeypatch):
    inv.save_checklist(cache, document("old"))
    active = cache / "checklist"
    original = OSError("original publication failure")
    rename = inv.rename_without_replace

    def publish(src, dst, *args, **kwargs):
        if Path(dst) == active:
            if Path(src).name.startswith(".checklist-stale-"):
                raise PermissionError("rollback failed")
            raise original
        return rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(inv, "rename_without_replace", publish)
    with pytest.raises(OSError) as caught:
        inv.save_checklist(cache, document("new"))
    assert caught.value is original
    retired = list(cache.glob(".checklist-stale-*"))
    assert len(retired) == 1
    import json

    assert (
        json.loads((retired[0] / "index.json").read_text())["meta"]["revision"] == "old"
    )
    assert list(cache.glob(".checklist-tmp-*")) == []


def test_superseded_file_unlink_failure_does_not_fail_committed_shards(
    cache, monkeypatch
):
    inv.save_checklist(cache, document("old", False))
    path = cache / "checklist.json"
    unlink = Path.unlink

    def fail(node, *args, **kwargs):
        if node == path:
            raise PermissionError("file busy")
        return unlink(node, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "unlink", fail)
        inv.save_checklist(cache, document("new"))
    assert inv.read_checklist(cache)["revision"] == "new"
    assert path.exists()
    inv.save_checklist(cache, document("newer"))
    assert not path.exists()


def test_retired_sweep_is_bounded_to_sixteen_successes(cache, monkeypatch):
    paths = [cache / f".checklist-tmp-{i:02d}" for i in range(23)]
    for path in paths:
        path.mkdir()
    old = time.time() - 7200
    ages(monkeypatch, {path: old for path in paths})
    inv._sweep_retired_dirs(cache)
    assert sum(not path.exists() for path in paths) == 16
    assert all(path.exists() for path in paths[16:])


def test_unreadable_retired_entry_does_not_abort_other_reclaims(cache, monkeypatch):
    bad = cache / ".checklist-tmp-bad"
    good = cache / ".checklist-tmp-good"
    bad.mkdir()
    good.mkdir()
    ages(monkeypatch, {bad: time.time() - 7200, good: time.time() - 7200})
    lstat = Path.lstat

    def fail(path, *args, **kwargs):
        if path == bad:
            raise PermissionError("entry busy")
        return lstat(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(Path, "lstat", fail)
        inv._sweep_retired_dirs(cache)
    assert bad.exists()
    assert not good.exists()


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_error_immediately_after_retirement_still_restores_old_form(
    cache, monkeypatch, big, error
):
    inv.save_checklist(cache, document("old"))
    before = inv.read_checklist(cache)
    active = cache / "checklist"
    rename = inv.rename_without_replace

    def retire(src, dst, *args, **kwargs):
        result = rename(src, dst, *args, **kwargs)
        if Path(src) == active:
            raise error("retirement completed before error")
        return result

    monkeypatch.setattr(inv, "rename_without_replace", retire)
    with pytest.raises(error):
        inv.save_checklist(cache, document("new", big))
    assert inv.read_checklist(cache) == before
    assert list(cache.glob(".checklist-stale-*")) == []
    assert list(cache.glob(".checklist-tmp-*")) == []
