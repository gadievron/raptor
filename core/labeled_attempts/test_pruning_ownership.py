"""Pool pruning removes only selected owned records and reports actual work."""

import os

import pytest

from core.labeled_attempts import pruning, write
from core.labeled_attempts.test_pruning import _attempt


@pytest.fixture
def records(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    paths = [
        write(_attempt(days_old=day, code="same-source"), project_dir=project)[0]
        for day in range(3)
    ]
    return project, paths


@pytest.mark.parametrize("value", [-1, -100, True, False, 1.5, "2", None])
def test_invalid_retention_count_is_rejected_before_touching_pool(records, value):
    project, paths = records
    with pytest.raises(ValueError):
        pruning.prune_pool(project, n_per_bucket=value)
    assert all(p.exists() for p in paths)


@pytest.mark.parametrize("error", [PermissionError, OSError])
def test_failed_unlink_is_not_reported_as_removal(records, monkeypatch, error):
    project, paths = records
    unlink = os.unlink

    def fail(path, *args, **kwargs):
        if str(path).endswith((".json", ".tmp")):
            raise error("cannot remove record")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as fault:
        fault.setattr(os, "unlink", fail)
        report = pruning.prune_pool(project, n_per_bucket=1)
    assert report.records_removed == 0
    assert report.removed_paths == ()
    assert report.records_kept == 3
    assert all(p.exists() for p in paths)


@pytest.mark.parametrize("kind", ["pool", "signature", "record"])
def test_pruning_does_not_follow_links_to_external_records(records, tmp_path, kind):
    project, paths = records
    pool = project / "labeled_attempts"
    if kind == "pool":
        external = tmp_path / "external-pool"
        pool.rename(external)
        pool.symlink_to(external, target_is_directory=True)
        preserved = [external / p.relative_to(pool) for p in paths]
    elif kind == "signature":
        signature = paths[0].parent
        external = tmp_path / "external-signature"
        signature.rename(external)
        signature.symlink_to(external, target_is_directory=True)
        preserved = [external / p.name for p in paths]
    else:
        external = tmp_path / "external-records"
        external.mkdir()
        preserved = []
        for path in paths:
            relocated = external / path.name
            path.rename(relocated)
            path.symlink_to(relocated)
            preserved.append(relocated)
    report = pruning.prune_pool(project, n_per_bucket=0)
    assert report.records_removed == 0
    assert all(p.exists() for p in preserved)


@pytest.mark.parametrize("location", ["root", "signature"])
def test_directory_enumeration_failure_is_best_effort(records, monkeypatch, location):
    project, paths = records
    target = project / "labeled_attempts" if location == "root" else paths[0].parent
    identity = target.stat().st_ino
    original = os.scandir

    def fail(path):
        info = os.fstat(path) if isinstance(path, int) else os.stat(path)
        if info.st_ino == identity:
            raise PermissionError("unreadable directory")
        return original(path)

    monkeypatch.setattr(os, "scandir", fail)
    report = pruning.prune_pool(project, n_per_bucket=0)
    assert report.records_removed == 0
    assert all(p.exists() for p in paths)


@pytest.mark.parametrize("change", ["edit", "replace"])
def test_record_changed_after_scan_is_preserved(records, monkeypatch, change):
    project, paths = records
    target = paths[2]
    replacement = target.read_bytes().replace(b"FND-X", b"FND-Y")
    remove = pruning._remove_candidate
    changed = False

    def update(pool, descriptor, identity, candidate):
        nonlocal changed
        if candidate.path == target and not changed:
            changed = True
            if change == "replace":
                fresh = target.with_suffix(".replacement")
                fresh.write_bytes(replacement)
                fresh.replace(target)
            else:
                target.write_bytes(replacement)
        return remove(pool, descriptor, identity, candidate)

    monkeypatch.setattr(pruning, "_remove_candidate", update)
    report = pruning.prune_pool(project, n_per_bucket=1)
    assert report.records_removed == 1 and report.records_kept == 2
    assert target.read_bytes() == replacement
    assert target not in report.removed_paths
    assert paths[0].exists()


@pytest.mark.parametrize("kind", ["file", "same-metadata", "symlink", "directory"])
def test_replacement_in_stat_rename_gap_is_restored(
    records, tmp_path, monkeypatch, kind
):
    project, paths = records
    target = paths[2]
    original = target.read_bytes()
    replacement = original.replace(b"FND-X", b"FND-Y")
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    rename = os.rename
    changed = False

    def update(src, dst, *args, **kwargs):
        nonlocal changed
        if src == target.name and str(dst).startswith(".prune-") and not changed:
            changed = True
            before = target.stat()
            if kind == "same-metadata":
                target.write_bytes(replacement)
                os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
            else:
                target.unlink()
                if kind == "file":
                    target.write_bytes(replacement)
                elif kind == "symlink":
                    target.symlink_to(outside)
                else:
                    target.mkdir()
                    (target / "keep").write_bytes(b"operator directory")
        return rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", update)
    report = pruning.prune_pool(project, n_per_bucket=1)
    assert report.records_removed == 1
    if kind == "directory":
        assert (target / "keep").read_bytes() == b"operator directory"
    elif kind == "symlink":
        assert target.is_symlink() and outside.read_bytes() == b"keep"
    else:
        assert target.read_bytes() == replacement
    assert not list(target.parent.glob(".prune-*"))


def test_publication_after_quarantine_is_not_removed(records, monkeypatch):
    project, paths = records
    target = paths[2]
    replacement = target.read_bytes().replace(b"FND-X", b"FND-Y")
    read = pruning._read_record
    published = False

    def republish(directory, name):
        nonlocal published
        result = read(directory, name)
        if name.startswith(".prune-") and result is not None and not published:
            published = True
            # Publish at the original name while the selected old record is
            # privately held. Removing the old inode must leave this one alone.
            target.write_bytes(replacement)
        return result

    # Target the first candidate: the name is absent only while that record's
    # quarantine is read; use its path for the independently published record.
    target = paths[1]
    monkeypatch.setattr(pruning, "_read_record", republish)
    report = pruning.prune_pool(project, n_per_bucket=1)
    assert report.records_removed == 2
    assert target.read_bytes() == replacement
    assert not list(target.parent.glob(".prune-*"))


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True])
def test_cancelled_removal_restores_owned_record(records, monkeypatch, error, after):
    project, paths = records
    target = paths[2]
    expected = target.read_bytes()
    failure = error("cancelled")
    rename = os.rename

    def fail(src, dst, *args, **kwargs):
        if src == target.name and str(dst).startswith(".prune-"):
            if after:
                rename(src, dst, *args, **kwargs)
            raise failure
        return rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(os, "rename", fail)
    with pytest.raises(error) as caught:
        pruning.prune_pool(project, n_per_bucket=1)
    assert caught.value is failure
    assert target.read_bytes() == expected
    assert not list(target.parent.glob(".prune-*"))


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_stream_setup_failure_closes_acquired_descriptors(records, monkeypatch, error):
    project, paths = records
    opened = []
    real_open = os.open
    failure = error("fdopen failed")

    def track(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def fail(*args, **kwargs):
        raise failure

    with monkeypatch.context() as fault:
        fault.setattr(os, "open", track)
        fault.setattr(os, "fdopen", fail)
        if error is OSError:
            report = pruning.prune_pool(project, n_per_bucket=0)
            assert report.records_seen == 0
        else:
            with pytest.raises(error) as caught:
                pruning.prune_pool(project, n_per_bucket=0)
            assert caught.value is failure
    assert opened
    for fd in opened:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert all(p.exists() for p in paths)


@pytest.mark.parametrize("location", ["pool", "signature"])
def test_replaced_directory_is_not_pruned_through_old_snapshot(
    records, tmp_path, monkeypatch, location
):
    project, paths = records
    victim = project / "labeled_attempts" if location == "pool" else paths[0].parent
    remove = pruning._remove_candidate
    moved = tmp_path / "operator-moved"
    replaced = False

    def update(*args):
        nonlocal replaced
        if not replaced:
            replaced = True
            victim.rename(moved)
            victim.mkdir()
            (victim / "operator").write_bytes(b"keep")
        return remove(*args)

    monkeypatch.setattr(pruning, "_remove_candidate", update)
    report = pruning.prune_pool(project, n_per_bucket=0)
    assert report.records_removed == 0
    assert (victim / "operator").read_bytes() == b"keep"
    preserved = [moved / p.relative_to(victim) for p in paths]
    assert all(p.exists() for p in preserved)


@pytest.mark.parametrize("kind", ["fifo", "directory", "oversized", "hidden"])
def test_non_records_are_not_read_or_removed(records, monkeypatch, kind):
    project, paths = records
    odd = paths[0].parent / (".private.json" if kind == "hidden" else "odd.json")
    if kind == "fifo":
        os.mkfifo(odd)
    elif kind == "directory":
        odd.mkdir()
    elif kind == "oversized":
        monkeypatch.setattr(pruning, "_MAX_RECORD_BYTES", 4096)
        odd.write_bytes(b"x" * 4097)
    else:
        odd.write_bytes(paths[0].read_bytes())
    report = pruning.prune_pool(project, n_per_bucket=0)
    assert report.records_removed == 3
    assert os.path.lexists(odd)


def test_dry_run_does_not_quarantine_or_remove(records, monkeypatch):
    project, paths = records

    def forbidden(*args, **kwargs):
        pytest.fail("dry-run must not mutate pool entries")

    with monkeypatch.context() as fault:
        fault.setattr(os, "rename", forbidden)
        fault.setattr(os, "unlink", forbidden)
        fault.setattr(os, "rmdir", forbidden)
        report = pruning.prune_pool(project, n_per_bucket=1, dry_run=True)
    assert report.records_removed == 2 and report.records_kept == 1
    assert all(p.exists() for p in paths)


def test_recovery_collision_preserves_both_new_publications(
    records, monkeypatch, caplog
):
    project, paths = records
    target = paths[2]
    original = target.read_bytes()
    first = original.replace(b"FND-X", b"FND-Y")
    second = original.replace(b"FND-X", b"FND-Z")
    rename = os.rename
    read = pruning._read_record
    changed = False

    def replace(src, dst, *args, **kwargs):
        nonlocal changed
        if src == target.name and str(dst).startswith(".prune-") and not changed:
            changed = True
            target.unlink()
            target.write_bytes(first)
        return rename(src, dst, *args, **kwargs)

    def publish(directory, name):
        loaded = read(directory, name)
        if name.startswith(".prune-") and loaded is not None and loaded[0] == first:
            target.write_bytes(second)
        return loaded

    monkeypatch.setattr(os, "rename", replace)
    monkeypatch.setattr(pruning, "_read_record", publish)
    report = pruning.prune_pool(project, n_per_bucket=1)
    assert report.records_removed == 1
    assert target.read_bytes() == second
    retained = list(target.parent.glob(".prune-*.tmp"))
    assert len(retained) == 1 and retained[0].read_bytes() == first
    assert any(str(retained[0]) in message for message in caplog.messages)
