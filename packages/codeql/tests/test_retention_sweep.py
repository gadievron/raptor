"""CodeQL housekeeping reclaims orphan scratch without widening its scope."""

import json
import os
import time
from pathlib import Path

import pytest

from packages.codeql.database_manager import DatabaseManager


@pytest.fixture
def manager(tmp_path):
    manager = DatabaseManager.__new__(DatabaseManager)
    manager.db_root = tmp_path / "cache"
    manager.db_root.mkdir()
    return manager


def metadata(repo, target):
    repo.mkdir(exist_ok=True)
    path = repo / "python-metadata.json"
    path.write_text(
        json.dumps(
            {"created_at": "2020-01-01T00:00:00+00:00", "database_path": str(target)}
        )
    )
    return path


def age(path):
    old = time.time() - 40 * 86400
    os.utime(path, (old, old), follow_symlinks=False)


@pytest.mark.parametrize("dry_run", [False, True])
@pytest.mark.parametrize(
    "name",
    [
        ".staging-python-1234-abcd",
        "python-db.stale.1234567890.1234",
        ".kept-python-1234-abcd",
    ],
)
@pytest.mark.parametrize(
    "kind", ["directory", "file", "dangling_link", "directory_link"]
)
def test_global_cleanup_finds_orphans_without_metadata(
    manager, tmp_path, dry_run, name, kind
):
    repo = manager.db_root / "unused-repo"
    repo.mkdir()
    orphan = repo / name
    target = tmp_path / "source-tree"
    target.mkdir()
    (target / "payload").write_text("keep")
    if kind == "directory":
        orphan.mkdir()
        (orphan / "payload").write_text("orphan")
    elif kind == "file":
        orphan.write_text("orphan")
    else:
        orphan.symlink_to(
            target if kind == "directory_link" else tmp_path / "absent",
            target_is_directory=True,
        )
    age(orphan)
    assert manager.cleanup_old_databases(days=7, dry_run=dry_run) == [str(orphan)]
    assert os.path.lexists(orphan) is dry_run
    assert (target / "payload").read_text() == "keep"


@pytest.mark.parametrize("target_kind", ["root", "repo", "sibling_repo", "nested"])
def test_metadata_cannot_select_roots_or_other_repository_trees(manager, target_kind):
    repo = manager.db_root / "repo"
    repo.mkdir()
    target = {
        "root": manager.db_root,
        "repo": repo,
        "sibling_repo": manager.db_root / "other" / "python-db",
        "nested": repo / "python-db" / "nested",
    }[target_kind]
    target.mkdir(parents=True, exist_ok=True)
    payload = target / "payload"
    payload.write_text("keep")
    sidecar = metadata(repo, target)
    assert manager.cleanup_old_databases(days=7) == []
    assert payload.read_text() == "keep"
    assert sidecar.exists()


@pytest.mark.parametrize("kind", ["repo", "metadata", "database"])
def test_metadata_cleanup_does_not_follow_symlink_entries(manager, tmp_path, kind):
    repo = manager.db_root / "repo"
    repo.mkdir()
    target = repo / "python-db"
    target.mkdir()
    (target / "payload").write_text("keep")
    sidecar = metadata(repo, target)
    if kind == "repo":
        real = tmp_path / "saved-repo"
        repo.rename(real)
        repo.symlink_to(real, target_is_directory=True)
    elif kind == "metadata":
        real = tmp_path / "saved-metadata.json"
        sidecar.rename(real)
        sidecar.symlink_to(real)
    else:
        real = tmp_path / "saved-database"
        target.rename(real)
        target.symlink_to(real, target_is_directory=True)
    assert manager.cleanup_old_databases(days=7) == []
    assert (target / "payload").read_text() == "keep"
    assert sidecar.exists()


@pytest.mark.parametrize(
    "days", [-1, float("nan"), float("inf"), -float("inf"), True, 10**30]
)
def test_invalid_retention_days_fail_before_any_removal(manager, days):
    repo = manager.db_root / "repo"
    repo.mkdir()
    target = repo / "python-db"
    target.mkdir()
    sidecar = metadata(repo, target)
    with pytest.raises(ValueError):
        manager.cleanup_old_databases(days=days)
    assert target.exists()
    assert sidecar.exists()


def test_removal_receipt_survives_metadata_unlink_failure(manager, monkeypatch):
    repo = manager.db_root / "repo"
    repo.mkdir()
    target = repo / "python-db"
    target.mkdir()
    sidecar = metadata(repo, target)
    unlink = Path.unlink

    def fail(path, *args, **kwargs):
        if path == sidecar:
            raise PermissionError("sidecar is busy")
        return unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail)
    assert manager.cleanup_old_databases(days=7) == [str(target)]
    assert not target.exists()
    assert sidecar.exists()


def test_unreadable_repository_does_not_cancel_other_cleanup(manager, monkeypatch):
    broken = manager.db_root / "a-broken"
    broken.mkdir()
    repo = manager.db_root / "b-good"
    repo.mkdir()
    target = repo / "python-db"
    target.mkdir()
    metadata(repo, target)
    iterdir = Path.iterdir
    glob = Path.glob

    def listdir(path):
        if path == broken:
            raise PermissionError("unreadable repository")
        return iterdir(path)

    def globdir(path, *args, **kwargs):
        if path == broken:
            raise PermissionError("unreadable repository")
        return glob(path, *args, **kwargs)

    monkeypatch.setattr(Path, "iterdir", listdir)
    monkeypatch.setattr(Path, "glob", globdir)
    assert manager.cleanup_old_databases(days=7) == [str(target)]


def test_global_sweep_preserves_recent_scratch_and_unrelated_names(manager):
    repo = manager.db_root / "repo"
    repo.mkdir()
    recent = repo / ".staging-python-1234-abcd"
    recent.mkdir()
    unrelated = repo / "notes.stale.backup"
    unrelated.write_text("keep")
    age(unrelated)
    assert manager.cleanup_old_databases(days=7) == []
    assert recent.exists()
    assert unrelated.exists()


@pytest.mark.parametrize(
    "name",
    [
        ".staging-python-1234-abcd",
        "python-db.stale.1234567890.1234",
        ".kept-python-1234-abcd",
    ],
)
@pytest.mark.parametrize("days", [0, 7, 30])
def test_global_scratch_grace_honours_cache_ttl_and_one_day_floor(manager, name, days):
    repo = manager.db_root / "repo"
    repo.mkdir()
    scratch = repo / name
    scratch.mkdir()
    old = time.time() - 2 * 86400
    os.utime(scratch, (old, old))
    result = manager.cleanup_old_databases(days=days)
    assert scratch.exists() is (days > 2)
    assert result == ([] if days > 2 else [str(scratch)])


@pytest.mark.parametrize(
    "name",
    [
        ".staging-python-1234-abcd",
        "python-db.stale.1234567890.1234",
        ".kept-python-1234-abcd",
    ],
)
def test_zero_day_cleanup_still_preserves_recent_scratch(manager, name):
    repo = manager.db_root / "repo"
    repo.mkdir()
    scratch = repo / name
    scratch.mkdir()
    old = time.time() - 2 * 3600
    os.utime(scratch, (old, old))
    assert manager.cleanup_old_databases(days=0) == []
    assert scratch.exists()


def test_failed_scratch_removal_retains_data_for_retry(manager, monkeypatch):
    repo = manager.db_root / "repo"
    repo.mkdir()
    scratch = repo / ".staging-python-1234-abcd"
    scratch.mkdir()
    age(scratch)
    with monkeypatch.context() as fault:
        fault.setattr(
            "packages.codeql.database_manager.rmtree_hardened", lambda path: False
        )
        assert manager.cleanup_old_databases(days=7) == []
    assert scratch.exists()
    assert manager.cleanup_old_databases(days=7) == [str(scratch)]
    assert not scratch.exists()


@pytest.mark.parametrize("name", ["javascript-db", "other-files"])
def test_sidecar_cannot_select_another_language_or_unrelated_tree(manager, name):
    repo = manager.db_root / "repo"
    repo.mkdir()
    target = repo / name
    target.mkdir()
    sidecar = metadata(repo, target)
    assert manager.cleanup_old_databases(days=7) == []
    assert target.exists()
    assert sidecar.exists()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"created_at": 123},
        {"created_at": "bad"},
        {"created_at": "2020-01-01", "database_path": ""},
    ],
)
def test_malformed_sidecar_does_not_block_valid_cleanup(manager, payload):
    repo = manager.db_root / "repo"
    repo.mkdir()
    (repo / "broken-metadata.json").write_text(json.dumps(payload))
    target = repo / "python-db"
    target.mkdir()
    metadata(repo, target)
    assert manager.cleanup_old_databases(days=7) == [str(target)]
