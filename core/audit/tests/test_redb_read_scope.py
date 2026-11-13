"""Helper-level lifetime checks, without claiming loader/read provenance."""
from dataclasses import replace
import os

import pytest

from core.audit.redb_read_scope import RedbReadScope, database_projection_digest
from packages.ghidra.model import REDatabase


def _scope(tmp_path):
    path = tmp_path / "view.json"
    path.write_text("{}")
    database = REDatabase(source_tool="fixture")
    info = path.stat()
    return RedbReadScope(
        path, path.resolve(),
        (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
        4096, database, database_projection_digest(database, 4096),
    )


def test_healthy_projection_and_metadata_are_only_lifetime_data(tmp_path):
    scope = _scope(tmp_path)
    assert scope.file_current()
    assert scope.current()
    # Construction is possible without invoking any loader: no read receipt is
    # established by a successful metadata/projection comparison.
    assert replace(scope).current()
    assert not replace(scope, projection_sha256=None).current()
    assert "database=" not in repr(scope)


def test_mutated_public_projection_refuses_unchanged_file(tmp_path):
    scope = _scope(tmp_path)
    scope.database.metadata["changed"] = True
    assert scope.file_current()
    assert not scope.current()


@pytest.mark.parametrize("change", ["rewrite", "replace", "missing", "directory", "alias"])
def test_original_file_identity_cannot_be_restamped(tmp_path, change):
    scope = _scope(tmp_path)
    original = scope.path.stat()
    if change == "rewrite":
        scope.path.write_text("[]")
        os.utime(scope.path, ns=(original.st_atime_ns, original.st_mtime_ns))
    elif change == "replace":
        replacement = tmp_path / "replacement.json"
        replacement.write_text("{}")
        os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
        replacement.replace(scope.path)
    elif change == "missing":
        scope.path.unlink()
    elif change == "directory":
        scope.path.unlink()
        scope.path.mkdir()
    else:
        other = tmp_path / "other.json"
        other.write_text("{}")
        scope.path.unlink()
        scope.path.symlink_to(other)
    assert not scope.file_current()
    assert not scope.current()


def test_file_and_projection_budgets_are_original(tmp_path):
    scope = _scope(tmp_path)
    assert not replace(scope, max_bytes=1).file_current()
    assert database_projection_digest(scope.database, 1) is None
    assert database_projection_digest(scope.database, 4096) == scope.projection_sha256


@pytest.mark.parametrize("value", [object(), {1: "key"}, (1,), float("nan"), float("inf")])
def test_non_json_projection_is_unavailable(value):
    database = REDatabase(source_tool="fixture", metadata={"value": value})
    assert database_projection_digest(database, 4096) is None


def test_unavailable_projection_fails_closed_without_swallowing_interrupts():
    class Unavailable:
        def to_dict(self):
            raise ValueError("unavailable")

    class Interrupted:
        def to_dict(self):
            raise KeyboardInterrupt("stop")

    assert database_projection_digest(Unavailable(), 4096) is None
    with pytest.raises(KeyboardInterrupt, match="stop"):
        database_projection_digest(Interrupted(), 4096)


@pytest.mark.parametrize("changes", [
    {"version": (1, 2, 3, 4, True)},
    {"version": (1, 2, 3, 4)},
    {"max_bytes": True},
    {"max_bytes": -1},
    {"projection_sha256": "A" * 64},
    {"projection_sha256": "0" * 63},
])
def test_invalid_metadata_is_rejected(tmp_path, changes):
    with pytest.raises(ValueError):
        replace(_scope(tmp_path), **changes)
