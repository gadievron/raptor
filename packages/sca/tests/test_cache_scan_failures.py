"""One bad entry or a database-like JSON name must not defeat cache GC."""

import contextlib
import os
import sqlite3
import time
from pathlib import Path
import pytest
from packages.sca import cache_budget as budget


@pytest.mark.parametrize(
    "name",
    [
        "feed.db.json",
        "feed.sqlite.json",
        "feed.sqlite3.json",
        "metadata.dbdriver.json",
        "npm-meta:thing.db.json",
        "lookup.sqlite-pool.json",
    ],
)
@pytest.mark.parametrize("policy", ["age", "size"])
def test_database_like_json_names_are_still_disposable(tmp_path, name, policy):
    path = tmp_path / name
    path.write_text('{"cached": true}')
    if policy == "age":
        os.utime(path, (time.time() - 60 * 86400,) * 2)
    result = budget.prune_cache(tmp_path, max_bytes=0 if policy == "size" else None)
    assert not path.exists()
    assert result.files_removed == 1 and result.errors == 0


@pytest.mark.parametrize(
    "name",
    [
        "osv.sqlite",
        "state.db",
        "state.db-wal",
        "state.db-shm",
        "state.db-journal",
        "state.sqlite3",
        "state.sqlite3-wal",
        "state.db3",
        "STATE.SQLITE",
        "STATE.DB-WAL",
    ],
)
def test_database_files_and_sidecars_survive_size_pruning(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b"database or sidecar")
    result = budget.prune_cache(tmp_path, max_bytes=0)
    assert path.read_bytes() == b"database or sidecar"
    assert result.files_removed == 0


@pytest.mark.parametrize("name", ["state.sqlite.json", "state.db.json"])
def test_real_sqlite_with_json_suffix_is_preserved_while_open(tmp_path, name):
    path = tmp_path / name
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("create table entries (value text)")
        connection.commit()
        result = budget.prune_cache(tmp_path, max_bytes=0)
        assert path.exists()
        assert result.files_removed == 0
        assert connection.execute("select count(*) from entries").fetchone() == (0,)


@pytest.mark.parametrize("namespace", ["", "stress/clones/project"])
def test_stat_failure_does_not_hide_later_files(tmp_path, monkeypatch, namespace):
    directory = tmp_path / namespace
    directory.mkdir(parents=True, exist_ok=True)
    bad = directory / "a-bad.json"
    bad.write_text("bad")
    good = directory / "z-good.json"
    good.write_text("good")
    scandir = os.scandir

    class Entry:
        def __init__(self, entry):
            self.entry = entry
            self.name = entry.name
            self.path = entry.path

        def stat(self, *args, **kwargs):
            if Path(self.path) == bad:
                raise FileNotFoundError("disappeared during scan")
            return self.entry.stat(*args, **kwargs)

    @contextlib.contextmanager
    def scan(path):
        with scandir(path) as rows:
            yield iter([Entry(row) for row in sorted(rows, key=lambda row: row.name)])

    with monkeypatch.context() as patch:
        patch.setattr(budget.os, "scandir", scan)
        if namespace:
            result = budget.EvictionResult()
            rows = list(budget._walk(directory, result))
            assert [path for path, info in rows] == [good]
            assert result.errors == 1
        else:
            result = budget.prune_cache(tmp_path, max_bytes=0)
            assert not good.exists()
            assert bad.exists()
            assert result.errors == 1


def test_project_disappearing_after_is_dir_does_not_abort_other_evictions(
    tmp_path, monkeypatch
):
    namespace = tmp_path / "inventory"
    bad, good = namespace / "bad", namespace / "good"
    for path in (bad, good):
        path.mkdir(parents=True)
        (path / "cached.json").write_text("cached")
    stat = Path.stat
    is_dir = Path.is_dir

    def race(path, *args, **kwargs):
        if path == bad and kwargs.get("follow_symlinks", True):
            raise FileNotFoundError("disappeared after directory probe")
        return stat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(
            Path, "is_dir", lambda path: True if path == bad else is_dir(path)
        )
        patch.setattr(Path, "stat", race)
        result = budget.prune_cache(tmp_path, max_bytes=0)
    assert not good.exists()
    assert bad.exists()
    assert result.errors == 1


def test_unreadable_inventory_namespace_does_not_hide_stress_cache(
    tmp_path, monkeypatch
):
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    project = tmp_path / "stress/clones/project"
    project.mkdir(parents=True)
    (project / "cached.json").write_text("cached")
    iterdir = Path.iterdir

    def refuse(path):
        if path == inventory:
            raise PermissionError("inventory unavailable")
        return iterdir(path)

    monkeypatch.setattr(Path, "iterdir", refuse)
    result = budget.prune_cache(tmp_path, max_bytes=0)
    assert not project.exists()
    assert result.errors == 1


@pytest.mark.parametrize("name", ["state.sqlite.json", "state.db.json"])
def test_new_empty_sqlite_database_with_json_suffix_is_preserved(tmp_path, name):
    path = tmp_path / name
    with contextlib.closing(sqlite3.connect(path)) as connection:
        assert path.stat().st_size == 0
        result = budget.prune_cache(tmp_path, max_bytes=0)
        assert path.exists()
        assert result.files_removed == 0
        connection.execute("create table entries (value text)")
        connection.commit()


@pytest.mark.parametrize("name", ["state.sqlite.json", "state.db.json"])
def test_short_header_reads_do_not_misclassify_real_database(
    tmp_path, monkeypatch, name
):
    path = tmp_path / name
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute("create table entries (value text)")
        connection.commit()
        read = os.read
        monkeypatch.setattr(budget.os, "read", lambda fd, n: read(fd, min(n, 3)))
        result = budget.prune_cache(tmp_path, max_bytes=0)
        assert path.exists()
        assert result.files_removed == 0
