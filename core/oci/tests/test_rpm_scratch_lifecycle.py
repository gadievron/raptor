"""RPM parsing owns actual SQLite files, connections and parser sidecars."""

from contextlib import contextmanager
from pathlib import Path
import sqlite3

import pytest

from core.oci import sbom
from core.oci.tests.test_sbom import _make_rpm_header
from core.run import scratch
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def database():
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE Packages (hnum INTEGER, blob BLOB)")
        connection.execute("INSERT INTO Packages VALUES (?, ?)", (1, _make_rpm_header("demo", "1.0", "1")))
        return connection.serialize()
    finally:
        connection.close()


@pytest.fixture
def placed_scratch(tmp_path, monkeypatch):
    original = scratch.tempfile.mkdtemp
    roots = []
    def allocate(*a, **kw):
        assert kw.get("dir") is None
        kw["dir"] = tmp_path
        result = original(*a, **kw)
        roots.append(Path(result))
        return result
    patch_module_attribute(monkeypatch, scratch, "tempfile", "mkdtemp", allocate)
    return roots


@pytest.mark.parametrize("parent_name", ["question?mark", "fragment#mark", "space percent%", "unicode-é"], ids=["question", "fragment", "space-percent", "unicode"])
def test_sqlite_uri_and_connection_lifetime(tmp_path, monkeypatch, database, parent_name):
    parent = tmp_path / parent_name
    parent.mkdir()
    roots, connections = [], []
    allocate = scratch.tempfile.mkdtemp
    connect = sbom.sqlite3.connect
    def create(*a, **kw):
        kw["dir"] = parent
        result = allocate(*a, **kw)
        roots.append(Path(result))
        return result
    def open_database(filename, **kw):
        assert str(roots[0]) in scratch._keepalive_paths
        result = connect(filename, **kw)
        connections.append(result)
        return result
    patch_module_attribute(monkeypatch, scratch, "tempfile", "mkdtemp", create)
    patch_module_attribute(monkeypatch, sbom, "sqlite3", "connect", open_database)
    result = sbom.parse_rpm_sqlite(database)
    assert [(item.name, item.version) for item in result] == [("demo", "1.0-1")]
    assert not roots[0].exists()
    assert str(roots[0]) not in scratch._keepalive_paths
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


@pytest.mark.parametrize("primary", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("secondary", [OSError, KeyboardInterrupt])
def test_body_error_survives_close_failure(database, placed_scratch, monkeypatch, primary, secondary):
    error = primary("parse fault")
    connections = []
    class Connection(sqlite3.Connection):
        def cursor(self, *a, **kw):
            raise error
        def close(self):
            super().close()
            raise secondary("close fault")
    original = sbom.sqlite3.connect
    def connect(*a, **kw):
        connection = original(*a, **kw, factory=Connection)
        connections.append(connection)
        return connection
    patch_module_attribute(monkeypatch, sbom, "sqlite3", "connect", connect)
    with pytest.raises(primary) as caught:
        sbom.parse_rpm_sqlite(database)
    assert caught.value is error
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_close_failure_still_removes_workspace(database, placed_scratch, monkeypatch, error):
    class Connection(sqlite3.Connection):
        def close(self):
            super().close()
            raise error("close fault")
    original = sbom.sqlite3.connect
    patch_module_attribute(monkeypatch, sbom, "sqlite3", "connect", lambda *a, **kw: original(*a, **kw, factory=Connection))
    with pytest.raises(error, match="close fault"):
        sbom.parse_rpm_sqlite(database)
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_connect_failure_reclaims_database_copy(database, placed_scratch, monkeypatch, error):
    def connect(*a, **kw):
        assert (placed_scratch[0] / "rpmdb.sqlite").read_bytes() == database
        raise error("connect fault")
    patch_module_attribute(monkeypatch, sbom, "sqlite3", "connect", connect)
    with pytest.raises(error, match="connect fault"):
        sbom.parse_rpm_sqlite(database)
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()


@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_interrupted_write_discards_partial_copy(database, placed_scratch, monkeypatch, error):
    class FaultPath(type(Path())):
        def write_bytes(self, data):
            super().write_bytes(data[:10])
            raise error("write fault")
    owner = sbom.scratch_dir
    @contextmanager
    def workspace(*a, **kw):
        with owner(*a, **kw) as root:
            yield FaultPath(root)
    monkeypatch.setattr(sbom, "scratch_dir", workspace)
    with pytest.raises(error, match="write fault"):
        sbom.parse_rpm_sqlite(database)
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()


@pytest.mark.parametrize("fail", [False, True], ids=["success", "parse-failure"])
def test_sidecars_and_restricted_subdirectories_are_reclaimed(tmp_path, database, placed_scratch, monkeypatch, fail):
    borrowed = tmp_path / "borrowed"
    borrowed.mkdir()
    (borrowed / "keep").write_text("retain")
    mode = borrowed.stat().st_mode
    original = sbom.sqlite3.connect
    def connect(*a, **kw):
        root = placed_scratch[0]
        (root / "rpmdb.sqlite-wal").write_bytes(b"sidecar")
        child = root / "restricted"
        child.mkdir()
        (child / "partial").write_bytes(b"partial")
        (child / "link").symlink_to(borrowed, target_is_directory=True)
        child.chmod(0)
        return original(*a, **kw)
    patch_module_attribute(monkeypatch, sbom, "sqlite3", "connect", connect)
    if fail:
        def parse(_blob):
            raise RuntimeError("parse fault")
        monkeypatch.setattr(sbom, "_parse_rpm_header", parse)
        with pytest.raises(RuntimeError, match="parse fault"):
            sbom.parse_rpm_sqlite(database)
    else:
        assert sbom.parse_rpm_sqlite(database)
    assert not placed_scratch[0].exists()
    assert (borrowed / "keep").read_text() == "retain"
    assert borrowed.stat().st_mode == mode


def test_invalid_sqlite_is_skipped_and_reclaimed(placed_scratch):
    assert sbom.parse_rpm_sqlite(b"not a database") == []
    assert len(placed_scratch) == 1 and not placed_scratch[0].exists()
