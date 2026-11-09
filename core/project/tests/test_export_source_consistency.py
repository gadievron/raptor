"""Never publish an archive assembled across changes to copied source files."""

import os
import sqlite3
import zipfile
from contextlib import closing

import pytest

import core.project.export as archives
from core.testing.module_bindings import patch_module_attribute
from core.understand_graph.ingest import _upsert_node
from core.understand_graph.tests.test_validates_join import _write_two_flow_run


def _ordered_walk(monkeypatch):
    original = archives.os.walk

    def ordered(*args, **kwargs):
        for root, directories, files in original(*args, **kwargs):
            yield root, directories, sorted(files)

    # Filesystem enumeration order is unspecified; exercise DB before WAL.
    patch_module_attribute(monkeypatch, archives, "os", "walk", ordered)


def test_stable_live_graph_wal_roundtrips_committed_rows(tmp_path):
    project = tmp_path / "project"
    graph = _write_two_flow_run(project / "run", tmp_path / "target")
    with closing(sqlite3.connect(graph)) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        snapshot = writer.execute("SELECT id FROM snapshots WHERE producer='understand'").fetchone()[0]
        _upsert_node(writer, snapshot, "finding", "export-A", {"id": "EXPORT-A"})
        writer.commit()
        result = archives.export_project(project, tmp_path / "export.zip")
        restored = tmp_path / "restored"
        restored.mkdir()
        with zipfile.ZipFile(result["path"]) as archive:
            for suffix in ("", "-wal", "-shm"):
                name = graph.name + suffix
                member = f"project/{graph.relative_to(project)}{suffix}"
                if member in archive.namelist():
                    (restored / name).write_bytes(archive.read(member))
        with closing(sqlite3.connect(restored / graph.name)) as readback:
            assert readback.execute("SELECT count(*) FROM nodes WHERE stable_key='finding://export-A'").fetchone()[0] == 1


def test_graph_checkpoint_during_export_preserves_previous_archive(tmp_path, monkeypatch):
    project = tmp_path / "project"
    graph = _write_two_flow_run(project / "run", tmp_path / "target")
    destination = tmp_path / "export.zip"
    destination.write_bytes(b"previous archive")
    _ordered_walk(monkeypatch)
    original = archives._write_zip_regular
    with closing(sqlite3.connect(graph)) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        snapshot = writer.execute("SELECT id FROM snapshots WHERE producer='understand'").fetchone()[0]
        _upsert_node(writer, snapshot, "finding", "export-A", {"id": "EXPORT-A"})
        writer.commit()
        checkpoints = []

        def checkpoint_after_database(zf, path, arcname, remaining):
            written = original(zf, path, arcname, remaining)
            if path == graph:
                checkpoints.append(writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone())
                writer.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES ('export-B','committed')")
                writer.commit()
            return written

        monkeypatch.setattr(archives, "_write_zip_regular", checkpoint_after_database)
        with pytest.raises(ValueError, match="changed during export"):
            archives.export_project(project, destination, force=True)
        assert len(checkpoints) == 1 and checkpoints[0][0] == 0
        assert writer.execute("SELECT count(*) FROM nodes WHERE stable_key='finding://export-A'").fetchone()[0] == 1
    assert destination.read_bytes() == b"previous archive"
    assert not list(tmp_path.glob(".export-*"))


@pytest.mark.parametrize("mutation", ["rewrite", "replace", "delete"])
def test_later_source_change_does_not_publish_mixed_archive(tmp_path, monkeypatch, mutation):
    project = tmp_path / "project"
    project.mkdir()
    first = project / "a.bin"
    first.write_bytes(b"AAAA")
    (project / "b.bin").write_bytes(b"BBBB")
    destination = tmp_path / "export.zip"
    destination.write_bytes(b"previous archive")
    _ordered_walk(monkeypatch)
    original = archives._write_zip_regular

    def change_previous_source(zf, path, arcname, remaining):
        written = original(zf, path, arcname, remaining)
        if path.name == "b.bin":
            if mutation == "rewrite":
                first.write_bytes(b"CCCC")
            elif mutation == "replace":
                replacement = tmp_path / "replacement"
                replacement.write_bytes(b"CCCC")
                os.replace(replacement, first)
            else:
                first.unlink()
        return written

    monkeypatch.setattr(archives, "_write_zip_regular", change_previous_source)
    with pytest.raises(ValueError, match="changed during export"):
        archives.export_project(project, destination, force=True)
    assert destination.read_bytes() == b"previous archive"
