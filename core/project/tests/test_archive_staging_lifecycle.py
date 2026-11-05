"""Project archives publish complete output and reclaim owned staging."""

import json
import os
from pathlib import Path
import types
import zipfile

import pytest

from core.project import export as archives


@pytest.fixture
def project(tmp_path):
    source = tmp_path / "demo"
    source.mkdir()
    (source / "data.txt").write_text("project data")
    return source


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "input.zip"
    with zipfile.ZipFile(path, "w") as output:
        output.writestr("demo/.project.json", json.dumps({
            "version": 1, "name": "demo", "target": "(imported)",
        }))
        output.writestr("demo/data.txt", "project data")
    return path


def _assert_no_staging(root):
    assert not list(root.rglob(".export-*"))
    assert not list(root.rglob(".import-*"))


@pytest.mark.parametrize("phase", ["write", "close", "hash", "publish"])
@pytest.mark.parametrize("cancel", [False, True], ids=["io-error", "cancel"])
def test_failed_export_preserves_previous_archive(project, tmp_path, monkeypatch, phase, cancel):
    dest = tmp_path / "previous.zip"
    dest.write_bytes(b"previous archive")
    error = KeyboardInterrupt if cancel else OSError

    def fail(*args, **kwargs):
        raise error("injected export failure")

    if phase in {"write", "close"}:
        proxy = types.ModuleType("archive_zipfile")
        proxy.__dict__.update(vars(zipfile))

        class FailingZip(zipfile.ZipFile):
            def write(self, *args, **kwargs):
                super().write(*args, **kwargs)
                if phase == "write":
                    fail()

            def close(self):
                armed = self.fp is not None and self.mode == "w"
                super().close()
                if phase == "close" and armed:
                    fail()

        proxy.ZipFile = FailingZip
        monkeypatch.setattr(archives, "zipfile", proxy)
    elif phase == "hash":
        monkeypatch.setattr(archives, "sha256_file", fail)
    else:
        proxy = types.ModuleType("archive_os")
        proxy.__dict__.update(vars(os))
        proxy.replace = fail
        monkeypatch.setattr(archives, "os", proxy)
    with pytest.raises(error, match="injected export failure"):
        archives.export_project(project, dest, force=True)
    assert dest.read_bytes() == b"previous archive"
    _assert_no_staging(tmp_path)


def test_failed_new_export_does_not_advertise_partial_zip(project, tmp_path, monkeypatch):
    dest = tmp_path / "new.zip"

    def fail(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(archives, "sha256_file", fail)
    with pytest.raises(OSError, match="disk full"):
        archives.export_project(project, dest)
    assert not dest.exists()
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("nested", [False, True], ids=["root", "nested"])
@pytest.mark.parametrize("alias", [False, True], ids=["direct", "source-alias"])
def test_export_inside_source_excludes_destination_and_staging(project, tmp_path, nested, alias):
    dest = project / ("archives/result.zip" if nested else "result.zip")
    dest.parent.mkdir(exist_ok=True)
    dest.write_bytes(b"old export")
    source = project
    if alias:
        source = tmp_path / "source-alias"
        source.symlink_to(project, target_is_directory=True)
    result = archives.export_project(source, dest, force=True)
    with zipfile.ZipFile(result["path"]) as output:
        assert output.namelist() == [f"{source.name}/data.txt"]
        assert output.read(output.namelist()[0]) == b"project data"
    _assert_no_staging(tmp_path)


def test_destination_created_during_export_is_not_replaced(project, tmp_path, monkeypatch):
    dest = tmp_path / "racing.zip"
    write = archives._write_project_zip

    def race(*args, **kwargs):
        write(*args, **kwargs)
        dest.write_bytes(b"other writer")

    monkeypatch.setattr(archives, "_write_project_zip", race)
    with pytest.raises(FileExistsError):
        archives.export_project(project, dest)
    assert dest.read_bytes() == b"other writer"
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("force", [False, True])
def test_destination_symlink_does_not_modify_target(project, tmp_path, force):
    target = tmp_path / "external"
    dest = tmp_path / "export.zip"
    dest.symlink_to(target)
    if force:
        archives.export_project(project, dest, force=True)
        assert not dest.is_symlink()
        assert zipfile.is_zipfile(dest)
    else:
        with pytest.raises(FileExistsError):
            archives.export_project(project, dest)
        assert dest.is_symlink()
    assert not target.exists()
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("mode", [0o600, 0o640, 0o444])
def test_force_export_preserves_existing_regular_file_mode(project, tmp_path, mode):
    dest = tmp_path / "export.zip"
    dest.write_bytes(b"old export")
    dest.chmod(mode)
    archives.export_project(project, dest, force=True)
    assert dest.stat().st_mode & 0o777 == mode
    assert zipfile.is_zipfile(dest)
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("phase", ["extract", "close", "annotations", "mark", "quarantine", "owner"])
@pytest.mark.parametrize("cancel", [False, True], ids=["io-error", "cancel"])
def test_failed_import_reclaims_staging(archive, tmp_path, monkeypatch, phase, cancel):
    error = KeyboardInterrupt if cancel else OSError
    from core.project import ProjectManager

    def fail(*args, **kwargs):
        raise error("injected import failure")

    if phase in {"extract", "close"}:
        proxy = types.ModuleType("archive_zipfile")
        proxy.__dict__.update(vars(zipfile))

        class FailingZip(zipfile.ZipFile):
            def open(self, name, *args, **kwargs):
                filename = name.filename if isinstance(name, zipfile.ZipInfo) else name
                if phase == "extract" and filename == "demo/data.txt":
                    fail()
                return super().open(name, *args, **kwargs)

            def close(self):
                armed = self.fp is not None and self.mode == "r"
                super().close()
                if phase == "close" and armed:
                    fail()

        proxy.ZipFile = FailingZip
        monkeypatch.setattr(archives, "zipfile", proxy)
    elif phase == "owner":
        monkeypatch.setattr(ProjectManager, "_output_dir_owner", fail)
    else:
        symbol = {"annotations": "_demote_imported_annotations",
                  "mark": "_mark_imported_runs",
                  "quarantine": "_quarantine_imported_privileged_artifacts"}[phase]
        monkeypatch.setattr(archives, symbol, fail)
    with pytest.raises((error, ValueError), match="injected import failure"):
        archives.import_project(archive, tmp_path / "registry", output_base=tmp_path / "output")
    _assert_no_staging(tmp_path)
    assert not (tmp_path / "output/demo").exists()
    assert not (tmp_path / "registry/demo.json").exists()


@pytest.mark.parametrize("cancel", [False, True], ids=["io-error", "cancel"])
def test_import_setup_failure_cleans_allocation(archive, tmp_path, monkeypatch, cancel):
    proxy = types.ModuleType("archive_os")
    proxy.__dict__.update(vars(os))
    error = KeyboardInterrupt if cancel else OSError
    allocated = []

    def fail_chmod(path, *args, **kwargs):
        allocated.append(Path(path))
        assert allocated[-1].is_dir()
        raise error("chmod failed")

    proxy.chmod = fail_chmod
    monkeypatch.setattr(archives, "os", proxy)
    with pytest.raises(error, match="chmod failed"):
        archives.import_project(archive, tmp_path / "registry", output_base=tmp_path / "output")
    assert allocated and all(not path.exists() for path in allocated)
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_import_cleanup_removes_restricted_children(archive, tmp_path, monkeypatch, mode):
    def fail(root):
        nested = root / "locked"
        nested.mkdir()
        (nested / "partial").write_text("partial")
        nested.chmod(mode)
        raise KeyboardInterrupt("cancelled after extraction")

    monkeypatch.setattr(archives, "_demote_imported_annotations", fail)
    with pytest.raises(KeyboardInterrupt, match="cancelled after extraction"):
        archives.import_project(archive, tmp_path / "registry", output_base=tmp_path / "output")
    _assert_no_staging(tmp_path)


def test_successful_import_keeps_published_tree(archive, tmp_path):
    result = archives.import_project(archive, tmp_path / "registry", output_base=tmp_path / "output")
    published = Path(result["output_dir"])
    assert (published / "data.txt").read_text() == "project data"
    assert (tmp_path / "registry/demo.json").is_file()
    _assert_no_staging(tmp_path)


@pytest.mark.parametrize("cancel", [False, True], ids=["io-error", "cancel"])
def test_failed_force_import_preserves_previous_project(archive, tmp_path, monkeypatch, cancel):
    registry, output = tmp_path / "registry", tmp_path / "output"
    result = archives.import_project(archive, registry, output_base=output)
    published = Path(result["output_dir"])
    (published / "local.txt").write_text("keep local data")
    registration = (registry / "demo.json").read_bytes()
    error = KeyboardInterrupt if cancel else OSError

    def fail(*args, **kwargs):
        raise error("quarantine failed")

    monkeypatch.setattr(archives, "_quarantine_imported_privileged_artifacts", fail)
    with pytest.raises((error, ValueError), match="quarantine failed"):
        archives.import_project(archive, registry, output_base=output, force=True)
    assert (published / "local.txt").read_text() == "keep local data"
    assert (registry / "demo.json").read_bytes() == registration
    _assert_no_staging(tmp_path)


def test_export_does_not_pack_abandoned_staging(project, tmp_path):
    abandoned = project / ".export-old"
    abandoned.mkdir()
    (abandoned / "archive.zip").write_bytes(b"old partial export")
    dest = tmp_path / "export.zip"
    archives.export_project(project, dest)
    with zipfile.ZipFile(dest) as output:
        assert output.namelist() == ["demo/data.txt"]
    assert (abandoned / "archive.zip").read_bytes() == b"old partial export"
