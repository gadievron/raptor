"""Artifact publication retains ownership of the private scratch root."""

from contextlib import contextmanager

import pytest

from core.project import export, report
from core.run import scratch
from core.project.tests import test_archive_staging_lifecycle as archive_cases

archive = archive_cases.archive


@pytest.fixture(params=["export", "import", "report"])
def artifact(request, tmp_path, monkeypatch, archive):
    roots = []
    state = {"error": None}
    real_scope = scratch.scratch_dir
    consumer = report if request.param == "report" else export
    source = tmp_path / "source"
    source.mkdir()
    (source / "data").write_bytes(b"artifact data")
    output = tmp_path / "output"

    @contextmanager
    def workspace(*args, **kwargs):
        assert kwargs["keepalive"] is True
        with real_scope(*args, **kwargs) as root:
            roots.append(root)
            yield root

    def observe():
        root = roots[-1]
        assert root.exists()
        assert str(root) in scratch._keepalive_paths
        nested = root / "restricted-debris"
        nested.mkdir()
        (nested / "partial").write_bytes(b"partial artifact")
        nested.chmod(0)
        if state["error"] is not None:
            raise state["error"]

    monkeypatch.setattr(consumer, "scratch_dir", workspace)
    if request.param == "import":
        publish = export.publish_new_directory

        def publish_child(child, destination):
            assert child.parent == roots[-1]
            assert child != roots[-1]
            observe()
            publish(child, destination)
            assert roots[-1].is_dir()

        monkeypatch.setattr(export, "publish_new_directory", publish_child)
        invoke = lambda: export.import_project(archive, tmp_path / "registry", output_base=output)
    elif request.param == "export":
        write = export._write_project_zip

        def build(*args, **kwargs):
            result = write(*args, **kwargs)
            observe()
            return result

        monkeypatch.setattr(export, "_write_project_zip", build)
        invoke = lambda: export.export_project(source, tmp_path / "result.zip")
    else:
        write = report._write_findings_directory

        def build(*args, **kwargs):
            result = write(*args, **kwargs)
            observe()
            return result

        monkeypatch.setattr(report, "_write_findings_directory", build)
        invoke = lambda: report.export_findings_directory([], output)
    return request.param, state, invoke, roots, source


def reclaimed(roots, source):
    assert len(roots) == 1 and not roots[0].exists()
    assert str(roots[0]) not in scratch._keepalive_paths
    assert (source / "data").read_bytes() == b"artifact data"


@pytest.mark.parametrize("error_type", [None, OSError, ValueError, KeyboardInterrupt, SystemExit])
def test_staging_releases_roots_on_success_and_failure(artifact, error_type):
    role, state, invoke, roots, source = artifact
    state["error"] = error_type("artifact failed") if error_type else None
    if error_type:
        with pytest.raises(error_type) as caught:
            invoke()
        assert caught.value is state["error"]
    else:
        invoke()
    reclaimed(roots, source)


@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup_type", [OSError, KeyboardInterrupt])
def test_staging_preserves_original_error(artifact, monkeypatch, error_type, cleanup_type):
    role, state, invoke, roots, source = artifact
    state["error"] = error_type("original failure")
    cleanup = report._clear_generated_findings_dir if role == "report" else scratch.rmtree_hardened
    calls = []

    def clean(root):
        calls.append(root)
        cleanup(root)
        raise cleanup_type("cleanup failed")

    monkeypatch.setattr(report if role == "report" else scratch,
                        "_clear_generated_findings_dir" if role == "report" else "rmtree_hardened", clean)
    with pytest.raises(error_type) as caught:
        invoke()
    assert caught.value is state["error"]
    assert calls == roots
    reclaimed(roots, source)


def test_cleanup_oserror_preserves_successful_artifact(artifact, monkeypatch):
    role, state, invoke, roots, source = artifact
    cleanup = report._clear_generated_findings_dir if role == "report" else scratch.rmtree_hardened
    calls = []

    def clean(root):
        calls.append(root)
        cleanup(root)
        raise OSError("cleanup failed")

    monkeypatch.setattr(report if role == "report" else scratch,
                        "_clear_generated_findings_dir" if role == "report" else "rmtree_hardened", clean)
    invoke()
    assert calls == roots
    reclaimed(roots, source)


@pytest.mark.parametrize("shape", ["empty", "populated", "file", "symlink", "dangling", "fifo"])
def test_import_publication_preserves_late_contender(tmp_path, monkeypatch, archive, shape):
    import os

    output = tmp_path / "output"
    publish = export.publish_new_directory
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "data").write_bytes(b"preserve")
    occupied = []

    def race(source, destination):
        assert str(source.parent) in scratch._keepalive_paths
        if shape in {"empty", "populated"}:
            destination.mkdir()
            if shape == "populated":
                (destination / "data").write_bytes(b"contender")
        elif shape == "file":
            destination.write_bytes(b"contender")
        elif shape in {"symlink", "dangling"}:
            destination.symlink_to(victim if shape == "symlink" else tmp_path / "missing")
        else:
            os.mkfifo(destination)
        occupied.append(destination.lstat().st_ino)
        publish(source, destination)

    monkeypatch.setattr(export, "publish_new_directory", race)
    with pytest.raises(OSError):
        export.import_project(archive, tmp_path / "registry", output_base=output)
    assert (output / "demo").lstat().st_ino == occupied[0]
    assert (victim / "data").read_bytes() == b"preserve"
    assert not list(output.glob(".import-*"))
    assert not (tmp_path / "registry" / "demo.json").exists()
    assert not scratch._keepalive_paths
