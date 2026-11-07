"""Merge publication and cleanup use real run directories and artifact bytes."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.project import clean, cli, merge
from core.run import pin, scratch
from core.testing.module_bindings import patch_module_attribute
from core.testing.module_state import isolated_module_state
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def merge_case(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    root = tmp_path / "output"
    root.mkdir()
    runs = []
    for name in ("scan-new", "scan-old"):
        run = root / name
        run.mkdir()
        (run / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": "scan", "status": "completed",
            "project": None, "project_source": "none",
        }))
        (run / "findings.json").write_text(json.dumps({"findings": [{
            "id": name, "file": name + ".c", "function": "main", "line": 1,
        }]}))
        (run / (name + ".txt")).write_text(name)
        runs.append(run)
    project = SimpleNamespace(
        name="demo", target=str(tmp_path / "source"), output_path=root,
        get_run_dirs_by_type=lambda: {"scan": runs},
    )
    monkeypatch.setattr(cli, "unique_run_suffix", lambda _sep: "merged")
    with isolated_module_state(pin, {"_frozen_pins": {}}):
        yield project, root, runs


def assert_no_staging(root):
    assert not list(root.glob(".raptor-merge-*"))


def test_complete_run_is_published_before_source_cleanup(merge_case, monkeypatch):
    project, root, runs = merge_case
    final = root / "scan-merged"
    original = clean.rmtree_hardened
    removed = []

    def remove(path):
        removed.append(path)
        metadata = json.loads((final / ".raptor-run.json").read_text())
        assert metadata["status"] == "completed"
        assert metadata["project"] == "demo"
        assert metadata["target_path"] == project.target
        assert len(json.loads((final / "findings.json").read_text())["findings"]) == 2
        assert (final / "scan-old.txt").read_text() == "scan-old"
        assert (final / "scan-new.txt").read_text() == "scan-new"
        return original(path)

    monkeypatch.setattr(clean, "rmtree_hardened", remove)
    cli._do_merge(project, "all", yes=True)
    assert removed == runs
    assert not any(path.exists() for path in runs)
    assert str(final.resolve()) in pin._frozen_pins
    assert all(".raptor-merge-" not in path for path in pin._frozen_pins)
    assert_no_staging(root)


@pytest.mark.parametrize("phase", ["copy", "metadata", "publication"])
@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_failure_reclaims_unpublished_artifacts(merge_case, monkeypatch, capsys, phase, error):
    project, root, runs = merge_case
    final = root / "scan-merged"
    observed = []
    if phase == "copy":
        original = merge.shutil.copy2

        def copy(source, destination, *a, **kw):
            path = Path(destination)
            assert str(path.parent.parent) in scratch._keepalive_paths
            assert path.parent.parent.parent == root
            assert not final.exists()
            original(source, destination, *a, **kw)
            path.parent.chmod(0o500)
            observed.append(path)
            raise error("copy fault")

        patch_module_attribute(monkeypatch, merge, "shutil", "copy2", copy)
    elif phase == "metadata":
        from core import json as json_module
        original = json_module.save_json

        def save(path, *a, **kw):
            if Path(path).name == ".raptor-run.json":
                assert not final.exists()
                observed.append(path)
                Path(path).write_bytes(b"partial metadata")
                raise error("metadata fault")
            return original(path, *a, **kw)

        monkeypatch.setattr(json_module, "save_json", save)
    else:
        from core import atomic_fs

        def publish(source, destination):
            assert (source / ".raptor-run.json").is_file()
            assert not final.exists()
            observed.append(source)
            raise error("publication fault")

        monkeypatch.setattr(atomic_fs, "publish_new_directory", publish)
    if issubclass(error, Exception):
        cli._do_merge(project, "all", yes=True)
        assert "preserved" in capsys.readouterr().out.lower()
    else:
        with pytest.raises(error, match="fault"):
            cli._do_merge(project, "all", yes=True)
    assert observed
    assert not final.exists()
    assert set(root.iterdir()) == set(runs)
    assert all((run / (run.name + ".txt")).is_file() for run in runs)
    assert pin._frozen_pins == {}
    assert_no_staging(root)


@pytest.mark.parametrize("kind", ["file", "directory", "populated", "symlink", "dangling", "fifo"])
def test_publication_preserves_existing_destination(merge_case, kind, capsys):
    project, root, runs = merge_case
    final = root / "scan-merged"
    outside = root.parent / "outside"
    outside.write_text("retain")
    if kind == "directory":
        final.mkdir()
    elif kind == "populated":
        final.mkdir()
        (final / "borrowed").write_text("retain")
    elif kind == "symlink":
        final.symlink_to(outside)
    elif kind == "dangling":
        final.symlink_to("missing")
    elif kind == "fifo":
        os.mkfifo(final)
    else:
        final.write_text("retain")
    identity = final.lstat().st_ino
    cli._do_merge(project, "all", yes=True)
    assert "publication failed" in capsys.readouterr().out
    assert final.lstat().st_ino == identity
    assert outside.read_text() == "retain"
    assert all(run.is_dir() for run in runs)
    assert pin._frozen_pins == {}
    assert_no_staging(root)


@pytest.mark.parametrize("timing", ["confirm", "copy", "cleanup"])
def test_replaced_sources_survive_cleanup(merge_case, monkeypatch, capsys, timing):
    project, root, runs = merge_case
    victim = runs[0]
    retired = root.parent / "retired"

    def replace():
        victim.rename(retired)
        victim.mkdir()
        (victim / "borrowed").write_text("replacement")

    if timing == "confirm":
        def confirm(_prompt):
            replace()
            return True
        monkeypatch.setattr(cli, "_confirm", confirm)
    elif timing == "copy":
        original = merge.merge_runs
        def copy(*a, **kw):
            result = original(*a, **kw)
            replace()
            return result
        monkeypatch.setattr(merge, "merge_runs", copy)
    else:
        original = clean._run_dir_size
        def size(path):
            result = original(path)
            if path == victim:
                replace()
            return result
        monkeypatch.setattr(clean, "_run_dir_size", size)
    cli._do_merge(project, "all", yes=timing != "confirm")
    assert (victim / "borrowed").read_text() == "replacement"
    assert not runs[1].exists()
    assert "source directory changed" in capsys.readouterr().out
    assert (root / "scan-merged" / ".raptor-run.json").is_file()
    assert_no_staging(root)


@pytest.mark.parametrize("kind", ["outside", "root", "symlink"])
def test_invalid_source_cannot_be_merged_or_deleted(merge_case, monkeypatch, capsys, kind):
    project, root, runs = merge_case
    outside = root.parent / "borrowed"
    outside.mkdir()
    (outside / "keep").write_text("retain")
    if kind == "outside":
        runs[0] = outside
    elif kind == "root":
        runs[0] = root
    else:
        link = root / "linked"
        link.symlink_to(outside, target_is_directory=True)
        runs[0] = link
    def no_copy(*a, **kw):
        pytest.fail("invalid source reached copying")
    monkeypatch.setattr(merge, "merge_runs", no_copy)
    cli._do_merge(project, "all", yes=True)
    assert "merge refused" in capsys.readouterr().out
    assert (outside / "keep").read_text() == "retain"
    assert all(run.exists() for run in runs)
    assert_no_staging(root)


@pytest.mark.parametrize("timing", ["pin", "size"])
def test_missing_merged_output_preserves_sources(merge_case, monkeypatch, capsys, timing):
    project, root, runs = merge_case
    final = root / "scan-merged"
    retired = root.parent / "completed"
    if timing == "pin":
        def freeze(*a):
            final.rename(retired)
        monkeypatch.setattr(pin, "freeze_run_pin", freeze)
    else:
        original = clean._run_dir_size
        def size(path):
            result = original(path)
            if final.exists():
                final.rename(retired)
            return result
        monkeypatch.setattr(clean, "_run_dir_size", size)
    cli._do_merge(project, "all", yes=True)
    assert all(run.exists() for run in runs)
    assert "source runs preserved" in capsys.readouterr().out
    assert (retired / "findings.json").is_file()
    assert_no_staging(root)


def test_failed_source_cleanup_does_not_skip_remaining_sources(merge_case, monkeypatch, capsys):
    project, root, runs = merge_case
    original = clean.rmtree_hardened
    attempted = []
    def remove(path):
        attempted.append(path)
        if path == runs[0]:
            return False
        return original(path)
    monkeypatch.setattr(clean, "rmtree_hardened", remove)
    cli._do_merge(project, "all", yes=True)
    assert attempted == runs
    assert runs[0].exists() and not runs[1].exists()
    assert "failed to delete" in capsys.readouterr().out
    assert (root / "scan-merged" / "findings.json").is_file()
    assert_no_staging(root)


def test_hardened_cleanup_reclaims_restricted_source_directories(merge_case, monkeypatch):
    project, root, runs = merge_case
    original = pin.freeze_run_pin
    restricted = []
    def freeze(*a):
        original(*a)
        for run in runs:
            child = run / "restricted"
            child.mkdir()
            (child / "data").write_text("temporary")
            child.chmod(0)
            restricted.append(child)
    monkeypatch.setattr(pin, "freeze_run_pin", freeze)
    try:
        cli._do_merge(project, "all", yes=True)
        assert not any(run.exists() for run in runs)
        assert (root / "scan-merged").is_dir()
    finally:
        for child in restricted:
            if child.exists():
                child.chmod(0o700)
    assert_no_staging(root)


def test_late_live_run_is_retained_without_blocking_other_cleanup(merge_case, monkeypatch, capsys):
    project, root, runs = merge_case
    active = set()
    original = merge.merge_runs
    def copy(*a, **kw):
        result = original(*a, **kw)
        active.add(runs[0])
        return result
    monkeypatch.setattr(merge, "merge_runs", copy)
    monkeypatch.setattr(clean, "run_is_live", lambda path: path in active)
    cli._do_merge(project, "all", yes=True)
    assert runs[0].exists() and not runs[1].exists()
    assert "resumed while merging" in capsys.readouterr().out
    assert_no_staging(root)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_cancellation_after_publication_preserves_complete_output(merge_case, monkeypatch, error):
    from core import atomic_fs
    project, root, runs = merge_case
    original = atomic_fs.publish_new_directory
    def publish(*a):
        original(*a)
        raise error("after rename")
    monkeypatch.setattr(atomic_fs, "publish_new_directory", publish)
    with pytest.raises(error, match="after rename"):
        cli._do_merge(project, "all", yes=True)
    assert all(run.is_dir() for run in runs)
    assert (root / "scan-merged" / ".raptor-run.json").is_file()
    assert (root / "scan-merged" / "scan-old.txt").is_file()
    assert pin._frozen_pins == {}
    assert_no_staging(root)


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
def test_cancellation_during_source_removal_retains_remaining_sources(merge_case, monkeypatch, error):
    project, root, runs = merge_case
    attempted = []
    def remove(path):
        attempted.append(path)
        raise error("removal")
    monkeypatch.setattr(clean, "rmtree_hardened", remove)
    with pytest.raises(error, match="removal"):
        cli._do_merge(project, "all", yes=True)
    assert attempted == [runs[0]]
    assert all(run.is_dir() for run in runs)
    assert (root / "scan-merged" / "findings.json").is_file()
    assert_no_staging(root)


def test_pin_failure_keeps_complete_output_and_sources(merge_case, monkeypatch, capsys):
    project, root, runs = merge_case
    def freeze(*a):
        raise OSError("pin failed")
    monkeypatch.setattr(pin, "freeze_run_pin", freeze)
    cli._do_merge(project, "all", yes=True)
    assert all(run.is_dir() for run in runs)
    assert (root / "scan-merged" / ".raptor-run.json").is_file()
    assert "pin failed" in capsys.readouterr().out
    assert_no_staging(root)


def test_failed_group_does_not_block_other_merges(merge_case, monkeypatch):
    project, root, runs = merge_case
    other = []
    for name in ("other-new", "other-old"):
        path = root / name
        path.mkdir()
        (path / "keep.txt").write_text(name)
        other.append(path)
    project.get_run_dirs_by_type = lambda: {"scan": runs, "other": other}
    original = merge.merge_runs
    def copy(sources, destination):
        result = original(sources, destination)
        if sources[0] in runs:
            raise OSError("first group")
        return result
    monkeypatch.setattr(merge, "merge_runs", copy)
    cli._do_merge(project, "all", yes=True)
    assert all(run.exists() for run in runs)
    assert not any(run.exists() for run in other)
    assert not (root / "scan-merged").exists()
    assert (root / "other-merged" / ".raptor-run.json").is_file()
    assert_no_staging(root)


def test_retained_output_path_is_terminal_escaped(merge_case, monkeypatch, capsys):
    project, root, runs = merge_case
    project.get_run_dirs_by_type = lambda: {"scan\x1b[2J": runs}
    def freeze(*a):
        raise OSError("pin failed")
    monkeypatch.setattr(pin, "freeze_run_pin", freeze)
    cli._do_merge(project, "all", yes=True)
    output = capsys.readouterr().out
    assert "pin failed" in output and "merged output left at" in output
    assert "\x1b" not in output
    assert all(run.exists() for run in runs)
    assert_no_staging(root)
