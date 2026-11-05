"""Project purge removes only an owned tree and retains failed registrations."""

from contextlib import contextmanager
import os

import pytest

from core.project import clean
from core.project import project as model
from core.testing.restricted_tree import restricted_tree


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_REGISTRY_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(model, "DEFAULT_OUTPUT_BASE", tmp_path / "out/projects")
    manager = model.ProjectManager(projects_dir=tmp_path / "state/projects")
    project = manager.create("demo", str(tmp_path / "target"))
    (project.output_path / "payload").write_text("keep until purged")
    (manager.projects_dir / ".active").symlink_to("demo.json")
    return manager, project


def _registration(manager):
    return (manager.projects_dir / "demo.json").read_bytes()


def _retained(manager, original):
    assert _registration(manager) == original
    assert os.readlink(manager.projects_dir / ".active") == "demo.json"


@pytest.mark.parametrize("spelling", ["base", "parent"])
@pytest.mark.parametrize("force", [False, True])
def test_shared_output_base_cannot_be_purged(managed, spelling, force):
    manager, project = managed
    root = project.output_path
    project.output_dir = str(model.DEFAULT_OUTPUT_BASE if spelling == "base" else root / "..")
    manager._save(project)
    before = _registration(manager)
    with pytest.raises(ValueError, match="strict child"):
        manager.delete("demo", purge=True, force=force)
    assert (root / "payload").read_text() == "keep until purged"
    _retained(manager, before)


@pytest.mark.parametrize("shape", ["file", "fifo", "symlink", "dangling"])
def test_non_directory_output_is_refused_without_losing_registration(managed, shape):
    manager, project = managed
    original_root = project.output_path
    path = model.DEFAULT_OUTPUT_BASE / "unexpected"
    if shape == "file":
        path.write_text("external data")
    elif shape == "fifo":
        os.mkfifo(path)
    else:
        path.symlink_to(original_root if shape == "symlink" else original_root / "absent")
    project.output_dir = str(path)
    manager._save(project)
    before = _registration(manager)
    with pytest.raises(ValueError, match="non-directory"):
        manager.delete("demo", purge=True, force=True)
    assert os.path.lexists(path)
    assert (original_root / "payload").read_text() == "keep until purged"
    _retained(manager, before)


@pytest.mark.parametrize("shape", ["same", "child", "parent", "alias"])
@pytest.mark.parametrize("force", [False, True])
def test_overlapping_project_claims_are_retained(managed, shape, force):
    manager, project = managed
    root = project.output_path
    other = manager.create("other", project.target)
    if shape == "same":
        other.output_dir = str(root)
    elif shape == "child":
        nested = root / "nested-project"
        nested.mkdir()
        other.output_dir = str(nested)
    elif shape == "parent":
        other.output_dir = str(root.parent)
    else:
        alias = root.parent / "alias"
        alias.symlink_to(root, target_is_directory=True)
        other.output_dir = str(alias)
    manager._save(other)  # Model a legacy or manually edited registry.
    before = _registration(manager)
    with pytest.raises(ValueError, match="overlaps project 'other'"):
        manager.delete("demo", purge=True, force=force)
    assert (root / "payload").read_text() == "keep until purged"
    assert manager.load("other") is not None
    _retained(manager, before)


@pytest.mark.parametrize("failure", ["receipt", "io-error", "cancel"])
@pytest.mark.parametrize("force", [False, True])
def test_failed_removal_retains_registration_and_bindings(managed, monkeypatch, failure, force):
    manager, project = managed
    before = _registration(manager)
    bindings = []
    monkeypatch.setattr(manager, "_rewrite_bindings", lambda *args: bindings.append(args))

    def fail(path):
        if failure == "receipt":
            return False
        if failure == "cancel":
            raise KeyboardInterrupt("cancelled purge")
        raise OSError("disk error")

    monkeypatch.setattr(model, "rmtree_hardened", fail)
    with pytest.raises(KeyboardInterrupt if failure == "cancel" else OSError):
        manager.delete("demo", purge=True, force=force)
    assert (project.output_path / "payload").read_text() == "keep until purged"
    assert bindings == []
    _retained(manager, before)


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_purge_reclaims_restricted_tool_output(managed, mode):
    manager, project = managed
    with restricted_tree(project.output_path, mode):
        manager.delete("demo", purge=True)
        assert not project.output_path.exists()
    assert manager.load("demo") is None
    assert not os.path.lexists(manager.projects_dir / ".active")


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_explicit_force_can_reclaim_restricted_output_root(managed, mode):
    manager, project = managed
    with restricted_tree(project.output_path):
        project.output_path.chmod(mode)
        manager.delete("demo", purge=True, force=True)
        assert not project.output_path.exists()
    assert manager.load("demo") is None


@pytest.mark.parametrize("phase", ["liveness", "claims"])
@pytest.mark.parametrize("replacement", ["directory", "symlink"])
def test_changed_output_identity_is_not_purged(managed, monkeypatch, phase, replacement):
    manager, project = managed
    root = project.output_path
    parked = root.with_name("original")
    before = _registration(manager)

    def replace():
        root.rename(parked)
        if replacement == "directory":
            root.mkdir()
            (root / "new-data").write_text("new owner")
        else:
            root.symlink_to(parked, target_is_directory=True)

    if phase == "liveness":
        def split(dirs):
            replace()
            return [], []
        monkeypatch.setattr(clean, "split_live_runs", split)
    else:
        listing = manager.list_projects
        def list_projects():
            result = listing()
            replace()
            return result
        monkeypatch.setattr(manager, "list_projects", list_projects)
    with pytest.raises(OSError, match="output directory changed"):
        manager.delete("demo", purge=True)
    assert (parked / "payload").read_text() == "keep until purged"
    assert os.path.lexists(root)
    if replacement == "directory":
        assert (root / "new-data").read_text() == "new owner"
    _retained(manager, before)


def test_new_output_after_missing_root_is_not_purged(managed, monkeypatch):
    manager, project = managed
    root = project.output_path
    (root / "payload").unlink()
    root.rmdir()
    before = _registration(manager)

    def split(dirs):
        root.mkdir()
        (root / "new-data").write_text("new owner")
        return [], []

    monkeypatch.setattr(clean, "split_live_runs", split)
    with pytest.raises(OSError, match="output directory changed"):
        manager.delete("demo", purge=True)
    assert (root / "new-data").read_text() == "new owner"
    _retained(manager, before)


def test_missing_output_still_allows_registry_cleanup(managed):
    manager, project = managed
    (project.output_path / "payload").unlink()
    project.output_path.rmdir()
    manager.delete("demo", purge=True)
    assert manager.load("demo") is None
    assert not os.path.lexists(manager.projects_dir / ".active")


@pytest.mark.parametrize("force", [False, True])
def test_live_run_guard_remains_in_force_unless_overridden(managed, monkeypatch, force):
    manager, project = managed
    run = project.output_path / "run"
    run.mkdir()
    before = _registration(manager)
    monkeypatch.setattr(clean, "split_live_runs", lambda dirs: ([], list(dirs)))
    if force:
        manager.delete("demo", purge=True, force=True)
        assert not project.output_path.exists()
    else:
        with pytest.raises(ValueError, match="live run"):
            manager.delete("demo", purge=True)
        assert run.is_dir()
        _retained(manager, before)


def test_purge_holds_output_claim_while_removing(managed, monkeypatch):
    manager, project = managed
    original_lock = manager._output_dir_claim_lock
    original_remove = model.rmtree_hardened
    held = []

    @contextmanager
    def claim(path):
        with original_lock(path):
            held.append(path)
            try:
                yield
            finally:
                held.pop()

    def remove(path):
        assert held == [project.output_path]
        assert manager.load("demo") is not None
        return original_remove(path)

    monkeypatch.setattr(manager, "_output_dir_claim_lock", claim)
    monkeypatch.setattr(model, "rmtree_hardened", remove)
    manager.delete("demo", purge=True)
    assert held == []
    assert not project.output_path.exists()


@pytest.mark.parametrize("force", [False, True])
def test_output_outside_expected_base_is_retained(managed, tmp_path, force):
    manager, project = managed
    outside = tmp_path / "custom-output"
    outside.mkdir()
    (outside / "payload").write_text("custom data")
    project.output_dir = str(outside)
    manager._save(project)
    before = _registration(manager)
    with pytest.raises(ValueError, match="strict child"):
        manager.delete("demo", purge=True, force=force)
    assert (outside / "payload").read_text() == "custom data"
    _retained(manager, before)


def test_partial_cleanup_retains_registration_until_successful_retry(managed, monkeypatch):
    manager, project = managed
    before = _registration(manager)

    def partial(path):
        (path / "payload").unlink()
        return False

    with monkeypatch.context() as fault:
        fault.setattr(model, "rmtree_hardened", partial)
        with pytest.raises(OSError, match="Could not remove"):
            manager.delete("demo", purge=True)
    assert project.output_path.exists()
    _retained(manager, before)
    manager.delete("demo", purge=True)
    assert not project.output_path.exists()
    assert manager.load("demo") is None
    assert not os.path.lexists(manager.projects_dir / ".active")
