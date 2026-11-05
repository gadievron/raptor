"""Output operations cannot remove or replace operator registry trees."""

import json
import os
import time
import zipfile

import pytest

from core.project import clean, export, registry_home
from core.project import project as model


@pytest.fixture(autouse=True)
def owned_registries(tmp_path, monkeypatch):
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "state"))


@pytest.mark.parametrize("kind", ["projects", "sessions", "explicit"])
@pytest.mark.parametrize("relation", ["same", "ancestor", "descendant"])
@pytest.mark.parametrize("alias", [False, True], ids=["direct", "alias"])
def test_registry_overlap_refused_without_reading_or_mutating_state(tmp_path, kind, relation, alias):
    root = {"projects": registry_home.projects_dir(),
            "sessions": registry_home.sessions_dir(),
            "explicit": tmp_path / "custom/projects"}[kind]
    root.mkdir(parents=True)
    marker = root / "state.json"
    marker.write_text("keep operator state")
    candidate = {"same": root, "ancestor": root.parent,
                 "descendant": root / "runs/old"}[relation]
    if alias:
        link = tmp_path / "output-alias"
        link.symlink_to(candidate, target_is_directory=True)
        candidate = link
    extra = root if kind == "explicit" else None
    with pytest.raises(ValueError, match="overlaps operator registry"):
        registry_home.refuse_registry_overlap(candidate, extra_projects_dir=extra)
    assert marker.read_text() == "keep operator state"
    assert not (root / "runs").exists()


@pytest.mark.parametrize("kind", ["projects", "sessions", "explicit"])
def test_unrelated_sibling_with_common_prefix_is_allowed(tmp_path, kind):
    root = {"projects": registry_home.projects_dir(),
            "sessions": registry_home.sessions_dir(),
            "explicit": tmp_path / "custom/projects"}[kind]
    extra = root if kind == "explicit" else None
    candidate = root.with_name(root.name + "-output")
    registry_home.refuse_registry_overlap(candidate, extra_projects_dir=extra)
    assert not candidate.exists()
    assert not root.exists()


def test_missing_registry_locations_are_protected_without_creation(tmp_path):
    candidate = tmp_path / "state"
    assert not candidate.exists()
    with pytest.raises(ValueError, match="overlaps operator registry"):
        registry_home.refuse_registry_overlap(candidate)
    assert not candidate.exists()


def test_registry_relocation_is_resolved_at_each_call(tmp_path, monkeypatch):
    previous = registry_home.projects_dir()
    with pytest.raises(ValueError, match="overlaps operator registry"):
        registry_home.refuse_registry_overlap(previous)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(tmp_path / "new-state"))
    registry_home.refuse_registry_overlap(previous)
    with pytest.raises(ValueError, match="overlaps operator registry"):
        registry_home.refuse_registry_overlap(registry_home.sessions_dir())


def test_invalid_registry_override_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, "relative")
    with pytest.raises(registry_home.RegistryHomeError):
        registry_home.refuse_registry_overlap(tmp_path / "output")


@pytest.mark.parametrize("kind", ["explicit", "configured"])
@pytest.mark.parametrize("force", [False, True])
def test_purge_retains_registry_nested_in_output(tmp_path, monkeypatch, kind, force):
    monkeypatch.setattr(model, "DEFAULT_OUTPUT_BASE", tmp_path / "output")
    manager = model.ProjectManager(projects_dir=tmp_path / "registry")
    project = manager.create("demo", str(tmp_path / "target"))
    root = project.output_path
    (root / "payload").write_text("project data")
    if kind == "explicit":
        manager = model.ProjectManager(projects_dir=root / "registry")
        manager._save(project)
        protected = manager.projects_dir
    else:
        monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(root / "operator"))
        protected = registry_home.sessions_dir()
        protected.mkdir(parents=True)
    (protected / "other.json").write_text("other operator state")
    bookmark = manager.projects_dir / ".active"
    bookmark.symlink_to("demo.json")
    registration = (manager.projects_dir / "demo.json").read_bytes()
    with pytest.raises(ValueError, match="overlaps operator registry"):
        manager.delete("demo", purge=True, force=force)
    assert (root / "payload").read_text() == "project data"
    assert (protected / "other.json").read_text() == "other operator state"
    assert (manager.projects_dir / "demo.json").read_bytes() == registration
    assert os.readlink(bookmark) == "demo.json"


@pytest.mark.parametrize("kind", ["projects", "sessions"])
@pytest.mark.parametrize("relation", ["same", "ancestor", "descendant"])
def test_run_cleanup_retains_registry_and_zeroes_deletion_receipt(tmp_path, monkeypatch, kind, relation):
    protected = registry_home.projects_dir() if kind == "projects" else registry_home.sessions_dir()
    protected.mkdir(parents=True)
    (protected / "state.json").write_text("operator state")
    candidate = {"same": protected, "ancestor": protected.parent,
                 "descendant": protected / "run-old"}[relation]
    candidate.mkdir(exist_ok=True)
    monkeypatch.setattr(clean, "run_is_live", lambda path: False)
    snapshots = []
    plan = {"delete_dirs": [candidate], "deleted": [candidate.name], "freed_bytes": 123}
    with pytest.raises(ValueError, match="overlaps operator registry"):
        clean.execute_clean(plan, output_path=tmp_path, before_delete=snapshots.append)
    assert (protected / "state.json").read_text() == "operator state"
    assert candidate.exists()
    assert snapshots == []
    assert plan["deleted"] == [] and plan["freed_bytes"] == 0


def test_cleanup_rechecks_registries_after_snapshot_callback(tmp_path, monkeypatch):
    root = tmp_path / "project"
    candidate = root / "old-run"
    candidate.mkdir(parents=True)
    (candidate / "data").write_text("run data")
    monkeypatch.setattr(clean, "run_is_live", lambda path: False)

    def relocate(path):
        monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(path / "operator"))
        registry = registry_home.sessions_dir()
        registry.mkdir(parents=True)
        (registry / "state.json").write_text("new operator state")

    plan = {"delete_dirs": [candidate]}
    with pytest.raises(ValueError, match="overlaps operator registry"):
        clean.execute_clean(plan, output_path=root, before_delete=relocate)
    assert (candidate / "data").read_text() == "run data"
    assert (registry_home.sessions_dir() / "state.json").read_text() == "new operator state"
    assert plan["deleted"] == [] and plan["freed_bytes"] == 0


def test_cleanup_of_unrelated_output_still_succeeds(tmp_path, monkeypatch):
    root = tmp_path / "project"
    candidate = root / "old-run"
    candidate.mkdir(parents=True)
    monkeypatch.setattr(clean, "run_is_live", lambda path: False)
    plan = {"delete_dirs": [candidate]}
    clean.execute_clean(plan, output_path=root)
    assert not candidate.exists()
    assert plan["deleted"] == [candidate.name]


@pytest.fixture
def archive(tmp_path):
    path = tmp_path / "input.zip"
    with zipfile.ZipFile(path, "w") as output:
        output.writestr("demo/.project.json", json.dumps({
            "version": 1, "name": "demo", "target": "(imported)",
        }))
        output.writestr("demo/data", "imported data")
    return path


@pytest.mark.parametrize("kind", ["explicit", "configured"])
def test_force_import_retains_registry_before_unregistering_project(archive, tmp_path, monkeypatch, kind):
    output_base = tmp_path / "output"
    root = output_base / "demo"
    projects = root / "registry" if kind == "explicit" else tmp_path / "registry"
    manager = model.ProjectManager(projects_dir=projects)
    manager.create("demo", "(imported)", output_dir=str(root), resolve_target=False)
    manager.create("other", "(imported)", output_dir=str(output_base / "other"), resolve_target=False)
    if kind == "configured":
        monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(root / "operator"))
        protected = registry_home.sessions_dir()
        protected.mkdir(parents=True)
        (protected / "state.json").write_text("session state")
    (root / "local-data").write_text("keep local data")
    before = {path.name: path.read_bytes() for path in projects.glob("*.json")}
    with pytest.raises(ValueError, match="overlaps operator registry"):
        export.import_project(archive, projects, output_base=output_base, force=True)
    assert (root / "local-data").read_text() == "keep local data"
    assert {path.name: path.read_bytes() for path in projects.glob("*.json")} == before
    assert not list(output_base.glob(".import-*"))
    if kind == "configured":
        assert (protected / "state.json").read_text() == "session state"


def test_new_import_cannot_claim_future_registry_parent(archive, tmp_path, monkeypatch):
    output_base = tmp_path / "output"
    root = output_base / "demo"
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(root / "operator"))
    with pytest.raises(ValueError, match="overlaps operator registry"):
        export.import_project(archive, tmp_path / "registry", output_base=output_base)
    assert not root.exists()
    assert not list(output_base.glob(".import-*"))


def test_sources_sweep_cannot_reap_an_operator_registry(tmp_path, monkeypatch):
    root = tmp_path / "project"
    cache = root / "_sources" / ("archive-" + "a" * 64)
    monkeypatch.setenv(registry_home.ENV_REGISTRY_HOME, str(cache / "operator"))
    protected = registry_home.sessions_dir()
    protected.mkdir(parents=True)
    (protected / "state.json").write_text("session state")
    old = time.time() - 2 * clean._SOURCES_SWEEP_GRACE_SECONDS
    os.utime(cache, (old, old))
    project = model.Project(name="demo", target=str(tmp_path / "target"), output_dir=str(root))
    plan = clean.plan_sources_sweep(project)
    assert plan["delete_dirs"] == [cache]
    with pytest.raises(ValueError, match="overlaps operator registry"):
        clean.execute_sources_sweep(project, plan)
    assert (protected / "state.json").read_text() == "session state"
