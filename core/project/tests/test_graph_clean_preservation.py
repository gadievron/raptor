"""Persistent project graph storage is never a run or a clean victim."""

import os

import pytest

from core.project.clean import clean_project, plan_clean
from core.project.project import Project
from core.run.metadata import generate_run_metadata
from core.testing.state_isolation import pin_user_state_dirs
from core.understand_graph import graph_summary, ingest_run
from core.understand_graph.tests.test_validates_join import _write_two_flow_run


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path / "user")
        patch.setenv("HOME", str(tmp_path / "home"))
        patch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
        patch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
        patch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
        yield


@pytest.fixture
def monkeypatch(_user_state_in_tmp):
    with pytest.MonkeyPatch.context() as patch:
        yield patch


def _project_graph(tmp_path):
    output, target, run = tmp_path / "project", tmp_path / "target", tmp_path / "seed"
    _write_two_flow_run(run, target)
    graph = output / "graph" / "raptor.graph.sqlite"
    assert ingest_run(run, str(target), graph_path=graph) == graph
    project = Project(name="fixture", target=str(target), output_dir=str(output))
    return project, graph


@pytest.mark.parametrize("legacy_stamp", [False, True])
def test_graph_directory_is_not_enumerated_or_stamped_as_a_run(tmp_path, legacy_stamp):
    project, graph = _project_graph(tmp_path)
    if legacy_stamp:
        generate_run_metadata(graph.parent)
    assert graph.parent not in project.get_run_dirs()
    assert all(graph.parent not in dirs for dirs in project.get_run_dirs_by_type().values())
    assert (graph.parent / ".raptor-run.json").exists() == legacy_stamp


def test_clean_keeps_old_graph_and_removes_only_old_runs(tmp_path):
    project, graph = _project_graph(tmp_path)
    # Model metadata stamped by older project enumeration, before graph/
    # was recognised as generated storage. Newer unknown runs must not
    # turn that historic misclassification into graph deletion.
    generate_run_metadata(graph.parent)
    os.utime(graph.parent, (100, 100))
    for stamp, name in [(200, "legacy-old"), (300, "legacy-new")]:
        run = project.output_path / name
        run.mkdir()
        generate_run_metadata(run)
        os.utime(run, (stamp, stamp))
    before = graph.read_bytes()
    assert graph.parent not in plan_clean(project, keep=1)["delete_dirs"]
    result = clean_project(project, keep=1)
    assert result["deleted"] == ["legacy-old"]
    assert graph.read_bytes() == before
    assert graph_summary(graph)["exists"]
